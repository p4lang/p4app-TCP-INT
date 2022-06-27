/* Copyright (C) 2021-2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tcp_int_opt.h"
#include "tcp_int_common.h"
#include "tcp_int_common.bpf.h"
#include "bits.bpf.h"

/* TCP INT option definition */
#define TCP_INT_OPT_KIND 0x72
struct tcp_int_opt {
    __u8 kind;
    __u8 len;
    tcp_int_val intval;
    tcp_int_val intvalecr;
    tcp_int_id id;
    tcp_int_id idecr;
    tcp_int_lat swlat;
    tcp_int_lat swlatecr;
} __attribute__((packed));

/* TCP INT configuration map */
#define TCP_INT_MAP_CONFIG_MAX_ENTRIES 16
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TCP_INT_MAP_CONFIG_MAX_ENTRIES);
    __type(key, __u16);
    __type(value, tcp_int_config_value);
} map_tcp_int_config SEC(".maps");

/* Perf events to user space */
#define TCP_INT_MAX_CPUS 256
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, TCP_INT_MAX_CPUS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} map_tcp_int_events SEC(".maps");

/* Histograms */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TCP_INT_HIST_TYPE_MAX);
    __type(key, enum tcp_int_hist_type);
    __type(value, struct tcp_int_hist);
} map_tcp_int_hists SEC(".maps");

/* Per switch-ID histograms */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TCP_INT_MAX_PERID_HISTS);
    __type(key, enum tcp_int_hist_type);
    __type(value, struct tcp_int_hist_perid);
} map_tcp_int_hists_perid SEC(".maps");

static inline void tcp_int_enable_tcp_opt_cb(struct bpf_sock_ops *skops)
{
    int cb_flags;

    cb_flags = skops->bpf_sock_ops_cb_flags |
               BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG |
               BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG;
    bpf_sock_ops_cb_flags_set(skops, cb_flags);
}

static inline void tcp_int_reserve_hdr_opt(struct bpf_sock_ops *skops,
                                           __u32 size)
{
    bpf_reserve_hdr_opt(skops, size, 0);
}

static inline void tcp_int_add_tcpopt(struct bpf_sock_ops *skops,
                                      struct tcp_int_state *istate)
{
    struct tcp_int_opt iopt = {0};

    iopt.kind = TCP_INT_OPT_KIND;
    iopt.len = sizeof(iopt);
    iopt.intvalecr = istate->intvalecr;
    iopt.idecr = istate->idecr;
    iopt.swlatecr.u24 = istate->swlatecr.u24;

    bpf_store_hdr_opt(skops, &iopt, sizeof(iopt), 0);
}

static inline void tcp_int_update_hist(enum tcp_int_hist_type type,
                                       tcp_int_id sid, __u64 val, bool linear)
{
    struct tcp_int_hist_perid *hist_perid_ptr;
    struct tcp_int_hist *hist_ptr;
    __u64 slot;

    hist_perid_ptr = bpf_map_lookup_elem(&map_tcp_int_hists_perid, &type);
    hist_ptr = bpf_map_lookup_elem(&map_tcp_int_hists, &type);
    if (!hist_perid_ptr || !hist_ptr) {
        return;
    }

    if (sid >= TCP_INT_MAX_PERID_HISTS) {
        sid = TCP_INT_MAX_PERID_HISTS - 1;
    }

    slot = linear ? val : log2l(val);
    if (slot >= TCP_INT_HIST_MAX_SLOTS) {
        slot = TCP_INT_HIST_MAX_SLOTS - 1;
    }
    __sync_fetch_and_add(&(hist_perid_ptr->hist[sid].slots[slot]), 1);
    __sync_fetch_and_add(&hist_ptr->slots[slot], 1);
}

static void tcp_int_update_hists(struct bpf_sock_ops *skops,
                                 struct tcp_int_opt *iopt)
{
    enum tcp_int_hist_type type;
    bool linear;
    __u64 val;

    for (type = 0; type < TCP_INT_HIST_TYPE_MAX; type++) {
        switch (type) {
        case TCP_INT_HIST_TYPE_SRTT:
            val = skops->srtt_us >> 3;
            linear = false;
            break;
        case TCP_INT_HIST_TYPE_CWND:
            val = skops->snd_cwnd;
            linear = false;
            break;
        case TCP_INT_HIST_TYPE_UTIL:
            val = tcp_int_ival_to_util_scaled(iopt->intvalecr);
            linear = true;
            break;
        case TCP_INT_HIST_TYPE_QDEPTH:
            val = tcp_int_ival_to_qdepth(iopt->intvalecr) /
                  TCP_INT_BYTES_IN_KBYTE;
            linear = false;
            break;
        case TCP_INT_HIST_TYPE_SID:
            val = iopt->idecr;
            linear = true;
            break;
        case TCP_INT_HIST_TYPE_SWLAT:
            val = be24tohl(iopt->swlatecr.u24)
                  << TCP_INT_SWLAT_BITSHIFT; // shift back to nanoseconds;
            linear = false;
            break;
        default:
            continue;
        }
        tcp_int_update_hist(type, iopt->idecr, val, linear);
    }
}

static void tcp_int_send_event(struct bpf_sock_ops *skops,
                               struct tcp_int_opt *iopt)
{
    struct tcp_int_event event = {0};

    event.ts_us = bpf_ktime_get_ns() / 1000;
    event.dport = bpf_ntohl(skops->remote_port);
    event.sport = skops->local_port;
    event.family = skops->family;
    event.saddr_v4 = skops->local_ip4;
    event.daddr_v4 = skops->remote_ip4;
    /* TODO add ipv6 support */
    event.snd_cwnd = skops->snd_cwnd;
    event.srtt_us = skops->srtt_us;
    event.rate_delivered = skops->rate_delivered;
    event.rate_interval_us = skops->rate_interval_us;
    event.mss = skops->mss_cache;
    event.lost_out = skops->lost_out;
    event.intval = iopt->intvalecr;
    event.sid = iopt->idecr;
    event.swlat = be24tohl(iopt->swlatecr.u24);
    event.return_swlat = be24tohl(iopt->swlat.u24);

    bpf_perf_event_output(skops, &map_tcp_int_events, BPF_F_CURRENT_CPU, &event,
                          sizeof(event));
}

static inline int tcp_int_is_ecr_enabled(void)
{
    int key = TCP_INT_CONFIG_KEY_ECR_DISABLE;
    tcp_int_config_value *ptr_enabled;

    ptr_enabled = bpf_map_lookup_elem(&map_tcp_int_config, &key);
    if (ptr_enabled)
        return !(ptr_enabled->u64);
    return 1;
}

static inline int tcp_int_is_mode_hist(void)
{
    int key = TCP_INT_CONFIG_KEY_HIST_ENABLE;
    tcp_int_config_value *ptr_enabled;

    ptr_enabled = bpf_map_lookup_elem(&map_tcp_int_config, &key);
    if (ptr_enabled)
        return ptr_enabled->u64;
    return 0;
}

static inline int tcp_int_is_mode_trace(void)
{
    int key = TCP_INT_CONFIG_KEY_TRACE_ENABLE;
    tcp_int_config_value *ptr_enabled;

    ptr_enabled = bpf_map_lookup_elem(&map_tcp_int_config, &key);
    if (ptr_enabled)
        return ptr_enabled->u64;
    return 0;
}

static inline int tcp_int_is_enabled(void)
{
    int key = TCP_INT_CONFIG_KEY_GLOBAL_ENABLE;
    tcp_int_config_value *ptr_enabled;

    ptr_enabled = bpf_map_lookup_elem(&map_tcp_int_config, &key);
    if (ptr_enabled)
        return ptr_enabled->u64;
    return 0;
}

static inline void tcp_int_process_tcpopt(struct bpf_sock_ops *skops,
                                          struct tcp_int_state *istate)
{
    struct tcp_int_opt iopt = {};
    int rv;

    iopt.kind = TCP_INT_OPT_KIND;

    rv = bpf_load_hdr_opt(skops, &iopt, sizeof(iopt), 0);
    if (rv != sizeof(iopt)) {
        return;
    }

    /* Request echo only if there is an update */
    if (iopt.id) {
        istate->intvalecr = iopt.intval;
        istate->idecr = iopt.id;
        istate->swlatecr.u24 = iopt.swlat.u24;
        istate->pending_ecr = true;
    }

    /* Ignore local events with no updates */
    if (iopt.idecr == 0) {
        return;
    }

    /* qdepth = qdepth_old * 7/8 + qdepth_new * 1/7 */
    istate->qdepth -= (istate->qdepth >> 3);
    istate->qdepth =
        istate->qdepth + (tcp_int_ival_to_qdepth(iopt.intvalecr) >> 3);

    if (tcp_int_is_enabled() && tcp_int_is_mode_hist()) {
        tcp_int_update_hists(skops, &iopt);
    }
    if (tcp_int_is_enabled() && tcp_int_is_mode_trace()) {
        tcp_int_send_event(skops, &iopt);
    }
}

SEC("sockops")
int tcp_int(struct bpf_sock_ops *skops)
{
    struct tcp_int_state *istate;

    istate = tcp_int_get_state(skops->sk);
    if (!istate)
        return 1;

    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        tcp_int_enable_tcp_opt_cb(skops);
        break;
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        if (tcp_int_is_enabled() ||
            (tcp_int_is_ecr_enabled() && istate->pending_ecr)) {
            tcp_int_reserve_hdr_opt(skops, sizeof(struct tcp_int_opt));
        }
        break;
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
        if (tcp_int_is_enabled() ||
            (tcp_int_is_ecr_enabled() && istate->pending_ecr)) {
            tcp_int_add_tcpopt(skops, istate);
            istate->pending_ecr = false;
        }
        break;
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
        tcp_int_process_tcpopt(skops, istate);
        break;
    default:
        break;
    }

    return 1;
}

char _license[] SEC("license") = "GPL";
