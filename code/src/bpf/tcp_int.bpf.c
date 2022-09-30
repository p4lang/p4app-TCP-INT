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
    /* XXX bit-fields are sent in reverse on the wire: */
    unsigned linkspeed : 4;
    unsigned tagfreqkey : 4;
    tcp_int_val intval;
    tcp_int_id id;
    tcp_int_lat hoplat;
    tcp_int_val intvalecr;
    unsigned linkspeedecr : 4;
    unsigned idecr : 4;
    tcp_int_latecr hoplatecr;
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
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, TCP_INT_NUM_CPUS);
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

/* Per hop-ID histograms */
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

static inline int tcp_int_is_mode_hist(void)
{
    int key = TCP_INT_CONFIG_KEY_HIST_ENABLE;
    tcp_int_config_value *ptr_enabled;

    ptr_enabled = bpf_map_lookup_elem(&map_tcp_int_config, &key);
    if (ptr_enabled)
        return ptr_enabled->u64;
    return 0;
}

static inline void tcp_int_update_hist(enum tcp_int_hist_type type,
                                       tcp_int_id hid, __u64 val, bool linear)
{
    struct tcp_int_hist_perid *hist_perid_ptr;
    struct tcp_int_hist *hist_ptr;
    __u64 slot;

    hist_perid_ptr = bpf_map_lookup_elem(&map_tcp_int_hists_perid, &type);
    hist_ptr = bpf_map_lookup_elem(&map_tcp_int_hists, &type);
    if (!hist_perid_ptr || !hist_ptr) {
        return;
    }

    if (hid >= TCP_INT_MAX_PERID_HISTS) {
        hid = TCP_INT_MAX_PERID_HISTS - 1;
    }

    slot = linear ? val : log2l(val);
    if (slot >= TCP_INT_HIST_MAX_SLOTS) {
        slot = TCP_INT_HIST_MAX_SLOTS - 1;
    }
    __sync_fetch_and_add(&(hist_perid_ptr->hist[hid].slots[slot]), 1);
    __sync_fetch_and_add(&hist_ptr->slots[slot], 1);
}

static inline void tcp_int_add_tcpopt(struct bpf_sock_ops *skops,
                                      struct tcp_int_state *istate)
{
    struct tcp_int_opt iopt = {0};
    __u64 val;

    iopt.kind = TCP_INT_OPT_KIND;
    iopt.len = sizeof(iopt);
    iopt.intvalecr = istate->intvalecr;
    iopt.idecr = istate->idecr;
    iopt.hoplatecr = istate->hoplatecr;

#if TCP_INT_ENABLE_DYNAMIC_TAGGING
    if (skops->packets_out < 1)
        iopt.tagfreqkey = TCP_INT_TAGFREQKEY_APPLIMITED;
    else if (istate->qdepth > TCP_INT_CONG_QDEPTH_THRESH)
        iopt.tagfreqkey = TCP_INT_TAGFREQKEY_CONGESTED;
    else
        iopt.tagfreqkey = TCP_INT_TAGFREQKEY_UNCONGESTED;
#else
    iopt.tagfreqkey = TCP_INT_TAGFREQKEY_SWITCH_DEFAULT;
#endif // TCP_INT_ENABLE_DYNAMIC_TAGGING

    bpf_store_hdr_opt(skops, &iopt, sizeof(iopt), 0);

    if (tcp_int_is_mode_hist()) {
        val = skops->skb_len >> TCP_INT_SKBLEN_BITSHIFT;
        tcp_int_update_hist(TCP_INT_HIST_TYPE_TXSKBLEN, iopt.idecr, val, true);
    }
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
        case TCP_INT_HIST_TYPE_HID:
            val = iopt->idecr;
            linear = true;
            break;
        case TCP_INT_HIST_TYPE_HLAT:
            val = tcp_int_hoplatecr_to_ns(iopt->hoplatecr);
            linear = false;
            break;
        case TCP_INT_HIST_TYPE_RXSKBLEN:
            val = skops->skb_len >> TCP_INT_SKBLEN_BITSHIFT;
            linear = true;
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
    event.hid = iopt->idecr;
    event.hoplat = iopt->hoplatecr;
    event.return_hoplat = be24tohl(iopt->hoplat.u24);
    event.segs_out = skops->segs_out;
    event.bytes_acked = skops->bytes_acked;
    event.total_retrans = skops->total_retrans;
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
    bool _tcp_int_is_enabled; /* Optimization: cache tcp_int_is_enabled() */
    int rv;

    iopt.kind = TCP_INT_OPT_KIND;

    rv = bpf_load_hdr_opt(skops, &iopt, sizeof(iopt), 0);
    if (rv != sizeof(iopt)) {
        return;
    }

    /* Request echo only if there is an update */
    if (iopt.id) {
        istate->intvalecr = iopt.intval;
        istate->idecr = tcp_int_id_to_idecr(iopt.id);
        istate->hoplatecr =
            tcp_int_hoplat_to_hoplatecr(be24tohl(iopt.hoplat.u24));
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

    _tcp_int_is_enabled = tcp_int_is_enabled();
    if (_tcp_int_is_enabled && tcp_int_is_mode_hist()) {
        tcp_int_update_hists(skops, &iopt);
    }
    if (_tcp_int_is_enabled && tcp_int_is_mode_trace()) {
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
