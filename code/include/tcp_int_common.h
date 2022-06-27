/* Copyright 2021-2022 Intel Corporation */
/* SPDX-License-Identifier:  Apache-2.0 */

#ifndef __TCP_INT_COMMON_H
#define __TCP_INT_COMMON_H

#include <tcp_int_opt.h>

#define TCP_INT_BYTES_IN_KBYTE 1024
#define TCP_INT_HIST_MAX_SLOTS 256
#define TCP_INT_MAX_PERID_HISTS (TCP_INT_TTL_INIT + 1)
#define TCP_INT_MAX_UTIL_PERCENT 100
#define TCP_INT_MAX_UTIL_SCALED 0x7f
#define TCP_INT_MIN_QDEPTH_SCALED 0x80
#define TCP_INT_MAX_CGROUP_PATH_LEN 128

#define tcp_int_swlat_to_us(x) ((x) * ((1 << TCP_INT_SWLAT_BITSHIFT) / 1000.0))

struct tcp_int_event {
    __u64 ts_us;
    __u32 family;
    __u16 sport;
    __u16 dport;
    union {
        __u8 saddr;
        __u32 saddr_v4;
        __u32 saddr_v6[4];
    };
    union {
        __u8 daddr;
        __u32 daddr_v4;
        __u32 daddr_v6[4];
    };
    __u32 snd_cwnd;
    __u32 srtt_us;
    __u32 rate_delivered;
    __u32 rate_interval_us;
    __u32 mss;
    __u32 lost_out;
    tcp_int_val intval;
    tcp_int_id sid;
    __u32 swlat;
    __u32 return_swlat;
} __attribute__((packed));
;

enum tcp_int_hist_type {
    TCP_INT_HIST_TYPE_SRTT = 0,
    TCP_INT_HIST_TYPE_CWND,
    TCP_INT_HIST_TYPE_SID,
    TCP_INT_HIST_TYPE_UTIL,
    TCP_INT_HIST_TYPE_QDEPTH,
    TCP_INT_HIST_TYPE_SWLAT,
    TCP_INT_HIST_TYPE_MAX
};

enum tcp_int_config_key {
    TCP_INT_CONFIG_KEY_GLOBAL_ENABLE = 1,
    TCP_INT_CONFIG_KEY_HIST_ENABLE,
    TCP_INT_CONFIG_KEY_TRACE_ENABLE,
    TCP_INT_CONFIG_KEY_ECR_DISABLE,
    TCP_INT_CONFIG_KEY_CGROUP_PATH
};

typedef union {
    __u64 u64;
    struct {
        char cbuf[TCP_INT_MAX_CGROUP_PATH_LEN];
    };
} tcp_int_config_value;

struct tcp_int_hist {
    __u32 slots[TCP_INT_HIST_MAX_SLOTS];
};

struct tcp_int_hist_perid {
    struct tcp_int_hist hist[TCP_INT_MAX_PERID_HISTS];
};

static inline bool tcp_int_ival_is_qdepth(tcp_int_val ival)
{
    return (ival >= TCP_INT_MIN_QDEPTH_SCALED);
}

static inline __u32 tcp_int_ival_to_util_scaled(tcp_int_val ival)
{
    return tcp_int_ival_is_qdepth(ival) ? TCP_INT_MAX_UTIL_SCALED : ival;
}

static inline __u32 tcp_int_ival_to_qdepth_scaled(tcp_int_val ival)
{
    return tcp_int_ival_is_qdepth(ival) ? (ival & TCP_INT_MAX_UTIL_SCALED) : 0;
}

static inline __u32 tcp_int_ival_to_util(tcp_int_val ival)
{
    return tcp_int_ival_is_qdepth(ival) ? 100 : (ival << TCP_INT_UTIL_BITSHIFT);
}

static inline __u32 tcp_int_ival_to_qdepth(tcp_int_val ival)
{
    return tcp_int_ival_to_qdepth_scaled(ival) << TCP_INT_QDEPTH_BITSHIFT;
}

#endif /* __TCP_INT_COMMON_H */
