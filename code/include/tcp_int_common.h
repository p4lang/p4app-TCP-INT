/* Copyright 2021-2022 Intel Corporation */
/* SPDX-License-Identifier:  Apache-2.0 */

#ifndef __TCP_INT_COMMON_H
#define __TCP_INT_COMMON_H

#include <tcp_int_opt.h>

#define TCP_INT_ENABLE_DYNAMIC_TAGGING 0
#define TCP_INT_CONG_QDEPTH_THRESH 10000
#define TCP_INT_TAGFREQKEY_SWITCH_DEFAULT 0xf
#define TCP_INT_TAGFREQKEY_APPLIMITED 0
#define TCP_INT_TAGFREQKEY_CONGESTED 4
#define TCP_INT_TAGFREQKEY_UNCONGESTED 7

#define TCP_INT_BYTES_IN_KBYTE 1024
#define TCP_INT_HIST_MAX_SLOTS 256
#define TCP_INT_MAX_PERID_HISTS (TCP_INT_TTL_INIT + 1)
#define TCP_INT_MIN_QDEPTH_SCALED 0x80
#define TCP_INT_MAX_CGROUP_PATH_LEN 128
#define TCP_INT_SKBLEN_BITSHIFT 8

/* HopLat is the upper 24 bits of a 32-bit unsigned that represents the sum of
 * hop latencies in ns. On the switch, HopLat is shifted up to perform
 * saturating addition, and then shifed back down before sending it to the next
 * hop/host.
 *
 * HopLatEcr is a 16-bit encoding (compression) of the 24-bit HopLat. If HopLat
 * overflows 15 bits, the tcp_int_hoplat_to_hoplatecr() macro shifts HopLat down
 * 8 bits and stores it in HopLatEcr with MSB set to 1, indicating that
 * HopLatEcr contains the shifted HopLat.
 *
 * N.B. These macros assume host order. The caller should convert the argument
 * to host order before using this macro.
 */
#define tcp_int_hoplatecr_to_ns(x)                                             \
    (((x)&0x8000) ? ((__u32)(x) << (TCP_INT_HLAT_BITSHIFT * 2))                \
                  : ((__u32)(x) << TCP_INT_HLAT_BITSHIFT))
#define tcp_int_hoplat_to_hoplatecr(x)                                         \
    (((x)&0xff8000) ? (((x) >> TCP_INT_HLAT_BITSHIFT) | 0x8000) : (x))

/* Id is a 8-bit field that identifies the most congested hop. On the switch, Id
 * is set to the packet's current TTL value. Thus, the Id decreases as the
 * packet traverses the hops.
 *
 * IdEcr is a 4-bit field that also identifies the congested hop, but in
 * ascending order, starting from 1 for the first hop. 0 indicates uninitialized
 * Ecr data.
 *
 * N.B. Because IdEcr is 4 bits (and 0 indicates uninitialized), it cannot be
 * used for paths longer than 15 hops.
 */
#define tcp_int_id_to_idecr(x) (TCP_INT_TTL_INIT - (x))

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
    tcp_int_id hid;
    __u32 hoplat;
    __u32 return_hoplat;
    __u32 segs_out;
    __u64 bytes_acked;
    __u32 total_retrans;
    __u8 link_speed;
} __attribute__((packed));
;

enum tcp_int_hist_type {
    TCP_INT_HIST_TYPE_SRTT = 0,
    TCP_INT_HIST_TYPE_CWND,
    TCP_INT_HIST_TYPE_HID,
    TCP_INT_HIST_TYPE_AVAILBW,
    TCP_INT_HIST_TYPE_QDEPTH,
    TCP_INT_HIST_TYPE_HLAT,
    TCP_INT_HIST_TYPE_RXSKBLEN,
    TCP_INT_HIST_TYPE_TXSKBLEN,
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

static inline __u32 tcp_int_ival_to_qdepth_scaled(tcp_int_val ival)
{
    return tcp_int_ival_is_qdepth(ival) ? (ival & TCP_INT_MIN_AVAILBW_SCALED)
                                        : 0;
}

static inline __u32 tcp_int_ival_to_qdepth(tcp_int_val ival)
{
    return tcp_int_ival_to_qdepth_scaled(ival) << TCP_INT_QDEPTH_BITSHIFT;
}

static inline __u32 tcp_int_ival_to_avail_bw(tcp_int_val ival)
{
    return tcp_int_ival_is_qdepth(ival) ? 0
                                        : (TCP_INT_MIN_AVAILBW_SCALED - ival);
}

static inline __u32 tcp_int_unmap_link_speed(__u8 mapped_link_speed)
{
    switch (mapped_link_speed) {
    case 1:
        return 10;
    case 2:
        return 25;
    case 3:
        return 40;
    case 4:
        return 50;
    case 5:
        return 100;
    case 6:
        return 200;
    case 7:
        return 400;
    default:
        return 0;
    }
}

#endif /* __TCP_INT_COMMON_H */
