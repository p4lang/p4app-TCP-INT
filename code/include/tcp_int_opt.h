/* Copyright 2021 Intel Corporation */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __TCP_INT_OPT_H
#define __TCP_INT_OPT_H

struct uint24 {
    unsigned u24 : 24;
} __attribute__((packed));

/* TCP INT option definitions */
typedef __u8 tcp_int_val;
typedef __u8 tcp_int_id;
typedef struct uint24 tcp_int_lat;
typedef __u16 tcp_int_latecr;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be24tohl(x) (bpf_ntohl((x) << 8))
#else
#define be24tohl(x) (x)
#endif

#define TCP_INT_UTIL_BITSHIFT 3
#define TCP_INT_QDEPTH_BITSHIFT 13
#define TCP_INT_HLAT_BITSHIFT 8
#define TCP_INT_MIN_AVAILBW_SCALED 0x7f
#define TCP_INT_MIN_QDEPTH_SCALED 0x80
#define TCP_INT_TTL_INIT 64
#define TCP_INT_MAX_SKBLEN 65536

#endif /* __TCP_INT_OPT_H */
