/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __TCP_INT_COMMON_BPF_H
#define __TCP_INT_COMMON_BPF_H

#include <bpf/bpf_helpers.h>
#include "tcp_int_opt.h"

#ifdef TCP_INT_DEBUG
#define tcp_int_printk(...) bpf_printk(__VA_ARGS__)
#else
#define tcp_int_printk(...)
#endif /* TCP_INT_DEBUG */

/* TCP INT state definition */
struct tcp_int_state {
    bool pending_ecr;         /* Indicates pending echo request */
    tcp_int_val intvalecr;    /* INT value to be echoed back (network order) */
    tcp_int_id idecr;         /* ID to be echoed back (network order) */
    __u32 qdepth;             /* Queue depth in data path */
    tcp_int_latecr hoplatecr; /* Sum of hop latencies on data path */
};

/* Attaches INT state to socket */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct tcp_int_state);
} map_tcp_int_state SEC(".maps");

static inline struct tcp_int_state *tcp_int_get_state(struct bpf_sock *sk)
{
    if (!sk)
        return NULL;

    return bpf_sk_storage_get(&map_tcp_int_state, sk, NULL,
                              BPF_SK_STORAGE_GET_F_CREATE);
}

#endif /* __TCP_INT_COMMON_BPF_H */
