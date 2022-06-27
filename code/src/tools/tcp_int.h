/* Copyright 2021-2022 Intel Corporation */
/* SPDX-License-Identifier:  Apache-2.0 */

#ifndef __TCP_INT_H
#define __TCP_INT_H

/* Default paths and config */
#define TCP_INT_BPF_PIN_PATH "/sys/fs/bpf/tcp-int"
#define TCP_INT_CGROUP_BASE_PATH                                               \
    "/sys/fs/cgroup/" // The base path is used for user input validation
#define TCP_INT_CGROUP_PATH TCP_INT_CGROUP_BASE_PATH "cgroup.tcp-int"
#define TCP_INT_PERF_BUFFER_PAGES 16
#define TCP_INT_PERF_POLL_TIMEOUT_MS 100
#define TCP_INT_HIST_MAX_EXTRA_HEADER_LEN 50

/* Exit return codes */
#define TCP_INT_OK 0
#define TCP_INT_ERR_BPF 40
#define TCP_INT_ERR_SYS 41

#endif /* __TCP_INT_H */
