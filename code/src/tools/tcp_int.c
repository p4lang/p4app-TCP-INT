/* Copyright 2021-2022 Intel Corporation */
/* SPDX-License-Identifier:  Apache-2.0 */

/* Copyright (c) 2020 Wenbo Zhang */
/* https://github.com/iovisor/bcc/blob/master/libbpf-tools/trace_helpers.c */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <bpf/bpf.h>
#include "tcp_int.h"
#include "tcp_int_common.h"
#include "bpf/tcp_int.skel.h"

static volatile sig_atomic_t tcp_int_exiting = 0;

static const char *tcp_int_doc =
    "Trace TCP congestion.\n"
    "\n"
    "USAGE: tcp_int [load,run,unload,help] [-d]\n"
    "\n"
    "EXAMPLES:\n"
    "    tcp_int load                                   # Loads tcp_int and "
    "related BPF programs with the default cgroup path\n"
    "    tcp_int load -c {path}                         # Loads tcp_int and "
    "related BPF programs with a custom cgroup2 mountpoint\n"
    "    tcp_int enable                                 # Enables tcp-int "
    "option handling\n"
    "    tcp_int trace                                  # Enables tcp-int and "
    "starts tracing\n"
    "    tcp_int hist                                   # Enables tcp-int and "
    "start histograming (all histograms)\n"
    "    tcp_int hist-int                               # Enables tcp-int and "
    "start histograming (INT-related histograms)\n"
    "    tcp_int hist-int-perid                         # Enables tcp-int and "
    "start histograming (INT-related histograms per hop ID)\n"
    "    tcp_int hist-[rtt,cwnd,qdepth,util,hoplat,\n"
    "                  hid,rxskblen,txskblen]           # Enables tcp-int and "
    "start histograming (selected histogram)\n"
    "    tcp_int ecr-enable                             # Enables echo replies "
    "(default = enabled)\n"
    "    tcp_int ecr-disable                            # Disables echo "
    "replies\n"
    "    tcp_int events-enable                          # Enables perf events "
    "(default = disabled)\n"
    "    tcp_int events-disable                         # Disables perf "
    "events\n"
    "    tcp_int disable                                # Disables tcp-int "
    "option handling\n"
    "    tcp_int unload                                 # Unloads all tcp_int "
    "BPF programs\n"
    "    tcp_int unload -d                              # Unloads all tcp_int "
    "BPF programs with debug enabled\n"
    "    tcp_int help                                   # Prints help "
    "message\n";

enum tcp_int_object_type {
    TCP_INT_OBJECT_SOCKOPS = 0,
    TCP_INT_OBJECT_MAP_STATE,
    TCP_INT_OBJECT_MAP_CONFIG,
    TCP_INT_OBJECT_MAP_EVENTS,
    TCP_INT_OBJECT_MAP_HISTS,
    TCP_INT_OBJECT_MAP_HISTS_PERID,
    TCP_INT_OBJECT_LINK_CGROUP,
    TCP_INT_OBJECT_MAX
};

static const char tcp_int_bpf_object_paths[][50] = {
    [TCP_INT_OBJECT_SOCKOPS] = TCP_INT_BPF_PIN_PATH "/sockops",
    [TCP_INT_OBJECT_MAP_STATE] = TCP_INT_BPF_PIN_PATH "/map_tcp_int_state",
    [TCP_INT_OBJECT_MAP_CONFIG] = TCP_INT_BPF_PIN_PATH "/map_tcp_int_config",
    [TCP_INT_OBJECT_MAP_EVENTS] = TCP_INT_BPF_PIN_PATH "/map_tcp_int_events",
    [TCP_INT_OBJECT_MAP_HISTS] = TCP_INT_BPF_PIN_PATH "/map_tcp_int_hists",
    [TCP_INT_OBJECT_MAP_HISTS_PERID] =
        TCP_INT_BPF_PIN_PATH "/map_tcp_int_hists_perid",
    [TCP_INT_OBJECT_LINK_CGROUP] = TCP_INT_BPF_PIN_PATH "/link_cgroup",
};

static const tcp_int_config_value TCP_INT_CONFIG_FALSE = {0};
static const tcp_int_config_value TCP_INT_CONFIG_TRUE = {1};

static void show_help(void) { fprintf(stdout, "%s", tcp_int_doc); }

#define min(x, y)                                                              \
    ({                                                                         \
        typeof(x) _min1 = (x);                                                 \
        typeof(y) _min2 = (y);                                                 \
        (void)(&_min1 == &_min2);                                              \
        _min1 < _min2 ? _min1 : _min2;                                         \
    })

static const char *validate_cgroup_path(const char *path)
{

    if (strlen(path) >= TCP_INT_MAX_CGROUP_PATH_LEN) {
        fprintf(stderr, "Cgroup path length is too long (max %d characters)\n",
                TCP_INT_MAX_CGROUP_PATH_LEN - 1);
        return NULL;
    }

    if (strncmp(path, TCP_INT_CGROUP_BASE_PATH,
                strlen(TCP_INT_CGROUP_BASE_PATH)) != 0) {
        fprintf(stderr,
                "Cgroup must be specified as an absolute path beginning with "
                "'%s'\n",
                TCP_INT_CGROUP_BASE_PATH);
        return NULL;
    }

    return path;
}

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
    int num_stars, num_spaces, i;
    bool need_plus;

    if (!val_max) {
        return;
    }

    num_stars = min(val, val_max) * width / val_max;
    num_spaces = width - num_stars;
    need_plus = val > val_max;

    for (i = 0; i < num_stars; i++)
        printf("*");
    for (i = 0; i < num_spaces; i++)
        printf(" ");
    if (need_plus)
        printf("+");
}

void print_linear_hist(unsigned int *vals, int vals_size, float base,
                       float step, int idx_min, int idx_max,
                       const char *val_type, bool norange)
{
    unsigned int val_max = 0;
    int i, j, stars_max = 40;
    unsigned int val = 0;
    bool fixed_max;

    fixed_max = (idx_max != -1);

    for (i = 0; i < vals_size; i++) {
        val = (fixed_max && (i > idx_max)) ? (val + vals[i]) : vals[i];
        if (val > 0) {
            if (!fixed_max && (idx_max < i)) {
                idx_max = i;
            }
            if (idx_min < 0)
                idx_min = i;
        }
        if (val > val_max)
            val_max = val;
    }

    if ((val_max == 0) || idx_max < 0)
        return;

    printf("     %-19s : count     distribution\n", val_type);
    for (i = idx_min; i <= idx_max; i++) {
        val = vals[i];
        if (fixed_max && i == idx_max) {
            for (j = i + 1; j < vals_size; j++) {
                val += vals[j];
            }
        }
        if (norange) {
            printf("%10.0f %-13s : %-8d |", base + i * step, "", val);
        } else if (fixed_max && i == idx_max) {
            printf("%10.1f -> %-10s : %-8d |", base + i * step, "INF", val);
        } else {
            printf("%10.1f -> %-10.1f : %-8d |", base + i * step,
                   base + (i + 1) * step, val);
        }
        print_stars(val, val_max, stars_max);
        printf("|\n");
    }
}

void print_log2_hist(unsigned int *vals, int vals_size, int idx_max,
                     const char *val_type)
{
    unsigned long long low, high;
    unsigned int val_max = 0;
    int stars, width, i, j;
    unsigned int val = 0;
    int stars_max = 40;
    bool fixed_max;

    fixed_max = (idx_max != -1);

    for (i = 0; i < vals_size; i++) {
        val = (fixed_max && (i > idx_max)) ? (val + vals[i]) : vals[i];
        if (val > 0)
            if (!fixed_max && (idx_max < i)) {
                idx_max = i;
            }
        if (val > val_max)
            val_max = val;
    }

    if ((val_max == 0) || idx_max < 0)
        return;

    printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
           idx_max <= 32 ? 19 : 29, val_type);

    if (idx_max <= 32)
        stars = stars_max;
    else
        stars = stars_max / 2;

    for (i = 0; i <= idx_max; i++) {
        low = (1ULL << (i + 1)) >> 1;
        high = (1ULL << (i + 1)) - 1;
        if (low == high)
            low -= 1;
        val = vals[i];
        if (fixed_max && i == idx_max) {
            for (j = i + 1; j < vals_size; j++) {
                val += vals[j];
            }
        }
        width = idx_max <= 32 ? 10 : 20;
        if (fixed_max && i == idx_max) {
            printf("%*lld -> %-*s : %-8d |", width, low, width, "INF", val);
        } else {
            printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
        }
        print_stars(val, val_max, stars);
        printf("|\n");
    }
}

static bool tcp_int_obj_is_loaded(enum tcp_int_object_type type)
{
    int fd;
    fd = bpf_obj_get(tcp_int_bpf_object_paths[type]);
    if (fd < 0) {
        return false;
    } else {
        close(fd);
        return true;
    }
}

static struct bpf_link *tcp_int_get_link(enum tcp_int_object_type type)
{
    struct bpf_link *link;
    int err;

    link = bpf_link__open(tcp_int_bpf_object_paths[type]);
    err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr,
                "Failed to get a link to the BPF object - %d. Verify it is "
                "loaded\n",
                err);
        return NULL;
    }

    return link;
}

static int tcp_int_get_fd(enum tcp_int_object_type type)
{
    int fd;

    fd = bpf_obj_get(tcp_int_bpf_object_paths[type]);
    if (fd < 0) {
        fprintf(
            stderr,
            "Failed to get an fd to the BPF object - %d. Verify it is loaded\n",
            fd);
        return -1;
    }

    return fd;
}

static int tcp_int_get_cgroup_fd(const char *path_val)
{
    int fd;

    if (mkdir(path_val, 0777) && errno != EEXIST) {
        fprintf(stderr, "Failed to create cgroup %s - %s.\n", path_val,
                strerror(errno));
        return -1;
    }

    fd = openat(0, path_val, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open cgroup %s - %d.\n", path_val, fd);
        return -1;
    }

    return fd;
}

static int tcp_int_attach_cgroup(struct tcp_int_bpf *tcp_in_obj,
                                 const char *path_val)
{
    struct bpf_link *cgroup_link;
    int err = TCP_INT_ERR_SYS;
    int cgroup_map_fd = -1;

    cgroup_map_fd = tcp_int_get_cgroup_fd(path_val);
    if (cgroup_map_fd == -1) {
        goto err;
    }

    cgroup_link =
        bpf_program__attach_cgroup(tcp_in_obj->progs.tcp_int, cgroup_map_fd);
    err = libbpf_get_error(cgroup_link);
    if (err) {
        fprintf(stderr, "Failed to attach to cgroup - %d.\n", err);
        goto err;
    }

    err = bpf_link__pin(cgroup_link,
                        tcp_int_bpf_object_paths[TCP_INT_OBJECT_LINK_CGROUP]);
    if (err < 0) {
        fprintf(stderr, "Failed to pin cgroup link - %d.\n", err);
        goto err;
    }

err:
    if (cgroup_map_fd != -1) {
        close(cgroup_map_fd);
    }

    return err;
}

static int tcp_int_set_config(__u16 cfg_key, tcp_int_config_value cfg_val)
{
    int err = TCP_INT_OK;
    int cfg_map;

    cfg_map = tcp_int_get_fd(TCP_INT_OBJECT_MAP_CONFIG);
    if (cfg_map < 0) {
        return TCP_INT_ERR_BPF;
    }

    err = bpf_map_update_elem(cfg_map, &cfg_key, &cfg_val, BPF_ANY);
    if (err < 0) {
        fprintf(stderr, "Failed to update TCP INT config. err code: %i\n", err);
        return TCP_INT_ERR_BPF;
    }

    return err;
}

static int tcp_int_get_config(__u16 cfg_key, tcp_int_config_value *ret_val)
{
    int err = TCP_INT_OK;
    int cfg_map;

    cfg_map = tcp_int_get_fd(TCP_INT_OBJECT_MAP_CONFIG);
    if (cfg_map < 0) {
        return -1;
    }

    err = bpf_map_lookup_elem(cfg_map, &cfg_key, ret_val);
    if (err < 0) {
        fprintf(stderr,
                "Failed to retrieve TCP-INT config state. err code: %i\n", err);
        return -1;
    }

    return err;
}

static int tcp_int_get_cgroup_path(char *path_buf)
{
    tcp_int_config_value cbuf_cfg_val;
    int err = TCP_INT_OK;

    err = tcp_int_get_config(TCP_INT_CONFIG_KEY_CGROUP_PATH, &cbuf_cfg_val);
    if (err) {
        return -1;
    }
    strncpy(path_buf, cbuf_cfg_val.cbuf, TCP_INT_MAX_CGROUP_PATH_LEN);

    return err;
}

static int tcp_int_set_cgroup_path(const char *path_val)
{
    tcp_int_config_value cbuf_cfg_val;
    int err = TCP_INT_OK;

    strncpy(cbuf_cfg_val.cbuf, path_val, TCP_INT_MAX_CGROUP_PATH_LEN - 1);
    err = tcp_int_set_config(TCP_INT_CONFIG_KEY_CGROUP_PATH, cbuf_cfg_val);

    return err;
}

static int tcp_int_remove_mountpoint(const char *mountpoint)
{
    int err;
    err = rmdir(mountpoint);

    /* Don't print a warning if mountpoint does not exist */
    if (err && errno != ENOENT) {
        fprintf(stderr,
                "Warning: Could not remove mountpoint %s. rmdir error: %s.\n",
                mountpoint, strerror(err));
    }
    return TCP_INT_OK;
}

static int tcp_int_bpf_detach_and_close(void)
{
    struct bpf_link *link;
    int destroy_count = 0;
    int err = TCP_INT_OK;
    int i;

    for (i = 0; i < TCP_INT_OBJECT_MAX; i++) {

        if (tcp_int_obj_is_loaded(i)) {
            link = tcp_int_get_link(i);
            if (!link) {
                err = TCP_INT_ERR_BPF;
                continue;
            }

            bpf_link__unpin(link);
            bpf_link__destroy(link);
            destroy_count++;
        }
    }

    if (err)
        fprintf(stderr, "Error unloading one or more TCP-INT BPF objects.\n"
                        "Verify it was loaded.\n");

    if (destroy_count == 0) {
        fprintf(
            stderr,
            "No TCP-INT BPF objects removed. Program was likely not loaded.\n");
    }

    return err;
}

static int tcp_int_unload(void)
{
    char cg_mountpoint[TCP_INT_MAX_CGROUP_PATH_LEN];
    int cg_err = TCP_INT_OK;
    int err = TCP_INT_OK;

    tcp_int_set_config(TCP_INT_CONFIG_KEY_GLOBAL_ENABLE, TCP_INT_CONFIG_FALSE);
    cg_err = tcp_int_get_cgroup_path(cg_mountpoint);
    err = tcp_int_bpf_detach_and_close();
    tcp_int_remove_mountpoint(TCP_INT_BPF_PIN_PATH);
    if (!cg_err) {
        tcp_int_remove_mountpoint(cg_mountpoint);
    }

    return err;
}

static int tcp_int_load(const char *cg_path)
{
    struct tcp_int_bpf *tcp_int_obj;
    bool pinned = false;
    int err;

    tcp_int_obj = tcp_int_bpf__open_and_load();
    if (!tcp_int_obj) {
        fprintf(stderr, "Failed to open and/or load main TCP-INT BPF object\n");
        return TCP_INT_ERR_BPF;
    }

    err = tcp_int_bpf__attach(tcp_int_obj);
    if (err) {
        fprintf(stderr, "Failed to attach main TCP-INT BPF object- %s\n",
                strerror(err));
        goto err;
    }

    err = bpf_object__pin(tcp_int_obj->obj, TCP_INT_BPF_PIN_PATH);
    if (err) {
        fprintf(stderr, "Failed to pin main TCP-INT BPF object- %s\n",
                strerror(err));
        goto err;
    }
    pinned = true;

    err = tcp_int_set_cgroup_path(cg_path);
    if (err) {
        fprintf(stderr, "Failed to store cgroup path in BPF map\n");
        goto err;
    }

    err = tcp_int_attach_cgroup(tcp_int_obj, cg_path);
    if (err) {
        fprintf(stderr, "Failed to attach cgroup- %s\n", strerror(err));
        goto err;
    }

    /* Set default config in eBPF map */
    err = tcp_int_set_config(TCP_INT_CONFIG_KEY_TRACE_ENABLE,
                             TCP_INT_CONFIG_FALSE);
    if (err) {
        fprintf(stderr, "Failed to set tracing to false in BPF map\n");
        goto err;
    }

err:
    /* If everything went okay, bpf object is pinned.
     * We can safely destroy local reference.
     */
    tcp_int_bpf__destroy(tcp_int_obj);

    if (err && pinned) {
        tcp_int_unload();
    }

    err = err ? TCP_INT_ERR_BPF : TCP_INT_OK;
    return err;
}

static int tcp_int_ecr_enable(bool enable)
{
    if (enable) {
        return tcp_int_set_config(TCP_INT_CONFIG_KEY_ECR_DISABLE,
                                  TCP_INT_CONFIG_FALSE);
    } else {
        return tcp_int_set_config(TCP_INT_CONFIG_KEY_ECR_DISABLE,
                                  TCP_INT_CONFIG_TRUE);
    }
}

static int tcp_int_events_enable(bool enable)
{
    if (enable) {
        return tcp_int_set_config(TCP_INT_CONFIG_KEY_TRACE_ENABLE,
                                  TCP_INT_CONFIG_TRUE);
    } else {
        return tcp_int_set_config(TCP_INT_CONFIG_KEY_TRACE_ENABLE,
                                  TCP_INT_CONFIG_FALSE);
    }
}

static __u64 tcp_int_get_tp(struct tcp_int_event *e)
{
    __u64 intv = e->rate_interval_us;
    __u64 rate = e->rate_delivered;
    __u64 tp = 0;

    if (rate && intv) {
        /* MB/sec */
        tp = rate * e->mss / intv;
    }

    return tp;
}

static void tcp_int_handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct tcp_int_event *e = data;
    static __u64 start_ts = 0;
    char saddr[48];
    char daddr[48];

    if (sizeof(struct tcp_int_event) > data_sz) {
        fprintf(stderr, "unexpected event size (%lu != %u)\n", sizeof(*e),
                data_sz);
        return;
    }

    if (start_ts == 0)
        start_ts = e->ts_us;

    inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));
    printf("%11.6f, %15s:%5d, %15s:%5d, %8d, %8d, %6d, %8lld, %7u, %12u, %9f, "
           "%3d, %11d, %21lld\n",
           (e->ts_us - start_ts) / 1000000.0, saddr, e->sport, daddr, e->dport,
           (e->srtt_us >> 3), (e->snd_cwnd * e->mss), e->total_retrans,
           tcp_int_get_tp(e), tcp_int_ival_to_util(e->intval),
           tcp_int_ival_to_qdepth(e->intval),
           tcp_int_hoplatecr_to_ns(e->hoplat) / 1000.0, e->hid, e->segs_out,
           e->bytes_acked);
}

static void tcp_int_handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void tcp_int_clean_hists(enum tcp_int_object_type type)
{
    struct tcp_int_hist *tcp_int_empty_hists = NULL;
    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts, .elem_flags = BPF_ANY,
                        .flags = BPF_ANY, );
    __u32 n_hists = TCP_INT_HIST_TYPE_MAX;
    int *keys = NULL;
    __u32 val_size;
    int hists_fd;
    int err;
    int i;

    switch (type) {
    case TCP_INT_OBJECT_MAP_HISTS:
        n_hists = TCP_INT_HIST_TYPE_MAX;
        break;
    case TCP_INT_OBJECT_MAP_HISTS_PERID:
        n_hists = TCP_INT_MAX_PERID_HISTS;
        break;
    default:
        return;
    }

    hists_fd = tcp_int_get_fd(type);
    if (hists_fd < 0) {
        return;
    }

    keys = malloc(n_hists * sizeof(int));
    if (!keys) {
        goto cleanup;
    }
    val_size = (type == TCP_INT_OBJECT_MAP_HISTS)
                   ? sizeof(struct tcp_int_hist)
                   : sizeof(struct tcp_int_hist_perid);
    tcp_int_empty_hists = calloc(n_hists, val_size);
    if (!tcp_int_empty_hists) {
        goto cleanup;
    }
    for (i = 0; i < n_hists; i++) {
        keys[i] = i;
    }

    err = bpf_map_update_batch(hists_fd, keys, tcp_int_empty_hists, &n_hists,
                               &opts);
    if (err < 0) {
        fprintf(stderr, "Failed to cleanup hist: %d\n", err);
    }

cleanup:
    if (keys) {
        free(keys);
    }
    if (tcp_int_empty_hists) {
        free(tcp_int_empty_hists);
    }
}

static int tcp_int_get_hist_total_count(struct tcp_int_hist *hist)
{
    int total_cnt = 0;
    int i;

    for (i = 0; i < TCP_INT_HIST_MAX_SLOTS; i++) {
        total_cnt += hist->slots[i];
    }

    return total_cnt;
}

static void tcp_int_print_hist(struct tcp_int_hist *hist,
                               enum tcp_int_hist_type type)
{
    float pstep;
    float step;
    float cnt;

    printf("\n");
    switch (type) {
    case TCP_INT_HIST_TYPE_SRTT:
        print_log2_hist(hist->slots, TCP_INT_HIST_MAX_SLOTS, -1, "SRTT [usec]");
        break;
    case TCP_INT_HIST_TYPE_CWND:
        print_log2_hist(hist->slots, TCP_INT_HIST_MAX_SLOTS, -1, "CWND [pkts]");
        break;
    case TCP_INT_HIST_TYPE_UTIL:
        cnt = (TCP_INT_MAX_UTIL_PERCENT >> TCP_INT_UTIL_BITSHIFT) + 1;
        step = TCP_INT_MAX_UTIL_PERCENT / cnt;
        print_linear_hist(hist->slots, TCP_INT_HIST_MAX_SLOTS, 0, step, 0,
                          cnt - 1, "BW UTIL. [\%]", false);
        break;
    case TCP_INT_HIST_TYPE_QDEPTH:
        print_log2_hist(hist->slots, TCP_INT_HIST_MAX_SLOTS, -1, "QDEPTH [KB]");
        break;
    case TCP_INT_HIST_TYPE_HLAT:
        print_log2_hist(hist->slots, TCP_INT_HIST_MAX_SLOTS, -1, "HLAT [ns]");
        break;
    case TCP_INT_HIST_TYPE_HID:
        print_linear_hist(hist->slots, TCP_INT_HIST_MAX_SLOTS, 0, 1, -1, -1,
                          "SWITCH HOP", true);
        break;
    case TCP_INT_HIST_TYPE_RXSKBLEN:
        pstep = TCP_INT_MAX_SKBLEN /
                (TCP_INT_MAX_SKBLEN >> TCP_INT_SKBLEN_BITSHIFT);
        print_linear_hist(hist->slots, TCP_INT_HIST_MAX_SLOTS, 0, pstep, 0, -1,
                          "RXSKBLEN [Bytes]", false);
        break;
    case TCP_INT_HIST_TYPE_TXSKBLEN:
        pstep = TCP_INT_MAX_SKBLEN /
                (TCP_INT_MAX_SKBLEN >> TCP_INT_SKBLEN_BITSHIFT);
        print_linear_hist(hist->slots, TCP_INT_HIST_MAX_SLOTS, 0, pstep, 0, -1,
                          "TXSKBLEN [Bytes]", false);
        break;
    default:
        break;
    }
}

static int tcp_int_print_hists_perid(enum tcp_int_hist_type type_min,
                                     enum tcp_int_hist_type type_max)
{
    struct tcp_int_hist_perid hists;
    int err = TCP_INT_OK;
    int hists_fd;
    int i;
    int j;

    hists_fd = tcp_int_get_fd(TCP_INT_OBJECT_MAP_HISTS_PERID);
    if (hists_fd < 0) {
        return TCP_INT_ERR_BPF;
    }

    for (i = 0; i < TCP_INT_MAX_PERID_HISTS; i++) {
        for (j = type_min; j <= type_max; j++) {
            err = bpf_map_lookup_elem(hists_fd, &j, &hists);
            if ((err < 0) || !tcp_int_get_hist_total_count(&hists.hist[i])) {
                break;
            }
            if (j == type_min) {
                printf("\n\n-- SWITCH HOP %02d "
                       "-------------------------------------------------------"
                       "------",
                       (1 + TCP_INT_TTL_INIT - i));
            }
            tcp_int_print_hist(&hists.hist[i], j);
        }
    }

    return err;
}

static int tcp_int_print_hists_pertype(enum tcp_int_hist_type type_min,
                                       enum tcp_int_hist_type type_max)
{
    struct tcp_int_hist hist;
    int err = TCP_INT_OK;
    int hists_fd;
    int i;

    hists_fd = tcp_int_get_fd(TCP_INT_OBJECT_MAP_HISTS);
    if (hists_fd < 0) {
        return TCP_INT_ERR_BPF;
    }

    for (i = type_min; i <= type_max; i++) {
        err = bpf_map_lookup_elem(hists_fd, &i, &hist);
        if (err < 0) {
            break;
        }
        tcp_int_print_hist(&hist, i);
    }

    return err;
}

static int tcp_int_trace(void)
{
    tcp_int_config_value trace_cfg_val_before;
    struct perf_buffer *pb = NULL;
    int err = TCP_INT_OK;

    err = tcp_int_get_config(TCP_INT_CONFIG_KEY_TRACE_ENABLE,
                             &trace_cfg_val_before);
    if (err) {
        goto cleanup;
    }

    pb = perf_buffer__new(tcp_int_get_fd(TCP_INT_OBJECT_MAP_EVENTS),
                          TCP_INT_PERF_BUFFER_PAGES, tcp_int_handle_event,
                          tcp_int_handle_lost_events, NULL, NULL);
    err = libbpf_get_error(pb);
    if (err) {
        fprintf(stderr, "Failed to open perf buffer: %d\n", err);
        err = TCP_INT_ERR_BPF;
        goto cleanup;
    }

    err = tcp_int_set_config(TCP_INT_CONFIG_KEY_TRACE_ENABLE,
                             TCP_INT_CONFIG_TRUE);
    if (err) {
        goto cleanup;
    }

    err = tcp_int_set_config(TCP_INT_CONFIG_KEY_GLOBAL_ENABLE,
                             TCP_INT_CONFIG_TRUE);
    if (err) {
        goto cleanup;
    }

    printf("Tracing TCP-INT... Hit Ctrl-C to end.\n");

    printf("%11s, %15s:%5s, %15s:%5s, %8s, %8s, %6s, %8s, %7s, %12s, %9s, %3s, "
           "%11s, %21s\n\n",
           "TIME(s)", "SIP", "SPORT", "DIP", "DPORT", "SRTT(US)", "CWND(B)",
           "LOST", "TP(MB/s)", "UTIL(\%)", "QDEPTH(B)", "HLAT(us)", "HID",
           "SOUT", "BA");

    while (!tcp_int_exiting) {
        err = perf_buffer__poll(pb, TCP_INT_PERF_POLL_TIMEOUT_MS);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(errno));
            goto cleanup;
        }
        err = TCP_INT_OK;
    }

cleanup:
    tcp_int_set_config(TCP_INT_CONFIG_KEY_TRACE_ENABLE, trace_cfg_val_before);
    perf_buffer__free(pb);
    return err;
}

static int tcp_int_hist(enum tcp_int_hist_type type_min,
                        enum tcp_int_hist_type type_max, bool perid)
{
    int err = TCP_INT_OK;

    tcp_int_clean_hists(TCP_INT_OBJECT_MAP_HISTS);
    tcp_int_clean_hists(TCP_INT_OBJECT_MAP_HISTS_PERID);

    err =
        tcp_int_set_config(TCP_INT_CONFIG_KEY_HIST_ENABLE, TCP_INT_CONFIG_TRUE);
    if (err) {
        goto cleanup;
    }

    err = tcp_int_set_config(TCP_INT_CONFIG_KEY_GLOBAL_ENABLE,
                             TCP_INT_CONFIG_TRUE);
    if (err) {
        goto cleanup;
    }

    printf("Tracing TCP-INT... Hit Ctrl-C to end.\n");

    while (!tcp_int_exiting) {
        sleep(1);
    }

    err = perid ? tcp_int_print_hists_perid(type_min, type_max)
                : tcp_int_print_hists_pertype(type_min, type_max);

cleanup:
    tcp_int_set_config(TCP_INT_CONFIG_KEY_HIST_ENABLE, TCP_INT_CONFIG_FALSE);
    return err;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stdout, format, args);
}

static void tcp_int_sig_int(int signo) { tcp_int_exiting = 1; }

int main(int argc, char **argv)
{
    const char *cgroup_path = TCP_INT_CGROUP_PATH;
    int rv = TCP_INT_OK;

    if (argc < 2) {
        show_help();
        return TCP_INT_OK;
    }

    if (argc == 3) {
        if (!strcmp(argv[2], "-d")) {
            libbpf_set_print(libbpf_print_fn);
        } else if (!strcmp(argv[2], "-c")) {
            fprintf(stderr, "Insufficient arguments provided\n");
            return TCP_INT_ERR_SYS;
        }
    }
    if ((argc > 3) && (!strcmp(argv[2], "-c"))) {
        cgroup_path = validate_cgroup_path(argv[3]);
        if (!cgroup_path) {
            return TCP_INT_ERR_SYS;
        }
    }

    if (signal(SIGINT, tcp_int_sig_int) == SIG_ERR) {
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        return TCP_INT_ERR_SYS;
    }

    if (!strcmp(argv[1], "load")) {
        rv = tcp_int_load(cgroup_path);
    } else if (!strcmp(argv[1], "unload")) {
        rv = tcp_int_unload();
    } else if (!strcmp(argv[1], "enable")) {
        rv = tcp_int_set_config(TCP_INT_CONFIG_KEY_GLOBAL_ENABLE,
                                TCP_INT_CONFIG_TRUE);
    } else if (!strcmp(argv[1], "disable")) {
        rv = tcp_int_set_config(TCP_INT_CONFIG_KEY_GLOBAL_ENABLE,
                                TCP_INT_CONFIG_FALSE);
    } else if (!strcmp(argv[1], "trace")) {
        rv = tcp_int_trace();
    } else if (!strcmp(argv[1], "hist")) {
        rv = tcp_int_hist(0, TCP_INT_HIST_TYPE_MAX, false);
    } else if (!strcmp(argv[1], "hist-rtt")) {
        rv =
            tcp_int_hist(TCP_INT_HIST_TYPE_SRTT, TCP_INT_HIST_TYPE_SRTT, false);
    } else if (!strcmp(argv[1], "hist-cwnd")) {
        rv =
            tcp_int_hist(TCP_INT_HIST_TYPE_CWND, TCP_INT_HIST_TYPE_CWND, false);
    } else if (!strcmp(argv[1], "hist-int")) {
        rv = tcp_int_hist(TCP_INT_HIST_TYPE_HID, TCP_INT_HIST_TYPE_QDEPTH,
                          false);
    } else if (!strcmp(argv[1], "hist-int-perid")) {
        rv = tcp_int_hist(TCP_INT_HIST_TYPE_UTIL, TCP_INT_HIST_TYPE_QDEPTH,
                          true);
    } else if (!strcmp(argv[1], "hist-qdepth")) {
        rv = tcp_int_hist(TCP_INT_HIST_TYPE_QDEPTH, TCP_INT_HIST_TYPE_QDEPTH,
                          false);
    } else if (!strcmp(argv[1], "hist-util")) {
        rv =
            tcp_int_hist(TCP_INT_HIST_TYPE_UTIL, TCP_INT_HIST_TYPE_UTIL, false);
    } else if (!strcmp(argv[1], "hist-hoplat")) {
        rv =
            tcp_int_hist(TCP_INT_HIST_TYPE_HLAT, TCP_INT_HIST_TYPE_HLAT, false);
    } else if (!strcmp(argv[1], "hist-hid")) {
        rv = tcp_int_hist(TCP_INT_HIST_TYPE_HID, TCP_INT_HIST_TYPE_HID, false);
    } else if (!strcmp(argv[1], "hist-rxskblen")) {
        rv = tcp_int_hist(TCP_INT_HIST_TYPE_RXSKBLEN,
                          TCP_INT_HIST_TYPE_RXSKBLEN, false);
    } else if (!strcmp(argv[1], "hist-txskblen")) {
        rv = tcp_int_hist(TCP_INT_HIST_TYPE_TXSKBLEN,
                          TCP_INT_HIST_TYPE_TXSKBLEN, false);
    } else if (!strcmp(argv[1], "ecr-enable")) {
        rv = tcp_int_ecr_enable(true);
    } else if (!strcmp(argv[1], "ecr-disable")) {
        rv = tcp_int_ecr_enable(false);
    } else if (!strcmp(argv[1], "events-enable")) {
        rv = tcp_int_events_enable(true);
    } else if (!strcmp(argv[1], "events-disable")) {
        rv = tcp_int_events_enable(false);
    } else {
        show_help();
    }

    return rv;
}
