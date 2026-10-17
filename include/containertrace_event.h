/* SPDX-License-Identifier: MIT */
#pragma once

/*
 * Shared event structures between the eBPF kernel program and the
 * user-space daemon.  Uses __u* types from <linux/types.h> (user-space)
 * or from vmlinux.h (BPF program), so both sides see identical layouts.
 */

#ifndef __BPF_PROGRAM__
#include <linux/types.h>
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define CT_MAX_COMM_LEN   16   /* task_struct->comm length */
#define CT_MAX_CONTAINERS 256  /* max simultaneously tracked containers */

/* Event types written to the BPF ring buffer */
#define CT_EVENT_CPU_TICK  1   /* normal CPU slice recorded */
#define CT_EVENT_VIOLATION 2   /* container exceeded its CPU quota */

/* ------------------------------------------------------------------ */
/* BPF map value types (shared kernel ↔ user)                         */
/* ------------------------------------------------------------------ */

/*
 * Resource limits for one container.  Written by the user-space
 * resolver into the container_limits BPF map (keyed by cgid).
 */
struct ct_limits {
    __u64 cpu_quota_ns;   /* CPU quota per period in ns  (0 = unlimited) */
    __u64 cpu_period_ns;  /* period length in ns         (default 100 ms) */
    __u64 mem_limit;      /* memory.max in bytes         (0 = unlimited) */
    __u64 pids_max;       /* pids.max                    (0 = unlimited) */
};

/*
 * Per-cgroup CPU accounting kept inside the kernel.
 * Written/updated by the BPF sched_switch handler.
 */
struct ct_cpu_stat {
    __u64 period_start_ns; /* ktime when the current period began */
    __u64 cpu_ns_used;     /* CPU ns consumed so far this period  */
};

/* ------------------------------------------------------------------ */
/* Ring-buffer event – exactly 64 bytes, cache-line aligned           */
/* ------------------------------------------------------------------ */

/*
 * Layout:
 *   [  0] timestamp_ns  8
 *   [  8] cgid          8
 *   [ 16] event_type    4
 *   [ 20] pid           4
 *   [ 24] comm         16
 *   [ 40] cpu_delta_ns  8   – time slice that triggered this event
 *   [ 48] cpu_used_ns   8   – accumulated usage in current period
 *   [ 56] cpu_quota_ns  8   – period quota  (0 = unlimited)
 *                       = 64 bytes
 */
struct ct_event {
    __u64 timestamp_ns;
    __u64 cgid;
    __u32 event_type;
    __u32 pid;
    __u8  comm[CT_MAX_COMM_LEN];
    __u64 cpu_delta_ns;
    __u64 cpu_used_ns;
    __u64 cpu_quota_ns;
} __attribute__((aligned(64)));
