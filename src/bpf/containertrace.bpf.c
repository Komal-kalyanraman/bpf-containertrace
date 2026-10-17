// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * containertrace.bpf.c – eBPF CO-RE kernel probes
 *
 * Attaches to the sched:sched_switch tracepoint to measure per-cgroup
 * CPU consumption with nanosecond resolution.  The user-space resolver
 * populates container_limits with the cgroup IDs of running Podman
 * containers; tasks in unregistered cgroups are ignored with a single
 * hash-map miss (fast path).
 */

#define __BPF_PROGRAM__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "containertrace_event.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* ------------------------------------------------------------------ */
/* BPF Maps                                                            */
/* ------------------------------------------------------------------ */

/*
 * Per-PID schedule-in timestamp.
 * LRU map so stale entries for exited tasks are evicted automatically.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key,   __u32);   /* pid */
    __type(value, __u64);   /* ktime_get_ns() at schedule-in */
} task_start_ts SEC(".maps");

/*
 * Container resource limits, keyed by cgroup-v2 ID (cgid).
 * Written by the user-space cgroup resolver.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_MAX_CONTAINERS);
    __type(key,   __u64);            /* cgid */
    __type(value, struct ct_limits);
} container_limits SEC(".maps");

/*
 * Per-container CPU accounting for the current period.
 * Written by this BPF program and read by user space for telemetry.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CT_MAX_CONTAINERS);
    __type(key,   __u64);              /* cgid */
    __type(value, struct ct_cpu_stat);
} container_cpu_stats SEC(".maps");

/*
 * Zero-copy ring buffer for events to user space (512 KB).
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

/* ------------------------------------------------------------------ */
/* sched:sched_switch handler                                          */
/* ------------------------------------------------------------------ */

/*
 * At the sched_switch tracepoint, the kernel context is still the
 * outgoing (prev) task – before context_switch() executes.  Therefore:
 *   bpf_get_current_cgroup_id()  →  prev task's cgroup
 *   bpf_get_current_comm()       →  prev task's comm
 *
 * Algorithm:
 *   1. Record schedule-in time for next_pid.
 *   2. Compute CPU slice for prev_pid from its recorded schedule-in time.
 *   3. Look up prev's cgid in container_limits (skip if not tracked).
 *   4. Accumulate CPU time; reset if the cgroup period has elapsed.
 *   5. Submit a CT_EVENT_CPU_TICK or CT_EVENT_VIOLATION to the ring buffer.
 */
SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 prev_pid = (__u32)BPF_CORE_READ(ctx, prev_pid);
    __u32 next_pid = (__u32)BPF_CORE_READ(ctx, next_pid);

    /* Record schedule-in timestamp for the incoming task. */
    bpf_map_update_elem(&task_start_ts, &next_pid, &now, BPF_ANY);

    /* The idle task (pid 0) does not belong to any container. */
    if (prev_pid == 0)
        return 0;

    /* Retrieve when the outgoing task was last scheduled in. */
    __u64 *start = bpf_map_lookup_elem(&task_start_ts, &prev_pid);
    if (!start)
        return 0;

    __u64 delta_ns = now - *start;
    bpf_map_delete_elem(&task_start_ts, &prev_pid);

    /*
     * bpf_get_current_cgroup_id() returns the innermost cgroupv2 ID
     * of the current (prev) task – the inode of its cgroup directory.
     */
    __u64 cgid = bpf_get_current_cgroup_id();

    /* Fast-path filter: skip cgroups not registered as containers. */
    struct ct_limits *limits = bpf_map_lookup_elem(&container_limits, &cgid);
    if (!limits)
        return 0;

    /* ---- Per-period CPU accounting ---- */
    struct ct_cpu_stat new_stat;
    struct ct_cpu_stat *stat = bpf_map_lookup_elem(&container_cpu_stats, &cgid);

    if (stat) {
        __u64 elapsed = now - stat->period_start_ns;
        if (limits->cpu_period_ns > 0 && elapsed >= limits->cpu_period_ns) {
            /* Period expired: start a fresh window. */
            new_stat.period_start_ns = now;
            new_stat.cpu_ns_used     = delta_ns;
        } else {
            new_stat.period_start_ns = stat->period_start_ns;
            new_stat.cpu_ns_used     = stat->cpu_ns_used + delta_ns;
        }
    } else {
        new_stat.period_start_ns = now;
        new_stat.cpu_ns_used     = delta_ns;
    }
    bpf_map_update_elem(&container_cpu_stats, &cgid, &new_stat, BPF_ANY);

    /* ---- Emit ring-buffer event ---- */
    struct ct_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns  = now;
    evt->cgid          = cgid;
    evt->pid           = prev_pid;
    evt->cpu_delta_ns  = delta_ns;
    evt->cpu_used_ns   = new_stat.cpu_ns_used;
    evt->cpu_quota_ns  = limits->cpu_quota_ns;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    if (limits->cpu_quota_ns > 0 &&
        new_stat.cpu_ns_used > limits->cpu_quota_ns) {
        evt->event_type = CT_EVENT_VIOLATION;
    } else {
        evt->event_type = CT_EVENT_CPU_TICK;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
