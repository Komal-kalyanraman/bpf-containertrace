# bpf-containertrace Architecture

## Overview

`bpf-containertrace` is a low-overhead container telemetry engine that
detects CPU quota violations with nanosecond resolution by operating
directly at the Linux kernel boundary.  It uses **eBPF CO-RE** (Compile
Once – Run Everywhere) to attach probes to kernel scheduler events and
streams violation events to user space via a zero-copy ring buffer.

---

## How It Works — End to End

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LINUX KERNEL SPACE                               │
│                                                                     │
│  sched:sched_switch tracepoint fires on every task context switch   │
│         │                                                           │
│         ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  handle_sched_switch() [containertrace.bpf.c]               │   │
│  │                                                             │   │
│  │  1. Record schedule-in timestamp for incoming task (LRU map)│   │
│  │  2. Compute CPU slice: now - start_ts (ns) for outgoing task│   │
│  │  3. Look up task's cgid in container_limits map             │   │
│  │     └─ if NOT found → skip (fast path, ~1 hash miss)        │   │
│  │  4. Accumulate cpu_ns_used in container_cpu_stats map       │   │
│  │     └─ if period elapsed (100ms default) → reset counter    │   │
│  │  5. Compare cpu_ns_used vs cpu_quota_ns                     │   │
│  │     ├─ > quota  → submit CT_EVENT_VIOLATION to ring buffer  │   │
│  │     └─ ≤ quota  → submit CT_EVENT_CPU_TICK  to ring buffer  │   │
│  └──────────────────────────────┬──────────────────────────────┘   │
│                                 │ BPF_MAP_TYPE_RINGBUF             │
│             ┌───────────────────┘ (512 KB, zero-copy)              │
└─────────────┼───────────────────────────────────────────────────────┘
              │
              ▼  mmap'd shared memory – no system call per event
┌─────────────────────────────────────────────────────────────────────┐
│                    USER SPACE (bpf-containertrace)                  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  main.c – event loop (ring_buffer__poll, 100ms timeout)      │  │
│  │                                                              │  │
│  │  ┌── handle_bpf_event() callback ──────────────────────────┐│  │
│  │  │  CT_EVENT_VIOLATION → [WARN] log with % over quota      ││  │
│  │  │  CT_EVENT_CPU_TICK  → [DEBUG] log (suppressed normally) ││  │
│  │  └──────────────────────────────────────────────────────────┘│  │
│  │                                                              │  │
│  │  Every 3s: cgroup_resolver_scan() – find new containers     │  │
│  │  Every 5s: print_stats_report()  – read container_cpu_stats │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  cgroup_resolver.c – Podman container discovery              │  │
│  │                                                              │  │
│  │  inotify watches (machine.slice + user session dirs)        │  │
│  │       │ IN_CREATE/IN_DELETE on libpod-*.scope dirs          │  │
│  │       ▼                                                      │  │
│  │  register_scope_at():                                        │  │
│  │    1. Parse cpu.max → ct_limits.cpu_quota_ns/period_ns      │  │
│  │    2. UPDATE container_limits BPF map (cgid → limits)  ←──  │  │
│  │       (done BEFORE name resolution – zero tracking gap)     │  │
│  │    3. popen("podman inspect") for container name            │  │
│  │    4. Log registration                                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## BPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `task_start_ts` | `LRU_HASH` (32k entries) | PID (`u32`) | schedule-in ktime (ns) | Store when each task was last scheduled in; LRU auto-evicts exited tasks |
| `container_limits` | `HASH` (256 entries) | cgroup ID (`u64`) | `struct ct_limits` | Written by resolver; read by BPF on every sched_switch to check quota |
| `container_cpu_stats` | `HASH` (256 entries) | cgroup ID (`u64`) | `struct ct_cpu_stat` | Per-container running CPU total for the current period; written by BPF, read by user-space stats reporter |
| `events` | `RINGBUF` (512 KB) | — | `struct ct_event` (64 bytes) | Zero-copy event stream kernel → user space |

---

## The 64-byte Event Structure

```c
struct ct_event {
    u64  timestamp_ns;   //  0: ktime_get_ns() at schedule-out
    u64  cgid;           //  8: cgroup v2 ID (inode of cgroup dir)
    u32  event_type;     // 16: CT_EVENT_CPU_TICK or CT_EVENT_VIOLATION
    u32  pid;            // 20: PID of the outgoing task
    u8   comm[16];       // 24: task comm (process name)
    u64  cpu_delta_ns;   // 40: this task's CPU slice (ns)
    u64  cpu_used_ns;    // 48: cgroup total in current period (ns)
    u64  cpu_quota_ns;   // 56: period quota (ns), 0 = unlimited
};                       // = 64 bytes (one cache line)
```

---

## CPU Violation Detection Logic

```
Each 100ms period:
  ╔══════════════════════════════════════════════════╗
  ║  Allowed: cpu_quota_ns = 50ms  (--cpus=0.5)      ║
  ║                                                  ║
  ║  Worker 1 runs: +12ms  → cpu_ns_used = 12ms  ✓   ║
  ║  Worker 2 runs: +12ms  → cpu_ns_used = 24ms  ✓   ║
  ║  Worker 3 runs: +13ms  → cpu_ns_used = 37ms  ✓   ║
  ║  Worker 4 runs: +14ms  → cpu_ns_used = 51ms  ✗   ║
  ║                         ^^^^^^^^^^^^^^^^^^^^^^   ║
  ║                         VIOLATION +2.0% over     ║
  ║                         emitted to ring buffer   ║
  ╚══════════════════════════════════════════════════╝
  → period resets → repeat
```

The kernel's CFS bandwidth controller throttles the cgroup after quota
is exhausted, but bpf-containertrace **detects the violation at the
exact moment it occurs** — before the kernel throttle even kicks in.

---

## Container Discovery

### Cgroup paths by Podman mode

| Mode | Cgroup path |
|------|-------------|
| Root Podman (`sudo podman`) | `/sys/fs/cgroup/machine.slice/libpod-<id>.scope/container/` |
| Rootless Podman (`podman`) | `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/user.slice/libpod-<id>.scope/container/` |

### Discovery mechanism

```
/sys/fs/cgroup/
├── machine.slice/           ◄── inotify watch (root Podman)
│   └── libpod-<id>.scope/
│       ├── cpu.max          ← limits parsed here
│       └── container/       ← tasks live here; its inode = cgid
└── user.slice/              ◄── inotify watch
    └── user-1000.slice/     ◄── inotify watch (added dynamically)
        └── user@1000.service/  ◄── inotify watch
            └── user.slice/  ◄── inotify watch (rootless Podman)
                └── libpod-<id>.scope/
                    └── container/
```

Three-layer discovery ensures nothing is missed:
1. **inotify** for immediate detection (< 200ms latency)
2. **Periodic rescan** every 3s as safety net
3. **Stale container GC** on each scan (stat() check on leaf cgroup)

### cgid

The cgroup identifier used as the BPF map key is the **inode number**
of the `container/` leaf cgroup directory:

```bash
stat /sys/fs/cgroup/.../libpod-<id>.scope/container | grep Inode
# Device: 0,31    Inode: 19625   ← this is the cgid
```

The BPF helper `bpf_get_current_cgroup_id()` returns the innermost
cgroup ID for the current task, matching this inode.

---

## Cross-Checking with Kernel Ground Truth

The Linux kernel independently tracks CPU bandwidth in `cpu.stat`:

```bash
# Find the cgroup path while container is running
CID=$(podman inspect <name> --format '{{.Id}}')
SCOPE=$(sudo find /sys/fs/cgroup -name "libpod-${CID}*" -type d | grep -v conmon)

# Read the kernel's throttle counters
watch -n 1 "cat $SCOPE/cpu.stat | grep -E 'usage_usec|nr_periods|nr_throttled|throttled_usec'"
```

| `cpu.stat` field | Relationship to bpf-containertrace |
|---|---|
| `usage_usec` | ≈ `nr_periods × cpu_quota_ns/1000` when always throttled |
| `nr_periods` | Total 100ms windows elapsed |
| `nr_throttled` | Periods where quota was exceeded = 100% when 4 workers vs 0.5 CPU quota |
| `throttled_usec` | Wall-clock time cgroup was frozen after quota exhaustion |

**Verified example** (`--cpus=0.5`, 4 workers, 8.6s):

```
usage_usec   = 4329ms  ≈ 86 periods × 50ms/period ✓
nr_throttled = 86/86   = 100% (quota hit every single period) ✓
throttled_us = 7766ms  = 90ms/period throttled
                         (4 workers burn 50ms in ~10ms wall-clock → 90ms frozen) ✓
```

Also compare with `podman stats` and `systemd-cgtop`:
```bash
# In a second terminal while container is running:
podman stats <container>          # CPU % ≈ 50% (0.5 cores / 1 core base)
sudo systemd-cgtop -d 1           # Live per-cgroup CPU usage tree
```

---

## Build Pipeline

```
vmlinux.h          ← bpftool btf dump /sys/kernel/btf/vmlinux
    │
    ▼
containertrace.bpf.c  ──(clang-18 -target bpf -O2)──►  containertrace.bpf.o
                                                              │
                                                    bpftool gen skeleton
                                                              │
                                                              ▼
main.c  ──────────────────────────────────────────►  containertrace.skel.h
cgroup_resolver.c                                    (auto-generated)
    │
    └──(gcc -O2)──► bpf-containertrace  (links: libbpf, libelf, zlib)
```

The skeleton (`containertrace.skel.h`) embeds the compiled BPF object
as a byte array and provides typed C API (`containertrace__open_and_load`,
`containertrace__attach`, etc.) so no BPF object files need to be
distributed separately.

---

## Resource Footprint

| Metric | Value |
|--------|-------|
| BPF maps RSS | ~2 MB (512 KB ring buf + hash maps) |
| Daemon RSS | < 2 MB |
| Hot-path heap allocations | **0 bytes** (all BPF maps are static; user-space uses fixed `ct_container[256]` array) |
| CPU overhead | < 0.5% (one hash lookup per task context switch in monitored cgroups; unmonitored tasks exit in one hash miss) |

---

## Current Limitations

- **CPU violations only**: memory and I/O limits parsed but not yet
  tracked in the BPF program (planned for next milestone)
- **No pods**: Podman pods share cgroups differently; pod tracking is
  out of scope for this initial release
- **Root required**: loading eBPF programs requires `CAP_BPF` /
  `CAP_SYS_ADMIN`; rootless daemon mode is a future goal
- **Violation rate**: the ring buffer emits one event per task
  schedule-out that crosses the quota; a very high-frequency workload
  can produce many events per second (ring buffer drops are logged
  automatically by libbpf if the 512 KB buffer fills)
