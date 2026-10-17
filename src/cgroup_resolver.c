// SPDX-License-Identifier: MIT
/*
 * cgroup_resolver.c – Podman container discovery via cgroup v2 + inotify
 *
 * Watches /sys/fs/cgroup/machine.slice/ for directories matching the pattern
 * "libpod-<container_id>.scope".  For each such scope the resolver:
 *
 *   1. Locates the leaf cgroup where tasks actually run.
 *      Podman (systemd cgroup manager) places container processes in
 *      <scope>/container/.  If that subdir is absent the scope itself is
 *      used as the leaf.
 *
 *   2. Reads cpu.max, memory.max, pids.max from the scope directory to
 *      build a struct ct_limits.
 *
 *   3. Registers (cgid → limits) in the BPF container_limits map so the
 *      kernel-side sched_switch handler starts tracking the container.
 *
 *   4. Removes the entry when the scope directory disappears.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <linux/types.h>
#include <bpf/bpf.h>

#include "cgroup_resolver.h"
#include "logger.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define MACHINE_SLICE      "/sys/fs/cgroup/machine.slice"
#define SCOPE_PREFIX       "libpod-"
#define CONMON_PREFIX      "libpod-conmon-"
#define INNER_CGROUP       "container"

/* How many times to retry looking for the inner container/ subdir. */
#define INNER_RETRY_MAX    10
#define INNER_RETRY_US     20000   /* 20 ms between retries */

/* Maximum CPU quota / period value from cpu.max ("max" keyword). */
#define CPU_MAX_UNLIMITED  UINT64_MAX

/* ------------------------------------------------------------------ */
/* Internal resolver state                                             */
/* ------------------------------------------------------------------ */

struct cgroup_resolver {
    struct ct_container containers[CT_MAX_CONTAINERS];
    int  count;
    int  inotify_fd;
    int  watch_fd;        /* inotify watch on MACHINE_SLICE */
    int  limits_map_fd;   /* BPF container_limits map */
    int  stats_map_fd;    /* BPF container_cpu_stats map */
};

/* ------------------------------------------------------------------ */
/* Helpers – cgroup file parsers                                       */
/* ------------------------------------------------------------------ */

/*
 * Parse /sys/fs/cgroup/<path>/cpu.max
 * Format: "<quota_us> <period_us>" or "max <period_us>"
 */
static void parse_cpu_max(const char *scope_path, struct ct_limits *lim)
{
    char path[CT_PATH_LEN + 16];
    snprintf(path, sizeof(path), "%s/cpu.max", scope_path);

    FILE *f = fopen(path, "r");
    if (!f) {
        lim->cpu_quota_ns  = 0;
        lim->cpu_period_ns = 100000000ULL; /* default 100 ms */
        return;
    }

    char quota_str[32] = {0};
    unsigned long long period_us = 100000;

    if (fscanf(f, "%31s %llu", quota_str, &period_us) == 2) {
        if (strcmp(quota_str, "max") == 0) {
            lim->cpu_quota_ns = 0; /* unlimited */
        } else {
            unsigned long long quota_us = strtoull(quota_str, NULL, 10);
            lim->cpu_quota_ns = quota_us * 1000ULL;
        }
        lim->cpu_period_ns = period_us * 1000ULL;
    } else {
        lim->cpu_quota_ns  = 0;
        lim->cpu_period_ns = 100000000ULL;
    }
    fclose(f);
}

/*
 * Parse /sys/fs/cgroup/<path>/memory.max
 * Format: "<bytes>" or "max"
 */
static void parse_memory_max(const char *scope_path, struct ct_limits *lim)
{
    char path[CT_PATH_LEN + 20];
    snprintf(path, sizeof(path), "%s/memory.max", scope_path);

    FILE *f = fopen(path, "r");
    if (!f) { lim->mem_limit = 0; return; }

    char buf[32] = {0};
    if (fscanf(f, "%31s", buf) == 1) {
        lim->mem_limit = (strcmp(buf, "max") == 0)
                         ? 0
                         : strtoull(buf, NULL, 10);
    } else {
        lim->mem_limit = 0;
    }
    fclose(f);
}

/*
 * Parse /sys/fs/cgroup/<path>/pids.max
 * Format: "<count>" or "max"
 */
static void parse_pids_max(const char *scope_path, struct ct_limits *lim)
{
    char path[CT_PATH_LEN + 16];
    snprintf(path, sizeof(path), "%s/pids.max", scope_path);

    FILE *f = fopen(path, "r");
    if (!f) { lim->pids_max = 0; return; }

    char buf[32] = {0};
    if (fscanf(f, "%31s", buf) == 1) {
        lim->pids_max = (strcmp(buf, "max") == 0)
                        ? 0
                        : strtoull(buf, NULL, 10);
    } else {
        lim->pids_max = 0;
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Helpers – container metadata                                        */
/* ------------------------------------------------------------------ */

/*
 * Extract the full container ID from a scope directory name.
 * Input:  "libpod-abc123....scope"
 * Output: "abc123...."  (up to CT_CONTAINER_ID_LEN-1 chars, NUL-terminated)
 */
static void extract_id(const char *scope_name, char *id_out, size_t len)
{
    const char *start = scope_name + strlen(SCOPE_PREFIX);
    /* Strip trailing ".scope" */
    size_t n = strlen(start);
    if (n > 6 && strcmp(start + n - 6, ".scope") == 0)
        n -= 6;
    if (n >= len)
        n = len - 1;
    memcpy(id_out, start, n);
    id_out[n] = '\0';
}

/*
 * Query Podman for the human-readable container name.
 * Falls back to the first 12 chars of the container ID.
 */
static void fetch_container_name(const char *full_id,
                                  char *name_out, size_t name_len)
{
    char cmd[256];
    /* Use --format without a leading slash – Podman names have no '/'. */
    snprintf(cmd, sizeof(cmd),
             "podman inspect --format '{{.Name}}' %.64s 2>/dev/null",
             full_id);

    FILE *f = popen(cmd, "r");
    if (f) {
        if (fgets(name_out, (int)name_len, f)) {
            /* Strip trailing newline */
            char *nl = strchr(name_out, '\n');
            if (nl) *nl = '\0';
        } else {
            f = NULL; /* fall through to fallback */
        }
        pclose(f);
    }

    /* Fallback: use a 12-char short ID if name is empty */
    if (!f || name_out[0] == '\0')
        snprintf(name_out, name_len, "%.12s", full_id);
}

/* ------------------------------------------------------------------ */
/* Core registration / deregistration                                  */
/* ------------------------------------------------------------------ */

/*
 * Find an existing slot by container ID, or allocate a free slot.
 * Returns NULL if the table is full.
 */
static struct ct_container *find_or_alloc(struct cgroup_resolver *res,
                                           const char *id)
{
    for (int i = 0; i < res->count; i++) {
        if (strcmp(res->containers[i].id, id) == 0)
            return &res->containers[i];
    }
    if (res->count >= CT_MAX_CONTAINERS)
        return NULL;
    return &res->containers[res->count++];
}

/*
 * Determine the cgroup path where actual tasks run.
 * Podman places tasks inside <scope>/container/.
 * Retries up to INNER_RETRY_MAX times to handle the window between
 * the scope dir appearing and the inner dir being created.
 */
static int find_leaf_cgroup(const char *scope_path,
                              char *leaf_out, size_t leaf_len,
                              uint64_t *cgid_out)
{
    char inner[CT_PATH_LEN];
    snprintf(inner, sizeof(inner), "%s/" INNER_CGROUP, scope_path);

    for (int attempt = 0; attempt < INNER_RETRY_MAX; attempt++) {
        struct stat st;
        if (stat(inner, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(leaf_out, leaf_len, "%s", inner);
            *cgid_out = (uint64_t)st.st_ino;
            return 0;
        }
        /* Inner cgroup not yet created; check the scope itself. */
        if (stat(scope_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(leaf_out, leaf_len, "%s", scope_path);
            *cgid_out = (uint64_t)st.st_ino;
            /* If this is the first attempt, try once more for inner. */
            if (attempt < 2) {
                usleep(INNER_RETRY_US);
                continue;
            }
            return 0;
        }
        /* Scope has disappeared (race with container stop). */
        return -ENOENT;
    }
    return -ENOENT;
}

/*
 * Register a Podman container scope with the BPF maps.
 */
static int register_scope(struct cgroup_resolver *res,
                           const char *scope_name)
{
    /* Skip the conmon monitor process scope. */
    if (strncmp(scope_name, CONMON_PREFIX, strlen(CONMON_PREFIX)) == 0)
        return 0;
    if (strncmp(scope_name, SCOPE_PREFIX, strlen(SCOPE_PREFIX)) != 0)
        return 0;

    char scope_path[CT_PATH_LEN];
    snprintf(scope_path, sizeof(scope_path),
             MACHINE_SLICE "/%s", scope_name);

    /* Determine the leaf cgroup (where tasks actually live). */
    char leaf_path[CT_PATH_LEN];
    uint64_t cgid = 0;
    if (find_leaf_cgroup(scope_path, leaf_path, sizeof(leaf_path), &cgid) != 0)
        return -ENOENT;

    /* Extract full container ID. */
    char full_id[CT_CONTAINER_ID_LEN];
    extract_id(scope_name, full_id, sizeof(full_id));

    /* Allocate or refresh slot. */
    struct ct_container *c = find_or_alloc(res, full_id);
    if (!c) {
        LOG_WARN("container table full, dropping %s", full_id);
        return -ENOMEM;
    }

    strncpy(c->id, full_id, sizeof(c->id) - 1);
    strncpy(c->scope_path, scope_path, sizeof(c->scope_path) - 1);
    strncpy(c->leaf_path, leaf_path, sizeof(c->leaf_path) - 1);
    c->cgid = cgid;

    /* Parse limits from the scope level (not the inner cgroup). */
    parse_cpu_max(scope_path, &c->limits);
    parse_memory_max(scope_path, &c->limits);
    parse_pids_max(scope_path, &c->limits);

    /* Resolve human-readable name via Podman (one-time on start). */
    fetch_container_name(full_id, c->name, sizeof(c->name));

    /* Push limits into the BPF map. */
    int err = bpf_map_update_elem(res->limits_map_fd, &cgid, &c->limits,
                                   BPF_ANY);
    if (err) {
        LOG_ERROR("bpf_map_update_elem(limits) cgid=%llu: %s",
                  (unsigned long long)cgid, strerror(errno));
        return err;
    }

    LOG_INFO("container registered: name=%-20s id=%.12s cgid=%-6llu "
             "cpu_quota=%s mem_limit=%s",
             c->name, c->id,
             (unsigned long long)cgid,
             c->limits.cpu_quota_ns ? "set" : "unlimited",
             c->limits.mem_limit    ? "set" : "unlimited");
    return 0;
}

/*
 * Deregister a container when its scope directory disappears.
 */
static void deregister_scope(struct cgroup_resolver *res,
                              const char *scope_name)
{
    if (strncmp(scope_name, CONMON_PREFIX, strlen(CONMON_PREFIX)) == 0)
        return;
    if (strncmp(scope_name, SCOPE_PREFIX, strlen(SCOPE_PREFIX)) != 0)
        return;

    char full_id[CT_CONTAINER_ID_LEN];
    extract_id(scope_name, full_id, sizeof(full_id));

    for (int i = 0; i < res->count; i++) {
        if (strcmp(res->containers[i].id, full_id) != 0)
            continue;

        struct ct_container *c = &res->containers[i];

        /* Remove from BPF maps. */
        bpf_map_delete_elem(res->limits_map_fd, &c->cgid);
        bpf_map_delete_elem(res->stats_map_fd,  &c->cgid);

        LOG_INFO("container deregistered: name=%-20s id=%.12s",
                 c->name, c->id);

        /* Compact the array by swapping with the last entry. */
        res->count--;
        if (i < res->count)
            res->containers[i] = res->containers[res->count];
        return;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

struct cgroup_resolver *cgroup_resolver_init(int limits_map_fd,
                                              int stats_map_fd)
{
    struct cgroup_resolver *res = calloc(1, sizeof(*res));
    if (!res)
        return NULL;

    res->limits_map_fd = limits_map_fd;
    res->stats_map_fd  = stats_map_fd;

    res->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (res->inotify_fd < 0) {
        LOG_ERROR("inotify_init1: %s", strerror(errno));
        free(res);
        return NULL;
    }

    res->watch_fd = inotify_add_watch(res->inotify_fd, MACHINE_SLICE,
                                       IN_CREATE | IN_DELETE |
                                       IN_MOVED_FROM | IN_MOVED_TO);
    if (res->watch_fd < 0) {
        LOG_ERROR("inotify_add_watch(%s): %s", MACHINE_SLICE, strerror(errno));
        close(res->inotify_fd);
        free(res);
        return NULL;
    }

    return res;
}

int cgroup_resolver_scan(struct cgroup_resolver *res)
{
    DIR *dir = opendir(MACHINE_SLICE);
    if (!dir) {
        LOG_ERROR("opendir(%s): %s", MACHINE_SLICE, strerror(errno));
        return -errno;
    }

    int found = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type != DT_DIR && ent->d_type != DT_UNKNOWN)
            continue;
        if (strncmp(ent->d_name, SCOPE_PREFIX, strlen(SCOPE_PREFIX)) != 0)
            continue;
        if (register_scope(res, ent->d_name) == 0)
            found++;
    }
    closedir(dir);

    if (found > 0)
        LOG_INFO("initial scan: %d Podman container(s) found", found);
    else
        LOG_INFO("initial scan: no running Podman containers");

    return found;
}

int cgroup_resolver_process_events(struct cgroup_resolver *res)
{
    /* inotify_event has a variable-length name field. */
    char buf[4096]
         __attribute__((aligned(__alignof__(struct inotify_event))));

    ssize_t len = read(res->inotify_fd, buf, sizeof(buf));
    if (len <= 0)
        return 0;   /* EAGAIN = no events pending */

    const char *ptr = buf;
    while (ptr < buf + len) {
        const struct inotify_event *ev =
            (const struct inotify_event *)ptr;

        if (ev->len > 0) {
            if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                if (ev->mask & IN_ISDIR)
                    register_scope(res, ev->name);
            } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                if (ev->mask & IN_ISDIR)
                    deregister_scope(res, ev->name);
            }
        }

        ptr += sizeof(struct inotify_event) + ev->len;
    }
    return 0;
}

int cgroup_resolver_get_inotify_fd(const struct cgroup_resolver *res)
{
    return res->inotify_fd;
}

const struct ct_container *cgroup_resolver_find_by_cgid(
        const struct cgroup_resolver *res, uint64_t cgid)
{
    for (int i = 0; i < res->count; i++) {
        if (res->containers[i].cgid == cgid)
            return &res->containers[i];
    }
    return NULL;
}

void cgroup_resolver_destroy(struct cgroup_resolver *res)
{
    if (!res)
        return;
    if (res->inotify_fd >= 0)
        close(res->inotify_fd);
    free(res);
}
