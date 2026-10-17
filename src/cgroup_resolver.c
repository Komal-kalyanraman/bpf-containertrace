// SPDX-License-Identifier: MIT
/*
 * cgroup_resolver.c – Podman container discovery via cgroup v2 + inotify
 *
 * Discovers containers for BOTH root Podman and rootless Podman:
 *
 *   Root Podman:     /sys/fs/cgroup/machine.slice/libpod-<id>.scope/
 *   Rootless Podman: /sys/fs/cgroup/user.slice/user-<uid>.slice/
 *                        user@<uid>.service/user.slice/libpod-<id>.scope/
 *
 * Discovery strategy:
 *   1. Initial recursive scan of CGROUP_ROOT for libpod-*.scope dirs.
 *      Only traverses directories that can contain Podman scopes
 *      (machine.slice, user.slice, user-*.slice, user@*.service).
 *   2. inotify watches on machine.slice + all relevant user session dirs,
 *      with dynamic watch creation when new session dirs appear.
 *   3. Periodic rescan (triggered by caller) as a safety net for any
 *      events missed by inotify.
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

#define CGROUP_ROOT          "/sys/fs/cgroup"
#define MACHINE_SLICE        CGROUP_ROOT "/machine.slice"
#define USER_SLICE_ROOT      CGROUP_ROOT "/user.slice"

#define SCOPE_PREFIX         "libpod-"
#define CONMON_PREFIX        "libpod-conmon-"
#define INNER_CGROUP         "container"

#define MAX_SCAN_DEPTH       6
#define MAX_INOTIFY_WATCHES  48
#define INNER_RETRY_MAX      10
#define INNER_RETRY_US       20000  /* 20 ms */

/* ------------------------------------------------------------------ */
/* Internal types                                                      */
/* ------------------------------------------------------------------ */

/* One inotify watch: maps a watch descriptor → the watched directory path. */
struct watch_dir {
    int  wd;
    char path[CT_PATH_LEN];
};

struct cgroup_resolver {
    struct ct_container containers[CT_MAX_CONTAINERS];
    int                 count;
    int                 inotify_fd;
    struct watch_dir    watches[MAX_INOTIFY_WATCHES];
    int                 num_watches;
    int                 limits_map_fd;
    int                 stats_map_fd;
};

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

static int  register_scope_at(struct cgroup_resolver *res,
                                const char *scope_path);
static void deregister_scope_at(struct cgroup_resolver *res,
                                  const char *scope_path);
static int  add_watch(struct cgroup_resolver *res, const char *path);
static void setup_watches_recursive(struct cgroup_resolver *res,
                                     const char *dir, int depth);
static void scan_for_scopes(struct cgroup_resolver *res,
                             const char *dir, int depth, int *count);

/* ------------------------------------------------------------------ */
/* cgroup file parsers                                                 */
/* ------------------------------------------------------------------ */

static void parse_cpu_max(const char *scope_path, struct ct_limits *lim)
{
    char path[CT_PATH_LEN + 16];
    snprintf(path, sizeof(path), "%s/cpu.max", scope_path);
    FILE *f = fopen(path, "r");
    if (!f) {
        lim->cpu_quota_ns  = 0;
        lim->cpu_period_ns = 100000000ULL;
        return;
    }
    char quota_str[32] = {0};
    unsigned long long period_us = 100000;
    if (fscanf(f, "%31s %llu", quota_str, &period_us) == 2) {
        lim->cpu_quota_ns  = (strcmp(quota_str, "max") == 0)
                             ? 0 : strtoull(quota_str, NULL, 10) * 1000ULL;
        lim->cpu_period_ns = period_us * 1000ULL;
    } else {
        lim->cpu_quota_ns  = 0;
        lim->cpu_period_ns = 100000000ULL;
    }
    fclose(f);
}

static void parse_memory_max(const char *scope_path, struct ct_limits *lim)
{
    char path[CT_PATH_LEN + 20];
    snprintf(path, sizeof(path), "%s/memory.max", scope_path);
    FILE *f = fopen(path, "r");
    if (!f) { lim->mem_limit = 0; return; }
    char buf[32] = {0};
    if (fscanf(f, "%31s", buf) == 1)
        lim->mem_limit = strcmp(buf, "max") == 0 ? 0 : strtoull(buf, NULL, 10);
    fclose(f);
}

static void parse_pids_max(const char *scope_path, struct ct_limits *lim)
{
    char path[CT_PATH_LEN + 16];
    snprintf(path, sizeof(path), "%s/pids.max", scope_path);
    FILE *f = fopen(path, "r");
    if (!f) { lim->pids_max = 0; return; }
    char buf[32] = {0};
    if (fscanf(f, "%31s", buf) == 1)
        lim->pids_max = strcmp(buf, "max") == 0 ? 0 : strtoull(buf, NULL, 10);
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Container ID extraction                                             */
/* ------------------------------------------------------------------ */

static void extract_id(const char *scope_name, char *id_out, size_t len)
{
    const char *start = scope_name + strlen(SCOPE_PREFIX);
    size_t n = strlen(start);
    if (n > 6 && strcmp(start + n - 6, ".scope") == 0)
        n -= 6;
    if (n >= len) n = len - 1;
    memcpy(id_out, start, n);
    id_out[n] = '\0';
}

/* ------------------------------------------------------------------ */
/* Container name resolution                                           */
/* ------------------------------------------------------------------ */

/*
 * Resolve the human-readable Podman container name.
 *
 * For root Podman:     run `podman inspect` directly.
 * For rootless Podman: the container DB is owned by the user; extract the
 *                      UID from the cgroup path and `runuser` as that UID.
 * Falls back to the 12-character short container ID on any failure.
 */
static void fetch_container_name(const char *full_id, const char *scope_path,
                                   char *name_out, size_t name_len)
{
    name_out[0] = '\0';

    char cmd[512];
    int  is_rootless = (strstr(scope_path, "/user@") != NULL);

    if (is_rootless) {
        /* Extract UID from "/user-<uid>.slice/" in the path. */
        const char *p = strstr(scope_path, "/user-");
        unsigned long uid = p ? strtoul(p + 6, NULL, 10) : 0;
        if (uid > 0) {
            snprintf(cmd, sizeof(cmd),
                     "runuser -u \"$(getent passwd %lu 2>/dev/null"
                     " | cut -d: -f1 || echo '#%lu')\" -- "
                     "podman inspect --format '{{.Name}}' %.64s 2>/dev/null",
                     uid, uid, full_id);
            FILE *f = popen(cmd, "r");
            if (f) {
                fgets(name_out, (int)name_len, f);
                pclose(f);
            }
        }
    } else {
        snprintf(cmd, sizeof(cmd),
                 "podman inspect --format '{{.Name}}' %.64s 2>/dev/null",
                 full_id);
        FILE *f = popen(cmd, "r");
        if (f) {
            fgets(name_out, (int)name_len, f);
            pclose(f);
        }
    }

    char *nl = strchr(name_out, '\n');
    if (nl) *nl = '\0';

    if (!name_out[0])
        snprintf(name_out, name_len, "%.12s", full_id);
}

/* ------------------------------------------------------------------ */
/* Leaf cgroup finder                                                  */
/* ------------------------------------------------------------------ */

/*
 * Determine the cgroup where container tasks actually run.
 * Podman places tasks inside <scope>/container/ with a short retry window
 * to handle the race between scope creation and inner cgroup setup.
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
        if (stat(scope_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (attempt < 2) { usleep(INNER_RETRY_US); continue; }
            snprintf(leaf_out, leaf_len, "%s", scope_path);
            *cgid_out = (uint64_t)st.st_ino;
            return 0;
        }
        return -ENOENT;
    }
    return -ENOENT;
}

/* ------------------------------------------------------------------ */
/* Container table helpers                                             */
/* ------------------------------------------------------------------ */

static struct ct_container *find_or_alloc(struct cgroup_resolver *res,
                                           const char *id)
{
    for (int i = 0; i < res->count; i++)
        if (strcmp(res->containers[i].id, id) == 0)
            return &res->containers[i];
    if (res->count >= CT_MAX_CONTAINERS) return NULL;
    return &res->containers[res->count++];
}

/* ------------------------------------------------------------------ */
/* Scope registration / deregistration                                 */
/* ------------------------------------------------------------------ */

static int register_scope_at(struct cgroup_resolver *res,
                               const char *scope_path)
{
    const char *scope_name = strrchr(scope_path, '/');
    scope_name = scope_name ? scope_name + 1 : scope_path;

    if (strncmp(scope_name, CONMON_PREFIX, strlen(CONMON_PREFIX)) == 0)
        return 0;
    if (strncmp(scope_name, SCOPE_PREFIX, strlen(SCOPE_PREFIX)) != 0)
        return 0;

    char full_id[CT_CONTAINER_ID_LEN];
    extract_id(scope_name, full_id, sizeof(full_id));

    struct ct_container *c = find_or_alloc(res, full_id);
    if (!c) {
        LOG_WARN("container table full, dropping %.12s", full_id);
        return -ENOMEM;
    }

    /* Already registered at the same path — nothing to do. */
    if (c->cgid != 0 && strcmp(c->scope_path, scope_path) == 0)
        return 0;

    char leaf_path[CT_PATH_LEN];
    uint64_t cgid = 0;
    if (find_leaf_cgroup(scope_path, leaf_path, sizeof(leaf_path), &cgid) != 0)
        return -ENOENT;

    strncpy(c->id,         full_id,    sizeof(c->id)         - 1);
    strncpy(c->scope_path, scope_path, sizeof(c->scope_path) - 1);
    strncpy(c->leaf_path,  leaf_path,  sizeof(c->leaf_path)  - 1);
    c->cgid = cgid;

    parse_cpu_max(scope_path,    &c->limits);
    parse_memory_max(scope_path, &c->limits);
    parse_pids_max(scope_path,   &c->limits);

    fetch_container_name(full_id, scope_path, c->name, sizeof(c->name));

    int is_rootless = (strstr(scope_path, "/user@") != NULL);

    int err = bpf_map_update_elem(res->limits_map_fd, &cgid, &c->limits,
                                   BPF_ANY);
    if (err) {
        LOG_ERROR("bpf_map_update_elem cgid=%llu: %s",
                  (unsigned long long)cgid, strerror(errno));
        return err;
    }

    LOG_INFO("container registered: name=%-20s id=%.12s cgid=%-6llu "
             "cpu_quota=%s mem_limit=%s%s",
             c->name, c->id, (unsigned long long)cgid,
             c->limits.cpu_quota_ns ? "set"       : "unlimited",
             c->limits.mem_limit    ? "set"       : "unlimited",
             is_rootless            ? " (rootless)" : "");
    return 0;
}

static void deregister_scope_at(struct cgroup_resolver *res,
                                  const char *scope_path)
{
    const char *scope_name = strrchr(scope_path, '/');
    scope_name = scope_name ? scope_name + 1 : scope_path;

    if (strncmp(scope_name, CONMON_PREFIX, strlen(CONMON_PREFIX)) == 0) return;
    if (strncmp(scope_name, SCOPE_PREFIX, strlen(SCOPE_PREFIX)) != 0)   return;

    char full_id[CT_CONTAINER_ID_LEN];
    extract_id(scope_name, full_id, sizeof(full_id));

    for (int i = 0; i < res->count; i++) {
        if (strcmp(res->containers[i].id, full_id) != 0) continue;

        struct ct_container *c = &res->containers[i];
        bpf_map_delete_elem(res->limits_map_fd, &c->cgid);
        bpf_map_delete_elem(res->stats_map_fd,  &c->cgid);

        LOG_INFO("container deregistered: name=%-20s id=%.12s", c->name, c->id);

        res->count--;
        if (i < res->count)
            res->containers[i] = res->containers[res->count];
        return;
    }
}

/* ------------------------------------------------------------------ */
/* inotify watch management                                            */
/* ------------------------------------------------------------------ */

static int add_watch(struct cgroup_resolver *res, const char *path)
{
    /* Avoid duplicate watches. */
    for (int i = 0; i < res->num_watches; i++)
        if (strcmp(res->watches[i].path, path) == 0)
            return res->watches[i].wd;

    if (res->num_watches >= MAX_INOTIFY_WATCHES) {
        LOG_WARN("max inotify watches reached, skipping %s", path);
        return -1;
    }

    int wd = inotify_add_watch(res->inotify_fd, path,
                               IN_CREATE | IN_DELETE | IN_MOVED_FROM |
                               IN_MOVED_TO | IN_DELETE_SELF);
    if (wd < 0)
        return -1;

    res->watches[res->num_watches].wd = wd;
    snprintf(res->watches[res->num_watches].path, CT_PATH_LEN, "%s", path);
    res->num_watches++;

    LOG_DEBUG("inotify watch: %s (wd=%d)", path, wd);
    return wd;
}

static const char *find_watch_path(const struct cgroup_resolver *res, int wd)
{
    for (int i = 0; i < res->num_watches; i++)
        if (res->watches[i].wd == wd) return res->watches[i].path;
    return NULL;
}

static void remove_watch_by_wd(struct cgroup_resolver *res, int wd)
{
    for (int i = 0; i < res->num_watches; i++) {
        if (res->watches[i].wd != wd) continue;
        res->num_watches--;
        if (i < res->num_watches)
            res->watches[i] = res->watches[res->num_watches];
        return;
    }
}

/*
 * Returns true for directory names that could contain libpod-*.scope
 * as children (directly or via further nesting).  Used both when
 * deciding what to recurse into during scanning and what new dirs
 * to add inotify watches to.
 *
 *   machine.slice          → contains root Podman scopes directly
 *   user.slice             → contains user-*.slice (at any level)
 *   user-<uid>.slice       → contains user@<uid>.service
 *   user@<uid>.service     → contains inner user.slice
 */
static int should_traverse(const char *dirname)
{
    return (strcmp(dirname,        "machine.slice") == 0 ||
            strcmp(dirname,        "user.slice")    == 0 ||
            strncmp(dirname, "user-", 5)            == 0 ||
            strncmp(dirname, "user@", 5)            == 0);
}

/*
 * Recursively add inotify watches on dirs that could host libpod-*.scope.
 * Called at init time on existing user session dirs.
 */
static void setup_watches_recursive(struct cgroup_resolver *res,
                                     const char *dir, int depth)
{
    if (depth <= 0) return;

    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (ent->d_type != DT_DIR && ent->d_type != DT_UNKNOWN) continue;
        if (!should_traverse(ent->d_name)) continue;

        char path[CT_PATH_LEN * 2];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        add_watch(res, path);
        setup_watches_recursive(res, path, depth - 1);
    }
    closedir(d);
}

/*
 * Recursively scan for libpod-*.scope directories.
 * Traverses only the dirs in should_traverse() so the walk is fast
 * even on a busy system (skips all unrelated cgroup subtrees).
 */
static void scan_for_scopes(struct cgroup_resolver *res,
                              const char *dir, int depth, int *count)
{
    if (depth <= 0) return;

    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (ent->d_type != DT_DIR && ent->d_type != DT_UNKNOWN) continue;

        char path[CT_PATH_LEN * 2];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

        if (strncmp(ent->d_name, SCOPE_PREFIX, strlen(SCOPE_PREFIX)) == 0) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (register_scope_at(res, path) == 0 && count)
                    (*count)++;
            }
        } else if (should_traverse(ent->d_name)) {
            scan_for_scopes(res, path, depth - 1, count);
        }
    }
    closedir(d);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

struct cgroup_resolver *cgroup_resolver_init(int limits_map_fd,
                                              int stats_map_fd)
{
    struct cgroup_resolver *res = calloc(1, sizeof(*res));
    if (!res) return NULL;

    res->limits_map_fd = limits_map_fd;
    res->stats_map_fd  = stats_map_fd;

    res->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (res->inotify_fd < 0) {
        LOG_ERROR("inotify_init1: %s", strerror(errno));
        free(res);
        return NULL;
    }

    /* Watch machine.slice (root Podman). */
    if (add_watch(res, MACHINE_SLICE) < 0)
        LOG_WARN("Could not watch %s: %s", MACHINE_SLICE, strerror(errno));

    /* Watch user.slice top-level so we see new user sessions arrive. */
    if (add_watch(res, USER_SLICE_ROOT) < 0)
        LOG_WARN("Could not watch %s: %s", USER_SLICE_ROOT, strerror(errno));

    /* For any user sessions already active, add watches recursively. */
    setup_watches_recursive(res, USER_SLICE_ROOT, 4);

    return res;
}

int cgroup_resolver_scan(struct cgroup_resolver *res)
{
    /* GC: remove entries whose leaf cgroup no longer exists. */
    for (int i = res->count - 1; i >= 0; i--) {
        struct ct_container *c = &res->containers[i];
        struct stat st;
        if (stat(c->leaf_path, &st) != 0) {
            bpf_map_delete_elem(res->limits_map_fd, &c->cgid);
            bpf_map_delete_elem(res->stats_map_fd,  &c->cgid);
            LOG_INFO("container gc: name=%s id=%.12s (scope gone)",
                     c->name, c->id);
            res->count--;
            if (i < res->count)
                res->containers[i] = res->containers[res->count];
        }
    }

    int before = res->count;
    int found  = 0;
    scan_for_scopes(res, CGROUP_ROOT, MAX_SCAN_DEPTH, &found);

    int new_ct = res->count - before;
    if (new_ct > 0)
        LOG_INFO("scan: %d new container(s) found (%d total)",
                 new_ct, res->count);
    else if (res->count == 0)
        LOG_DEBUG("scan: no running Podman containers");

    return res->count;
}

int cgroup_resolver_process_events(struct cgroup_resolver *res)
{
    char buf[4096]
        __attribute__((aligned(__alignof__(struct inotify_event))));

    ssize_t len = read(res->inotify_fd, buf, sizeof(buf));
    if (len <= 0)
        return 0;

    const char *ptr = buf;
    while (ptr < buf + len) {
        const struct inotify_event *ev =
            (const struct inotify_event *)ptr;
        ptr += sizeof(*ev) + ev->len;

        /* Watched directory itself was deleted. */
        if (ev->mask & IN_DELETE_SELF) {
            remove_watch_by_wd(res, ev->wd);
            continue;
        }

        if (ev->len == 0) continue;

        const char *parent = find_watch_path(res, ev->wd);
        if (!parent) continue;

        char full_path[CT_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", parent, ev->name);

        if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
            if (!(ev->mask & IN_ISDIR)) continue;

            if (strncmp(ev->name, SCOPE_PREFIX, strlen(SCOPE_PREFIX)) == 0) {
                register_scope_at(res, full_path);
            } else if (should_traverse(ev->name)) {
                /* New user session dir appeared; watch it and scan it. */
                add_watch(res, full_path);
                setup_watches_recursive(res, full_path, 3);
                scan_for_scopes(res, full_path, 3, NULL);
            }
        } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
            if (ev->mask & IN_ISDIR)
                if (strncmp(ev->name, SCOPE_PREFIX, strlen(SCOPE_PREFIX)) == 0)
                    deregister_scope_at(res, full_path);
        }
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
    for (int i = 0; i < res->count; i++)
        if (res->containers[i].cgid == cgid) return &res->containers[i];
    return NULL;
}

int cgroup_resolver_get_count(const struct cgroup_resolver *res)
{
    return res ? res->count : 0;
}

const struct ct_container *cgroup_resolver_get_container(
        const struct cgroup_resolver *res, int idx)
{
    if (!res || idx < 0 || idx >= res->count) return NULL;
    return &res->containers[idx];
}

void cgroup_resolver_destroy(struct cgroup_resolver *res)
{
    if (!res) return;
    if (res->inotify_fd >= 0)
        close(res->inotify_fd);
    free(res);
}
