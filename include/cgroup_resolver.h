/* SPDX-License-Identifier: MIT */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "containertrace_event.h"

/* ------------------------------------------------------------------ */
/* Container tracking entry                                            */
/* ------------------------------------------------------------------ */

#define CT_CONTAINER_ID_LEN  65  /* full 64-char container ID + NUL */
#define CT_NAME_LEN          64  /* human-readable name + NUL */
#define CT_PATH_LEN         256  /* cgroup path + NUL */

struct ct_container {
    char             id[CT_CONTAINER_ID_LEN];    /* full container ID */
    char             name[CT_NAME_LEN];          /* display name      */
    char             scope_path[CT_PATH_LEN];    /* .scope cgroup dir */
    char             leaf_path[CT_PATH_LEN];     /* leaf cgroup dir   */
    uint64_t         cgid;                       /* leaf cgroup inode */
    struct ct_limits limits;
};

/* ------------------------------------------------------------------ */
/* Resolver handle (opaque to callers)                                 */
/* ------------------------------------------------------------------ */

struct cgroup_resolver;

/*
 * Allocate and initialise the resolver.
 * @limits_map_fd  – fd of the container_limits BPF hash map
 * @stats_map_fd   – fd of the container_cpu_stats BPF hash map
 * Returns NULL on failure.
 */
struct cgroup_resolver *cgroup_resolver_init(int limits_map_fd,
                                             int stats_map_fd);

/*
 * Scan /sys/fs/cgroup/machine.slice for active Podman containers
 * and register them in the BPF maps.
 * Safe to call multiple times; existing entries are refreshed.
 */
int cgroup_resolver_scan(struct cgroup_resolver *res);

/*
 * Drain pending inotify events and register / deregister containers.
 * Call from the main poll loop.
 */
int cgroup_resolver_process_events(struct cgroup_resolver *res);

/* Returns the inotify fd (add to poll/select as needed). */
int cgroup_resolver_get_inotify_fd(const struct cgroup_resolver *res);

/* Lookup a container by its BPF-reported cgroup ID. */
const struct ct_container *cgroup_resolver_find_by_cgid(
        const struct cgroup_resolver *res, uint64_t cgid);

/* Iterate over registered containers (for periodic stats). */
int cgroup_resolver_get_count(const struct cgroup_resolver *res);
const struct ct_container *cgroup_resolver_get_container(
        const struct cgroup_resolver *res, int idx);

/* Release all resources. */
void cgroup_resolver_destroy(struct cgroup_resolver *res);
