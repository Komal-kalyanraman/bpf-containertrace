/* SPDX-License-Identifier: MIT */
#pragma once

#include <stdio.h>
#include <time.h>

/* Simple timestamp-prefixed logger.  No heap allocation. */

static inline void _ct_log_ts(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    fprintf(stderr, "[%02d:%02d:%02d.%03ld] ",
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            ts.tv_nsec / 1000000L);
}

#define LOG_INFO(fmt, ...)  do { _ct_log_ts(); fprintf(stderr, "[INFO]  " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_WARN(fmt, ...)  do { _ct_log_ts(); fprintf(stderr, "[WARN]  " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_ERROR(fmt, ...) do { _ct_log_ts(); fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); } while(0)

#ifdef CT_DEBUG
#define LOG_DEBUG(fmt, ...) do { _ct_log_ts(); fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)
#else
#define LOG_DEBUG(fmt, ...) do { } while(0)
#endif
