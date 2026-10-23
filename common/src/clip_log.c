/*
 * clip_log.c — CLICOM Logging Implementation
 *
 * Writes timestamped log lines to stderr and optionally to a log file.
 * Phase 3+ will add a mutex for thread safety.
 */

#include "clip_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Platform shims ─────────────────────────────────────────────────────── */

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
   /* localtime_s is the safe Windows version: localtime_s(&tm_buf, &now) */
   static void clip_localtime(struct tm* out, const time_t* t) {
       localtime_s(out, t);
   }
#else
   /* POSIX: localtime_r(&now, &tm_buf) */
   static void clip_localtime(struct tm* out, const time_t* t) {
       localtime_r(t, out);
   }
#endif

/* ── Module state ───────────────────────────────────────────────────────── */

static ClipLogLevel g_max_level = CLIP_LOG_INFO;
static FILE*        g_log_file  = NULL;

static const char* const k_level_str[] = {
    "ERROR",   /* CLIP_LOG_ERROR = 0 */
    "WARN ",   /* CLIP_LOG_WARN  = 1 */
    "INFO ",   /* CLIP_LOG_INFO  = 2 */
    "DEBUG"    /* CLIP_LOG_DEBUG = 3 */
};

/* ── Public API ─────────────────────────────────────────────────────────── */

void clip_log_init(ClipLogLevel max_level, const char* log_file)
{
    g_max_level = max_level;

    if (log_file && *log_file) {
        FILE* f = fopen(log_file, "a");
        if (f) {
            g_log_file = f;
        } else {
            fprintf(stderr, "[WARN ] clip_log: could not open log file: %s\n",
                    log_file);
        }
    }
}

void clip_log(ClipLogLevel level, const char* fmt, ...)
{
    va_list args;
    char    time_buf[20]; /* "HH:MM:SS\0" */
    struct  tm tm_info;

    if (level > g_max_level) {
        return;
    }

    /* Format current local time */
    {
        time_t now = time(NULL);
        clip_localtime(&tm_info, &now);
        strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_info);
    }

    /* stderr output */
    fprintf(stderr, "[%s] [%s] ", time_buf, k_level_str[level]);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    fflush(stderr);

    /* Log file output (if configured) */
    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%s] ", time_buf, k_level_str[level]);
        va_start(args, fmt);
        vfprintf(g_log_file, fmt, args);
        va_end(args);
        fputc('\n', g_log_file);
        fflush(g_log_file);
    }
}

void clip_log_close(void)
{
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}
