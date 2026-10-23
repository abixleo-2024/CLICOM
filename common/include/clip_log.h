/*
 * clip_log.h — CLICOM Logging Interface
 *
 * Simple levelled logging. Writes timestamped lines to stderr.
 * Optionally also writes to a log file.
 *
 * Usage:
 *   clip_log_init(CLIP_LOG_INFO, NULL);       // stderr only
 *   clip_log_init(CLIP_LOG_DEBUG, "app.log"); // stderr + file
 *   CLIP_LOGI("Server started on port %d", port);
 *   clip_log_close();
 */

#ifndef CLIP_LOG_H
#define CLIP_LOG_H

#include <stdarg.h>

typedef enum {
    CLIP_LOG_ERROR = 0,
    CLIP_LOG_WARN  = 1,
    CLIP_LOG_INFO  = 2,
    CLIP_LOG_DEBUG = 3
} ClipLogLevel;

/*
 * Initialize logging.
 *   max_level : messages above this level are suppressed.
 *   log_file  : path to append log output; NULL for stderr only.
 */
void clip_log_init(ClipLogLevel max_level, const char* log_file);

/* Emit a log line at the given level. Thread-safe via mutex (Phase 3+). */
void clip_log(ClipLogLevel level, const char* fmt, ...);

/* Flush and close the log file (if open). */
void clip_log_close(void);

/* Convenience macros */
#define CLIP_LOGE(...) clip_log(CLIP_LOG_ERROR, __VA_ARGS__)
#define CLIP_LOGW(...) clip_log(CLIP_LOG_WARN,  __VA_ARGS__)
#define CLIP_LOGI(...) clip_log(CLIP_LOG_INFO,  __VA_ARGS__)
#define CLIP_LOGD(...) clip_log(CLIP_LOG_DEBUG, __VA_ARGS__)

#endif /* CLIP_LOG_H */
