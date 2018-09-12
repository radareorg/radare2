#ifndef R_LOG_H
#define R_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum r_log_level {
	R_LOG_DEBUG = 0,
	R_LOG_INFO,
	R_LOG_WARNING,
	R_LOG_ERROR,
	R_LOG_CRITICAL
} RLogLevel;

R_API void r_log_msg(const char *str);
R_API void r_log_error(const char *str);
R_API void r_log_file(const char *str);
R_API void r_log_progress(const char *str, int percent);
R_API void r_log(RLogLevel level, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif //  R_LOG_H
