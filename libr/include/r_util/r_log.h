#ifndef R_LOG_H
#define R_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	R_LOG_LEVEL_DEBUG,
	R_LOG_LEVEL_INFO,
	R_LOG_LEVEL_WARNING,
	R_LOG_LEVEL_ERROR
} RLogLevel;

typedef void (*RLog)(RLogLevel level, const char *str);
typedef void (*RLogF)(RLogLevel level, const char *format, va_list ap);

R_API void r_log_set(RLog log, RLogF logf);
R_API void r_log(RLogLevel level, const char *str);
R_API void r_logf_list(RLogLevel level, const char *format, va_list ap);
R_API void r_logf(RLogLevel level, const char *format, ...);

#define R_LOGD(s)	r_log (R_LOG_LEVEL_DEBUG, (s))
#define R_LOGI(s)	r_log (R_LOG_LEVEL_INFO, (s))
#define R_LOGW(s)	r_log (R_LOG_LEVEL_WARNING, (s))
#define R_LOGE(s)	r_log (R_LOG_LEVEL_ERROR, (s))

#define R_LOGFD(...)	r_logf (R_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define R_LOGFI(...)	r_logf (R_LOG_LEVEL_INFO, __VA_ARGS__)
#define R_LOGFW(...)	r_logf (R_LOG_LEVEL_WARNING, __VA_ARGS__)
#define R_LOGFE(...)	r_logf (R_LOG_LEVEL_ERROR, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif //  R_LOG_H
