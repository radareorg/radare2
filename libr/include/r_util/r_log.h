#ifndef R_LOG_H
#define R_LOG_H

#include <r_userconf.h>
#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef R_LOG_ORIGIN
// log.origin = module or function name
#define R_LOG_ORIGIN __FUNCTION__
#endif
#ifndef R_LOG_SOURCE
// log.source = file:line
#define R_LOG_SOURCE __FILE__
#endif

#ifndef R_LOG_DISABLE
#define R_LOG_DISABLE 0
#endif

// unused, but could be a good replacement for eprintf when fully transitioned?
#define etrace(m) eprintf ("--> %s:%d : %s\n", __FUNCTION__, __LINE__, m)

#define R_LOGLVL_DEFAULT R_LOGLVL_TODO

// TODO .rename to R_LOG_LEVEL_XXXX
typedef enum r_log_level {
	R_LOGLVL_FATAL = 0, // This will call r_sys_breakpoint() and trap the process for debugging!
	R_LOGLVL_ERROR = 1,
	R_LOGLVL_INFO = 2,
	R_LOGLVL_WARN = 3,
	R_LOGLVL_TODO = 4,
	R_LOGLVL_DEBUG = 5,
	R_LOGLVL_LAST = 6,
} RLogLevel;

typedef bool (*RLogCallback)(void *user, int type, const char *origin, const char *msg);

typedef struct r_log_t {
	int level; // skip messages lower than this level
	int traplevel; // skip messages lower than this level
	void *user;
	char *file;
	char *filter;
	bool color; // colorize depending on msg level
	bool quiet; // be quiet in the console
	bool show_origin;
	bool show_source;
	bool show_ts;
	RList *cbs;
} RLog;

typedef struct r_log_source_t {
	const char *file;
	ut32 lineno;
	const char *source;
} RLogSource;

R_API bool r_log_init(void);
R_API void r_log_fini(void);
R_API bool r_log_match(int level, const char *origin);
R_API void r_log_message(RLogLevel level, const char *origin, const char *func, int line, const char *fmt, ...);
R_API void r_log_vmessage(RLogLevel level, const char *origin, const char *func, int line, const char *fmt, va_list ap);
R_API void r_log_add_callback(RLogCallback cb, void *user);
R_API void r_log_del_callback(RLogCallback cb);

#if R_LOG_DISABLE
#define R_LOG(f,...) do {} while(0)
#define R_LOG_FATAL(f,...) do {} while(0)
#define R_LOG_ERROR(f,...) do {} while(0)
#define R_LOG_INFO(f,...) do {} while(0)
#define R_LOG_TODO(f,...) do {} while(0)
#define R_LOG_WARN(f,...) do {} while(0)
#define R_LOG_DEBUG(f,...) do {} while(0)
#else
#define R_LOG(f,...) if (R_UNLIKELY(r_log_match(R_LOGLVL_INFO, R_LOG_ORIGIN))) {r_log_message (R_LOGLVL_INFO, R_LOG_ORIGIN, __FILE__, __LINE__, f, ##__VA_ARGS__);}
#define R_LOG_FATAL(f,...) if (R_UNLIKELY(r_log_match(R_LOGLVL_FATAL, R_LOG_ORIGIN))) {r_log_message (R_LOGLVL_FATAL, R_LOG_ORIGIN, __FILE__, __LINE__, f, ##__VA_ARGS__);}
#define R_LOG_ERROR(f,...) if (R_UNLIKELY(r_log_match(R_LOGLVL_ERROR, R_LOG_ORIGIN))) {r_log_message (R_LOGLVL_ERROR, R_LOG_ORIGIN, __FILE__, __LINE__, f, ##__VA_ARGS__);}
#define R_LOG_INFO(f,...) if (R_UNLIKELY(r_log_match(R_LOGLVL_INFO, R_LOG_ORIGIN))) {r_log_message (R_LOGLVL_INFO, R_LOG_ORIGIN, __FILE__, __LINE__, f, ##__VA_ARGS__);}
#define R_LOG_TODO(f,...) if (R_UNLIKELY(r_log_match(R_LOGLVL_TODO, R_LOG_ORIGIN))) {r_log_message(R_LOGLVL_TODO, R_LOG_ORIGIN, __FILE__, __LINE__, f, ##__VA_ARGS__);}
#define R_LOG_WARN(f,...) if (R_UNLIKELY(r_log_match(R_LOGLVL_WARN, R_LOG_ORIGIN))) {r_log_message (R_LOGLVL_WARN, R_LOG_ORIGIN, __FILE__, __LINE__, f, ##__VA_ARGS__);}
#define R_LOG_DEBUG(f,...) if (R_UNLIKELY(r_log_match(R_LOGLVL_DEBUG, R_LOG_ORIGIN))) {r_log_message (R_LOGLVL_DEBUG, R_LOG_ORIGIN, __FILE__, __LINE__, f, ##__VA_ARGS__);}
#endif

R_API void r_log_set_file(const char *expr);
R_API void r_log_set_filter(const char *expr);
R_API void r_log_set_colors(bool show_colors);
R_API void r_log_show_origin(bool show_origin);
R_API void r_log_show_source(bool show_source);
R_API void r_log_set_quiet(bool be_quiet);
R_API void r_log_set_level(RLogLevel level);
R_API void r_log_show_ts(bool ts);
R_API RLogLevel r_log_get_level(void);
R_API RLogLevel r_log_get_traplevel(void);
R_API void r_log_set_traplevel(RLogLevel level);
R_API void r_log_set_callback(RLogCallback cbfunc);

R_API void r_log(const char *funcname, const char *filename, ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) R_PRINTF_CHECK(6, 7);
R_API void r_vlog(const char *funcname, const char *filename, ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, va_list args);

#ifdef __cplusplus
}
#endif

#endif //  R_LOG_H
