#ifndef R_LOG_H
#define R_LOG_H

#include <r_userconf.h>
#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef R_LOG_ORIGIN
#define R_LOG_ORIGIN __FILE__
#endif

typedef enum r_log_level {
	R_LOGLVL_NONE = 0,
	R_LOGLVL_FATAL = 1, // This will call r_sys_breakpoint() and trap the process for debugging!
	R_LOGLVL_INFO = 2,
	R_LOGLVL_WARN = 3,
	R_LOGLVL_DEBUG = 4,
	R_LOGLVL_ERROR = 5,
} RLogLevel;

#define R_LOGLVL_DEFAULT R_LOGLVL_WARN

typedef bool (*RLogCallback)(void *user, int type, const char *origin, const char *msg);

typedef struct r_log_t {
	int level; // skip messages lower than this level
	int traplevel; // skip messages lower than this level
	void *user;
	char *file;
	char *filter;
	bool color; // colorize depending on msg level
	bool quiet; // be quiet in the console
	bool ts;
	RList *cbs;
	// RLogCallback cb;
} RLog;

typedef struct r_log_source_t {
	const char *file;
	ut32 lineno;
	const char *source;
} RLogSource;

R_API void r_log_init(void);
R_API void r_log_fini(void);
R_API bool r_log_match(int level, const char *origin);
R_API void r_log_message(RLogLevel level, const char *origin, const char *fmt, ...);
R_API void r_log_vmessage(RLogLevel level, const char *origin, const char *fmt, va_list ap);
R_API void r_log_add_callback(RLogCallback cb);
R_API void r_log_del_callback(RLogCallback cb);

#define R_LOG(f,...) if (r_log_match(R_LOGLVL_INFO, R_LOG_ORIGIN)) {r_log_message(R_LOGLVL_INFO, R_LOG_ORIGIN, f, ##__VA_ARGS__);}
#define R_LOG_WARN(f,...) if (r_log_match(R_LOGLVL_WARN, R_LOG_ORIGIN)) {r_log_message(R_LOGLVL_WARN, R_LOG_ORIGIN, f, ##__VA_ARGS__);}
#define R_LOG_INFO(f,...) if (r_log_match(R_LOGLVL_INFO, R_LOG_ORIGIN)) {r_log_message(R_LOGLVL_INFO, R_LOG_ORIGIN, f, ##__VA_ARGS__);}
#define R_LOG_DEBUG(f,...) if (r_log_match(R_LOGLVL_DEBUG, R_LOG_ORIGIN)) {r_log_message(R_LOGLVL_DEBUG, R_LOG_ORIGIN, f, ##__VA_ARGS__);}
#define R_LOG_ERROR(f,...) if (r_log_match(R_LOGLVL_ERROR, R_LOG_ORIGIN)) {r_log_message(R_LOGLVL_ERROR, R_LOG_ORIGIN, f, ##__VA_ARGS__);}
#define R_LOG_FATAL(f,...) if (r_log_match(R_LOGLVL_FATAL, R_LOG_ORIGIN)) {r_log_message(R_LOGLVL_FATAL, R_LOG_ORIGIN, f, ##__VA_ARGS__);}

#if 0
RLogSource s = { __FILE__, R_FUNCTION, __LINE__, "bin" };
typedef void (*RLogCallback) (const char *output, const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) R_PRINTF_CHECK(7, 8);

#define R_LOG(lvl, tag, fmtstr, ...) r_log (R_FUNCTION, __FILE__, \
	__LINE__, lvl, tag, fmtstr, ##__VA_ARGS__);
#define R_LOG_SILLY(fmtstr, ...) r_log (R_FUNCTION, __FILE__, \
	__LINE__, R_LOGLVL_SILLY, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_DEBUG(fmtstr, ...) r_log (R_FUNCTION, __FILE__, \
	__LINE__, R_LOGLVL_DEBUG, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_VERBOSE(fmtstr, ...) r_log (R_FUNCTION, __FILE__, \
	__LINE__, R_LOGLVL_VERBOSE, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_INFO(fmtstr, ...) r_log (R_FUNCTION, __FILE__, \
	__LINE__, R_LOGLVL_INFO, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_WARN(fmtstr, ...) r_log (R_FUNCTION, __FILE__, \
	__LINE__, R_LOGLVL_WARN, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_ERROR(fmtstr, ...) r_log (R_FUNCTION, __FILE__, \
	__LINE__, R_LOGLVL_ERROR, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_FATAL(fmtstr, ...) r_log (R_FUNCTION, __FILE__, \
	__LINE__, R_LOGLVL_FATAL, NULL, fmtstr, ##__VA_ARGS__);
#endif


// Called by r_core to set the configuration variables
R_API void r_log_set_file(const char *expr);
R_API void r_log_set_filter(const char *expr);
// R_API void r_log_set_srcinfo(bool show_info);
R_API void r_log_set_colors(bool show_colors);
R_API void r_log_set_quiet(bool be_quiet);
R_API void r_log_set_level(RLogLevel level);
R_API void r_log_set_ts(bool ts);
R_API void r_log_set_traplevel(RLogLevel level);
// TODO: r_log_set_options(enum RLogOptions)

// Functions for adding log callbacks
R_API void r_log_set_callback(RLogCallback cbfunc);
// TODO: r_log_get_callbacks()

/* Define r_log as weak so it can be 'overwritten' externally
   This allows another method of output redirection on POSIX (Windows?)
   You can override this function to handle all logging logic / output yourself */
R_API R_WEAK void r_log(const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) R_PRINTF_CHECK(6, 7);

R_API R_WEAK void r_vlog(const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, va_list args);

#ifdef __cplusplus
}
#endif

#endif //  R_LOG_H
