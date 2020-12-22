#ifndef R_LOG_H
#define R_LOG_H

#include <r_userconf.h>

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__GNUC__)
#define MACRO_LOG_FUNC __FUNCTION__
#define MACRO_WEAK_SYM
// TODO: Windows weak symbols?
#elif defined(__EMSCRIPTEN__) // TODO: test upon Emscripten's version once it supports weak symbols
#define MACRO_LOG_FUNC __func__
#define MACRO_WEAK_SYM
#else
#define MACRO_LOG_FUNC __func__
#define MACRO_WEAK_SYM __attribute__ ((weak))
#endif

typedef enum r_log_level {
	R_LOGLVL_SILLY = 0,
	R_LOGLVL_DEBUG = 1,
	R_LOGLVL_VERBOSE = 2,
	R_LOGLVL_INFO = 3,
	R_LOGLVL_WARN = 4,
	R_LOGLVL_ERROR = 5,
	R_LOGLVL_FATAL = 6, // This will call r_sys_breakpoint() and trap the process for debugging!
	R_LOGLVL_NONE = 0xFF
} RLogLevel;

#if R_CHECKS_LEVEL >= 2
#define R_DEFAULT_LOGLVL R_LOGLVL_WARN
#else
#define R_DEFAULT_LOGLVL R_LOGLVL_ERROR
#endif

typedef void (*RLogCallback) (const char *output, const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) R_PRINTF_CHECK(7, 8);

#define R_VLOG(lvl, tag, fmtstr, args) r_vlog (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, lvl, tag, fmtstr, args);

#define R_LOG(lvl, tag, fmtstr, ...) r_log (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, lvl, tag, fmtstr, ##__VA_ARGS__);
#define R_LOG_SILLY(fmtstr, ...) r_log (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, R_LOGLVL_SILLY, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_DEBUG(fmtstr, ...) r_log (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, R_LOGLVL_DEBUG, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_VERBOSE(fmtstr, ...) r_log (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, R_LOGLVL_VERBOSE, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_INFO(fmtstr, ...) r_log (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, R_LOGLVL_INFO, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_WARN(fmtstr, ...) r_log (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, R_LOGLVL_WARN, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_ERROR(fmtstr, ...) r_log (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, R_LOGLVL_ERROR, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_FATAL(fmtstr, ...) r_log (MACRO_LOG_FUNC, __FILE__, \
	__LINE__, R_LOGLVL_FATAL, NULL, fmtstr, ##__VA_ARGS__);

#ifdef __cplusplus
extern "C" {
#endif

// Called by r_core to set the configuration variables
R_API void r_log_set_level(RLogLevel level);
R_API void r_log_set_file(const char *filename);
R_API void r_log_set_srcinfo(bool show_info);
R_API void r_log_set_colors(bool show_colors);
R_API void r_log_set_traplevel(RLogLevel level);
// TODO: r_log_set_options(enum RLogOptions)

// Functions for adding log callbacks
R_API void r_log_add_callback(RLogCallback cbfunc);
R_API void r_log_del_callback(RLogCallback cbfunc);
// TODO: r_log_get_callbacks()

/* Define r_log as weak so it can be 'overwritten' externally
   This allows another method of output redirection on POSIX (Windows?)
   You can override this function to handle all logging logic / output yourself */
R_API MACRO_WEAK_SYM void r_log(const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) R_PRINTF_CHECK(6, 7);

R_API MACRO_WEAK_SYM void r_vlog(const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, va_list args);

#ifdef __cplusplus
}
#endif

#endif //  R_LOG_H
