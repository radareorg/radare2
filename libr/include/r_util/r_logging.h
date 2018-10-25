#ifndef R_LOGGING_H
#define R_LOGGING_H

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__GNUC__)
#define MACRO_LOG_FUNC __FUNCTION__
#define MACRO_WEAK_SYM
// TODO: Windows weak symbols?
#else
#define MACRO_LOG_FUNC __func__
#define MACRO_WEAK_SYM __attribute__ ((weak))
#endif

typedef enum r_logging_level {
	R_LOGLVL_SILLY     = 0,
	R_LOGLVL_DEBUG     = 1,
	R_LOGLVL_VERBOSE   = 2,
	R_LOGLVL_INFO      = 3,
	R_LOGLVL_WARN      = 4,
	R_LOGLVL_ERROR     = 5,
	R_LOGLVL_FATAL     = 6, // This will call r_sys_breakpoint() and trap the process for debugging!
	R_LOGLVL_NONE      = 0xFF
} RLoggingLevel;

typedef void (*RLoggingFuncdef)(const char *output, const char *funcname,
	const char *filename, ut32 lineno, RLoggingLevel level, const char *fmtstr, ...);

#define R_LOG(lvl, fmtstr, ...) _r_logging_internal (MACRO_LOG_FUNC, __FILE__,\
 __LINE__, lvl, fmtstr, ##__VA_ARGS__);
#define R_LOG_SILLY(fmtstr, ...) _r_logging_internal (MACRO_LOG_FUNC, __FILE__,\
 __LINE__, R_LOGLVL_SILLY, fmtstr, ##__VA_ARGS__);
#define R_LOG_DEBUG(fmtstr, ...) _r_logging_internal (MACRO_LOG_FUNC, __FILE__,\
 __LINE__, R_LOGLVL_DEBUG, fmtstr, ##__VA_ARGS__);
#define R_LOG_VERBOSE(fmtstr, ...) _r_logging_internal (MACRO_LOG_FUNC, __FILE__,\
 __LINE__, R_LOGLVL_VERBOSE, fmtstr, ##__VA_ARGS__);
#define R_LOG_INFO(fmtstr, ...) _r_logging_internal (MACRO_LOG_FUNC, __FILE__,\
 __LINE__, R_LOGLVL_INFO, fmtstr, ##__VA_ARGS__);
#define R_LOG_WARN(fmtstr, ...) _r_logging_internal (MACRO_LOG_FUNC, __FILE__,\
 __LINE__, R_LOGLVL_WARN, fmtstr, ##__VA_ARGS__);
#define R_LOG_ERROR(fmtstr, ...) _r_logging_internal (MACRO_LOG_FUNC, __FILE__,\
 __LINE__, R_LOGLVL_ERROR, fmtstr, ##__VA_ARGS__);
#define R_LOG_FATAL(fmtstr, ...) _r_logging_internal (MACRO_LOG_FUNC, __FILE__,\
 __LINE__, R_LOGLVL_FATAL, fmtstr, ##__VA_ARGS__);

#ifdef __cplusplus
extern "C" {
#endif

// Called by r_core to set the configuration variables
R_API void r_logging_set_level(RLoggingLevel level);
R_API void r_logging_set_file(const char *filename);
R_API void r_logging_set_srcinfo(bool show_info);
R_API void r_logging_set_colors(bool show_colors);
R_API void r_logging_set_traplevel(RLoggingLevel level);

// Functions for setting logging callbacks externally
R_API void r_logging_set_callback(RLoggingFuncdef cbfunc);
// TODO: r_logging_add_callback(cbfunc, *context)
// TODO: r_logging_get_callbacks()
// TODO: r_logging_remove_callback(cbfunc, *context)

/* Define _r_logging_internal as weak so it can be 'overwritten' externally
   This allows another method of output redirection on POSIX (Windows?)
   You can override this function to handle all logging logic / output yourself */
R_API MACRO_WEAK_SYM void _r_logging_internal(const char *funcname, const char *filename,
	ut32 lineno, RLoggingLevel level, const char *fmtstr, ...);

#ifdef __cplusplus
}
#endif

#endif //  R_LOGGING_H
