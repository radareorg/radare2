/* radare - LGPL - Copyright 2007-2013 - pancake */

#define LOG_CONFIGSTR_SIZE 512
#define LOG_OUTPUTBUF_SIZE 512

#include <r_core.h>
#include <stdarg.h>

// TODO: Use thread-local storage to make these variables thread-safe
static RLogCallback cb_main_output = NULL; // Function to call when outputting log string
static int cfg_loglvl = R_LOGLVL_ERROR; // Log level output
static int cfg_logtraplvl = R_LOGLVL_FATAL; // Log trap level
static bool cfg_logsrcinfo = false; // Print out debug source info with the output
static bool cfg_logcolors = false; // Output colored log text based on level
static char cfg_logfile[LOG_CONFIGSTR_SIZE] = ""; // Output text to filename
static const char *level_tags[] = { // Log level to tag string lookup array
	[R_LOGLVL_SILLY]     = "SILLY",
	[R_LOGLVL_VERBOSE]   = "VERBOSE",
	[R_LOGLVL_DEBUG]     = "DEBUG",
	[R_LOGLVL_INFO]      = "INFO",
	[R_LOGLVL_WARN]      = "WARNING",
	[R_LOGLVL_ERROR]     = "ERROR",
	[R_LOGLVL_FATAL]     = "FATAL"
};

// cconfig.c configuration callback functions below
R_API void r_log_set_level(RLogLevel level) {
	cfg_loglvl = level;
}

R_API void r_log_set_traplevel(RLogLevel level) {
	cfg_logtraplvl = level;
}

R_API void r_log_set_file(const char *filename) {
	int value_len = r_str_nlen (filename, LOG_CONFIGSTR_SIZE) + 1;
	strncpy (cfg_logfile, filename, value_len);
}

R_API void r_log_set_srcinfo(bool show_info) {
	cfg_logsrcinfo = show_info;
}

R_API void r_log_set_colors(bool show_info) {
	cfg_logcolors = show_info;
}

/**
 * \brief Set the main callback for the logging API
 * \param cbfunc RLogCallback style function to be called

  This is used by cons/cons.c:r_cons_new to set the log output
  to r_cons. If r_cons is unavailable and this is never called
  then _r_log_internal will use its fallback to stderr in r_util
*/
R_API void r_log_set_main_callback(RLogCallback cbfunc) {
	// TODO: RList of callbacks with setter/remove methods
	cb_main_output = cbfunc;
}

/**
 * \brief Internal logging function used by preprocessor macros
 * \param funcname Contains the function name of the calling function
 * \param filename Contains the filename that funcname is defined in
 * \param lineno The line number that this log call is being made from in filename
 * \param lvl Logging level for output
 * \param fmtstr A printf like string

  This function is used by the R_LOG_* preprocessor macros for logging
*/
R_API void _r_log_internal(const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) {
	if (level < cfg_loglvl && level < cfg_logtraplvl) {
		// Don't print if output level is lower than current level
		// Don't ignore fatal/trap errors
		return;
	}

	// Setup varadic arguments
	va_list args, args_copy;
	va_start (args, fmtstr);
	va_copy (args_copy, args);

	// TODO: Colors

	// Build output string with src info, and formatted output
	char output_buf[LOG_OUTPUTBUF_SIZE] = ""; // Big buffer for building the output string
	const char *default_tag = R_BETWEEN (0, level, sizeof (level_tags) - 1) ? level_tags[level] : "";
	if (!tag) {
		tag = default_tag;
	}
	int offset = snprintf (output_buf, LOG_OUTPUTBUF_SIZE, "%s: ", tag);
	if (cfg_logsrcinfo) {
		offset += snprintf (output_buf + offset, LOG_OUTPUTBUF_SIZE - offset, "%s in %s:%i: ", funcname, filename, lineno);
	}
	vsnprintf (output_buf + offset, LOG_OUTPUTBUF_SIZE - offset, fmtstr, args);

	// Actually print out the string with our callbacks
	if (cb_main_output) {
		cb_main_output (output_buf, funcname, filename, lineno, level, NULL, fmtstr, args_copy);
	} else {
		fprintf (stderr, "%s", output_buf);
	}

	// Log to file if enabled
	if (cfg_logfile[0] != 0x00) {
		FILE *file = r_sandbox_fopen (cfg_logfile, "a+"); // TODO: Optimize (static? Needs to remake on cfg change though)
		if (!file) {
			file = r_sandbox_fopen (cfg_logfile, "w+");
		}
		if (file) {
			fprintf (file, "%s", output_buf);
			fclose (file);
		} else {
			eprintf ("%s failed to write to file: %s\n", MACRO_LOG_FUNC, cfg_logfile);
		}
	}

	va_end (args);
	va_end (args_copy);

	if (level >= cfg_logtraplvl && level != R_LOGLVL_NONE) {
		fflush (stdout); // We're about to exit HARD, flush buffers before dying
		fflush (stderr);
		// TODO: call r_cons_flush if libr_cons is being used
		r_sys_breakpoint (); // *oof*
	}
}
