/* radare - LGPL - Copyright 2007-2013 - pancake */

#define LOGGING_CONFIGSTR_SIZE 512
#define LOGGING_OUTPUTBUF_SIZE 512

#include <r_core.h>
#include <stdarg.h>

// TODO: Use thread-local storage to make these variables thread-safe
static RLoggingFuncdef cb_logfunc_print = NULL; // Function to call when outputting log string
static int cfg_loglvl = R_LOGLVL_ERROR; // Logging level output
static int cfg_logtraplvl = R_LOGLVL_FATALTRAP; // Logging trap level
static bool cfg_logsrcinfo = false; // Print out debug source info with the output
static bool cfg_logcolors = false; // Output colored log text based on level
static char cfg_logfile[LOGGING_CONFIGSTR_SIZE] = ""; // Output text to filename
static const char *level_tags[] = { // Log level to tag string lookup array
	[R_LOGLVL_SILLY]     = "SILLY: ",
	[R_LOGLVL_VERBOSE]   = "VERBOSE: ",
	[R_LOGLVL_DEBUG]     = "DEBUG: ",
	[R_LOGLVL_INFO]      = "INFO: ",
	[R_LOGLVL_WARN]      = "WARNING: ",
	[R_LOGLVL_ERROR]     = "ERROR: ",
	[R_LOGLVL_FATAL]     = "FATAL: ",
	[R_LOGLVL_FATALTRAP] = "FATAL: "
};

// cconfig.c configuration callback functions below
R_API void r_logging_set_level(RLoggingLevel level) {
	cfg_loglvl = level;
}

R_API void r_logging_set_traplevel(RLoggingLevel level) {
	cfg_logtraplvl = level;
}

R_API void r_logging_set_file(const char *filename) {
	int value_len = strnlen (filename, LOGGING_CONFIGSTR_SIZE) + 1;
	strncpy (cfg_logfile, filename, value_len);
}

R_API void r_logging_set_srcinfo(bool show_info) {
	cfg_logsrcinfo = show_info;
}

R_API void r_logging_set_colors(bool show_info) {
	cfg_logcolors = show_info;
}

/**
 * \brief Set the logging callback function for printing
 * \param cbfunc RLoggingFuncdef style function to be called
*/
R_API void r_logging_set_callback(RLoggingFuncdef cbfunc) {
	// TODO: RList of callbacks with setter/remove methods
	cb_logfunc_print = cbfunc;
}

/**
 * \brief Internal logging function used by preprocessor macros
 * \param funcname Contains the function name of the calling function
 * \param filename Contains the filename that funcname is defined in
 * \param lineno The line number that this log call is being made from in filename
 * \param lvl Logging level for output
 * \param fmtstr A printf like string
 * This function is used by the R_LOG_* preprocessor macros for logging/debugging
*/
R_API void _r_logging_internal(const char *funcname, const char *filename,
	ut32 lineno, ut32 level, const char *fmtstr, ...) {
	if (level < cfg_loglvl && level < cfg_logtraplvl) {
		// Don't print if output level is lower than current level
		// Don't ignore fatal/trap errors
		return;
	}

	// Setup varadic arguments
	va_list args;
	va_start (args, fmtstr);

	// TODO: Colors

	// Build output string with src info, and formatted output
	char output_buf[LOGGING_OUTPUTBUF_SIZE] = ""; // Big buffer for building the output string
	const char *tag = R_BETWEEN (0, level, sizeof (level_tags) - 1) ? level_tags[level] : "";
	int offset = snprintf (output_buf, LOGGING_OUTPUTBUF_SIZE, "%s", tag);
	if (cfg_logsrcinfo) {
		offset += snprintf (output_buf + offset, LOGGING_OUTPUTBUF_SIZE - offset, "%s in %s:%i: ", funcname, filename, lineno);
	}
	vsnprintf (output_buf + offset, LOGGING_OUTPUTBUF_SIZE - offset, fmtstr, args);

	// Actually print out the string with our callbacks
	if (cb_logfunc_print) {
		cb_logfunc_print (output_buf, funcname, filename, lineno, level, fmtstr, args);
	} else {
		if (level < R_LOGLVL_ERROR) {
			fprintf (stdout, "%s", output_buf);
		} else {
			fprintf (stderr, "%s", output_buf);
		}
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
			eprintf ("_r_log_internal failed to write to file: %s\n", cfg_logfile);
		}
	}

	va_end (args);

	if (level >= cfg_logtraplvl && level != R_LOGLVL_NONE) {
		fflush (stdout); // We're about to exit HARD, flush buffers before dying
		fflush (stderr);
		// TODO: call r_cons_flush if libr_cons is being used
		r_sys_breakpoint (); // *oof*
	}
}
