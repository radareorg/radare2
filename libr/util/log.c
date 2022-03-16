/* radare - LGPL - Copyright 2007-2022 - pancake, ret2libc */

#define R_LOG_ORIGIN "util.log"

#include <r_core.h>
#include <stdarg.h>

static const char *level_tags[] = { // Log level to tag string lookup array
	[R_LOGLVL_NONE]      = "NONE",
	[R_LOGLVL_INFO]      = "INFO",
	[R_LOGLVL_WARN]      = "WARNING",
	[R_LOGLVL_DEBUG]     = "DEBUG",
	[R_LOGLVL_ERROR]     = "ERROR",
	[R_LOGLVL_FATAL]     = "FATAL"
};

static const char *level_name(int i) {
	if (i >= 0 && i < 6) {
		return level_tags[i];
	}
	return "UNKNOWN";
}

static R_TH_LOCAL RLog *log = NULL;

// shouldnt be necessary as global thread-local instance
R_API void r_log_init(void) {
	if (!log) {
		log = R_NEW0 (RLog);
	}
}

R_API void r_log_fini(void) {
	if (log) {
		free (log->file);
		free (log->filter);
		free (log);
		log = NULL;
	}
}

R_API void r_log_set_ts(bool ts) {
	r_log_init ();
	log->ts = ts;
}

R_API void r_log_set_level(RLogLevel level) {
	r_log_init ();
	log->level = level;
}

R_API void r_log_set_traplevel(RLogLevel level) {
	r_log_init ();
	log->traplevel = level;
}

R_API void r_log_set_filter(const char *s) {
	r_log_init ();
	R_FREE (log->filter);
	if (R_STR_ISNOTEMPTY (s)) {
		log->filter = strdup (s);
	}
}

R_API void r_log_set_file(const char *filename) {
	r_log_init ();
	free (log->file);
	log->file = strdup (filename);
}

R_API void r_log_set_colors(bool color) {
	r_log_init ();
	log->color = color;
}

R_API void r_log_set_quiet(bool bq) {
	r_log_init ();
	log->quiet = bq;
}

R_API bool r_log_match(int level, const char *origin) { // , const char *sub_origin, const char *fmt, ...) {
	r_log_init ();
	if (R_STR_ISNOTEMPTY (log->filter)) {
		if (strstr (origin, log->filter)) {
			return false;
		}
	}
	if (log->cbs) {
		RListIter *iter;
		RLogCallback cb;
		r_list_foreach (log->cbs, iter, cb) {
			if (cb (log->user, level, origin, NULL)) {
				return true;
			}
		}
	}
	
	return level < log->level;
}

R_API void r_log_vmessage(RLogLevel level, const char *origin, const char *fmt, va_list ap) {
	char out[512];
	r_log_init ();
	int type = 3;
	vsnprintf (out, sizeof (out), fmt, ap);
	if (log->cbs) {
		RListIter *iter;
		RLogCallback cb;
		r_list_foreach (log->cbs, iter, cb) {
			cb (log->user, type, NULL, out);
		}
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (log->color) {
		if (level > 3) {
			r_strbuf_appendf (sb, Color_RED "[%s] " Color_YELLOW "[%s] " Color_RESET, level_name (level), origin);
		} else {
			r_strbuf_appendf (sb, Color_GREEN "[%s] " Color_YELLOW "[%s] " Color_RESET, level_name (level), origin);
		}
	} else {
		r_strbuf_appendf (sb, "[%s] [%s] ", level_name (level), origin);
	}
	char ts[32] = {0};
	if (log->ts) {
		ut64 now = r_time_now ();
		if (log->color) {
			r_strbuf_appendf (sb, ts, sizeof (ts), Color_CYAN "[ts:%" PFMT64u "] " Color_RESET, now);
		} else {
			r_strbuf_appendf (sb, ts, sizeof (ts), "[ts:%" PFMT64u "] ", now);
		}
	}
	r_strbuf_appendf (sb, "%s%s\n", ts, out);
	char * s = r_strbuf_drain (sb);
	sb = NULL;
	if (!log->quiet) {
		eprintf ("%s", s);
	}
	if (R_STR_ISNOTEMPTY (log->file)) {
		r_file_dump (log->file, (const ut8*)s, strlen (s), true);
	}
	if (log->traplevel && (level >= log->traplevel || level == R_LOGLVL_FATAL)) {
		r_sys_backtrace ();
		r_sys_breakpoint ();
	}
}

R_API void r_log_message(RLogLevel level, const char *origin, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	r_log_vmessage (level, origin, fmt, ap);
	va_end (ap);
}

R_API void r_log_add_callback(RLogCallback cb) {
	r_log_init ();
	if (!log->cbs) {
		log->cbs = r_list_new ();
	}
	if (!r_list_contains (log->cbs, cb)) {
		r_list_append (log->cbs, cb);
	}
}

R_API void r_log_del_callback(RLogCallback cb) {
	r_log_init ();
	r_list_delete_data (log->cbs, cb);
}

R_API void r_log(const char *funcname, const char *filename, ut32 lineno, RLogLevel level, const char *origin, const char *fmtstr, ...) {
	va_list args;
	va_start (args, fmtstr);
	// r_vlog (funcname, filename, lineno, level, tag, fmtstr, args);
	r_log_vmessage (level, origin, fmtstr, args);
	va_end (args);
}
