/* radare - LGPL - Copyright 2010-2022 - pancake, ret2libc */

#define R_LOG_ORIGIN "util.log"

#include <r_core.h>
#include <stdarg.h>

static const char *level_tags[] = { // Log level to tag string lookup array
	[R_LOGLVL_FATAL]     = "FATAL",
	[R_LOGLVL_ERROR]     = "ERROR",
	[R_LOGLVL_INFO]      = "INFO",
	[R_LOGLVL_WARN]      = "WARN",
	[R_LOGLVL_DEBUG]     = "DEBUG",
};

static const char *level_name(int i) {
	if (i >= 0 && i < R_LOGLVL_LAST) {
		return level_tags[i];
	}
	return "UNKN";
}

static R_TH_LOCAL RLog *rlog = NULL;

// shouldnt be necessary as global thread-local instance
R_API void r_log_init(void) {
	if (!rlog) {
		rlog = R_NEW0 (RLog);
		rlog->level = R_LOGLVL_DEFAULT;
	}
}

R_API void r_log_fini(void) {
	if (rlog) {
		free (rlog->file);
		free (rlog->filter);
		free (rlog);
		rlog = NULL;
	}
}

R_API void r_log_show_ts(bool ts) {
	r_log_init ();
	rlog->show_ts = ts;
}

R_API RLogLevel r_log_get_level(void) {
	return rlog->level;
}

R_API RLogLevel r_log_get_traplevel(void) {
	return rlog->traplevel;
}

R_API void r_log_set_level(RLogLevel level) {
	r_log_init ();
	rlog->level = level;
}

R_API void r_log_set_traplevel(RLogLevel level) {
	r_log_init ();
	rlog->traplevel = level;
}

R_API void r_log_set_filter(const char *s) {
	r_log_init ();
	R_FREE (rlog->filter);
	if (R_STR_ISNOTEMPTY (s)) {
		rlog->filter = strdup (s);
	}
}

R_API void r_log_set_file(const char *filename) {
	r_log_init ();
	free (rlog->file);
	rlog->file = strdup (filename);
}

R_API void r_log_show_origin(bool show_origin) {
	r_log_init ();
	rlog->show_origin = show_origin;
}

R_API void r_log_show_source(bool show_source) {
	r_log_init ();
	rlog->show_source = show_source;
}

R_API void r_log_set_colors(bool color) {
	r_log_init ();
	rlog->color = color;
}

R_API void r_log_set_quiet(bool bq) {
	r_log_init ();
	rlog->quiet = bq;
}

R_API bool r_log_match(int level, const char *origin) { // , const char *sub_origin, const char *fmt, ...) {
	r_log_init ();
	if (R_STR_ISNOTEMPTY (origin) && R_STR_ISNOTEMPTY (rlog->filter)) {
		if (strstr (origin, rlog->filter)) {
			return false;
		}
	}
	if (rlog->cbs) {
		RListIter *iter;
		RLogCallback cb;
		r_list_foreach (rlog->cbs, iter, cb) {
			if (cb (rlog->user, level, origin, NULL)) {
				return true;
			}
		}
	}
	return level <= rlog->level;
}

R_API void r_log_vmessage(RLogLevel level, const char *origin, const char *func, int line, const char *fmt, va_list ap) {
	char out[512];
	r_log_init ();
	int type = 3;
	vsnprintf (out, sizeof (out), fmt, ap);
	if (rlog->cbs) {
		RListIter *iter;
		RLogCallback cb;
		r_list_foreach (rlog->cbs, iter, cb) {
			cb (rlog->user, type, NULL, out);
		}
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (func && r_str_startswith (func, "./")) {
		func += 2;
	}
	if (rlog->color) {
		const char *k = Color_YELLOW;
		switch (level) {
		case R_LOGLVL_FATAL:
		case R_LOGLVL_ERROR:
			k = Color_RED;
			break;
		case R_LOGLVL_INFO:
			k = Color_YELLOW;
			break;
		case R_LOGLVL_WARN:
			k = Color_MAGENTA;
			break;
		case R_LOGLVL_DEBUG:
			k = Color_GREEN;
			break;
		default:
			break;
		}
		r_strbuf_appendf (sb, "%s%s:", k, level_name (level));
		if (rlog->show_origin) {
			r_strbuf_appendf (sb, " "Color_YELLOW "[%s]" Color_RESET, origin);
		} else {
			r_strbuf_appendf (sb, Color_RESET);
		}
		if (rlog->show_source) {
			r_strbuf_appendf (sb, " [%s:%d]", func, line);
		}
	} else {
		r_strbuf_appendf (sb, "%s:", level_name (level));
		if (rlog->show_origin) {
			r_strbuf_appendf (sb, " [%s]", origin);
		}
		if (rlog->show_source) {
			r_strbuf_appendf (sb, " [%s:%d]", func, line);
		}
	}
	char ts[32] = {0};
	if (rlog->show_ts) {
		ut64 now = r_time_now ();
		if (rlog->color) {
			r_strbuf_appendf (sb, ts, sizeof (ts), Color_CYAN "[ts:%" PFMT64u "]" Color_RESET, now);
		} else {
			r_strbuf_appendf (sb, ts, sizeof (ts), "[ts:%" PFMT64u "]", now);
		}
	}
	r_strbuf_appendf (sb, "%s %s\n", ts, out);
	char * s = r_strbuf_drain (sb);
	sb = NULL;
	if (!rlog->quiet) {
		eprintf ("%s", s);
	}
	if (R_STR_ISNOTEMPTY (rlog->file)) {
		r_file_dump (rlog->file, (const ut8*)s, strlen (s), true);
	}
	if (rlog->traplevel && (level >= rlog->traplevel || level == R_LOGLVL_FATAL)) {
		r_sys_backtrace ();
		r_sys_breakpoint ();
	}
	free (s);
}

R_API void r_log_message(RLogLevel level, const char *origin, const char *func, int line, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	r_log_vmessage (level, origin, func, line, fmt, ap);
	va_end (ap);
}

R_API void r_log_add_callback(RLogCallback cb, void *user) {
	r_log_init ();
	if (!rlog->cbs) {
		rlog->cbs = r_list_new ();
	}
	if (user) {
		rlog->user = user;
	}
	if (!r_list_contains (rlog->cbs, cb)) {
		r_list_append (rlog->cbs, cb);
	}
}

R_API void r_log_del_callback(RLogCallback cb) {
	r_log_init ();
	r_list_delete_data (rlog->cbs, cb);
}

R_API void r_log(const char *funcname, const char *filename, ut32 lineno, RLogLevel level, const char *origin, const char *fmtstr, ...) {
	va_list args;
	va_start (args, fmtstr);
	r_log_vmessage (level, origin? origin: filename, funcname, lineno, fmtstr, args);
	va_end (args);
}
