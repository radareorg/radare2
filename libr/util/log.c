/* radare - LGPL - Copyright 2010-2025 - pancake */

#define R_LOG_ORIGIN "util.log"

#include <r_core.h>
#include <stdarg.h>

static R_TH_LOCAL RLog *rlog = NULL;
typedef struct r_log_cbuser_t {
	void *user;
	RLogCallback cb;
} RLogCallbackUser;

static const char *level_tags[] = {
	// Log level to tag string lookup array
	[R_LOG_LEVEL_FATAL] = "FATAL",
	[R_LOG_LEVEL_ERROR] = "ERROR",
	[R_LOG_LEVEL_INFO] = "INFO",
	[R_LOG_LEVEL_WARN] = "WARN",
	[R_LOG_LEVEL_TODO] = "TODO",
	[R_LOG_LEVEL_DEBUG] = "DEBUG",
	[R_LOG_LEVEL_TRACE] = "TRACE",
};

R_API int r_log_level_fromstring(const char *ll) {
	int i;
	for (i = 0; i < R_LOG_LEVEL_LAST; i++) {
		const char *m = r_log_level_tostring (i);
		if (r_str_casecmp (m, ll) == 0) {
			return i;
		}
	}
	return -1;
}

R_API const char *r_log_level_tostring(int i) {
	if (i >= 0 && i < R_LOG_LEVEL_LAST) {
		return level_tags[i];
	}
	return "UNKN";
}

R_API const char *r_log_level_tocolor(int level) {
	const char *k = Color_YELLOW;
	switch (level) {
	case R_LOG_LEVEL_FATAL:
	case R_LOG_LEVEL_ERROR:
		k = Color_RED;
		break;
	case R_LOG_LEVEL_INFO:
		k = Color_YELLOW;
		break;
	case R_LOG_LEVEL_WARN:
		k = Color_MAGENTA;
		break;
	case R_LOG_LEVEL_DEBUG:
		k = Color_GREEN;
		break;
	case R_LOG_LEVEL_TODO:
	case R_LOG_LEVEL_TRACE:
		k = Color_CYAN;
		break;
	default:
		break;
	}
	return k;
}

// shouldnt be necessary as global thread-local instance
R_API bool r_log_init(void) {
	if (!rlog) {
		rlog = R_NEW0 (RLog);
		if (!rlog) {
			return false;
		}
		rlog->level = R_LOG_LEVEL_DEFAULT;
	}
	return true;
}

R_API void r_log_fini(void) {
	if (rlog) {
		RLog *log = rlog;
		rlog = NULL;
		r_list_free (log->cbs);
		free (log->file);
		free (log->filter);
		free (log);
	}
}

R_API void r_log_show_ts(bool ts) {
	if (r_log_init ()) {
		rlog->show_ts = ts;
	}
}

R_API RLogLevel r_log_get_level(void) {
	return rlog->level;
}

R_API RLogLevel r_log_get_traplevel(void) {
	return rlog? rlog->traplevel: R_LOG_LEVEL_FATAL;
}

R_API void r_log_set_level(RLogLevel level) {
	if (r_log_init ()) {
		rlog->level = level;
	}
}

R_API void r_log_set_traplevel(RLogLevel level) {
	if (r_log_init ()) {
		rlog->traplevel = level;
	}
}

R_API void r_log_set_filter(const char *s) {
	if (r_log_init ()) {
		R_FREE (rlog->filter);
		if (R_STR_ISNOTEMPTY (s)) {
			rlog->filter = strdup (s);
		}
	}
}

R_API void r_log_set_file(const char *filename) {
	if (r_log_init ()) {
		free (rlog->file);
		rlog->file = strdup (filename);
	}
}

R_API void r_log_show_origin(bool show_origin) {
	if (r_log_init ()) {
		rlog->show_origin = show_origin;
	}
}

R_API void r_log_show_source(bool show_source) {
	if (r_log_init ()) {
		rlog->show_source = show_source;
	}
}

R_API void r_log_set_colors(bool color) {
	if (r_log_init ()) {
		rlog->color = color;
	}
}

R_API void r_log_set_quiet(bool bq) {
	if (r_log_init ()) {
		rlog->quiet = bq;
	}
}

R_API bool r_log_match(int level, const char *origin) {
	if (!r_log_init ()) {
		return false;
	}
	if (R_STR_ISNOTEMPTY (origin) && R_STR_ISNOTEMPTY (rlog->filter)) {
		if (!strstr (origin, rlog->filter)) {
			return false;
		}
	}
	if (rlog->cbs) {
		RListIter *iter;
		RLogCallbackUser *cbu;
		r_list_foreach (rlog->cbs, iter, cbu) {
			if (cbu->cb (cbu->user, level, origin, NULL)) {
				return true;
			}
		}
	}
	return level <= rlog->level;
}

R_API void r_log_vmessage(RLogLevel level, const char *origin, const char *func, int line, const char *fmt, va_list ap) {
	char out[512];
	if (!r_log_init ()) {
		return;
	}
	vsnprintf (out, sizeof (out), fmt, ap);
	if (rlog->cbs) {
		RListIter *iter;
		RLogCallbackUser *cbu;
		r_list_foreach (rlog->cbs, iter, cbu) {
			if (cbu->cb (cbu->user, level, origin, out)) {
				return;
			}
		}
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (func && r_str_startswith (func, "./")) {
		func += 2;
	}
	if (rlog->color) {
		const char *k = r_log_level_tocolor (level);
		r_strbuf_appendf (sb, "%s%s:", k, r_log_level_tostring (level));
		if (rlog->show_origin) {
			r_strbuf_appendf (sb, " " Color_YELLOW "[%s]" Color_RESET, origin);
		} else {
			r_strbuf_appendf (sb, Color_RESET);
		}
		if (rlog->show_source) {
			r_strbuf_appendf (sb, " [%s:%d]", func, line);
		}
	} else {
		r_strbuf_appendf (sb, "%s:", r_log_level_tostring (level));
		if (rlog->show_origin) {
			r_strbuf_appendf (sb, " [%s]", origin);
		}
		if (rlog->show_source) {
			r_strbuf_appendf (sb, " [%s:%d]", func, line);
		}
	}
	char ts[32] = { 0 };
	if (rlog->show_ts) {
		ut64 now = r_time_now ();
		if (rlog->color) {
			r_strbuf_appendf (sb, ts, sizeof (ts), Color_CYAN "[ts:%" PFMT64u "]" Color_RESET, now);
		} else {
			r_strbuf_appendf (sb, ts, sizeof (ts), "[ts:%" PFMT64u "]", now);
		}
	}
	r_strbuf_appendf (sb, "%s %s\n", ts, out);
	char *s = r_strbuf_drain (sb);
	sb = NULL;
	if (!rlog->quiet) {
		eprintf ("%s", s);
	}
	if (rlog->cb_printf) {
		rlog->cb_printf ("%s", s);
	}
	if (R_STR_ISNOTEMPTY (rlog->file)) {
		r_file_dump (rlog->file, (const ut8 *)s, strlen (s), true);
	}
	free (s);
	if (rlog->traplevel && (level >= rlog->traplevel || level == R_LOG_LEVEL_FATAL)) {
		r_sys_backtrace ();
		r_sys_breakpoint ();
	}
}

R_API void r_log_message(RLogLevel level, const char *origin, const char *func, int line, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	r_log_vmessage (level, origin, func, line, fmt, ap);
	va_end (ap);
}

R_API void r_log_add_callback(RLogCallback cb, void *user) {
	if (!r_log_init ()) {
		return;
	}
	if (!rlog->cbs) {
		rlog->cbs = r_list_newf (free);
	}
	RLogCallbackUser *cbu = R_NEW (RLogCallbackUser);
	cbu->cb = cb;
	cbu->user = user;
	r_list_append (rlog->cbs, cbu);
}

R_API void r_log_del_callback(RLogCallback cb) {
	if (r_log_init ()) {
		RLogCallbackUser *p;
		RListIter *iter;
		r_list_foreach (rlog->cbs, iter, p) {
			if (cb == p->cb) {
				r_list_delete (rlog->cbs, iter);
				return;
			}
		}
	}
}

R_API void r_log(const char *funcname, const char *filename, ut32 lineno, RLogLevel level, const char *origin, const char *fmtstr, ...) {
	va_list args;
	va_start (args, fmtstr);
	r_log_vmessage (level, origin? origin: filename, funcname, lineno, fmtstr, args);
	va_end (args);
}
