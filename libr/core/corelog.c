/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_core.h>

R_API int r_core_log_list(RCore *core, int n, int nth, char fmt) {
	R_RETURN_VAL_IF_FAIL (core && core->log, 0);
	int printed = 0;
	int count = 0, idx, id = core->log->first;
	RStrpool *sp = core->log->sp;
	char *str = sp->str;
	PJ *pj = NULL;

	if (fmt == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	for (idx = 0; str && *str; id++) {
		if ((n && n <= id) || !n) {
			switch (fmt) {
			case 'j':
				pj_o (pj);
				pj_kn (pj, "id", id);
				pj_ks (pj, "msg", str);
				pj_end (pj);
				break;
			case 'J':
				pj_o (pj);
				pj_kn (pj, "id", id);
				if (*str == '{') {
					pj_k (pj, "obj");
					pj_raw (pj, str);
				} else {
					pj_ks (pj, "msg", str);
				}
				pj_end (pj);
				break;
			case 't':
				r_kons_println (core->cons, str);
				break;
			case '*':
				{
					char *b = r_base64_encode_dyn ((const ut8*)str, -1);
					r_cons_printf ("T base64:%s\n", b);
					free (b);
				}
				// r_cons_printf ("\"T %s\"\n", str);
				break;
			default:
				r_cons_printf ("%d %s\n", id, str);
				break;
			}
			printed++;
			if (nth && printed >= nth) {
				break;
			}
		}
		str = r_strpool_next (sp, idx);
		if (!str) {
			break;
		}
		idx = r_strpool_get_index (sp, str);
		count++;
	}
	if (fmt == 'j') {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_printf ("%s\n", s);
		free (s);
	}
	return count;
}

R_API RCoreLog *r_core_log_new(void) {
	RCoreLog *log = R_NEW0 (RCoreLog);
	r_core_log_init (log);
	return log;
}

R_API void r_core_log_init(RCoreLog *log) {
	R_RETURN_IF_FAIL (log);
	log->first = 1;
	log->last = 1;
	log->sp = r_strpool_new ();
}

R_API void r_core_log_free(RCoreLog *log) {
	if (log) {
		r_log_fini ();
		r_strpool_free (log->sp);
		free (log);
	}
}

R_API bool r_core_log_run(RCore *core, const char *_buf, RCoreLogCallback cb_runline) {
	char *obuf = strdup (_buf);
	char *buf = obuf;
	while (buf) {
		char *nl = strchr (buf, '\n');
		if (nl) {
			*nl = 0;
		}
		char *sp = strchr (buf, ' ');
		if (sp) {
			cb_runline (core, atoi (buf), sp + 1);
		}
		if (nl) {
			buf = nl + 1;
		} else {
			break;
		}
	}
	free (obuf);
	return true;
}

R_API char *r_core_log_get(RCore *core, int index) {
	R_RETURN_VAL_IF_FAIL (core && core->config, NULL);
	const char *host = r_config_get (core->config, "http.sync");
	if (R_STR_ISNOTEMPTY (host)) {
		char *url = index > 0
			? r_str_newf ("%s/cmd/T%%20%d", host, index)
			: r_str_newf ("%s/cmd/T", host);
		char *res = r_socket_http_get (url, NULL, NULL, NULL);
		free (url);
		return res? res: strdup ("");
	}
	return NULL;
}

R_API void r_core_log_add(RCore *core, const char *msg) {
	// NOTE we cant use r_return here because it can create a recursive loop
	if (!core || !core->log) {
		return;
	}
	r_strpool_append (core->log->sp, msg);
	core->log->last++;
	if (R_STR_ISNOTEMPTY (core->cmdlog)) {
		if (core->in_log_process) {
			// avoid infinite recursive calls
			return;
		}
		core->in_log_process = true;
		r_core_cmd0 (core, core->cmdlog);
		core->in_log_process = false;
	}
}

R_API void r_core_log_del(RCore *core, int n) {
	int idx;
	if (n > 0) {
		if (n + 1 >= core->log->last) {
			core->log->first = core->log->last;
			r_strpool_empty (core->log->sp);
			return;
		}
		if (n < core->log->first) {
			return;
		}
		idx = n - core->log->first;
		if (idx < 0) {
			return;
		}
		core->log->first += idx + 1;
		char *msg = r_strpool_get_i (core->log->sp, idx);
		if (R_STR_ISEMPTY (msg)) {
			core->log->first = core->log->last;
			r_strpool_empty (core->log->sp);
		} else {
			r_strpool_slice (core->log->sp, idx);
		}
	} else {
		core->log->first = core->log->last;
		r_strpool_empty (core->log->sp);
	}
}
