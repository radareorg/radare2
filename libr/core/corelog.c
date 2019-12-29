/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_core.h>

R_API int r_core_log_list(RCore *core, int n, int nth, char fmt) {
	int printed = 0;
	int count = 0, i, idx, id = core->log->first;
	RStrpool *sp = core->log->sp;
	char *str = sp->str;

	if (fmt == 'j') {
		r_cons_printf ("[");
	}
	for (i = idx = 0; str && *str; i++, id++) {
		if ((n && n <= id) || !n) {
			switch (fmt) {
			case 'j':
				r_cons_printf ("%s[%d,\"%s\"]",
					printed? ",": "", id, str);
				break;
			case 't':
				r_cons_println (str);
				break;
			case '*':
				r_cons_printf ("\"T %s\"\n", str);
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
		r_cons_printf ("]\n");
	}
	return count;
}

R_API RCoreLog *r_core_log_new() {
	RCoreLog *log = R_NEW0 (RCoreLog);
	if (!log) {
		return NULL;
	}
	r_core_log_init (log);
	return log;
}

R_API void r_core_log_init(RCoreLog *log) {
	log->first = 1;
	log->last = 1;
	log->sp = r_strpool_new (0);
}

R_API void r_core_log_free(RCoreLog *log) {
	r_strpool_free (log->sp);
	free (log);
}

R_API bool r_core_log_run(RCore *core, const char *_buf, RCoreLogCallback runLine) {
	char *obuf = strdup (_buf);
	char *buf = obuf;
	while (buf) {
		char *nl = strchr (buf, '\n');
		if (nl) {
			*nl = 0;
		}
		char *sp = strchr (buf, ' ');
		if (sp) {
			runLine (core, atoi (buf), sp + 1);
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
	const char *host = r_config_get (core->config, "http.sync");
	if (host && *host) {
		char *url = index > 0
			? r_str_newf ("%s/cmd/T%%20%d", host, index)
			: r_str_newf ("%s/cmd/T", host);
		char *res = r_socket_http_get (url, NULL, NULL);
		free (url);
		return res? res: strdup ("");
	}
	return NULL;
}

R_API void r_core_log_add(RCore *core, const char *msg) {
	static bool inProcess = false;
	r_strpool_append (core->log->sp, msg);
	core->log->last++;
	if (core->cmdlog && *core->cmdlog) {
		if (inProcess) {
			// avoid infinite recursive calls
			return;
		}
		inProcess = true;
		r_core_cmd0 (core, core->cmdlog);
		inProcess = false;
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
		// if (idx >= core->log->last) {
		if (!msg || !*msg) {
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
