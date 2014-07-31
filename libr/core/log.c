/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_core.h>

R_API int r_core_log_list(RCore *core, int n, int nth, char fmt) {
	int printed = 0;
	int count = 0, i, idx, id = core->log->first;
	RStrpool *sp = core->log->sp;
	char *str = sp->str;

	if (fmt=='j') r_cons_printf ("[");
	for (i=idx=0; str && *str; i++, id++) {
		if ((n&&n<=id)||!n) {
			switch (fmt) {
			case 'j':r_cons_printf ("%s[%d,\"%s\"]",
				printed?",":"",id, str); break;
			case 't':r_cons_printf ("%s\n", str); break;
			case '*':r_cons_printf ("\"l %s\"\n", str); break;
			default: r_cons_printf ("%d %s\n", id, str); break;
			}
			printed++;
			if (nth && printed >= nth) break;
		}
		str = r_strpool_next (sp, idx);
		if (!str) break;
		idx = r_strpool_get_index (sp, str);
		count++;
	}
	if (fmt == 'j')
		r_cons_printf ("]\n");
	return count;
}

R_API RCoreLog *r_core_log_new () {
	RCoreLog *log = R_NEW0 (RCoreLog);
	r_core_log_init (log);
	return log;
}

R_API void r_core_log_init (RCoreLog *log) {
	log->first = 1;
	log->last = 1;
	log->sp = r_strpool_new (0);
}

R_API void r_core_log_free(RCoreLog *log) {
	r_strpool_free (log->sp);
	free (log);
}

R_API void r_core_log_add(RCore *core, const char *msg) {
	r_strpool_append (core->log->sp, msg);
	core->log->last++;
}

R_API void r_core_log_del(RCore *core, int n) {
	int idx;
	if (n>0) {
		if (n > core->log->last)
			n = core->log->last;
		idx = n-core->log->first;
		if (idx<0) return;
		core->log->first += idx+1;
		/* s= */ r_strpool_get_i (core->log->sp, idx);
		r_strpool_slice (core->log->sp, idx);
	} else {
		core->log->first = core->log->last;
		r_strpool_empty (core->log->sp);
	}
}
