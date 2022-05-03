/* radare - LGPL - Copyright 2009-2021 - pancake */

#include <r_userconf.h>
#include <r_util.h>

// typedef struct { int rc; } RSystem;

// sh
char *get_argv(const char *l, int *argpos, int pos) {
	int a0 = argpos[(pos*2)];
	int a1 = argpos[(pos*2) + 1];
	return r_str_ndup (l + a0, a1 - a0);
}

R_API int r_sys_tem_statement(const char *l) {
#define MAXARG 16
	l = r_str_trim_head_ro (l);
	int argc = 0;
	int argv[32]; // max 16 args
	int i, pos = 0;
	int inquote = 0;
	bool escaped = false;
	int cmdpos = 0;
	for (pos = cmdpos; l[pos]; pos++) {
		char lc = l[pos];
		if (lc == '\\') {
			escaped = !escaped;
		} else if (lc == '"' || lc == '\'') {
			if (inquote) {
				inquote = 0;
			}
			inquote = lc;
		} else if (lc == ';') {
			if (!inquote) {
				// XXX shouldnt have this char
				R_LOG_ERROR ("Too many arguments\n");
				return -1;
			}
		} else if (lc == ' ') {
			argv[1+(argc * 2)] = pos;
			argv[2+(argc * 2)] = pos + 1;
			argc++;
			if (argc + 2 >= MAXARG) {
				R_LOG_ERROR ("Too many arguments\n");
				return -1;
			}
		}
	}
	argv[1+(argc*2)] = pos;
	argc++;
	char *progname = NULL;
	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; i < argc; i++) {
		char *s = get_argv (l, argv, i);
		// unescape and remove heading/tail quotes if any
		// eprintf ("ARG %d %s \n", i, s);
		if (i == 0) {
			progname = s;
		} else {
			r_strbuf_append (sb, " ");
			// TODO: replace env vars 
			// s = r_str_replace (s, "$FOO", "TMP", 1);
			r_strbuf_append (sb, s);
			free (s);
		}
	}
	char *sbs = r_strbuf_drain (sb);
	r_str_trim (sbs);
	// run command and return rc
	if (R_STR_ISNOTEMPTY (progname)) {
		if (!strcmp (progname, "false")) {
			free (sbs);
			return 1;
		}
		if (!strcmp (progname, "true")) {
			free (sbs);
			return 0;
		}
		if (!strcmp (progname, "ls")) {
			char *s = r_syscmd_ls (sbs, 80);
			eprintf ("%s\n", s);
			free (s);
		} else if (!strcmp (progname, "mktemp")) {
			char *d = r_syscmd_mktemp (sbs);
			printf ("%s\n", d);
			free (d);
			return d? 0: 1;
		} else if (!strcmp (progname, "mkdir")) {
			return r_syscmd_mkdir (sbs);
		} else if (!strcmp (progname, "pwd")) {
			char *wd = r_sys_getdir ();
			eprintf ("%s\n", wd);
			free (wd);
		} else if (!strcmp (progname, "echo")) {
			eprintf ("%s\n", sbs);
		} else {
			free (sbs);
			return r_sys_cmd (l);
		}
	}
	free (sbs);
	return 0;
}

R_API int r_sys_tem_line(const char *l) {
	int pos = 0;
	int inquote = 0;
	bool escaped = false;
	int rc = 0;
	int cmdpos = 0;
	int nextpos = 0;
repeat:
	for (pos = cmdpos; l[pos]; pos++) {
		char lc = l[pos];
		char ld = l[pos + 1];
		if (lc == '\\') {
			escaped = !escaped;
		} else if (lc == '"' || lc == '\'') {
			if (inquote) {
				if (lc == inquote) {
					inquote = 0;
				}
			} else {
				inquote = lc;
			}
		} else if (lc == '|' && ld == '|') {
			if (!inquote) {
				if (pos == cmdpos) {
					if (rc) {
						nextpos = pos + 2;
						cmdpos += 2;
						break;
					} else {
						// eprintf ("|| failed\n");
						return 1;
					}
				} else {
					nextpos = pos - 1;
					break;
				}
			}
		} else if (lc == '&' && ld == '&') {
			if (!inquote) {
				if (pos == cmdpos) {
					if (rc) {
						// eprintf ("&& failed\n");
						return 1;
					} else {
						cmdpos += 2;
						nextpos = pos + 2;
						break;
					}
				} else {
					nextpos = pos - 1;
					break;
				}
			}
		} else if (lc == ';') {
			if (!inquote) {
				// end of command
				nextpos = pos;
				break;
			}
		}
	}
	if (nextpos) {
		char *s = r_str_ndup (l + cmdpos, nextpos - cmdpos);
		rc = r_sys_tem_statement (s);
		free (s);
		cmdpos = nextpos + 1;
		nextpos = 0;
		goto repeat;
	} else {
		// eprintf ("RUN (%s)\n", l + cmdpos);
		rc = r_sys_tem_statement (l + cmdpos);
	}
	//r_sys_setenv ("?", rc);
	// separate by ; honor quotes
	return rc;
}

R_API int r_sys_tem(const char *s) {
	int rc = 0;
	char *ss = strdup (s);
	char *line;
	RListIter *iter;
	RList *lines = r_str_split_list (ss, "\n", 0);
	r_list_foreach (lines, iter, line) {
		char *l = r_str_trim_dup (line);
		rc = r_sys_tem_line (l);
		free (l);
	}
	r_list_free (lines);
	free (ss);
	return rc;
}
