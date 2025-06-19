/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_La = {
	"Usage:", "La[qj]", " # asm/anal plugin list",
	"La",  "", "List arch plugins (See rasm2 -L)",
	"Laq",  "", "Only list the plugin name",
	"Laj",  "", "Full list, but in JSON format",
	NULL
};

static RCoreHelpMessage help_msg_LA = {
	"Usage:", "LA[qj]", " # analysis plugin list",
	"LA",  "", "List analysis plugins (See rasm2 -L)",
	"LAq",  "", "Only list the plugin name",
	"LAj",  "", "Full list, but in JSON format",
	NULL
};

// TODO #7967 help refactor: move to another place
static RCoreHelpMessage help_msg_L = {
	"Usage:", "L[acio]", "[-name][ file]",
	"L",  "", "show this help",
	"L", " blah."R_LIB_EXT, "load plugin file",
	"L-", "duk", "unload core plugin by name or file name",
	"La", "[qj]", "list arch plugins",
	"LA", "[qj]", "list analysis plugins",
	"Lb", "[qj]", "list bin plugins",
	"Lc", "[j]", "list core plugins",
	"Ld", "[j]", "list debug plugins (dL)",
	"LD", "[j]", "list supported decompilers (e cmd.pdc=?)",
	"Le", "[j]", "list esil plugins",
	"Lg", "[j]", "list egg plugins",
	"Lh", "", "list hash plugins (ph)",
	"Li", "[j]", "list bin plugins (iL)",
	"Ll", "[qj]", "list lang plugins (#!)",
	"LL", "", "lock screen",
	"Lm", "[j]", "list fs plugins (mL)",
	"Lo", "[j]", "list io plugins (oL)",
	"Lp", "[j]", "list parser plugins (e asm.parser=?)",
	"Ls", "[qj]", "list assembler plugins",
	"Lt", "[j]", "list color themes (eco)",
	NULL
};

static RCoreHelpMessage help_msg_T = {
	"Usage:", "T", "[-][ num|msg] # text-log utility with timestamps",
	"T", "", "list all Text log messages",
	"T", " message", "add new log message",
	"T", " 123", "list log from 123",
	"T", " 10 3", "list 3 log messages starting from 10",
	"T*", "", "list in radare commands",
	"T-", "", "delete all logs",
	"T-", " 123", "delete logs before 123",
	"Tl", "", "get last log message id",
	"Tj", "", "list in json format",
	"Tm", " [idx]", "display log messages without index",
	"TT", "", "enter into the text log chat console",
	"T=", "[.]", "pull logs from remote r2 instance specified by http.sync",
	"T=&", "", "start background thread syncing with the remote server",
	NULL
};

static void screenlock(RCore *core) {
	//  char *pass = r_cons_input ("Enter new password: ");
	char *pass = r_cons_password (Color_INVERT "Enter new password:"Color_INVERT_RESET);
	if (!pass || !*pass) {
		return;
	}
	char *again = r_cons_password (Color_INVERT "Type it again:"Color_INVERT_RESET);
	if (!again || !*again) {
		free (pass);
		return;
	}
	if (strcmp (pass, again)) {
		R_LOG_ERROR ("Password mismatch!");
		free (pass);
		free (again);
		return;
	}
	bool running = true;
	r_kons_clear_buffer (core->cons);
	ut64 begin = r_time_now ();
	ut64 last = UT64_MAX;
	int tries = 0;
	do {
		r_cons_clear00 ();
		r_cons_printf ("Retries: %d\n", tries);
		char *begstr = r_time_usecs_tostring (begin);
		r_cons_printf ("Locked ts: %s\n", begstr);
		free (begstr);
		if (last != UT64_MAX) {
			char *endstr = r_time_usecs_tostring (last);
			r_cons_printf ("Last try: %s\n", endstr);
			free (endstr);
		}
		r_cons_newline ();
		r_cons_flush ();
		char *msg = r_cons_password ("radare2 password: ");
		if (msg && !strcmp (msg, pass)) {
			running = false;
		} else {
			R_LOG_ERROR ("Invalid password");
			last = r_time_now ();
			tries++;
		}
		free (msg);
		int n = r_num_rand (10) + 1;
		r_sys_usleep (n * 100000);
	} while (running);
	r_cons_set_cup (true);
	free (pass);
	R_LOG_INFO ("Unlocked!");
}

static int textlog_chat(RCore *core) {
	char prompt[64];
	char buf[1024];
	int lastmsg = 0;
	const char *me = r_config_get (core->config, "cfg.user");
	char msg[2048];

	eprintf ("Type '/help' for commands:\n");
	snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
	r_line_set_prompt (core->cons->line, prompt);
	for (;;) {
		r_core_log_list (core, lastmsg, 0, 0);
		lastmsg = core->log->last;
		if (r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL) < 0) {
			return 1;
		}
		if (!*buf) {
			continue;
		}
		if (!strcmp (buf, "/help")) {
			eprintf ("/quit           quit the chat (same as ^D)\n");
			eprintf ("/name <nick>    set cfg.user name\n");
			eprintf ("/log            show full log\n");
			eprintf ("/clear          clear text log messages\n");
		} else if (!strncmp (buf, "/name ", 6)) {
			snprintf (msg, sizeof (msg) - 1, "* '%s' is now known as '%s'", me, buf + 6);
			r_core_log_add (core, msg);
			r_config_set (core->config, "cfg.user", buf + 6);
			me = r_config_get (core->config, "cfg.user");
			snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
			r_line_set_prompt (core->cons->line, prompt);
			return 0;
		} else if (!strcmp (buf, "/log")) {
			r_core_log_list (core, 0, 0, 0);
			return 0;
		} else if (!strcmp (buf, "/clear")) {
			// r_core_log_del (core, 0);
			r_core_cmd_call (core, "T-");
			return 0;
		} else if (!strcmp (buf, "/quit")) {
			return 0;
		} else if (*buf == '/') {
			R_LOG_ERROR ("Unknown command: %s", buf);
		} else {
			snprintf (msg, sizeof (msg), "[%s] %s", me, buf);
			r_core_log_add (core, msg);
		}
	}
	return 1;
}

static int getIndexFromLogString(const char *s) {
	int len = strlen (s);
	const char *m = s + len;
	int nlctr = 2;
	const char *nl = NULL;
	while (m > s) {
		if (*m == '\n') {
			nl = m;
			if (--nlctr < 1) {
				return atoi (m + 1);
			}
		}
		m--;
	}
		return atoi (nl?nl + 1: s);
	return -1;
}

static char *expr2cmd(RCoreLog *log, const char *line) {
	if (!line || !*line) {
		return NULL;
	}
	line++;
	if (!strncmp (line, "add-comment", 11)) {
		line += 11;
		if (*line == ' ') {
			char *sp = strchr (line + 1, ' ');
			if (sp) {
				char *msg = sp + 1;
				ut64 addr = r_num_get (NULL, line);
				return r_str_newf ("CCu base64:%s @ 0x%"PFMT64x"\n", msg, addr);
			}
		}
		R_LOG_ERROR ("Cannot parse add-comment expression");
	}
	if (!strncmp (line, "del-comment", 11)) {
		if (line[11] == ' ') {
			return r_str_newf ("CC-%s\n", line + 12);
		}
		R_LOG_ERROR ("Cannot parse add-comment expression");
	}
	return NULL;
}

static int log_callback_r2(RCore *core, int count, const char *line) {
	if (*line == ':') {
		char *cmd = expr2cmd (core->log, line);
		if (cmd) {
			r_cons_printf ("%s\n", cmd);
			r_core_cmd (core, cmd, 0);
			free (cmd);
		}
	}
	return 0;
}

static int log_callback_all(RCore *log, int count, const char *line) {
	r_cons_printf ("%.2d %s\n", count, line);
	return 0;
}

R_API void r_core_log_view(RCore *core, int num, int shift) {
	if (num < 1) {
		num = 1;
	}
	int i;
	int cons_width = r_cons_get_size (NULL);
	if (cons_width < 1) {
		cons_width = 60;
	}
	for (i = num - 3; i < num + 3; i++) {
		r_cons_printf ("%s", (num == i)? "* ": "  ");
		if (i < 1) {
			r_cons_printf ("   ^\n");
			continue;
		}
		if (i >= core->log->last) {
			r_cons_printf ("   $\n");
			continue;
		}
		if (i < core->log->first) {
			r_cons_printf ("   ^\n");
			continue;
		}
		const char *msg = r_strpool_get_i (core->log->sp, i);
		if (msg) {
			size_t msglen = strlen (msg);
			if (shift < msglen) {
				msg += shift;
			}
			char *m = r_str_ndup (msg, cons_width);
			char *nl = strchr (m, '\n');
			if (nl) {
				*nl = 0;
			}
			r_cons_printf ("%.2d %s\n", i, m);
			free (m);
		} else {
			r_cons_printf ("%.2d ..\n", i);
		}
	}
}

static int cmd_log(void *data, const char *input) {
	RCore *core = (RCore *) data;
	const char *arg, *input2;
	int n, n2;

	if (!input) {
		return 1;
	}

	input2 = (input && *input)? input + 1: "";
	arg = strchr (input2, ' ');
	n = atoi (input2);
	n2 = arg? atoi (arg + 1): 0;

	switch (*input) {
	case 'e': // "Te" shell: less
		{
			char *p = strchr (input, ' ');
			if (p) {
				char *b = r_file_slurp (p + 1, NULL);
				if (b) {
					r_cons_less_str (core->cons, b, NULL);
					free (b);
				} else {
					R_LOG_ERROR ("File not found");
				}
			} else {
				static RCoreHelpMessage help_msg_less = {
					"less", " [filename]", "view file with pagination",
				};
				r_core_cmd_help (core, help_msg_less);
			}
		}
		break;
	case 'v': // "Tv"
		{
			char *args = strdup (input + 2);
			char *arg = strchr (args, ' ');
			int shift = 0;
			if (arg) {
				*arg++ = 0;
				shift = r_num_math (core->num, arg);
			}
			int index = (int)r_num_math (core->num, args);
			r_core_log_view (core, index, shift);
			free (args);
		}
		break;
	case 'l': // "Tl"
		r_cons_printf ("%.2d\n", core->log->last - 1);
		break;
	case '-': //  "T-"
		r_core_log_del (core, n);
		break;
	case '?': // "T?"
		r_core_cmd_help (core, help_msg_T);
		break;
	case 'T': // "TT" Ts ? as ms?
		if (r_cons_is_interactive ()) {
			textlog_chat (core);
		} else {
			R_LOG_ERROR ("The TT command needs scr.interactive=true");
		}
		break;
	case '=': // "T="
		if (input[1] == '&') { //  "T=&"
			if (input[2] == '&') { // "T=&&"
				r_cons_break_push (NULL, NULL);
				while (!r_cons_is_breaked ()) {
					r_core_cmd_call (core, "T=");
					void *bed = r_cons_sleep_begin();
					r_sys_sleep (1);
					r_cons_sleep_end (bed);
				}
				r_cons_break_pop ();
			} else {
				// TODO: Sucks that we can't enqueue functions, only commands
				R_LOG_INFO ("Background thread syncing with http.sync started");
				RCoreTask *task = r_core_task_new (core, true, "T=&&", NULL, core);
				r_core_task_enqueue (&core->tasks, task);
			}
		} else {
			if (atoi (input + 1) > 0 || (input[1] == '0')) {
				core->sync_index = 0;
			} else {
				RCoreLogCallback log_callback = (input[1] == '*')
					? log_callback_all: log_callback_r2;
				char *res = r_core_log_get (core, core->sync_index);
				if (res) {
					int idx = getIndexFromLogString (res);
					if (idx != -1) {
						core->sync_index = idx + 1;
					}
					r_core_log_run (core, res, log_callback);
					free (res);
				} else {
					r_cons_printf ("Please check e http.sync\n");
				}
			}
		}
		break;
	case ' ': // "T "
		if (n > 0 || *input == '0') {
			r_core_log_list (core, n, n2, *input);
		} else {
			const char *arg = r_str_trim_head_ro (input + 1);
			if (r_str_startswith (arg, "base64:")) {
				ut8 *s = r_base64_decode_dyn (arg + 7, -1, NULL);
				if (s) {
					r_core_log_add (core, (const char *)s);
					free (s);
				} else {
					R_LOG_ERROR ("Invalid base64 stream");
				}
			} else {
				r_core_log_add (core, arg);
			}
		}
		break;
	case 'm': // "Tm"
		if (n > 0) {
			r_core_log_list (core, n, 1, 't');
		} else {
			r_core_log_list (core, n, 0, 't');
		}
		break;
	case 'j': // "Tj"
	case '*':
	case '\0':
		r_core_log_list (core, n, n2, *input);
		break;
	}
	return 0;
}

static int cmd_plugins(void *data, const char *input) {
	RCore *core = (RCore *) data;
	switch (input[0]) {
	case 0:
		r_core_cmd_help (core, help_msg_L);
		break;
	case '-':
		r_lib_close (core->lib, r_str_trim_head_ro (input + 1));
		break;
	case ' ':
		r_lib_open (core->lib, r_str_trim_head_ro (input + 1));
		break;
	case '?':
		r_core_cmd_help (core, help_msg_L);
		break;
	case 't': // "Lt"
		if (input[1] == 'j') {
			r_core_cmd_call (core, "ecoj");
		} else {
			r_core_cmd_call (core, "eco");
		}
		break;
	case 'b': // "Lb"
		if (input[1] == 'j') { // "Lbj"
			PJ *pj = r_core_pj_new (core);
			r_bin_list (core->bin, pj, 'j');
			char *s = pj_drain (pj);
			r_cons_println (s);
			free (s);
		} else {
			r_bin_list (core->bin, NULL, 0);
		}
		break;
	case 'm': // "Lm"
		if (input[1] == 'j') {
			r_core_cmd_call (core, "mLj");
		} else {
			r_core_cmd_call (core, "mL");
		}
		break;
	case 'e': // "Le"
		r_core_cmdf (core, "aeL%s", input + 1);
		break;
	case 'd': // "Ld"
		r_core_cmdf (core, "dL%s", input + 1);
		break;
	case 'h': // "Lh"
		switch (input[1]) {
		case 'j': r_core_cmd_call (core, "phj"); break;
		case 'q': r_core_cmd_call (core, "phq"); break;
		case 0: r_core_cmd_call (core, "ph"); break;
		default: r_core_cmd_help_match (core, help_msg_L, "Lh"); break;
		}
		break;
	case 'A': // "LA"
		if (input[1] == '?') { // "La?"
			r_core_cmd_help (core, help_msg_LA);
		} else { // asm plugins
			int mode = input[1];
			PJ *pj = (mode == 'j')? r_core_pj_new (core): NULL;
			RListIter *iter;
			RAnalPlugin *item;
			if (pj) {
				pj_a (pj);
			}
			r_list_foreach (core->anal->plugins, iter, item) {
				switch (mode) {
				case 'j':
					pj_o (pj);
					r_lib_meta_pj (pj, &item->meta);
					pj_end (pj);
					break;
				case 'q':
					r_kons_printf (core->cons, "%s\n", item->meta.name);
					break;
				default:
					r_kons_printf (core->cons, "%-12s %5s %s\n",
						item->meta.name,
						item->meta.license,
						item->meta.desc);
					break;
				}
			}
			if (pj) {
				pj_end (pj);
				char *s = pj_drain (pj);
				r_kons_printf (core->cons, "%s\n", s);
				free (s);
			}
		}
		break;
	case 'a': // "La" // list arch plugins
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_L, "La");
		} else {
			int mode = input[1];
			PJ *pj = (mode == 'j')? r_core_pj_new (core): NULL;
			RList *list;
			RListIter *iter;
			RArchPlugin *item;
			if (pj) {
				pj_a (pj);
			}
			r_list_foreach (core->anal->arch->plugins, iter, item) {
				char *cpu;
				RListIter *iter2;
				switch (mode) {
				case 'j':
					pj_o (pj);
					r_lib_meta_pj (pj, &item->meta);
					if (item->arch) {
						pj_ks (pj, "arch", item->arch);
					}
					pj_ks (pj, "endian", (item->endian == R_SYS_ENDIAN_BIG)? "big": "little");
					if (item->cpus) {
						pj_ka (pj, "cpus");
						list = r_str_split_list (strdup (item->cpus), ",", 0);
						r_list_foreach (list, iter2, cpu) {
							pj_s (pj, cpu);
						}
						r_list_free (list);
						pj_end (pj);
					}
					pj_ka (pj, "bits");
					int i;
					for (i = 0; i < 8; i++) {
						ut8 b = 0xff & (item->bits >> (i * 8));
						if (b) {
							pj_n (pj, b);
						}
					}
					pj_end (pj);
					pj_end (pj);
					break;
				case 'q':
					r_cons_printf ("%s\n", item->meta.name);
					break;
				default:
					r_cons_printf ("%-12s %5s %s (%s)\n",
						item->meta.name,
						item->meta.license,
						item->meta.desc,
						item->arch);
					break;
				}
			}
			if (pj) {
				pj_end (pj);
				char *s = pj_drain (pj);
				r_cons_printf ("%s\n", s);
				free (s);
			}
		}
		break;
	case 'p': // "Lp"
		if (input[1] == 'j') { // "Lpj"
			RConfigNode *node = r_config_node_get (core->config, "asm.parser");
			if (node && node->options) {
				char *opt;
				RListIter *iter;
				PJ *pj = r_core_pj_new (core);
				pj_a (pj);
				r_list_foreach (node->options, iter, opt) {
					pj_o (pj);
					pj_ks (pj, "name", opt);
					// TODO: parse plugin must use the meta struct
					// pj_ks (pj, "description", opt);
					pj_end (pj);
				}
				pj_end (pj);
				char *s = pj_drain (pj);
				r_cons_printf ("%s\n", s);
				free (s);
			}
		} else {
			r_core_cmd_call (core, "e asm.parser=?");
		}
		break;
	case 'D': // "LD"
		if (input[1] == ' ') {
			r_core_cmdf (core, "e cmd.pdc=%s", r_str_trim_head_ro (input + 2));
		} else if (input[1] == 'j') {
			char *deco;
			RListIter *iter;
			char *decos = r_core_cmd_str (core, "e cmd.pdc=?");
			RList *list = r_str_split_list (decos, "\n", 0);
			PJ *pj = r_core_pj_new (core);
			pj_o (pj);
			pj_ka (pj, "decompilers");
			r_list_foreach (list, iter, deco) {
				if (*deco) {
					pj_s (pj, deco);
				}
			}
			pj_end (pj);
			pj_end (pj);
			char *s = pj_drain (pj);
			r_cons_printf ("%s\n", s);
			free (s);
			r_list_free (list);
			free (decos);
		} else {
			r_core_cmd_call (core, "e cmd.pdc=?");
		}
		break;
	case 'l': // "Ll"
		if (input[1] == 'j') { // "Llj" "#!?j"
			r_core_list_lang (core, 'j');
		} else if (input[1] == 'q') { // "Llq" "#!?q"
			r_core_list_lang (core, 'q');
		} else if (input[1] == ',') { // "Ll,"
			r_core_list_lang (core, ',');
		} else if (input[1] == '?') { // "Ll?"
			r_cons_printf ("Usage: Ll[,jq] - list r_lang plugins\n");
		} else {
			r_core_list_lang (core, 0);
		}
		break;
	case 'L': // "LL"
		if (r_config_get_b (core->config, "scr.interactive")) {
			screenlock (core);
		} else {
			R_LOG_ERROR ("lock screen requires scr.interactive");
		}
		break;
	case 'g': // "Lg"
		if (input[1] == 'j') {
			r_core_cmd_call (core, "gLj");
		} else {
			r_core_cmd_call (core, "gL");
		}
		break;
	case 'o': // "Lo"
	case 'i': // "Li"
		r_core_cmd_callf (core, "%cL%s", input[0], input + 1);
		break;
	case 'c': { // "Lc"
		RListIter *iter;
		RCorePlugin *cp;
		switch (input[1]) {
		case 'j': { // "Lcj"
			PJ *pj = r_core_pj_new (core);
			if (!pj) {
				return 1;
			}
			pj_a (pj);
			r_list_foreach (core->rcmd->plist, iter, cp) {
				pj_o (pj);
				r_lib_meta_pj (pj, &cp->meta);
				if (cp->meta.name) {
					bool found;
					RLibPlugin *plugin = ht_pp_find (core->lib->plugins_ht, cp->meta.name, &found);
					if (found && plugin) {
						if (plugin->file) {
							pj_ks (pj, "path", plugin->file);
						}
					}
				}
				pj_end (pj);
			}
			pj_end (pj);
			r_cons_println (pj_string (pj));
			pj_free (pj);
			break;
			}
		case '-':
			r_core_cmd_callf (core, "L-%s", r_str_trim_head_ro (input + 2));
			break;
		case ' ':
			{
				const char *arg = r_str_trim_head_ro (input + 2);
				char *p = r_file_home (arg);
				if (r_file_exists (p)) {
					r_lib_open (core->lib, p);
				} else {
					if (strchr (arg, '.')) {
						r_lib_open (core->lib, arg);
					} else {
						char *q = r_str_newf ("%s.%s", arg, R_LIB_EXT);
						r_lib_open (core->lib, q);
						free (q);
					}
				}
				free (p);
			}
			break;
		case 'v':
			r_lib_list (core->lib);
			break;
		case 'q':
			r_list_foreach (core->rcmd->plist, iter, cp) {
				r_cons_printf ("%s\n", cp->meta.name);
			}
			break;
		case 0:
			r_list_foreach (core->rcmd->plist, iter, cp) {
				r_cons_printf ("%-10s %s\n", cp->meta.name, cp->meta.desc);
			}
			break;
		case '?':
			r_core_cmd_help (core, help_msg_L);
			break;
		default:
			r_core_return_invalid_command (core, "Lc", input[1]);
			break;
		}
		}
		break;
	default:
		r_core_return_invalid_command (core, "L", *input);
		break;
	}
	return 0;
}

#endif
