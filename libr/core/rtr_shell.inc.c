/* radare - Copyright 2009-2025 - pancake */

static bool rtr_visual(RCore *core, TextLog T, const char *cmd) {
	bool autorefresh = false;
	if (cmd) {
		r_kons_break_push (core->cons, NULL, NULL);
		for (;;) {
			char *ret;
			r_kons_clear00 (core->cons);
			ret = rtrcmd (T, cmd);
			r_cons_println (core->cons, ret);
			free (ret);
			r_cons_flush (core->cons);
			if (r_cons_is_breaked (core->cons)) {
				break;
			}
			r_sys_sleep (1);
		}
		r_kons_break_pop (core->cons);
	} else {
		const char *cmds[] = { "px", "pd", "pxa", "dr", "sr SP;pxa", NULL };
		int cmdidx = 0;
		char *ret, ch;
		free (rtrcmd (T, "e scr.color=true"));
		free (rtrcmd (T, "e scr.html=false"));
		for (;;) {
			r_kons_clear00 (core->cons);
			ret = rtrcmd (T, cmds[cmdidx]);
			if (ret) {
				r_cons_println (core->cons, ret);
				free (ret);
			}
			r_cons_flush (core->cons);
			if (autorefresh) {
				r_kons_printf (core->cons, "(auto-refresh)\n");
				r_cons_flush (core->cons);
				r_kons_break_push (core->cons, NULL, NULL);
				r_sys_sleep (1);
				if (r_cons_is_breaked (core->cons))  {
					autorefresh = false;
					ch = r_cons_readchar (core->cons);
				} else {
					r_kons_break_pop (core->cons);
					continue;
				}
				r_kons_break_pop (core->cons);
			} else {
				ch = r_cons_readchar (core->cons);
			}
#if 0
TODO:
 i   insert hex/string/asm
 0-9 follow jumps
#endif
			switch (ch) {
			case '?':
				r_kons_clear00 (core->cons);
				r_kons_printf (core->cons, "Remote Visual keys:\n"
				" hjkl : move\n"
				" HJKL : move faster\n"
				" +-*/ : change block size\n"
				" pP   : rotate print modes\n"
				" T    : enter TextLog chat console\n"
				" @    : enter auto-refresh mode\n"
				" i    : insert hexpair\n"
				" q    : quit this mode and go back to the shell\n"
				" sS   : step / step over\n"
				" .    : seek entry or pc\n");
				r_cons_flush (core->cons);
				r_cons_any_key (core->cons, NULL);
				break;
			case 'i':
				{
#if R2__UNIX__
#define COLORFLAGS (core->print->flags & R_PRINT_FLAGS_COLOR)
#else
#define COLORFLAGS 0
#endif
					char buf[1024];
					if (COLORFLAGS) {
						r_line_set_prompt (core->cons->line, Color_RESET":> ");
					} else {
						r_line_set_prompt (core->cons->line, ":> ");
					}
					showcursor (core, true);
					r_cons_fgets (core->cons, buf + 3, sizeof (buf) - 3, 0, NULL);
					memcpy (buf, "wx ", 3);
					if (buf[3]) {
						buf[sizeof (buf) - 1] = 0;
						char *res = rtrcmd (T, buf);
						if (res) {
							r_cons_println (core->cons, res);
							free (res);
						}
						r_cons_flush (core->cons);
					}
				}
				break;
			case 's':
				free (rtrcmd (T, "ds;.dr*"));
				break;
			case 'S':
				free (rtrcmd (T, "dso;.dr*"));
				break;
			case '.':
				free (rtrcmd (T, "s entry0;dr?rip;?? sr PC"));
				break;
			case ':':
				{
					int ret;
					eprintf ("Press <enter> to return to Visual mode.\n");
					do {
						char buf[1024];
#if R2__UNIX__
						r_line_set_prompt (core->cons->line, Color_RESET":> ");
#else
						r_line_set_prompt (core->cons->line, ":> ");
#endif
						showcursor (core, true);
						r_cons_fgets (core->cons, buf, sizeof (buf), 0, NULL);
						if (*buf) {
							r_line_hist_add (core->cons->line, buf);
							char *res = rtrcmd (T, buf);
							if (res) {
								r_cons_println (core->cons, res);
								free (res);
							}
							r_cons_flush (core->cons);
							ret = true;
						} else {
							ret = false;
							r_kons_clear00 (core->cons);
							showcursor (core, false);
						}
					} while (ret);
				}
				break;
			case '@': autorefresh = true; break;
			case 'j':
				if (cmdidx == 1) {
					free (rtrcmd (T, "so")); break;
				} else {
					free (rtrcmd (T, "s+16")); break;
				}
				break;
			case 'k': free (rtrcmd (T, "s-16")); break;
			case 'h': free (rtrcmd (T, "s-1")); break;
			case 'l': free (rtrcmd (T, "s+1")); break;
			case 'J':
				if (cmdidx == 1) {
					free (rtrcmd (T, "4so"));
				} else {
					free (rtrcmd (T, "s+32"));
				}
				break;
			case 'K': free (rtrcmd (T, "s-32")); break;
			case 'H': free (rtrcmd (T, "s-2")); break;
			case 'L': free (rtrcmd (T, "s+2")); break;
			case 'T': rtr_textlog_chat (core, T); break;
			case '+': free (rtrcmd (T, "b+1")); break;
			case '*': free (rtrcmd (T, "b+16")); break;
			case '-': free (rtrcmd (T, "b-1")); break;
			case '/': free (rtrcmd (T, "b-16")); break;
			case 'p': cmdidx++;
				if (!cmds[cmdidx]) {
					cmdidx = 0;
				}
				break;
			case 'P': cmdidx--;
				if (cmdidx < 0) {
					cmdidx = 2;
				}
				break;
			case 'q': return false;
			}
		}
	}
	return true;
}

// XXX: this needs to be moved to use the standard shell like in !=! and support visual+panels
static void __rtr_shell(RCore *core, int nth) {
	char *host = "";
	char *port= "";
	char *file= "";
	char prompt[64], prompt2[64], *str, *ptr;
	int len;
	const char* res;
	RSocket *s = NULL;
	if (nth < 0 || nth >= RTR_MAX_HOSTS) {
		R_LOG_ERROR ("Invalid fd");
		return;
	}
	if (!rtr_host[nth].fd || rtr_host[nth].fd->fd < 1) {
		R_LOG_ERROR ("Invalid connection");
		return;
	}
	const char *proto = rtr_proto_tostring (rtr_host[nth].proto);
	if (!proto) {
		R_LOG_ERROR ("Unknown protocol");
		return;
	}
	host = strdup (rtr_host[nth].host);
	port = r_str_newf ("%d", rtr_host[nth].port);

	if (!r_config_get_b (core->config, "scr.interactive")) {
		eprintf ("Set scr.interfactive to use the remote r2 shell.\n");
		return;
	}

	TextLog T = { host, port, file };
	snprintf (prompt, sizeof (prompt), "[%s://%s:%s/%s]> ", proto, host, port, file);
	snprintf (prompt2, sizeof (prompt2), "[%s:%s]$ ", host, port);
	for (;;) {
		r_line_set_prompt (core->cons->line, prompt);
		res = r_line_readline (core->cons);
		if (R_STR_ISEMPTY (res)) {
			break;
		}
		if (*res == 'q') {
			break;
		}
		if (!strcmp (res, "!sh")) {
			for (;;) {
				r_line_set_prompt (core->cons->line, prompt2);
				res = r_line_readline (core->cons);
				if (!res || !*res || !strcmp (res, "exit")) {
					break;
				}
				ptr = r_str_uri_encode (res);
				char *uri = r_str_newf ("http://%s:%s/%s!%s", host, port, file, res);
				str = r_socket_http_get (uri, NULL, NULL, &len);
				if (str) {
					str[len] = 0;
					res = strstr (str, "\n\n");
					if (res) {
						res = strstr (res + 1, "\n\n");
					}
					res = res? res + 2: str;
					const char *tail = (res[strlen (res) - 1] == '\n')? "": "\n";
					printf ("%s%s", res, tail);
					r_line_hist_add (core->cons->line, str);
					free (str);
				}
				free (ptr);
				free (uri);
			}
		} else if (res[0] == 'v' || res[0] == 'V') {
			if (res[1] == ' ') {
				rtr_visual (core, T, res + 1);
			} else {
				rtr_visual (core, T, NULL);
			}
		} else if (!strcmp (res, "TT")) {
			rtr_textlog_chat (core, T);
		} else {
			char *cmdline = r_str_newf ("%d %s", nth, res);
			r_core_rtr_cmd (core, cmdline);
			r_cons_flush (core->cons);
			r_line_hist_add (core->cons->line, res);
		}
	}
	r_socket_free (s);
	free (host);
	free (port);
}

