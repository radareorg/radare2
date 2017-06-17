/* radare - Copyright 2009-2016 - pancake, nibble */

#include "r_core.h"
#include "r_socket.h"
#include "gdb/include/libgdbr.h"
#include "gdb/include/gdbserver/core.h"

#if 0
SECURITY IMPLICATIONS
=====================
- no ssl
- no auth
- commands can be executed by anyone
- default is to listen on localhost
- can access full filesystem
- follow symlinks
#endif

#define USE_THREADS 1
#define rtr_n core->rtr_n
#define rtr_host core->rtr_host

static RSocket *s = NULL;
static RThread *httpthread = NULL;
static RThread *rapthread = NULL;
static const char *listenport = NULL;

typedef struct {
	const char *host;
	const char *port;
	const char *file;
} TextLog;

typedef struct {
	RCore *core;
	int launch;
	char *path;
} HttpThread;

typedef struct {
	RCore *core;
	const char* input;
} RapThread;

static void http_logf(RCore *core, const char *fmt, ...) {
	bool http_log_enabled = r_config_get_i (core->config, "http.log");
	va_list ap;
	va_start (ap, fmt);
	if (http_log_enabled) {
		const char *http_log_file = r_config_get (core->config, "http.logfile");
		if (http_log_file && *http_log_file) {
			char * msg = calloc (4096, 1);
			vsnprintf (msg, 4095, fmt, ap);
			r_file_dump (http_log_file, (const ut8*)msg, -1, true);
			free (msg);
		} else {
			vfprintf (stderr, fmt, ap);
		}
	}
	va_end (ap);
}

static char *rtrcmd (TextLog T, const char *str) {
	char *res, *ptr2;
	char *ptr = r_str_uri_encode (str);
	char *uri = r_str_newf ("http://%s:%s/%s%s", T.host, T.port, T.file, ptr? ptr: str);
	int len;
	free (ptr);
	ptr2 = r_socket_http_get (uri, NULL, &len);
	free (uri);
	if (ptr2) {
		ptr2[len] = 0;
		res = strstr (ptr2, "\n\n");
		if (res) {
			res = strstr (res + 1, "\n\n");
		}
		return res? res + 2: ptr2;
	}
	return NULL;
}

static void showcursor(RCore *core, int x) {
	if (core && core->vmode) {
		r_cons_show_cursor (x);
		r_cons_enable_mouse (x? r_config_get_i (core->config, "scr.wheel"): false);
	} else {
		r_cons_enable_mouse (false);
	}
	r_cons_flush ();
}

// TODO: rename /name to /nick or /so?
// clone of textlog_chat () using rtrcmd()
static void rtr_textlog_chat (RCore *core, TextLog T) {
	char prompt[64];
	char buf[1024];
	int lastmsg = 0;
	const char *me = r_config_get (core->config, "cfg.user");
	char *ret, msg[1024];

	eprintf ("Type '/help' for commands and ^D to quit:\n");
	char *oldprompt = strdup (r_line_singleton ()->prompt);
	snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
	r_line_set_prompt (prompt);
	ret = rtrcmd (T, msg);
	for (;;) {
		if (lastmsg >= 0) {
			snprintf (msg, sizeof (msg) - 1, "T %d", lastmsg);
		} else {
			strcpy (msg, "T");
		}
		ret = rtrcmd (T, msg);
		r_cons_println (ret);
		free (ret);
		ret = rtrcmd (T, "Tl");
		lastmsg = atoi (ret)-1;
		free (ret);
		if (r_cons_fgets (buf, sizeof (buf) - 1, 0, NULL) < 0) {
			goto beach;
		}
		if (!*buf) {
			continue;
		}
		if (!strcmp (buf, "/help")) {
			eprintf ("/quit           quit the chat (same as ^D)\n");
			eprintf ("/nick <nick>    set cfg.user nick name\n");
			eprintf ("/log            show full log\n");
			eprintf ("/clear          clear text log messages\n");
		} else if (!strncmp (buf, "/nick ", 6)) {
			snprintf (msg, sizeof (msg) - 1, "* '%s' is now known as '%s'", me, buf+6);
			r_cons_println (msg);
			r_core_log_add (core, msg);
			r_config_set (core->config, "cfg.user", buf+6);
			me = r_config_get (core->config, "cfg.user");
			snprintf (prompt, sizeof (prompt) - 1, "[%s]> ", me);
			r_line_set_prompt (prompt);
		} else if (!strcmp (buf, "/log")) {
			char *ret = rtrcmd (T, "T");
			if (ret) {
				r_cons_println (ret);
				free (ret);
			}
		} else if (!strcmp (buf, "/clear")) {
			//r_core_log_del (core, 0);
			free (rtrcmd (T, "T-"));
		} else if (!strcmp (buf, "/quit")) {
			goto beach;
		} else if (*buf=='/') {
			eprintf ("Unknown command: %s\n", buf);
		} else {
			snprintf (msg, sizeof (msg) - 1, "T [%s] %s", me, buf);
			free (rtrcmd (T, msg));
		}
	}
beach:
	r_line_set_prompt (oldprompt);
	free (oldprompt);
}

static bool rtr_visual(RCore *core, TextLog T, const char *cmd) {
	bool autorefresh = false;
	if (cmd) {
		r_cons_break_push (NULL, NULL);
		for (;;) {
			char *ret;
			r_cons_clear00 ();
			ret = rtrcmd (T, cmd);
			r_cons_println (ret);
			free (ret);
			r_cons_flush ();
			if (r_cons_is_breaked ()) {
				break;
			}
			r_sys_sleep (1);
		}
		r_cons_break_pop ();
	} else {
		const char *cmds[] = { "px", "pd", "pxa", "dr", "sr SP;pxa", NULL };
		int cmdidx = 0;
		char *ret, ch;
		free (rtrcmd (T, "e scr.color=true"));
		free (rtrcmd (T, "e scr.html=false"));
		for (;;) {
			r_cons_clear00 ();
			ret = rtrcmd (T, cmds[cmdidx]);
			if (ret) {
				r_cons_println (ret);
				free (ret);
			}
			r_cons_flush ();
			if (autorefresh) {
				r_cons_printf ("(auto-refresh)\n");
				r_cons_flush ();
				r_cons_break_push (NULL, NULL);
				r_sys_sleep (1);
				if (r_cons_is_breaked ())  {
					autorefresh = false;
					ch = r_cons_readchar ();
				} else {
					r_cons_break_pop ();
					continue;
				}
				r_cons_break_pop ();
			} else {
				ch = r_cons_readchar ();
			}
#if 0
TODO:
 i   insert hex/string/asm
 0-9 follow jumps
#endif
			switch (ch) {
			case '?':
				r_cons_clear00 ();
				r_cons_printf ("Remote Visual keys:\n"
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
				r_cons_flush ();
				r_cons_any_key (NULL);
				break;
			case 'i':
				{
#if __UNIX__
#define COLORFLAGS (core->print->flags & R_PRINT_FLAGS_COLOR)
#else
#define COLORFLAGS 0
#endif
					char buf[1024];
					if (COLORFLAGS) {
						r_line_set_prompt (Color_RESET":> ");
					} else {
						r_line_set_prompt (":> ");
					}
					showcursor (core, true);
					r_cons_fgets (buf+3, sizeof (buf) - 4, 0, NULL);
					memcpy (buf, "wx ", 3);
					if (buf[3]) {
						char *res = rtrcmd (T, buf);
						if (res) {
							r_cons_println (res);
							free (res);
						}
						r_cons_flush ();
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
#if __UNIX__
						r_line_set_prompt (Color_RESET":> ");
#else
						r_line_set_prompt (":> ");
#endif
						showcursor (core, true);
						r_cons_fgets (buf, sizeof (buf), 0, NULL);
						if (*buf) {
							r_line_hist_add (buf);
							char *res = rtrcmd (T, buf);
							if (res) {
								r_cons_println (res);
								free (res);
							}
							r_cons_flush ();
							ret = true;
						} else {
							ret = false;
							//r_cons_any_key ();
							r_cons_clear00 ();
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
			case 'p': cmdidx++; if (!cmds[cmdidx]) cmdidx = 0; break;
			case 'P': cmdidx--; if (cmdidx<0) cmdidx = 2; break;
			case 'q': return false;
			}
		}
	}
	return true;
}

R_API int r_core_rtr_http_stop(RCore *u) {
	RCore *core = (RCore*)u;
	const int timeout = 1; // 1 second
	const char *port;
	RSocket* sock;

#if __WINDOWS__
	r_socket_http_server_set_breaked (&r_cons_singleton()->breaked);
#endif
	if (((size_t)u) > 0xff) {
		port = listenport? listenport: r_config_get (
			core->config, "http.port");
		sock = r_socket_new (0);
		(void)r_socket_connect (sock, "localhost",
			port, R_SOCKET_PROTO_TCP, timeout);
		r_socket_free (sock);
	}
	r_socket_free (s);
	s = NULL;
	return 0;
}

static char *rtr_dir_files (const char *path) {
	char *ptr = strdup ("<html><body>\n");
	const char *file;
	RListIter *iter;
	// list files
	RList *files = r_sys_dir (path);
	eprintf ("Listing directory %s\n", path);
	r_list_foreach (files, iter, file) {
		if (file[0] == '.') continue;
		ptr = r_str_appendf (ptr, "<a href=\"%s%s\">%s</a><br />\n",
			path, file, file);
	}
	r_list_free (files);
	return r_str_append (ptr, "</body></html>\n");
}

#if __UNIX__
static void dietime (int sig) {
	eprintf ("It's Die Time!\n");
	exit (0);
}
#endif

static void activateDieTime (RCore *core) {
	int dt = r_config_get_i (core->config, "http.dietime");
	if (dt > 0) {
#if __UNIX__
		signal (SIGALRM, dietime);
		alarm (dt);
#else
		eprintf ("http.dietime only works on *nix systems\n");
#endif
	}
}

// return 1 on error
static int r_core_rtr_http_run(RCore *core, int launch, const char *path) {
	RConfig *newcfg = NULL, *origcfg = NULL;
	char headers[128] = R_EMPTY;
	RSocketHTTPRequest *rs;
	char buf[32];
	int ret = 0;
	RSocket *s;
	char *dir;
	int iport, timeout = r_config_get_i (core->config, "http.timeout");
	const char *host = r_config_get (core->config, "http.bind");
	const char *root = r_config_get (core->config, "http.root");
	const char *homeroot = r_config_get (core->config, "http.homeroot");
	const char *port = r_config_get (core->config, "http.port");
	const char *allow = r_config_get (core->config, "http.allow");
	const char *httpui = r_config_get (core->config, "http.ui");

	if (!r_file_is_directory (root)) {
		if (!r_file_is_directory (homeroot)) {
			eprintf ("Cannot find http.root (%s) or http.homeroot (%s)\n", root, homeroot);
			return false;
		}
		return false;
	}

	if (path && atoi (path)) {
		port = path;
		path = NULL;
	} else {
		if (core->file && (!path || !*path)) {
			if (!strcmp (httpui, "p")
			|| !strcmp (httpui, "m")
			|| !strcmp (httpui, "enyo")
			|| !strcmp (httpui, "t")) {
				path = httpui;
			}
		}
	}

	if (!strcmp (port, "0")) {
		r_num_irand ();
		iport = 1024 + r_num_rand (45256);
		snprintf (buf, sizeof (buf), "%d", iport);
		port = buf;
	}
	s = r_socket_new (false);
	{
		if (host && *host) {
			if (!strcmp (host, "::1")) {
				s->local = true;
			} else if (!strcmp (host, "localhost")) {
				s->local = true;
			} else if (!strcmp (host, "127.0.0.1")) {
				s->local = true;
			} else if (!strcmp (host, "local")) {
				s->local = true;
				r_config_set (core->config, "http.bind", "localhost");
			} else if (host[0]=='0' || !strcmp (host, "public")) {
				// public
				host = "127.0.0.1";
				r_config_set (core->config, "http.bind", "0.0.0.0");
				s->local = false;
			} else {
				s->local = true;
			}
		} else {
			s->local = true;
		}
	}
	if (!r_socket_listen (s, port, NULL)) {
		r_socket_free (s);
		eprintf ("Cannot listen on http.port\n");
		return 1;
	}
	if (launch=='H') {
		const char *browser = r_config_get (core->config, "http.browser");
		r_sys_cmdf ("%s http://%s:%d/%s &",
			browser, host, atoi (port), path? path:"");
	}

	origcfg = core->config;
	newcfg = r_config_clone (core->config);
	core->config = newcfg;

	r_config_set (core->config, "asm.cmtright", "false");
#if 0
	// WHY
	r_config_set (core->config, "scr.html", "true");
#endif
	r_config_set (core->config, "scr.color", "false");
	r_config_set (core->config, "asm.bytes", "false");
	r_config_set (core->config, "scr.interactive", "false");
	bool restoreSandbox = false;
	if (r_config_get_i (core->config, "http.sandbox")) {
		//(void)r_config_get_i (core->config, "cfg.sandbox");
		r_config_set (core->config, "cfg.sandbox", "true");
		restoreSandbox = true;
	}
	eprintf ("Starting http server...\n");
	eprintf ("open http://%s:%d/\n", host, atoi (port));
	eprintf ("r2 -C http://%s:%d/cmd/\n", host, atoi (port));
	core->http_up = true;

	ut64 newoff, origoff = core->offset;
	int newblksz, origblksz = core->blocksize;
	ut8 *newblk, *origblk = core->block;

	newblk = malloc (core->blocksize);
	memcpy (newblk, core->block, core->blocksize);

	core->block = newblk;
// TODO: handle mutex lock/unlock here
	r_cons_break_push ((RConsBreak)r_core_rtr_http_stop, core);
	while (!r_cons_is_breaked ()) {
		/* restore environment */
		core->config = origcfg;
		r_config_set (origcfg, "scr.html", r_config_get (origcfg, "scr.html"));
		r_config_set (origcfg, "scr.color", r_config_get (origcfg, "scr.color"));
		r_config_set (origcfg, "scr.interactive", r_config_get (origcfg, "scr.interactive"));
		core->http_up = 0; // DAT IS NOT TRUE AT ALL.. but its the way to enable visual

		newoff = core->offset;
		newblk = core->block;
		newblksz = core->blocksize;

		core->offset = origoff;
		core->block = origblk;
		core->blocksize = origblksz;

// backup and restore offset and blocksize

		/* this is blocking */
		activateDieTime (core);
		rs = r_socket_http_accept (s, timeout);

		origoff = core->offset;
		origblk = core->block;
		origblksz = core->blocksize;
		core->offset = newoff;
		core->block = newblk;
		core->blocksize = newblksz;
		/* set environment */
// backup and restore offset and blocksize
		core->http_up = 1;
		core->config = newcfg;
		r_config_set (newcfg, "scr.html", r_config_get (newcfg, "scr.html"));
		r_config_set (newcfg, "scr.color", r_config_get (newcfg, "scr.color"));
		r_config_set (newcfg, "scr.interactive", r_config_get (newcfg, "scr.interactive"));

		if (!rs) {
			r_sys_usleep (100);
			continue;
		}
		if (allow && *allow) {
			bool accepted = false;
			const char *allows_host;
			char *p, *peer = r_socket_to_string (rs->s);
			char *allows = strdup (allow);
			//eprintf ("Firewall (%s)\n", allows);
			int i, count = r_str_split (allows, ',');
			p = strchr (peer, ':');
			if (p) {
				*p = 0;
			}
			for (i = 0; i < count; i++) {
				allows_host = r_str_word_get0 (allows, i);
				//eprintf ("--- (%s) (%s)\n", host, peer);
				if (!strcmp (allows_host, peer)) {
					accepted = true;
					break;
				}
			}
			free (peer);
			free (allows);
			if (!accepted) {
				r_socket_http_close (rs);
				continue;
			}
		}
		if (!rs->method || !rs->path) {
			http_logf (core, "Invalid http headers received from client\n");
			r_socket_http_close (rs);
			continue;
		}
		dir = NULL;

		if (r_config_get_i (core->config, "http.verbose")) {
			char *peer = r_socket_to_string (rs->s);
			http_logf (core, "[HTTP] %s %s\n", peer, rs->path);
			free (peer);
		}
		if (r_config_get_i (core->config, "http.dirlist")) {
			if (r_file_is_directory (rs->path)) {
				dir = strdup (rs->path);
			}
		}
		if (r_config_get_i (core->config, "http.cors")) {
			strcpy (headers, "Access-Control-Allow-Origin: *\n"
				"Access-Control-Allow-Headers: Origin, "
				"X-Requested-With, Content-Type, Accept\n");
		}
		if (!strcmp (rs->method, "OPTIONS")) {
			r_socket_http_response (rs, 200, "", 0, headers);
		} else if (!strcmp (rs->method, "GET")) {
			if (!strncmp (rs->path, "/up/", 4)) {
				if (r_config_get_i (core->config, "http.upget")) {
					const char *uproot = r_config_get (core->config, "http.uproot");
					if (!rs->path[3] || (rs->path[3]=='/' && !rs->path[4])) {
						char *ptr = rtr_dir_files (uproot);
						r_socket_http_response (rs, 200, ptr, 0, headers);
						free (ptr);
					} else {
						char *path = r_file_root (uproot, rs->path + 4);
						if (r_file_exists (path)) {
							int sz = 0;
							char *f = r_file_slurp (path, &sz);
							if (f) {
								r_socket_http_response (rs, 200, f, sz, headers);
								free (f);
							} else {
								r_socket_http_response (rs, 403, "Permission denied", 0, headers);
								http_logf (core, "http: Cannot open '%s'\n", path);
							}
						} else {
							if (dir) {
								char *resp = rtr_dir_files (dir);
								r_socket_http_response (rs, 404, resp, 0, headers);
								free (resp);
							} else {
								http_logf (core, "File '%s' not found\n", path);
								r_socket_http_response (rs, 404, "File not found\n", 0, headers);
							}
						}
						free (path);
					}
				} else {
					r_socket_http_response (rs, 403, "Permission denied\n", 0, NULL);
				}
			} else if (!strncmp (rs->path, "/cmd/", 5)) {
				char *cmd = rs->path + 5;
				const char *httpcmd = r_config_get (core->config, "http.uri");
				const char *httpref = r_config_get (core->config, "http.referer");
				bool httpref_enabled;
				char *refstr = NULL;
				if (httpref && *httpref) {
					httpref_enabled = true;
					if (strstr (httpref, "http")) {
						refstr = strdup (httpref);
					} else {
						refstr = r_str_newf ("http://localhost:%d/", atoi (port));
					}
				} else {
					httpref_enabled = false;
				}

				while (*cmd == '/') {
					cmd++;
				}
				if (httpref_enabled && (!rs->referer || (refstr && !strstr (rs->referer, refstr)))) {
					r_socket_http_response (rs, 503, "", 0, headers);
				} else {
					if (httpcmd && *httpcmd) {
						int len; // do remote http query and proxy response
						char *res, *bar = r_str_newf ("%s/%s", httpcmd, cmd);
						res = r_socket_http_get (bar, NULL, &len);
						if (res) {
							res[len] = 0;
							r_cons_println (res);
						}
						free (bar);
					} else {
						char *out, *cmd = rs->path + 5;
						r_str_uri_decode (cmd);
						r_config_set (core->config, "scr.interactive", "false");
						if (!strcmp (cmd, "=h*")) {
							if (r_sandbox_enable (0)) {
								out = NULL;
							} else {
								/* do stuff */
								out = NULL;
								r_socket_http_close (rs);
								free (dir);
								free (refstr);
								ret = -2;
								goto the_end;
							}
						}
						if (*cmd == ':') {
							/* commands in /cmd/: starting with : do not show any output */
							r_core_cmd0 (core, cmd + 1);
							out = NULL;
						} else {
							out = r_core_cmd_str_pipe (core, cmd);
						}
						if (out) {
							char *res = r_str_uri_encode (out);
							char *newheaders = r_str_newf (
								"Content-Type: text/plain\n%s", headers);
							r_socket_http_response (rs, 200, out, 0, newheaders);
							free (out);
							free (newheaders);
							free (res);
						} else {
							r_socket_http_response (rs, 200, "", 0, headers);
						}
					}
				}
				free (refstr);
			} else {
				const char *root = r_config_get (core->config, "http.root");
				const char *homeroot = r_config_get (core->config, "http.homeroot");
				char *path;
				if (!strcmp (rs->path, "/")) {
					free (rs->path);
					rs->path = strdup ("/index.html");
				}
				if (homeroot && *homeroot) {
					char *homepath = r_file_abspath (homeroot);
					path = r_file_root (homepath, rs->path);
					free (homepath);
					if (!r_file_exists (path) && !r_file_is_directory (path)) {
						free (path);
						path = r_file_root (root, rs->path);
					}
				} else {
					path = r_file_root (root, rs->path);
				}
				// FD IS OK HERE
				if (rs->path [strlen (rs->path) - 1] == '/') {
					path = r_str_append (path, "index.html");
					//rs->path = r_str_append (rs->path, "index.html");
				} else {
					//snprintf (path, sizeof (path), "%s/%s", root, rs->path);
					if (r_file_is_directory (path)) {
						char *res = r_str_newf ("Location: %s/\n%s", rs->path, headers);
						r_socket_http_response (rs, 302, NULL, 0, res);
						r_socket_http_close (rs);
						free (path);
						free (res);
						R_FREE (dir);
						continue;
					}
				}
				if (r_file_exists (path)) {
					int sz = 0;
					char *f = r_file_slurp (path, &sz);
					if (f) {
						const char *ct = NULL;
						if (strstr (path, ".js")) {
							ct = "Content-Type: application/javascript\n";
						}
						if (strstr (path, ".css")) {
							ct = "Content-Type: text/css\n";
						}
						if (strstr (path, ".html")) {
							ct = "Content-Type: text/html\n";
						}
						char *hdr = r_str_newf ("%s%s", ct, headers);
						r_socket_http_response (rs, 200, f, sz, hdr);
						free (hdr);
						free (f);
					} else {
						r_socket_http_response (rs, 403, "Permission denied", 0, headers);
						http_logf (core, "http: Cannot open '%s'\n", path);
					}
				} else {
					if (dir) {
						char *resp = rtr_dir_files (dir);
						http_logf (core, "Dirlisting %s\n", dir);
						r_socket_http_response (rs, 404, resp, 0, headers);
						free (resp);
					} else {
						http_logf (core, "File '%s' not found\n", path);
						r_socket_http_response (rs, 404, "File not found\n", 0, headers);
					}
				}
				free (path);
			}
		} else if (!strcmp (rs->method, "POST")) {
			ut8 *ret;
			int retlen;
			char buf[128];
			if (r_config_get_i (core->config, "http.upload")) {
				ret = r_socket_http_handle_upload (rs->data, rs->data_length, &retlen);
				if (ret) {
					ut64 size = r_config_get_i (core->config, "http.maxsize");
					if (size && retlen > size) {
						r_socket_http_response (rs, 403, "403 File too big\n", 0, headers);
					} else {
						char *filename = r_file_root (
							r_config_get (core->config, "http.uproot"),
							rs->path + 4);
						http_logf (core, "UPLOADED '%s'\n", filename);
						r_file_dump (filename, ret, retlen, 0);
						free (filename);
						snprintf (buf, sizeof (buf),
							"<html><body><h2>uploaded %d bytes. Thanks</h2>\n", retlen);
							r_socket_http_response (rs, 200, buf, 0, headers);
					}
					free (ret);
				}
			} else {
				r_socket_http_response (rs, 403, "403 Forbidden\n", 0, headers);
			}
		} else {
			r_socket_http_response (rs, 404, "Invalid protocol", 0, headers);
		}
		r_socket_http_close (rs);
		free (dir);
	}
the_end:
	{
		int timeout = r_config_get_i (core->config, "http.timeout");
		const char *host = r_config_get (core->config, "http.bind");
		const char *port = r_config_get (core->config, "http.port");
		const char *cors = r_config_get (core->config, "http.cors");
		const char *allow = r_config_get (core->config, "http.allow");
		const char *httpui = r_config_get (core->config, "http.ui");
		core->config = origcfg;
		r_config_set_i (core->config, "http.timeout", timeout);
		r_config_set (core->config, "http.bind", host);
		r_config_set (core->config, "http.port", port);
		r_config_set (core->config, "http.cors", cors);
		r_config_set (core->config, "http.allow", allow);
		r_config_set (core->config, "http.ui", httpui);
	}
	r_cons_break_pop ();
	core->http_up = false;
	r_socket_free (s);
	r_config_free (newcfg);
	if (restoreSandbox) {
		r_sandbox_disable (true);
	}
	/* refresh settings - run callbacks */
	r_config_set (origcfg, "scr.html", r_config_get (origcfg, "scr.html"));
	r_config_set (origcfg, "scr.color", r_config_get (origcfg, "scr.color"));
	r_config_set (origcfg, "scr.interactive", r_config_get (origcfg, "scr.interactive"));
	return ret;
}

static int r_core_rtr_http_thread (RThread *th) {
	if (!th) {
		return false;
	}
	HttpThread *ht = th->user;
	if (!ht || !ht->core) {
		return false;
	}
	int ret = r_core_rtr_http_run (ht->core, ht->launch, ht->path);
	R_FREE (ht->path);
	if (ret) {
		int p = r_config_get_i (ht->core->config, "http.port");
		r_config_set_i (ht->core->config, "http.port",  p + 1);
		if (p >= r_config_get_i (ht->core->config, "http.maxport")) {
			return false;
		}
	}
	return ret;
}

R_API int r_core_rtr_http(RCore *core, int launch, const char *path) {
	int ret;
	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: connect disabled\n");
		return 1;
	}
	if (launch == '-') {
		if (httpthread) {
			eprintf ("Press ^C to stop the webserver\n");
			r_th_free (httpthread);
			httpthread = NULL;
		} else {
			eprintf ("No webserver running\n");
		}
		return 0;
	}
	if (core->http_up) {
		eprintf ("http server is already running\n");
		return 1;
	}
	if (launch == '&') {
		if (httpthread) {
			eprintf ("HTTP Thread is already running\n");
			eprintf ("This is experimental and probably buggy. Use at your own risk\n");
			eprintf ("TODO: Use different eval environ for scr. for the web\n");
			eprintf ("TODO: Visual mode should be enabled on local\n");
		} else {
			const char *tpath = r_str_trim_const (path + 1);
			//HttpThread ht = { core, launch, strdup (tpath) };
			HttpThread *ht = calloc (sizeof (HttpThread), 1);
			ht->core = core;
			ht->launch = launch;
			ht->path = strdup (tpath);
			httpthread = r_th_new (r_core_rtr_http_thread, ht, false);
			r_th_start (httpthread, true);
			eprintf ("Background http server started.\n");
		}
		return 0;
	}
	do {
		ret = r_core_rtr_http_run (core, launch, path);
	} while (ret == -2);
	return ret;
}

static int r_core_rtr_gdb_cb(libgdbr_t *g, void *core_ptr, const char *cmd, char *out_buf, size_t max_len) {
	int ret;
	RList *list;
	RListIter *iter;
	gdb_reg_t *gdb_reg;
	utX val_big;
	ut64 m_off, reg_val;
	bool be;
	RDebugPid *dbgpid;
	if (!core_ptr || ! cmd) {
		return -1;
	}
	RCore *core = (RCore*) core_ptr;
	switch (cmd[0]) {
	case 'd':
		switch (cmd[1]) {
		case 'm': // dm
			if (snprintf (out_buf, max_len - 1, "%"PFMT64x, r_debug_get_baddr (core->dbg, NULL)) < 0) {
				return -1;
			}
			return 0;
		case 'p': // dp
			switch (cmd[2]) {
			case '\0': // dp
				// TODO support multiprocess
				snprintf (out_buf, max_len - 1, "QC%x", core->dbg->tid);
				return 0;
			case 't':
				switch (cmd[3]) {
				case '\0': // dpt
					if (!core->dbg->h->threads) {
						return -1;
					}
					if (!(list = core->dbg->h->threads(core->dbg, core->dbg->pid))) {
						return -1;
					}
					memset (out_buf, 0, max_len);
					out_buf[0] = 'm';
					ret = 1;
					r_list_foreach (list, iter, dbgpid) {
						// Max length of a hex pid = 8?
						if (ret >= max_len - 9) {
							break;
						}
						snprintf (out_buf + ret, max_len - ret - 1, "%x,", dbgpid->pid);
						ret = strlen (out_buf);
					}
					if (ret > 1) {
						ret--;
						out_buf[ret] = '\0';
					}
					return 0;
				case 'r': // dptr -> return current tid as int
					return core->dbg->tid;
				default:
					return r_core_cmd (core, cmd, 0);
				}
			}
			break;
		case 'r': // dr
			be = r_config_get_i (core->config, "cfg.bigendian");
			ret = 0;
			if (!(gdb_reg = g->registers)) {
				return -1;
			}
			while (*gdb_reg->name) {
				if (ret + gdb_reg->size * 2 >= max_len - 1) {
					return -1;
				}
				if (gdb_reg->size <= 8) {
					reg_val = r_reg_getv (core->dbg->reg, gdb_reg->name);
					if (!be) {
						switch (gdb_reg->size) {
						case 2:
							reg_val = r_swap_ut16 (reg_val) & 0xFFFF;
							break;
						case 4:
							reg_val = r_swap_ut32 (reg_val) & 0xFFFFFFFF;
							break;
						case 8:
							reg_val = r_swap_ut64 (reg_val);
							break;
						default:
							eprintf ("%s: Unsupported reg size: %d\n", __func__,
								 (int) gdb_reg->size);
						}
					}
					snprintf (out_buf + ret, gdb_reg->size * 2 + 1,
						  gdb_reg->size == 2 ? "%04"PFMT64x
						  : gdb_reg->size == 4 ? "%08"PFMT64x
						  : "%016"PFMT64x, reg_val);
				} else {
					r_reg_get_value_big (core->dbg->reg,
							     r_reg_get (core->dbg->reg, gdb_reg->name, -1),
							     &val_big);
					switch (gdb_reg->size) {
					case 10:
						if (be) {
							snprintf (out_buf + ret, gdb_reg->size * 2 + 1,
								  "%04x%016"PFMT64x, val_big.v80.High,
								  val_big.v80.Low);
						} else {
							snprintf (out_buf + ret, gdb_reg->size * 2 + 1,
								  "%016"PFMT64x"%04x", r_swap_ut64 (val_big.v80.Low),
								  r_swap_ut16 (val_big.v80.High));
						}
						break;
					case 12:
						if (be) {
							snprintf (out_buf + ret, gdb_reg->size * 2 + 1,
								  "%08"PFMT32x"%016"PFMT64x, val_big.v96.High,
								  val_big.v96.Low);
						} else {
							snprintf (out_buf + ret, gdb_reg->size * 2 + 1,
								  "%016"PFMT64x"%08"PFMT32x, r_swap_ut64 (val_big.v96.Low),
								  r_swap_ut32 (val_big.v96.High));
						}
						break;
					case 16:
						if (be) {
							snprintf (out_buf + ret, gdb_reg->size * 2 + 1,
								  "%016"PFMT64x"%016"PFMT64x, val_big.v128.High,
								  val_big.v128.Low);
						} else {
							snprintf (out_buf + ret, gdb_reg->size * 2 + 1,
								  "%016"PFMT64x"%016"PFMT64x, r_swap_ut64 (val_big.v128.Low),
								  r_swap_ut64 (val_big.v128.High));
						}
						break;
					default:
						eprintf ("%s: big registers not yet supported\n", __func__);
						break;
					}
				}
				ret += gdb_reg->size * 2;
				gdb_reg++;
			}
			out_buf[ret] = '\0';
			return ret;
		default:
			return r_core_cmd (core, cmd, 0);
		}
		break;
	case 'm':
		sscanf (cmd + 1, "%"PFMT64x" %d", &m_off, &ret);
		return r_io_read_at (core->io, m_off, (ut8*) out_buf, ret);
	}
	return -1;
}

// path = "<port> <file_name>"
static int r_core_rtr_gdb_run(RCore *core, int launch, const char *path) {
	RSocket *sock;
	int p, ret;
	char port[10];
	char *file = NULL, *args = NULL;
	libgdbr_t *g;
	RCoreFile *cf;

	if (!core || !path) {
		return -1;
	}
	while (*path && isspace (*path)) {
		path++;
	}
	if (!*path) {
		eprintf ("gdbserver: Port not specified\n");
		return -1;
	}
	if (path && (p = atoi (path))) {
		if (p < 0 || p > 65535) {
			eprintf ("gdbserver: Invalid port: %s\n", port);
			return -1;
		}
		snprintf (port, sizeof (port) - 1, "%d", p);
		if (!(file = strchr (path, ' '))) {
			eprintf ("gdbserver: File not specified\n");
			return -1;
		}
		while (isspace (*file)) {
			file++;
		}
		if (!*file) {
			eprintf ("gdbserver: File not specified\n");
			return -1;
		}
	}
	if (file) {
		args = strchr (file, ' ');
		if (args) {
			*args++ = '\0';
			while (isspace (*args)) {
				args++;
			}
		} else {
			args = "";
		}
	} else {
		args = "";
	}

	if (!(cf = r_core_file_open (core, file, R_IO_READ, 0))) {
		eprintf ("Cannot open file (%s)\n", file);
		return -1;
	}
	r_core_file_reopen_debug (core, args);

	if (!(sock = r_socket_new (false))) {
		eprintf ("gdbserver: Could not open socket for listening\n");
		return -1;
	}
	if (!r_socket_listen (sock, port, NULL)) {
		r_socket_free (sock);
		eprintf ("gdbserver: Cannot listen on port: %s\n", port);
		return -1;
	}
	if (!(g = R_NEW0(libgdbr_t))) {
		r_socket_free (sock);
		eprintf ("gdbserver: Cannot alloc libgdbr instance\n");
		return -1;
	}
	gdbr_init (g, true);
	gdbr_set_architecture (g, r_config_get (core->config, "asm.arch"), r_config_get_i (core->config, "asm.bits"));
	core->gdbserver_up = 1;
	eprintf ("gdbserver started on port: %s, file: %s\n", port, file);

	while (1) {
		if (!(g->sock = r_socket_accept (sock))) {
			break;
		}
		g->connected = 1;
		ret = gdbr_server_serve (g, r_core_rtr_gdb_cb, (void*) core);
		r_socket_close (g->sock);
		g->connected = 0;
		if (ret < 0) {
			break;
		}
	}
	core->gdbserver_up = 0;
	gdbr_cleanup (g);
	free (g);
	r_socket_free (sock);
	return 0;
}

R_API int r_core_rtr_gdb(RCore *core, int launch, const char *path) {
	int ret;
	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: connect disabled\n");
		return -1;
	}
	// TODO: do stuff with launch
	if (core->gdbserver_up) {
		eprintf ("gdbserver is already running\n");
		return -1;
	}
	ret = r_core_rtr_gdb_run (core, launch, path);
	return ret;
}

R_API void r_core_rtr_help(RCore *core) {
	const char* help_msg[] = {
	"Usage:", " =[:!+-=hH] [...]", " # radare remote command execution protocol",
	"\nrap commands:", "", "",
	"=", "", "list all open connections",
	"=<", "[fd] cmd", "send output of local command to remote fd",
	"=", "[fd] cmd", "exec cmd at remote 'fd' (last open is default one)",
	"=!", " cmd", "run command via r_io_system",
	"=+", " [proto://]host", "add host (default=rap://, tcp://, udp://)",
	"=-", "[fd]", "remove all hosts or host 'fd'",
	"==", "[fd]", "open remote session with host 'fd', 'q' to quit",
	"=!=", "", "disable remote cmd mode",
	"!=!", "", "enable remote cmd mode",
	"\nrap server:","","",
	"=", ":port", "listen on given port using rap protocol (o rap://9999)",
	"=&", ":port", "start rap server in background",
	"=", ":host:port cmd", "run 'cmd' command on remote server",
	"\nhttp server:", "", "",
	"=h", " port", "listen for http connections (r2 -qc=H /bin/ls)",
	"=h-", "", "stop background webserver",
	"=h*", "", "restart current webserver",
	"=h&", " port", "start http server in background)",
	"=H", " port", "launch browser and listen for http",
	"=H&", " port", "launch browser and listen for http in background",
	"\ngdbserver:", "", "",
	"=g", " port file", "listen on 'port' for debugging 'file' using gdbserver",
	NULL };
	r_core_cmd_help (core, help_msg);
}

R_API void r_core_rtr_pushout(RCore *core, const char *input) {
	int fd = atoi (input);
	const char *cmd = NULL;
	char *str = NULL;
	if (fd) {
		for (rtr_n = 0; rtr_host[rtr_n].fd->fd != fd \
			&& rtr_n < RTR_MAX_HOSTS - 1; rtr_n++);
		if (!(cmd = strchr (input, ' '))) {
			eprintf ("Error\n");
			return;
		}
	} else cmd = input;

	if (!rtr_host[rtr_n].fd->fd) {
		eprintf("Error: Unknown host\n");
		return;
	}

	if (!(str = r_core_cmd_str (core, cmd))) {
		eprintf ("Error: radare_cmd_str returned NULL\n");
		return;
	}

	switch (rtr_host[rtr_n].proto) {
	case RTR_PROT_RAP:
		eprintf ("Error: Cannot use '=<' to a rap connection.\n");
		break;
	case RTR_PROT_TCP:
	case RTR_PROT_UDP:
	default:
		r_socket_write (rtr_host[rtr_n].fd, str, strlen (str));
		break;
	}
	free (str);
}

R_API void r_core_rtr_list(RCore *core) {
	int i;
	for (i = 0; i < RTR_MAX_HOSTS; i++) {
		if (!rtr_host[i].fd)
			continue;
		r_cons_printf ("%i - ", rtr_host[i].fd->fd);
		switch (rtr_host[i].proto) {
		case RTR_PROT_HTTP: r_cons_printf ( "http://"); break;
		case RTR_PROT_TCP: r_cons_printf ("tcp://"); break;
		case RTR_PROT_UDP: r_cons_printf ("udp://"); break;
		default: r_cons_printf ("rap://"); break;
		}
		r_cons_printf ("%s:%i/%s\n", rtr_host[i].host,
			rtr_host[i].port, rtr_host[i].file);
	}
}

R_API void r_core_rtr_add(RCore *core, const char *_input) {
	char *port, input[1024], *host = NULL, *file = NULL, *ptr = NULL, buf[1024];
	int proto, i, timeout, ret;
	RSocket *fd;

	timeout = r_config_get_i (core->config, "http.timeout");
	strncpy (input, _input, sizeof (input) - 4);
	input[sizeof(input)-4] = '\0';
	/* Parse uri */
	if ((ptr = strstr (input, "tcp://"))) {
		proto = RTR_PROT_TCP;
		host = ptr + 6;
	} else if ((ptr = strstr(input, "http://"))) {
		proto = RTR_PROT_HTTP;
		host = ptr + 7;
	} else if ((ptr = strstr(input, "udp://"))) {
		proto = RTR_PROT_UDP;
		host = ptr + 6;
	} else if ((ptr = strstr(input, "rap://"))) {
		proto = RTR_PROT_RAP;
		host = ptr + 6;
	} else {
		proto = RTR_PROT_RAP;
		host = input;
	}
	while (*host && ISWHITECHAR (*host))
		host++;

	if (!(ptr = strchr (host, ':'))) {
		ptr = host;
		port = "80";
	} else {
		*ptr++ = '\0';
		port = ptr;
	}

	if (!(file = strchr (ptr, '/'))) {
		eprintf ("Error: Missing '/'\n");
		return;
	}
	*file++ = 0;
	port = r_str_chop (port);
	while (*file == ' ') {
		file++;
	}
	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: connect disabled\n");
		return;
	}

	fd = r_socket_new (false);
	if (!fd) {
		eprintf ("Error: Cannot create new socket\n");
		return;
	}
	switch (proto) {
	case RTR_PROT_HTTP:
		{
			char prompt[64], prompt2[64], *str, *ptr;
			int len, flen = strlen (file);
			bool is_valid, is_visual;
			const char* res;

			is_visual = (file[flen - 1] == 'V');
			is_valid = (file[flen - (is_visual? 2: 1)] == '/');

			if (is_valid) {
				TextLog T = { host, port, file };
				if (is_visual) {
					file[flen - 1] = 0; // remove V from url
					rtr_visual (core, T, NULL);
				}
				snprintf (prompt, sizeof (prompt), "[http://%s:%s/%s]> ",
						host, port, file);
				snprintf (prompt2, sizeof (prompt2), "[%s:%s]$ ", host, port);
				for (;;) {
					r_line_set_prompt (prompt);
					res = r_line_readline ();
					if (!res || !*res) break;
					if (*res == 'q') break;
					if (!strcmp (res, "!sh")) {
						for (;;) {
							r_line_set_prompt (prompt2);
							res = r_line_readline ();
							if (!res || !*res || !strcmp (res, "exit")) {
								break;
							}
							ptr = r_str_uri_encode (res);
							char *uri = r_str_newf ("http://%s:%s/%s!%s", host, port, file, res);
							str = r_socket_http_get (uri, NULL, &len);
							if (str) {
								str[len] = 0;
								res = strstr (str, "\n\n");
								if (res) res = strstr (res+1, "\n\n");
								res = res? res + 2: str;
								const char *tail = (res[strlen (res) - 1] == '\n')? "": "\n";
								printf ("%s%s", res, tail);
								r_line_hist_add (str);
								free (str);
							}
							free (ptr);
							free (uri);
						}
					} else if (res[0]=='V') {
						if (res[1]==' ') {
							rtr_visual (core, T, res+1);
						} else {
							rtr_visual (core, T, NULL);
						}
					} else if (!strcmp (res, "TT")) {
						rtr_textlog_chat (core, T);
					} else {
						ptr = r_str_uri_encode (res);
						if (ptr) res = ptr;
						char *uri = r_str_newf ("http://%s:%s/%s%s", host, port, file, res);
						if (ptr == res) free (ptr);
						str = r_socket_http_get (uri, NULL, &len);
						if (str) {
							str[len] = 0;
							res = strstr (str, "\n\n");
							if (res) res = strstr (res+1, "\n\n");
							if (res) res += 2; else res = str;
							printf ("%s%s", res, (res[strlen (res)-1]=='\n')?"":"\n");
							r_line_hist_add (str);
							free (str);
						}
						free (uri);
					}
				}
			} else {
				char *http_uri = r_str_newf ("http://%s:%s/%s", host, port, file);
				str = r_socket_http_get (http_uri, NULL, &len);
				if (str) {
					str[len] = 0;
					res = strstr (str, "\n\n");
					if (res) res = strstr (res + 1, "\n\n");
					printf ("%s", res? res + 2: str);
					free (str);
				} else eprintf ("HTTP connection has failed\n");
				free (http_uri);
			}
			r_socket_free (fd);
			return;
		}
		break;
	case RTR_PROT_RAP:
		if (!r_socket_connect_tcp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			eprintf ("Error: Cannot connect to '%s' (%s)\n", host, port);
			r_socket_free (fd);
			return;
		}
		eprintf ("Connected to %s at port %s\n", host, port);
		/* send */
		buf[0] = RTR_RAP_OPEN;
		buf[1] = 0;
		buf[2] = (ut8)(strlen (file) + 1);
		memcpy (buf + 3, file, buf[2]);
		r_socket_write (fd, buf, 3 + buf[2]);
		/* read */
		eprintf ("waiting... ");
		fflush (stdout);
		r_socket_read (fd, (ut8*)buf, 5);
		i = r_read_at_be32 (buf, 1);
		if (buf[0] != (char)(RTR_RAP_OPEN | RTR_RAP_REPLY) || i <= 0) {
			eprintf ("Error: Wrong reply\n");
			r_socket_free (fd);
			return;
		}
		eprintf ("ok\n");
		break;
	case RTR_PROT_TCP:
		if (!r_socket_connect_tcp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			core->num->value = 1;
			eprintf ("Error: Cannot connect to '%s' (%s)\n", host, port);
			r_socket_free (fd);
			return;
		}
		core->num->value = 0;
		eprintf ("Connected to: %s at port %s\n", host, port);
		break;
	case RTR_PROT_UDP:
		if (!r_socket_connect_udp (fd, host, port, timeout)) { //TODO: Use rap.ssl
			core->num->value = 1;
			eprintf ("Error: Cannot connect to '%s' (%s)\n", host, port);
			r_socket_free (fd);
			return;
		}
		core->num->value = 0;
		eprintf ("Connected to: %s at port %s\n", host, port);
		break;
	}
	ret = core->num->value;
	for (i = 0; i < RTR_MAX_HOSTS; i++) {
		if (rtr_host[i].fd) {
			continue;
		}
		rtr_host[i].proto = proto;
		strncpy (rtr_host[i].host, host, sizeof (rtr_host[i].proto)-1);
		rtr_host[i].port = r_num_get (core->num, port);
		strncpy (rtr_host[i].file, file, sizeof (rtr_host[i].file)-1);
		rtr_host[i].fd = fd;
		rtr_n = i;
		break;
	}
	core->num->value = ret;
	// double free wtf is freed this here? r_socket_free(fd);
	//r_core_rtr_list (core);
}

R_API void r_core_rtr_remove(RCore *core, const char *input) {
	int fd, i;

	if (IS_DIGIT(input[0])) {
		fd = r_num_math (core->num, input);
		for (i = 0; i < RTR_MAX_HOSTS; i++)
			if (rtr_host[i].fd && rtr_host[i].fd->fd == fd) {
				r_socket_free (rtr_host[i].fd);
				rtr_host[i].fd = NULL;
				if (rtr_n == i) {
					for (rtr_n = 0; !rtr_host[rtr_n].fd \
						&& rtr_n < RTR_MAX_HOSTS - 1; rtr_n++);
				}
				break;
		}
	} else {
		for (i = 0; i < RTR_MAX_HOSTS; i++) {
			if (rtr_host[i].fd) {
				r_socket_free (rtr_host[i].fd);
				rtr_host[i].fd = NULL;
			}
		}
		memset (rtr_host, '\0', RTR_MAX_HOSTS * sizeof (RCoreRtrHost));
		rtr_n = 0;
	}
}

R_API void r_core_rtr_session(RCore *core, const char *input) {
	char prompt[64], buf[1024];
	int fd;

	prompt[0] = 0;
	if (IS_DIGIT(input[0])) {
		fd = r_num_math (core->num, input);
		for (rtr_n = 0; rtr_host[rtr_n].fd \
			&& rtr_host[rtr_n].fd->fd != fd \
			&& rtr_n < RTR_MAX_HOSTS - 1; rtr_n++);
	}

	for (;;) {
		if (rtr_host[rtr_n].fd)
			snprintf (prompt, sizeof (prompt),
				"fd:%d> ", rtr_host[rtr_n].fd->fd);
		free (r_line_singleton ()->prompt);
		r_line_singleton ()->prompt = strdup (prompt);
		if (r_cons_fgets (buf, sizeof (buf), 0, NULL) < 1) {
			break;
		}
		if (!*buf || *buf == 'q') {
			break;
		}
		if (*buf == 'V') {
			eprintf ("Visual mode not supported\n");
			continue;
		}
		r_core_rtr_cmd (core, buf);
		r_cons_flush ();
	}
}

static ut8 *r_rap_packet(ut8 type, ut32 len) {
	ut8 *buf = malloc (len + 5);
	if (buf) {
		buf[0] = type;
		r_write_be32 (buf + 1, len);
	}
	return buf;
}

static void r_rap_packet_fill(ut8 *buf, const ut8* src, int len) {
	if (buf && src && len > 0) {
		ut32 curlen = r_read_be32 (buf + 1);
		memcpy (buf + 5, src, R_MIN (curlen, len));
	}
}

static void r_core_rtr_rap_run(RCore *core, const char *input) {
	/* ouch, this hurts a bit, isnt? */
	r_core_cmdf (core, "o rap://%s", input);
}

static int r_core_rtr_rap_thread (RThread *th) {
	if (!th) {
		return false;
	}
	RapThread *rt = th->user;
	if (!rt || !rt->core) {
		return false;
	}
	r_core_rtr_rap_run (rt->core, rt->input);
	return true;
}

R_API void r_core_rtr_cmd(RCore *core, const char *input) {
	char bufw[1024], bufr[8], *cmd_output = NULL;
	const char *cmd = NULL;
	unsigned int cmd_len;
	int i, fd = atoi (input);

	// "=:"
	if (*input == ':' && !strchr (input + 1, ':')) {
		r_core_rtr_rap_run (core, input);
		return;
	}

	if (*input == '&') { // "=h&"
		if (rapthread) {
			eprintf ("RAP Thread is already running\n");
			eprintf ("This is experimental and probably buggy. Use at your own risk\n");
		} else {
			RapThread rt = { core, input + 1 };
			rapthread = r_th_new (r_core_rtr_rap_thread, &rt, false);
			r_th_start (rapthread, true);
			eprintf ("Background rap server started.\n");
		}
		return;
	}

	if (fd != 0) {
		RSocket *fh = rtr_host[rtr_n].fd;
		for (rtr_n = 0; fh && fh->fd != fd && rtr_n < RTR_MAX_HOSTS - 1; rtr_n++) {
			/* do nothing */
		}
		if (!(cmd = strchr (input, ' '))) {
			eprintf ("Error\n");
			return;
		}
	} else {
		cmd = input;
	}

	if (!rtr_host[rtr_n].fd){
		eprintf ("Error: Unknown host\n");
		core->num->value = 1; // fail
		return;
	}

	if (rtr_host[rtr_n].proto != RTR_PROT_RAP) {
		eprintf ("Error: Not a rap:// host\n");
		return;
	}

	core->num->value = 0; // that's fine
	while (IS_WHITESPACE (*cmd)) {
		cmd++;
	}
	RSocket *fh = rtr_host[rtr_n].fd;
	if (!strlen (cmd)) {
		// just check if we can connect
		r_socket_close (fh);
		return;
	}
	/* send request */
	bufw[0] = RAP_RMT_CMD;
	i = strlen (cmd) + 1;
	r_write_be32 (bufw + 1, i);
	memcpy (bufw + 5, cmd, i);
	r_socket_write (fh, bufw, 5 + i);
	/* read response */
	r_socket_read (fh, (ut8*)bufr, 5);
	if (bufr[0] == (char)(RAP_RMT_CMD)) {
		cmd_len = r_read_at_be32 (bufr, 1);
		char *rcmd = calloc (1, cmd_len + 1);
		if (rcmd) {
			r_socket_read (fh, (ut8*)rcmd, cmd_len);
			char *res = r_core_cmd_str (core, rcmd);
			if (res) {
				int res_len = strlen (res) + 1;
				ut8 *pkt = r_rap_packet ((RAP_RMT_CMD | RAP_RMT_REPLY), res_len);
				r_rap_packet_fill (pkt, (const ut8*)res, res_len);
				r_socket_write (fh, pkt, 5 + res_len);
				free (res);
				free (pkt);
			}
			free (rcmd);
		}
		/* read response */
		r_socket_read (fh, (ut8*)bufr, 5);
	}

	if (bufr[0] != (char)(RAP_RMT_CMD | RTR_RAP_REPLY)) {
		eprintf ("Error: Wrong reply\n");
		return;
	}
	cmd_len = r_read_at_be32 (bufr, 1);
	if (cmd_len < 1 || cmd_len > 16384) {
		eprintf ("Error: cmd_len is wrong\n");
		return;
	}
	cmd_output = calloc (1, cmd_len + 1);
	if (!cmd_output) {
		eprintf ("Error: Allocating cmd output\n");
		return;
	}
	r_socket_read (fh, (ut8*)cmd_output, cmd_len);
	//ensure the termination
	cmd_output[cmd_len] = 0;
	r_cons_println (cmd_output);
	free ((void *)cmd_output);
}

// TODO: support len for binary data?
R_API char *r_core_rtr_cmds_query (RCore *core, const char *host, const char *port, const char *cmd) {
	RSocket *s = r_socket_new (0);
	const int timeout = 0;
	char *rbuf = NULL;
	int retries = 6;
	ut8 buf[1024];

	for (; retries > 0; r_sys_usleep (10 * 1000)) {
		if (r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, timeout)) {
			break;
		}
		retries--;
	}
	if (retries > 0) {
		rbuf = strdup ("");
		r_socket_write (s, (void*)cmd, strlen (cmd));
		//r_socket_write (s, "px\n", 3);
		for (;;) {
			int ret = r_socket_read (s, buf, sizeof (buf));
			if (ret < 1) break;
			buf[ret] = 0;
			rbuf = r_str_append (rbuf, (const char *)buf);
		}
	} else {
		eprintf ("Cannot connect\n");
	}
	r_socket_free (s);
	return rbuf;
}

R_API int r_core_rtr_cmds (RCore *core, const char *port) {
	unsigned char buf[4097];
	RSocket *ch = NULL;
	RSocket *s;
	int i, ret;
	char *str;

	if (!port || port[0] == '?') {
		r_cons_printf ("Usage: .:[tcp-port]    run r2 commands for clients\n");
		return false;
	}

	s = r_socket_new (0);
	if (!r_socket_listen (s, port, NULL)) {
		eprintf ("Error listening on port %s\n", port);
		r_socket_free (s);
		return false;
	}

	eprintf ("Listening for commands on port %s\n", port);
	listenport = port;
	r_cons_break_push ((RConsBreak)r_core_rtr_http_stop, core);
	for (;;) {
		if (r_cons_is_breaked ()) {
			break;
		}
		ch = r_socket_accept (s);
		buf[0] = 0;
		ret = r_socket_read (ch, buf, sizeof (buf) - 1);
		if (ret > 0) {
			buf[ret] = 0;
			for (i = 0; buf[i]; i++) {
				if (buf[i] == '\n') {
					buf[i] = buf[i + 1]? ';': '\0';
				}
			}
			if (!r_config_get_i (core->config, "scr.prompt") &&
			    !strcmp ((char *)buf, "q!")) {
				r_socket_close (ch);
				break;
			}
			str = r_core_cmd_str (core, (const char *)buf);
			if (str && *str)  {
				r_socket_write (ch, str, strlen (str));
			} else {
				r_socket_write (ch, "\n", 1);
			}
			free (str);
		}
		r_socket_close (ch);
		ch = NULL;
	}
	r_cons_break_pop ();
	r_socket_free (s);
	r_socket_free (ch);
	return 0;
}
