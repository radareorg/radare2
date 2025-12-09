// included from rtr.c

#define WEBCONFIG 1

typedef struct {
	const char *ext;
	const char *type;
} ExtAndType;

static const ExtAndType eat[] = {
	{ ".js", "application/javascript" },
	{ ".png", "application/png" },
	{ ".jpg", "image/jpg" },
	{ ".jpeg", "image/jpeg" },
	{ ".gif", "image/gif" },
	{ ".mp4", "video/mp4" },
	{ ".sh", "application/x-sh" },
	{ ".json", "application/json" },
	{ ".ttf", "font/ttf" },
	{ ".woff", "font/woff" },
	{ ".gz", "application/gzip" },
	{ ".zip", "application/zip" },
	{ ".pdf", "application/pdf" },
	{ ".txt", "text/plain" },
	{ ".md", "text/plain" },
	{ ".css", "text/css" },
	{ ".html", "text/html" },
	{NULL, NULL}
};

static char * R_NONNULL guess_filetype(const char *path) {
	const char *lastdot = r_str_lchr (path, '.');
	if (lastdot) {
		const ExtAndType *neat = eat;
		while (neat->ext) {
			if (!strcmp (neat->ext, lastdot)) {
				return r_str_newf ("Content-Type: %s\n", neat->type);
			}
			neat++;
		}
	}
	// binary by default, but never NULL
	return strdup ("Content-Type: application/octet-stream\n");
}

static char *cmdstr (RCore *core, const char *cmd) {
	char *out;
	RConsContext *ctx = core->cons->context;
	ctx->noflush = false;
	bool restoreSandbox = false;
	bool oldSandbox = r_config_get_b (core->config, "cfg.sandbox");
	if (r_config_get_b (core->config, "http.sandbox")) {
		//(void)r_config_get_i (core->config, "cfg.sandbox");
		r_config_set_b (core->config, "cfg.sandbox", true);
		restoreSandbox = true;
	}
#if WEBCONFIG
	const bool orig_scr_html = r_config_get_b (core->config, "scr.html");
	const int orig_scr_color = r_config_get_i (core->config, "scr.color");
	const bool orig_scr_interactive = r_config_get_b (core->config, "scr.interactive");
	r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
	r_config_set_b (core->config, "asm.bytes", false);
	r_config_set_b (core->config, "scr.interactive", false);
#endif
	out = r_core_cmd_str_pipe (core, cmd);
#if WEBCONFIG
	/* refresh settings - run callbacks */
	r_config_set_b (core->config, "scr.html", orig_scr_html);
	r_config_set_i (core->config, "scr.color", orig_scr_color);
	r_config_set_b (core->config, "scr.interactive", orig_scr_interactive);
#endif
	if (restoreSandbox) {
		if (!oldSandbox) {
			r_sandbox_disable (true);
		}
		r_config_set_b (core->config, "cfg.sandbox", oldSandbox);
	}
	return out;
}

// return 1 on error WHY
static int r_core_rtr_http_run(RCore *core, int launch, int browse, const char *path) {
	RConfig *newcfg = NULL, *origcfg = NULL;
	char headers[128] = {0};
	RSocketHTTPRequest *rs;
	char buf[32];
	int ret = 0;
	RSocket *s;
	RSocketHTTPOptions so;
	char *dir;
	int iport;
	const char *host = r_config_get (core->config, "http.bind");
	const char *index = r_config_get (core->config, "http.index");
	const char *root = r_config_get (core->config, "http.root");
	const char *homeroot = r_config_get (core->config, "http.homeroot");
	const char *port = r_config_get (core->config, "http.port");
	const char *allow = r_config_get (core->config, "http.allow");
	const char *basepath = r_config_get (core->config, "http.basepath");
	const char *httpui = r_config_get (core->config, "http.ui");
	const char *httpauthfile = r_config_get (core->config, "http.authfile");
	char *pfile = NULL;

	if (!r_file_is_directory (root)) {
		if (!r_file_is_directory (homeroot)) {
			R_LOG_ERROR ("Cannot find http.root or http.homeroot");
		}
	}
	if (!path) {
		return false;
	}
	char *arg = strchr (path, ' ');
	if (arg) {
		path = arg + 1;
	}
	if (path && atoi (path)) {
		port = path;
		r_config_set (core->config, "http.port", port);
		path = NULL;
	} else {
		if (core->io->desc && (!path || !*path)) {
			path = httpui;
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
		if (R_STR_ISNOTEMPTY (host)) {
			if (!strcmp (host, "::1")) {
				s->local = true;
			} else if (!strcmp (host, "localhost")) {
				s->local = true;
			} else if (!strcmp (host, "127.0.0.1")) {
				s->local = true;
			} else if (!strcmp (host, "local")) {
				s->local = true;
				r_config_set (core->config, "http.bind", "localhost");
			} else if (R_STR_ISEMPTY (host) || !strcmp (host, "public")) {
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
		memset (&so, 0, sizeof (so));
	}
	if (!r_socket_listen (s, port, NULL)) {
		r_socket_free (s);
		R_LOG_ERROR ("Cannot listen on http.port");
		return 1;
	}

	if (browse == 'H') {
		const char *browser = r_config_get (core->config, "http.browser");
		r_sys_cmdf ("%s http://%s:%d/%s &",
			browser, host, atoi (port), r_str_get (path));
	}

	so.httpauth = r_config_get_i (core->config, "http.auth");

	if (so.httpauth) {
		if (!httpauthfile) {
			r_socket_free (s);
			R_LOG_ERROR ("No user list set for HTTP Authentication");
			return 1;
		}
		pfile = r_file_slurp (httpauthfile, NULL);
		if (pfile) {
			so.authtokens = r_str_split_list (pfile, "\n", 0);
		} else {
			r_socket_free (s);
			R_LOG_ERROR ("Empty list of HTTP users");
			return 1;
		}
		so.timeout = r_config_get_i (core->config, "http.timeout");
		so.accept_timeout = 1;
	}

	origcfg = core->config;
	newcfg = r_config_clone (core->config);
	core->config = newcfg;
	eprintf ("Starting http server...\n");
	eprintf ("open http://%s:%s/\n", host, port);
	eprintf ("r2 -C http://%s:%s/cmd/\n", host, port);
	eprintf ("r2 r2web://%s:%s/cmd/\n", host, port);
	core->http_up = true;

	/* Register this HTTP session so r2agent -L can discover it */
	r_core_session_register (core, "r2web", atoi (port));

	ut64 newoff, origoff = core->addr;
	int newblksz, origblksz = core->blocksize;
	ut8 *newblk, *origblk = core->block;

	newblk = malloc (core->blocksize);
	if (!newblk) {
		r_socket_free (s);
		r_list_free (so.authtokens);
		free (pfile);
		return 1;
	}
	memcpy (newblk, core->block, core->blocksize);

	core->block = newblk;
// TODO: handle mutex lock/unlock here
	r_cons_break_push (core->cons, (RConsBreak)r_core_rtr_http_stop, core);
	while (!r_cons_is_breaked (core->cons) && core->http_up) {
		/* restore environment */
		core->config = origcfg;
#if WEBCONFIG
		r_config_set_b (origcfg, "scr.html", r_config_get_b (origcfg, "scr.html"));
		r_config_set_i (origcfg, "scr.color", r_config_get_i (origcfg, "scr.color"));
		r_config_set_b (origcfg, "scr.interactive", r_config_get_b (origcfg, "scr.interactive"));
#endif

		newoff = core->addr;
		newblk = core->block;
		newblksz = core->blocksize;

		core->addr = origoff;
		core->block = origblk;
		core->blocksize = origblksz;

		// backup and restore offset and blocksize
		/* this is blocking */
		activateDieTime (core);

		void *bed = r_cons_sleep_begin (core->cons);
		rs = r_socket_http_accept (s, &so);
		if (!core->http_up) {
			eprintf ("^C\n");
			break;
		}
		r_cons_sleep_end (core->cons, bed);
		if (!rs) {
			bed = r_cons_sleep_begin (core->cons);
			r_sys_usleep (100);
			r_cons_sleep_end (core->cons, bed);
			continue;
		}

		if (r_config_get_b (core->config, "http.channel")) {
			// start a new thread with
			// char *res = r_core_cmd_str_r (core, cmd);
			if (rs) {
				r_socket_http_response (rs, 200, "TODO", 0, headers);
				r_socket_http_close (rs);
			}
			continue;
		}

		if (*basepath && strcmp (basepath, "/")) {
			if (R_STR_ISEMPTY (rs->path) || !strcmp (rs->path, "/")) {
				char *res = r_str_newf ("Location: %s/\n%s", basepath, headers);
				r_socket_http_response (rs, 302, NULL, 0, res);
				r_socket_http_close (rs);
				continue;
			}
			if (r_str_startswith (rs->path, basepath)) {
				char *p = strdup (rs->path + strlen (basepath));
				free (rs->path);
				rs->path = p;
			}
		}

		origoff = core->addr;
		origblk = core->block;
		origblksz = core->blocksize;
		core->addr = newoff;
		core->block = newblk;
		core->blocksize = newblksz;
		/* set environment */
		// backup and restore offset and blocksize
		core->http_up = true;
		core->config = newcfg;
#if WEBCONFIG
		r_config_set_b (newcfg, "scr.html", r_config_get_b (newcfg, "scr.html"));
		r_config_set_i (newcfg, "scr.color", r_config_get_i (newcfg, "scr.color"));
		r_config_set_b (newcfg, "scr.interactive", r_config_get_b (newcfg, "scr.interactive"));
#endif
		if (R_STR_ISNOTEMPTY (allow)) {
			bool accepted = false;
			const char *allows_host;
			char *p, *peer = r_socket_tostring (rs->s);
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

		if (!rs->auth) {
			r_socket_http_response (rs, 401, "", 0, NULL);
		}
		if (r_config_get_b (core->config, "http.verbose")) {
			char *peer = r_socket_tostring (rs->s);
			http_logf (core, "[HTTP] %s %s\n", peer, rs->path);
			free (peer);
		}
		if (r_config_get_b (core->config, "http.dirlist")) {
			if (r_file_is_directory (rs->path)) {
				dir = strdup (rs->path);
			}
		}
		if (r_config_get_b (core->config, "http.cors")) {
			r_str_ncpy (headers,
				"Access-Control-Allow-Origin: *\n"
				"Access-Control-Allow-Headers: Origin, "
				"X-Requested-With, Content-Type, Accept\n",
				sizeof (headers));
		} else {
			headers[0] = 0;
		}
		if (!strcmp (rs->method, "OPTIONS")) {
			r_socket_http_response (rs, 200, "", 0, headers);
		} else if (!strcmp (rs->method, "GET")) {
			if (r_str_startswith (rs->path, "/up/")) {
				if (r_config_get_i (core->config, "http.upget")) {
					const char *uproot = r_config_get (core->config, "http.uproot");
					if (!rs->path[3] || (rs->path[3] == '/' && !rs->path[4])) {
						char *ptr = rtr_dir_files (uproot);
						r_socket_http_response (rs, 200, ptr, 0, headers);
						free (ptr);
					} else {
						char *path = r_file_root (uproot, rs->path + 4);
						if (r_file_exists (path)) {
							size_t sz = 0;
							char *f = r_file_slurp (path, &sz);
							if (f) {
								r_socket_http_response (rs, 200, f, (int)sz, headers);
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
					r_socket_http_response (rs, 403, "", 0, NULL);
				}
			} else if (r_str_startswith (rs->path, "/cmd/")) {
				const bool colon = r_config_get_b (core->config, "http.colon");
				if (colon && rs->path[5] != ':') {
					r_socket_http_response (rs, 403, "Permission denied", 0, headers);
				} else {
					char *cmd = rs->path + 5;
					const char *httpcmd = r_config_get (core->config, "http.uri");
					const char *httpref = r_config_get (core->config, "http.referer");
					const bool httpref_enabled = (httpref && *httpref);
					char *refstr = NULL;
					if (httpref_enabled) {
						if (strstr (httpref, "http")) {
							refstr = strdup (httpref);
						} else {
							refstr = r_str_newf ("http://localhost:%d/", atoi (port));
						}
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
							bed = r_cons_sleep_begin (core->cons);
							res = r_socket_http_get (bar, NULL, NULL, &len);
							r_cons_sleep_end (core->cons, bed);
							if (res) {
								res[len] = 0;
								r_cons_println (core->cons, res);
							}
							free (bar);
						} else {
							char *out, *cmd = rs->path + 5;
							r_str_uri_decode (cmd);
							// r_config_set_b (core->config, "scr.interactive", false);

							if (!r_sandbox_enable (0) &&
									(!strcmp (cmd, "=h*") ||
									 !strcmp (cmd, "=h--"))) {
								out = NULL;
							} else if (*cmd == ':') {
								/* commands in /cmd/: starting with : do not show any output */
								r_core_cmd0 (core, cmd + 1);
								out = NULL;
							} else {
								out = cmdstr (core, cmd);
							}

							if (out) {
								char *res = r_str_uri_encode (out);
								char *newheaders = r_str_newf ("Content-Type: text/plain\n%s", headers);
								r_socket_http_response (rs, 200, out, 0, newheaders);
								free (out);
								free (newheaders);
								free (res);
							} else {
								r_socket_http_response (rs, 200, "", 0, headers);
							}

							if (!r_sandbox_enable (0)) {
								if (!strcmp (cmd, "=h*")) {
									/* do stuff */
									r_socket_http_close (rs);
									free (dir);
									free (refstr);
									ret = -2;
									goto the_end;
								} else if (!strcmp (cmd, "=h--")) {
									r_socket_http_close (rs);
									free (dir);
									free (refstr);
									ret = 0;
									goto the_end;
								}
							}
						}
					}
					free (refstr);
				}
			} else {
				const char *root = r_config_get (core->config, "http.root");
				const char *homeroot = r_config_get (core->config, "http.homeroot");
				char *path = NULL;
				if (!strcmp (rs->path, "/")) {
					free (rs->path);
					if (*index == '/') {
						rs->path = strdup (index);
						path = strdup (index);
					} else {
						rs->path = r_str_newf ("/%s", index);
						path = r_file_root (root, rs->path);
					}
				} else if (homeroot && *homeroot) {
					char *homepath = r_file_abspath (homeroot);
					path = r_file_root (homepath, rs->path);
					free (homepath);
					if (!r_file_exists (path) && !r_file_is_directory (path)) {
						free (path);
						path = r_file_root (root, rs->path);
					}
				} else {
					if (*index == '/') {
						path = strdup (index);
					} else {
					}
				}
				// FD IS OK HERE
				if (rs->path [strlen (rs->path) - 1] == '/') {
					path = (*index == '/')? strdup (index): r_str_append (path, index);
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
					size_t sz = 0;
					char *f = r_file_slurp (path, &sz);
					if (f) {
						char *ct = guess_filetype (path);
						char *hdr = r_str_newf ("%s%s", ct, headers);
						r_socket_http_response (rs, 200, f, (int)sz, hdr);
						free (hdr);
						free (f);
						free (ct);
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
			if (r_str_startswith (rs->path, "/cmd")) {
				char *out = cmdstr (core, (const char *)rs->data);
				if (out) {
					char *res = r_str_uri_encode (out);
					char *newheaders = r_str_newf ("Content-Type: text/plain\n%s", headers);
					r_socket_http_response (rs, 200, out, 0, newheaders);
					// eprintf ("(%s)->(%s)\n", cmd, out);
					free (out);
					free (newheaders);
					free (res);
				} else {
					r_socket_http_response (rs, 200, "", 0, headers);
				}
			} else if (r_config_get_b (core->config, "http.upload")) {
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
							"<html><body><h2>uploaded %d byte(s). Thanks</h2>\n", retlen);
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
	r_cons_break_pop (core->cons);
	core->http_up = false;
	free (pfile);
	r_socket_free (s);
	r_config_free (newcfg);
	/* Unregister this HTTP session */
	r_core_session_unregister (core);
	return ret;
}

#define USE_HTTP_THREADS 1

#if USE_HTTP_THREADS
static RThreadFunctionRet r_core_rtr_http_thread(RThread *th) {
	if (!th) {
		return false;
	}
	HttpThread *ht = th->user;
	if (!ht || !ht->core) {
		return false;
	}
	if (r_config_get_b (ht->core->config, "http.sandbox")) {
		R_LOG_WARN ("Background webserver requires http.sandbox=false to run properly");
	}
	int ret = r_core_rtr_http_run (ht->core, ht->launch, ht->browse, ht->path);
	R_FREE (ht->path);
#if 0
	if (ret) {
		int p = r_config_get_i (ht->core->config, "http.port");
		r_config_set_i (ht->core->config, "http.port",  p + 1);
		if (p >= r_config_get_i (ht->core->config, "http.maxport")) {
			return R_TH_STOP;
		}
	}
#endif
	return ret ? R_TH_REPEAT : R_TH_STOP;
}
#endif

R_API int r_core_rtr_http(RCore *core, int launch, int browse, const char *path) {
	RCorePriv *priv = core->priv;
	int ret;
	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("sandbox: connect is not permitted");
		return 1;
	}
	if (launch == '-') {
		if (priv->httpthread) {
			R_LOG_INFO ("Press ^C to stop the webserver");
			r_th_kill_free (priv->httpthread);
			priv->httpthread = NULL;
		} else {
			R_LOG_ERROR ("No webserver running");
		}
		return 0;
	}
	if (core->http_up) {
		R_LOG_ERROR ("http server is already running");
		return 1;
	}
	if (launch == '&') {
#if USE_HTTP_THREADS
		if (priv->httpthread) {
			eprintf ("HTTP Thread is already running\n");
			eprintf ("This is experimental and probably buggy. Use at your own risk\n");
			R_LOG_TODO ("Use different eval environ for scr. for the web");
			R_LOG_TODO ("Visual mode should be enabled on local");
		} else {
			const char *tpath = r_str_trim_head_ro (path + 1);
			//HttpThread ht = { core, launch, strdup (tpath) };
			HttpThread *ht = calloc (sizeof (HttpThread), 1);
			ht->core = core;
			ht->launch = launch;
			ht->browse = browse;
			ht->path = strdup (tpath);
			priv->httpthread = r_th_new (r_core_rtr_http_thread, ht, false);
			if (priv->httpthread) {
				r_th_setname (priv->httpthread, "httpthread");
			}
			r_th_start (priv->httpthread);
			R_LOG_INFO ("Background http server started");
		}
		return 0;
#else
		while (*path == '&') {
			path++;
		}
		return r_core_cmdf (core, "& =h%s", path);
#endif
	}
	do {
		ret = r_core_rtr_http_run (core, launch, browse, path);
	} while (ret == -2);
	return ret;
}
