// included from rtr.c

// return 1 on error
static int r_core_rtr_http_run(RCore *core, int launch, int browse, const char *path) {
	RConfig *newcfg = NULL, *origcfg = NULL;
	char headers[128] = R_EMPTY;
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
	const char *httpui = r_config_get (core->config, "http.ui");
	const char *httpauthfile = r_config_get (core->config, "http.authfile");
	char *pfile = NULL;

	if (!r_file_is_directory (root)) {
		if (!r_file_is_directory (homeroot)) {
			eprintf ("Cannot find http.root (%s) or http.homeroot (%s)\n", root, homeroot);
			return false;
		}
		return false;
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
		memset (&so, 0, sizeof (so));
	}
	if (!r_socket_listen (s, port, NULL)) {
		r_socket_free (s);
		eprintf ("Cannot listen on http.port\n");
		return 1;
	}

	if (browse == 'H') {
		const char *browser = r_config_get (core->config, "http.browser");
		r_sys_cmdf ("%s http://%s:%d/%s &",
			browser, host, atoi (port), path? path:"");
	}

	so.httpauth = r_config_get_i (core->config, "http.auth");

	if (so.httpauth) {
		if (!httpauthfile) {
			r_socket_free (s);
			eprintf ("No user list set for HTTP Authentication\n");
			return 1;
		}

		int sz;
		pfile = r_file_slurp (httpauthfile, &sz);

		if (pfile) {
			so.authtokens = r_str_split_list (pfile, "\n", 0);
		} else {
			r_socket_free (s);
			eprintf ("Empty list of HTTP users\n");
			return 1;
		}

		so.timeout = r_config_get_i (core->config, "http.timeout");
		so.accept_timeout = 1;
	}

	origcfg = core->config;
	newcfg = r_config_clone (core->config);
	core->config = newcfg;

	r_config_set (core->config, "asm.cmt.right", "false");
#if 0
	// WHY
	r_config_set (core->config, "scr.html", "true");
#endif
	r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
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
	if (!newblk) {
		r_socket_free (s);
		r_list_free (so.authtokens);
		free (pfile);
		return 1;
	}
	memcpy (newblk, core->block, core->blocksize);

	core->block = newblk;
// TODO: handle mutex lock/unlock here
	r_cons_break_push ((RConsBreak)r_core_rtr_http_stop, core);
	while (!r_cons_is_breaked ()) {
		/* restore environment */
		core->config = origcfg;
		r_config_set (origcfg, "scr.html", r_config_get (origcfg, "scr.html"));
		r_config_set_i (origcfg, "scr.color", r_config_get_i (origcfg, "scr.color"));
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

		void *bed = r_cons_sleep_begin ();
		rs = r_socket_http_accept (s, &so);
		r_cons_sleep_end (bed);

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
		r_config_set_i (newcfg, "scr.color", r_config_get_i (newcfg, "scr.color"));
		r_config_set (newcfg, "scr.interactive", r_config_get (newcfg, "scr.interactive"));

		if (!rs) {
			bed = r_cons_sleep_begin ();
			r_sys_usleep (100);
			r_cons_sleep_end (bed);
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

		if (!rs->auth) {
			r_socket_http_response (rs, 401, "", 0, NULL);
		}

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
					r_socket_http_response (rs, 403, "", 0, NULL);
				}
			} else if (!strncmp (rs->path, "/cmd/", 5)) {
				const bool colon = r_config_get_i (core->config, "http.colon");
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
							bed = r_cons_sleep_begin ();
							res = r_socket_http_get (bar, NULL, &len);
							r_cons_sleep_end (bed);
							if (res) {
								res[len] = 0;
								r_cons_println (res);
							}
							free (bar);
						} else {
							char *out, *cmd = rs->path + 5;
							r_str_uri_decode (cmd);
							r_config_set (core->config, "scr.interactive", "false");

							if (!r_sandbox_enable (0) &&
									(!strcmp (cmd, "=h*") ||
									 !strcmp (cmd, "=h--"))) {
								out = NULL;
							} else if (*cmd == ':') {
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
				char *path;
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
	r_cons_break_pop ();
	core->http_up = false;
	free (pfile);
	r_socket_free (s);
	r_config_free (newcfg);
	if (restoreSandbox) {
		r_sandbox_disable (true);
	}
	/* refresh settings - run callbacks */
	r_config_set (origcfg, "scr.html", r_config_get (origcfg, "scr.html"));
	r_config_set_i (origcfg, "scr.color", r_config_get_i (origcfg, "scr.color"));
	r_config_set (origcfg, "scr.interactive", r_config_get (origcfg, "scr.interactive"));
	return ret;
}

#if 0
static RThreadFunctionRet r_core_rtr_http_thread (RThread *th) {
	if (!th) {
		return false;
	}
	HttpThread *ht = th->user;
	if (!ht || !ht->core) {
		return false;
	}
	eprintf ("WARNING: Background webserver requires http.sandbox=false to run properly\n");
	int ret = r_core_rtr_http_run (ht->core, ht->launch, ht->browse, ht->path);
	R_FREE (ht->path);
	if (ret) {
		int p = r_config_get_i (ht->core->config, "http.port");
		r_config_set_i (ht->core->config, "http.port",  p + 1);
		if (p >= r_config_get_i (ht->core->config, "http.maxport")) {
			return R_TH_STOP;
		}
	}
	return ret ? R_TH_REPEAT : R_TH_STOP;
}
#endif

R_API int r_core_rtr_http(RCore *core, int launch, int browse, const char *path) {
	int ret;
	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: connect disabled\n");
		return 1;
	}
	if (launch == '-') {
		if (httpthread) {
			eprintf ("Press ^C to stop the webserver\n");
			r_th_kill_free (httpthread);
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
		while (*path == '&') {
			path++;
		}
		return r_core_cmdf (core, "& =h%s", path);
	}
#if 0
		if (httpthread) {
			eprintf ("HTTP Thread is already running\n");
			eprintf ("This is experimental and probably buggy. Use at your own risk\n");
			eprintf ("TODO: Use different eval environ for scr. for the web\n");
			eprintf ("TODO: Visual mode should be enabled on local\n");
		} else {
			const char *tpath = r_str_trim_head_ro (path + 1);
			//HttpThread ht = { core, launch, strdup (tpath) };
			HttpThread *ht = calloc (sizeof (HttpThread), 1);
			ht->core = core;
			ht->launch = launch;
			ht->browse = browse;
			ht->path = strdup (tpath);
			httpthread = r_th_new (r_core_rtr_http_thread, ht, false);
			if (httpthread) {
				r_th_setname (httpthread, "httpthread");
			}
			r_th_start (httpthread, true);
			eprintf ("Background http server started.\n");
		}
		return 0;
	}
#endif
	do {
		ret = r_core_rtr_http_run (core, launch, browse, path);
	} while (ret == -2);
	return ret;
}
