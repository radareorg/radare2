/* radare2 - LGPL - Copyright 2013-2025 - pancake */

#include "index.h"
#include <r_main.h>
#include <r_core.h>

#if __APPLE__ && (__arm__ || __arm64__ || __aarch64__)
#define USE_IOS_JETSAM 1

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
extern int memorystatus_control(uint32_t command, pid_t pid, uint32_t flags, void *buffer, size_t buffersize);

#else
#define USE_IOS_JETSAM 0
#endif

static int usage(bool v) {
	printf("Usage: r2agent [-adhsLjv] [-p port]\n"
	       "  -a        listen for everyone (localhost by default)\n"
	       "  -d        run in daemon mode (background)\n"
	       "  -h        show this help message\n"
	       "  -s        run in sandbox mode\n"
	       "  -u        enable http authorization access\n"
	       "  -t        user:password authentication file\n"
	       "  -p [port] specify listening port (defaults to 8080)\n"
	       "  -L        list currently loaded r2 sessions and exit\n"
	       "  -v        show r2 version information and exit\n"
	       "  -j        output JSON when used with -v or -L\n");
	return !v;
}

R_API int r_main_r2agent(int argc, const char **argv) {
	RSocket *s;
	RCons *cons = NULL;
	RSocketHTTPOptions so = {0};
	int c;
	bool dodaemon = false;
	bool dosandbox = false;
	bool listenlocal = true;
	const char *port = "8080";
	const char *httpauthfile = NULL;
	char *pfile = NULL;

	RGetopt opt;
	bool list_sessions = false;
	bool list_json = false;
	bool show_version = false;
	r_getopt_init (&opt, argc, argv, "adhup:t:svLj");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			listenlocal = false;
			break;
		case 's':
			dosandbox = true;
			break;
		case 'd':
			dodaemon = true;
			break;
		case 'h':
			return usage(true);
		case 'v':
			show_version = true;
			break;
		case 'u':
			so.httpauth = true;
			break;
		case 't':
			httpauthfile = opt.arg;
			break;
		case 'p':
			port = opt.arg;
			break;
		case 'L':
			list_sessions = true;
			break;
		case 'j':
			list_json = true;
			break;
		default:
			return usage(false);
		}
	}
	if (opt.ind != argc) {
		return usage (false);
	}

	if (show_version) {
		int mode = list_json ? 'j' : 0;
		return r_main_version_print ("r2agent", mode);
	}

	if (list_sessions) {
		RCore *core = r_core_new ();
		if (!core) {
			R_LOG_ERROR ("Unable to create RCore instance");
			return 1;
		}
		const char *cmd = list_json ? "=lj" : "=l";
		char *out = r_core_cmd_str (core, cmd);
		if (out) {
			printf ("%s\n", out);
			free (out);
		}
		r_core_free (core);
		return 0;
	}

	so.accept_timeout = 0;
	so.timeout = 3;

	if (so.httpauth) {
		if (!httpauthfile) {
			R_LOG_ERROR ("No authentication user list set");
			return usage (false);
		}

		size_t sz;
		pfile = r_file_slurp(httpauthfile, &sz);
		if (pfile) {
			so.authtokens = r_str_split_list(pfile, "\n", 0);
		} else {
			R_LOG_ERROR("Empty list of HTTP users");
			return usage(false);
		}
	}
#if USE_IOS_JETSAM
	memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, r_sys_getpid(), 256, NULL, 0);
#endif
	if (dodaemon) {
#if LIBC_HAVE_FORK
		int pid = r_sys_fork ();
		if (pid > 0) {
			printf ("%d\n", pid);
			return 0;
		}
#endif
	}

	s = r_socket_new (false);
	s->local = listenlocal;
	if (!r_socket_listen (s, port, NULL)) {
		R_LOG_ERROR ("Cannot listen on %d", s->port);
		r_socket_free (s);
		return 1;
	}

	R_LOG_INFO ("http://localhost:%d/", s->port);
	/* Create a pid file in tmpdir/r2/<pid>.pid so r2 (=l) can discover this server */
	char *pidfile = NULL;
	{
		char *tmpdir = r_file_tmpdir ();
		char *tmpdir_r2 = r_str_newf ("%s/r2", tmpdir);
		r_sys_mkdir (tmpdir_r2);
		int pid = r_sys_getpid ();
		char *fn = r_str_newf ("%s/%d.pid", tmpdir_r2, pid);
		char *suri = r_str_newf ("r2web://127.0.0.1:%d/cmd", s->port);
		if (r_file_dump (fn, (const ut8 *)suri, strlen(suri), false)) {
			pidfile = fn; /* keep ownership to remove on exit */
		} else {
			free (fn);
		}
		free (suri);
		free (tmpdir_r2);
		free (tmpdir);
	}

	if (dosandbox && !r_sandbox_enable (true)) {
		R_LOG_ERROR ("Cannot enable the sandbox");
		free (pfile);
		r_list_free (so.authtokens);
		r_socket_free (s);
		if (pidfile) {
			r_file_rm (pidfile);
			free (pidfile);
		}
		return 1;
	}

	cons = r_cons_new ();

	while (!r_cons_is_breaked (cons)) {
		char *res = NULL;
		RSocketHTTPRequest *rs = r_socket_http_accept (s, &so);
		if (!rs) {
			R_LOG_ERROR ("Failed to accept http client");
			continue;
		}
		if (!rs->auth) {
			r_socket_http_response (rs, 401, "", 0, NULL);
		}
		if (!strcmp (rs->method, "GET")) {
			if (r_str_startswith (rs->path, "/proc/kill/")) {
				/* TODO: show page here? */
				int pid = atoi (rs->path + strlen("/proc/kill/"));
				if (pid > 0) {
#if R2__WINDOWS__
					r_sandbox_kill (pid, 0);
#else
					r_sandbox_kill (pid, SIGKILL);
#endif
				}
			} else if (r_str_startswith (rs->path, "/file/open/")) {
				int session_port = 3000 + r_num_rand (1024);
				char *filename = rs->path + strlen ("/file/open/");
				char *escaped_filename = r_str_escape (filename);
				char *cmd = r_str_newf ("r2 -q %s-e http.port=%d -c=h \"%s\"",
					listenlocal ? "" : "-e http.bind=public ",
					session_port, escaped_filename);

				/* TODO: use r_sys api to get pid when running in bg */
				int pid = r_sys_cmdbg (cmd);
				free (cmd);
				free (escaped_filename);

				res = r_str_newf ("<html><body>"
						 "<a href='/'>back</a><hr size=1/>"
						 " - <a target='_blank' href='http://localhost:%d/'>open</a><br />"
						 " - <a href='/proc/kill/%d'>kill</a><br />"
						 "</body></html>",
					session_port, pid);
				R_LOG_DEBUG ("child pid %d", pid);
			}
		}
		r_socket_http_response (rs, 200, res ? res : page_index, 0, NULL);
		r_socket_http_close (rs);
		R_FREE (res);
	}

	r_cons_free2 (cons);
	free (pfile);
	r_list_free (so.authtokens);
	r_socket_free (s);
	/* Remove pid file created at startup so sessions list stays clean */
	if (pidfile) {
		r_file_rm (pidfile);
		free (pidfile);
	}
	return 0;
}
