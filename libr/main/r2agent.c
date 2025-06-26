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

static int usage(int v) {
	printf ("Usage: r2agent [-adhs] [-p port]\n"
	"  -a        listen for everyone (localhost by default)\n"
	"  -d        run in daemon mode (background)\n"
	"  -h        show this help message\n"
	"  -s        run in sandbox mode\n"
	"  -u        enable http authorization access\n"
	"  -t        user:password authentication file\n"
	"  -p [port] specify listening port (defaults to 8080)\n");
	return !v;
}

static int showversion(void) {
	return r_main_version_print ("r2agent", 0);
}

R_API int r_main_r2agent(int argc, const char **argv) {
	RSocket *s;
	RCons *cons = NULL;
	RSocketHTTPOptions so;
	int c;
	int dodaemon = 0;
	int dosandbox = 0;
	bool listenlocal = true;
	const char *port = "8080";
	const char *httpauthfile = NULL;
	char *pfile = NULL;
	memset (&so, 0, sizeof (so));

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "adhup:t:sv");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			listenlocal = false;
			break;
		case 's':
			dosandbox = 1;
			break;
		case 'd':
			dodaemon = 1;
			break;
		case 'h':
			return usage (1);
		case 'v':
			return showversion ();
		case 'u':
			so.httpauth = true;
			break;
		case 't':
			httpauthfile = opt.arg;
			break;
		case 'p':
			port = opt.arg;
			break;
		default:
			return usage (0);
		}
	}
	if (opt.ind != argc) {
		return usage (0);
	}

	so.accept_timeout = 0;
	so.timeout = 3;

	if (so.httpauth) {
		if (!httpauthfile) {
			R_LOG_ERROR ("No authentication user list set");
			return usage (0);
		}

		size_t sz;
		pfile = r_file_slurp (httpauthfile, &sz);
		if (pfile) {
			so.authtokens = r_str_split_list (pfile, "\n", 0);
		} else {
			R_LOG_ERROR ("Empty list of HTTP users");
			return usage (0);
		}
	}
#if USE_IOS_JETSAM
	memorystatus_control (MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, r_sys_getpid (), 256, NULL, 0);
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
	if (dosandbox && !r_sandbox_enable (true)) {
		R_LOG_ERROR ("Cannot enable the sandbox");
		free (pfile);
		r_list_free (so.authtokens);
		r_socket_free (s);
		return 1;
	}

	cons = r_cons_new ();

	while (!r_cons_singleton ()->context->breaked) {
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
				// TODO: show page here?
				int pid = atoi (rs->path + strlen ("/proc/kill/"));
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
					listenlocal? "": "-e http.bind=public ",
					session_port, escaped_filename);

				// TODO: use r_sys api to get pid when running in bg
				int pid = r_sys_cmdbg (cmd);
				free (cmd);
				free (escaped_filename);

				res = r_str_newf (
				"<html><body>"
				"<a href='/'>back</a><hr size=1/>"
				" - <a target='_blank' href='http://localhost:%d/'>open</a><br />"
				" - <a href='/proc/kill/%d'>kill</a><br />"
				"</body></html>", session_port, pid);
				R_LOG_DEBUG ("child pid %d", pid);
			}
		}
		r_socket_http_response (rs, 200, res? res: page_index, 0, NULL);
		r_socket_http_close (rs);
		R_FREE (res);
	}
	r_cons_free2 (cons);
	free (pfile);
	r_list_free (so.authtokens);
	r_socket_free (s);
	return 0;
}
