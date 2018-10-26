/* radare2 - LGPL - Copyright 2013-2018 - pancake */

#include <getopt.c>
#include <r_core.h>
#include <signal.h>

#if __APPLE__ && (__arm__ || __arm64__ || __aarch64__)
#define USE_IOS_JETSAM 1

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
extern int memorystatus_control(uint32_t command, pid_t pid, uint32_t flags, void *buffer, size_t buffersize);

#else
#define USE_IOS_JETSAM 0
#endif

#if __WINDOWS__
int main() {
	eprintf ("r2agent: Not yet implemented for this platform.\n");
	return 1;
}
#else
#include "index.h"

static int usage (int v) {
	printf ("Usage: r2agent [-adhs] [-p port]\n"
	"  -a        listen for everyone (localhost by default)\n"
	"  -d        run in daemon mode (background)\n"
	"  -h        show this help message\n"
	"  -s        run in sandbox mode\n"
	"  -p [port] specify listening port (defaults to 8080)\n");
	return !v;
}

static int showversion() {
	printf (R2_VERSION"\n");
	return 0;
}

int main(int argc, char **argv) {
	RSocket *s;
	RSocketHTTPRequest *rs;
	int c, timeout = 3;
	int dodaemon = 0;
	int dosandbox = 0;
	bool listenlocal = true;
	const char *port = "8080";

	while ((c = getopt (argc, argv, "adhp:sv")) != -1) {
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
		case 'p':
			port = optarg;
			break;
		default:
			return usage (0);
		}
	}
	if (optind != argc) {
		return usage (0);
	}

#if USE_IOS_JETSAM
	memorystatus_control (MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid (), 256, NULL, 0);
#endif
	if (dodaemon) {
#if LIBC_HAVE_FORK
		int pid = fork ();
		if (pid > 0) {
			printf ("%d\n", pid);
			return 0;
		}
#endif
	}
	s = r_socket_new (false);
	s->local = listenlocal;
	if (!r_socket_listen (s, port, NULL)) {
		eprintf ("Cannot listen on %d\n", s->port);
		r_socket_free (s);
		return 1;
	}

	eprintf ("http://localhost:%d/\n", s->port);
	if (dosandbox && !r_sandbox_enable (true)) {
		eprintf ("sandbox: Cannot be enabled.\n");
		return 1;
	}

	(void)r_cons_new ();

	while (!r_cons_singleton ()->context->breaked) {
		char *result_heap = NULL;
		const char *result = page_index;

		rs = r_socket_http_accept (s, 0, timeout);
		if (!rs) {
			continue;
		}
		if (!strcmp (rs->method, "GET")) {
			if (!strncmp (rs->path, "/proc/kill/", 11)) {
				// TODO: show page here?
				int pid = atoi (rs->path + 11);
				if (pid > 0) {
					kill (pid, SIGKILL);
				}
			} else if (!strncmp (rs->path, "/file/open/", 11)) {
				int pid;
				int session_port = 3000 + r_num_rand (1024);
				char *filename = rs->path + 11;
				char *escaped_filename = r_str_escape (filename);
				int escaped_len = strlen (escaped_filename);
				char *cmd;

				if (!(cmd = malloc (escaped_len + 40))) {
					perror ("malloc");
					return 1;
				}
				sprintf (cmd, "r2 -q %s-e http.port=%d -c=h \"%s\"",
					listenlocal? "": "-e http.bind=public ",
					session_port, escaped_filename);

				// TODO: use r_sys api to get pid when running in bg
				pid = r_sys_cmdbg (cmd);
				free (cmd);
				free (escaped_filename);
				result = result_heap = malloc (1024 + escaped_len);
				if (!result) {
					perror ("malloc");
					return 1;
				}
				sprintf (result_heap,
				"<html><body>"
				"<a href='/'>back</a><hr size=1/>"
				" - <a target='_blank' href='http://localhost:%d/'>open</a><br />"
				" - <a href='/proc/kill/%d'>kill</a><br />"
				"</body></html>", session_port, pid);
				eprintf ("\nchild pid %d\n\n", pid);
			}
		}
		r_socket_http_response (rs, 200, result, 0, NULL);
		r_socket_http_close (rs);
		free (result_heap);
		result_heap = NULL;
	}
	r_cons_free ();
	r_socket_free (s);
	return 0;
}
#endif
