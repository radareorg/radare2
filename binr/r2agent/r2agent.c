/* radare2 - LGPL - Copyright 2013 - pancake */

#include <getopt.c>
#include <r_core.h>
#include <signal.h>


#if __WINDOWS__
int main() {
	eprintf ("r2agent: Not yet implemented for this platform.\n");
	return 1;
}
#else
#include "index.h"

static int usage (int v) {
	printf ("Usage: r2agent [-adhs] [-p port]\n"
	"  -a       listen for everyone (localhost by default)\n"
	"  -d       run in daemon mode (background)\n"
	"  -h       show this help message\n"
	"  -s       run in sandbox mode\n"
	"  -p 8392  specify listening port (defaults to 8080)\n");
	return !!!v;
}

int main(int argc, char **argv) {
	RSocket *s;
	RSocketHTTPRequest *rs;
	int c, timeout = 3;
	int dodaemon = 0;
	int dosandbox = 0;
	int listenlocal = 1; 
	const char *port = "8080";

	// TODO: add flag to specify if listen in local or 0.0.0.0
	while ((c = getopt (argc, argv, "ahp:ds")) != -1) {
		switch (c) {
		case 'a':
			listenlocal = 0;
			break;
		case 's':
			dosandbox = 1;
			break;
		case 'd':
			dodaemon = 1;
			break;
		case 'h':
			return usage (1);
		case 'p':
			port = optarg;
			break;
		}
	}
	if (optind != argc)
		return usage (1);
	if (dodaemon) {
		int pid = fork ();
		if (pid >0) {
			printf ("%d\n", pid);
			return 0;
		}
	}
	s = r_socket_new (R_FALSE);
	s->local = listenlocal;
	if (!r_socket_listen (s, port, NULL)) {
		eprintf ("Cannot listen on %d\n", s->port);
		r_socket_free (s);
		return 1;
	}
	
	eprintf ("http://localhost:%d/\n", s->port);
	if (dosandbox && !r_sandbox_enable (R_TRUE)) {
		eprintf ("sandbox: Cannot be enabled.\n");
		return 1;
	}
	while (!r_cons_singleton ()->breaked) {
		char *result_heap = NULL;
		const char *result = page_index;

		rs = r_socket_http_accept (s, timeout);
		if (!rs) continue;
		if (!strcmp (rs->method, "GET")) {
			if (!strncmp (rs->path, "/proc/kill/", 11)) {
				// TODO: show page here?
				int pid = atoi (rs->path+11);
				if (pid>0) kill (pid, 9);
			} else
			if (!strncmp (rs->path, "/file/open/", 11)) {
				int pid;
				int session_port = 3000 + r_num_rand (1024);
				char *filename = rs->path +11;
				int filename_len = strlen (filename);
				char *cmd;

				if (!(cmd = malloc (filename_len+40))) {
					perror ("malloc");
					return 1;
				}
				sprintf (cmd, "r2 -q -e http.port=%d -c=h \"%s\"",
					session_port, filename);

				// TODO: use r_sys api to get pid when running in bg
				pid = r_sys_cmdbg (cmd);
				free (cmd);
				result = result_heap = malloc (1024+filename_len);
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
	}
	r_socket_free (s);
	return 0;
}
#endif
