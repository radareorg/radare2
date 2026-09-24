#include <r_debug.h>
#include <gdbclient/xml.h>
#include "minunit.h"

#if R2__UNIX__ && !__wasi__
#include <sys/socket.h>
#include <unistd.h>

static bool send_response(int fd, const char *payload) {
	ut8 checksum = 0;
	const char *p;
	for (p = payload; *p; p++) {
		checksum += (ut8)*p;
	}
	char *packet = r_str_newf ("$%s#%02x", payload, checksum);
	size_t len = strlen (packet);
	bool ret = write (fd, packet, len) == len;
	free (packet);
	return ret;
}

static bool test_gdb_processes_xml(void) {
	const char *tails[] = {
		"",
		"<item>",
		"<item></item>",
		"<item><column name=\"pid\">2</item>",
		"<item><column name=\"pid\">123456</column></item>",
		"<item><column name=\"pid\">2</column></item>",
		"<item><column name=\"pid\">2</column><column name=\"command\">bad</item>"
	};
	RCons *cons = r_cons_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tails); i++) {
		int fds[2];
		mu_assert_eq (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), 0, "create GDB socket pair");
		libgdbr_t g;
		mu_assert_eq (gdbr_init (&g, false), 0, "initialize GDB client");
		g.sock->fd = fds[0];
		g.stub_features.qXfer_features_read = true;
		g.stub_features.pkt_sz = 4096;
		g.num_retries = 1;
		char *response = r_str_newf (
			"l<osdata type=\"processes\">"
			"<item><column name=\"pid\">1234</column>"
			"<column name=\"command\">/bin/test</column></item>%s</osdata>", tails[i]);
		// Queue the XML reply and the failed /proc/1234/status open reply.
		mu_assert_true (send_response (fds[1], response), "send process XML");
		free (response);
		mu_assert_true (send_response (fds[1], "F-1,2"), "send procfs open failure");
		RList *list = r_list_newf ((RListFree)r_debug_pid_free);
		int ret = gdbr_read_processes_xml (&g, 0, list);
		gdbr_cleanup (&g);
		close (fds[1]);
		mu_assert_eq (ret, i? -1: 0, "reject malformed process XML");
		mu_assert_eq (r_list_length (list), 1, "retain the valid process entry");
		RDebugPid *process = r_list_first (list);
		mu_assert_notnull (process, "valid process entry");
		mu_assert_eq (process->pid, 1234, "retained process PID");
		mu_assert_streq (process->path, "/bin/test", "retained process command");
		r_list_free (list);
	}
	r_cons_free (cons);
	mu_end;
}
#endif

int main(int argc, char **argv) {
#if R2__UNIX__ && !__wasi__
	mu_run_test (test_gdb_processes_xml);
#endif
	return tests_passed != tests_run;
}
