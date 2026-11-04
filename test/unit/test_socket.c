#include <r_socket.h>
#include <r_util.h>
#include "minunit.h"

#if R2__UNIX__ && LIBC_HAVE_FORK
static void *sandbox_fork(void *user) {
	int *pid = user;
	*pid = r_sys_fork ();
	return NULL;
}

static void *sandbox_proc_open(void *user) {
	char *argv[] = { "sandbox-fork-test", NULL };
	return r_socket_proc_open (argv);
}

static bool test_r_socket_proc_sandbox(void) {
	int pid = 0;
	r_sandbox_run (R_SANDBOX_GRAIN_NONE, sandbox_fork, &pid);
	mu_assert_eq (pid, -1, "sandbox denial reports fork failure");
	RSocketProc *sp = r_sandbox_run (R_SANDBOX_GRAIN_NONE, sandbox_proc_open, NULL);
	mu_assert_null (sp, "sandbox refuses process creation without killing the caller");
	RSocketProc failed = { .pid = -1, .fd0 = { -1, -1 }, .fd1 = { -1, -1 } };
	mu_assert_eq (r_socket_proc_close (&failed), 0, "cleanup ignores failed fork PID");
	failed.pid = 0;
	mu_assert_eq (r_socket_proc_close (&failed), 0, "cleanup ignores unset PID");
	mu_end;
}
#endif

#if R2_NETWORK && R2__UNIX__ && !__wasi__
#include <sys/socket.h>
#include <unistd.h>

static bool test_r_socket_gets_buffer_limit(void) {
	int fds[2];
	mu_assert_eq (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), 0, "create socket pair");
	char input[1500];
	memset (input, 'A', sizeof (input));
	mu_assert_eq (write (fds[1], input, sizeof (input)), sizeof (input), "write input line");

	RSocket socket = { .fd = fds[0] };
	struct {
		char buf[1500];
		char guard;
	} output = { .guard = 'G' };
	int ret = r_socket_gets (&socket, output.buf, sizeof (output.buf));

	mu_assert_eq (ret, sizeof (output.buf) - 1, "reserve space for terminator");
	mu_assert_eq (output.buf[sizeof (output.buf) - 2], 'A', "read line contents");
	mu_assert_eq (output.buf[sizeof (output.buf) - 1], '\0', "terminate line");
	mu_assert_eq (output.guard, 'G', "preserve byte after output buffer");
	close (fds[0]);
	close (fds[1]);
	mu_end;
}
#endif

static bool test_r_socket_http_handle_upload(void) {
	const char *body = "--------------------------d74496d66958873e\r\n"
		"Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
		"Content-Type: text/plain\r\n\r\n"
		"HELLO\r\n"
		"--------------------------d74496d66958873e--\r\n";
	int len = 0;
	ut8 *data = r_socket_http_handle_upload ((const ut8 *)body, strlen (body), &len);
	mu_assert_notnull (data, "parse multipart upload");
	mu_assert_eq (len, 5, "upload length");
	mu_assert_memeq (data, (const ut8 *)"HELLO", 5, "upload contents");
	free (data);

	// trailer scan lands on the leading dashes
	const char *shortbody = "----------\nContent-Disposition: form-data; \n\n";
	data = r_socket_http_handle_upload ((const ut8 *)shortbody, strlen (shortbody), &len);
	mu_assert_null (data, "reject truncated multipart body");
	mu_assert_eq (len, 0, "no upload length");
	mu_end;
}

#if !R2_NETWORK
static bool test_network_disabled(void) {
	RSocket socket = { .fd = -1 };
	mu_assert_null (r_socket_new (false), "no socket allocation");
	mu_assert (!r_socket_connect (&socket, "localhost", "1", R_SOCKET_PROTO_TCP, 1), "no connect");
	mu_assert (!r_socket_listen (&socket, "1", NULL), "no listen");
	mu_assert (!r_socket_spawn (&socket, "false", 1), "no spawn");
	mu_assert_null (r_socket_accept (&socket), "no accept");
	mu_assert_eq (r_socket_read (&socket, NULL, 0), -1, "no read");
	mu_assert_eq (r_socket_write (&socket, NULL, 0), -1, "no write");
	r_sys_setenv ("R2_CURL", "1");
	int code = 1, length = 1;
	mu_assert_null (r_socket_http_get ("https://localhost/", NULL, &code, &length), "no HTTP GET");
	mu_assert_eq (code, 0, "clear status");
	mu_assert_eq (length, 0, "clear length");
	mu_assert_null (r_socket_http_post ("https://localhost/", NULL, "", NULL, NULL), "no HTTP POST");
	mu_assert (!r_socket_http_download ("https://localhost/", NULL, "unused"), "no download");
	r_sys_setenv ("R2_CURL", NULL);
	mu_end;
}
#endif

static int all_tests(void) {
	mu_run_test (test_r_socket_http_handle_upload);
#if R2__UNIX__ && LIBC_HAVE_FORK
	mu_run_test (test_r_socket_proc_sandbox);
#endif
#if !R2_NETWORK
	mu_run_test (test_network_disabled);
#endif
#if R2_NETWORK && R2__UNIX__ && !__wasi__
	mu_run_test (test_r_socket_gets_buffer_limit);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
