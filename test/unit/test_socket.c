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

typedef struct {
	bool enabled;
	int calls;
} RapCommandState;

static bool rap_config_get_b(void *user, const char *key) {
	RapCommandState *state = user;
	return !strcmp (key, "rap.reverse") && state->enabled;
}

static char *rap_command(void *user, const char *cmd) {
	RapCommandState *state = user;
	state->calls++;
	return strdup (cmd);
}

static bool test_r_socket_rap_reverse(void) {
	int fds[2];
	mu_assert_eq (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), 0, "create socket pair");
	RSocket client = { .fd = fds[0] };
	RSocket server = { .fd = fds[1] };
	RapCommandState state = {0};
	RCoreBind bind = { .core = &state, .cmdStr = rap_command, .cfgGetB = rap_config_get_b };
	const ut8 packets[] = {
		RAP_PACKET_CMD, 0, 0, 0, 3, 'p', 'd', 0,
		RAP_PACKET_CMD, 0, 0, 0, 3, 'p', 'd', 0,
		RAP_PACKET_CMD | RAP_PACKET_REPLY, 0, 0, 0, 3, 'o', 'k', 0,
	};
	int mode;
	// Disabled, enabled, legacy binding, missing command callback, no binding.
	for (mode = 0; mode < 5; mode++) {
		state.enabled = mode == 1;
		state.calls = 0;
		bind.cfgGetB = mode == 2? NULL: rap_config_get_b;
		bind.cmdStr = mode == 3? NULL: rap_command;
		bool execute = mode == 1 || mode == 2;
		mu_assert_eq (r_socket_write (&server, packets, sizeof (packets)), sizeof (packets), "queue server commands and reply");
		char *res = r_socket_rap_client_command (&client, "", mode == 4? NULL: &bind);
		mu_assert_streq (res, "ok", "read final reply after reverse commands");
		free (res);
		mu_assert_eq (state.calls, execute? 2: 0, "honor reverse command setting");
		ut8 request[6];
		const ut8 expected_request[] = { RAP_PACKET_CMD, 0, 0, 0, 1, 0 };
		mu_assert_eq (r_socket_read_block (&server, request, sizeof (request)), sizeof (request), "read client request");
		mu_assert_memeq (request, expected_request, sizeof (request), "preserve request format");
		int i;
		for (i = 0; i < 2; i++) {
			ut8 header[5], response[3];
			int length = execute? 3: 1;
			mu_assert_true (r_socket_ready (&server, 1, 0) > 0, "reverse reply is available");
			mu_assert_eq (r_socket_read_block (&server, header, sizeof (header)), sizeof (header), "read reverse reply header");
			mu_assert_eq (header[0], RAP_PACKET_CMD | RAP_PACKET_REPLY, "reverse reply type");
			mu_assert_eq (r_read_be32 (header + 1), length, "reverse reply length");
			mu_assert_eq (r_socket_read_block (&server, response, length), length, "read reverse reply");
			mu_assert_memeq (response, execute? "pd": "", length, "disabled commands receive empty replies");
		}
	}
	close (fds[0]);
	close (fds[1]);
	mu_end;
}

static bool test_r_socket_rap_invalid_reply(void) {
	const struct {
		ut8 packet[8];
		int size;
	} cases[] = {
		{ {0}, 0 },
		{ {RAP_PACKET_CMD, 0, 0, 0}, 4 },
		{ {RAP_PACKET_READ | RAP_PACKET_REPLY, 0, 0, 0, 1, 0}, 6 },
		{ {RAP_PACKET_CMD, 0, 0, 0x40, 1}, 5 },
		{ {RAP_PACKET_CMD | RAP_PACKET_REPLY, 0, 0, 0x40, 1}, 5 },
		{ {RAP_PACKET_CMD | RAP_PACKET_REPLY, 0, 0, 0, 0}, 5 },
		{ {RAP_PACKET_CMD, 0, 0, 0, 3, 'p', 'd'}, 7 },
		{ {RAP_PACKET_CMD | RAP_PACKET_REPLY, 0, 0, 0, 3, 'o', 'k'}, 7 },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		int fds[2];
		mu_assert_eq (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), 0, "create socket pair");
		mu_assert_eq (write (fds[1], cases[i].packet, cases[i].size), cases[i].size, "queue invalid reply");
		shutdown (fds[1], SHUT_WR);
		RSocket client = { .fd = fds[0] };
		RapCommandState state = { .enabled = true };
		RCoreBind bind = { .core = &state, .cmdStr = rap_command, .cfgGetB = rap_config_get_b };
		char *res = r_socket_rap_client_command (&client, "", &bind);
		mu_assert_null (res, "reject malformed or truncated reply");
		mu_assert_eq (state.calls, 0, "never execute malformed commands");
		close (fds[0]);
		close (fds[1]);
	}
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
	mu_run_test (test_r_socket_rap_reverse);
	mu_run_test (test_r_socket_rap_invalid_reply);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
