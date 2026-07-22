#include <r_socket.h>
#include "minunit.h"

#if R2__UNIX__ && !__wasi__
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

static int all_tests(void) {
#if R2__UNIX__ && !__wasi__
	mu_run_test (test_r_socket_gets_buffer_limit);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
