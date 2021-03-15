#include <r_util.h>
#include <r_socket.h>
#include "minunit.h"

static bool test_r2pipe(void) {
	R2Pipe *r = r2pipe_open ("radare2 -q0 -");
	mu_assert ("r2pipe can spawn", r);
	char *hello = r2pipe_cmd (r, "?e hello world");
	mu_assert_streq (hello, "hello world\n", "r2pipe hello world");
	free (hello);
	r2pipe_close (r);
	mu_end;
}

static bool test_r2pipe_404(void) {
	R2Pipe *r = r2pipe_open ("rodoro2 -q0 -");
	mu_assert ("r2pipe can spawn", !r);
	mu_end;
}

static int all_tests() {
	mu_run_test (test_r2pipe);
	mu_run_test (test_r2pipe_404);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
