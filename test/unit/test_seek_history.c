#include <r_core.h>
#include "minunit.h"

bool test_seek_history_prompt_wrap(void) {
	RCore *core = r_core_new ();
	RLine *line = core->cons->line;
	line->user = core;
	int i;
	for (i = 0; i < R_IO_UNDOS + 2; i++) {
		r_io_sundo_push (core->io, i, 0);
	}
	line->offset_hist_index = 0;
	for (i = R_IO_UNDOS + 1; i >= 3; i--) {
		mu_assert_true (r_line_hist_offset_up (line), "older seek exists");
		mu_assert_eq (r_num_get (NULL, line->state.buffer.data), i, "wrapped older address");
	}
	mu_assert_false (r_line_hist_offset_up (line), "oldest seek reached");
	for (i = 4; i <= R_IO_UNDOS + 1; i++) {
		mu_assert_true (r_line_hist_offset_down (line), "newer seek exists");
		mu_assert_eq (r_num_get (NULL, line->state.buffer.data), i, "wrapped newer address");
	}
	mu_assert_false (r_line_hist_offset_down (line), "end of prompt history");
	mu_assert_streq (line->state.buffer.data, "", "clear prompt at end");
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_seek_history_prompt_wrap);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
