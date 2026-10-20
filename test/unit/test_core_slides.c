#include <r_core.h>
#include "minunit.h"

static void slides_resize(void *user) {
}

static int slides_prompt_eof(RCons *cons, char *buf, int len) {
	return -1;
}

bool test_slides_load_failure(void) {
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "scr.interactive", true);
	r_core_visual_slides (core, "");
	mu_assert_true (r_config_get_b (core->config, "scr.interactive"), "empty filename preserves interactive mode");
	r_core_visual_slides (core, "/nonexistent/r2-slides/deck.r2.md");
	mu_assert_true (r_config_get_b (core->config, "scr.interactive"), "failed load preserves interactive mode");
	r_core_free (core);
	mu_end;
}

bool test_slides_cleanup(void) {
	char *filename = NULL;
	int fd = r_file_mkstemp ("r2-slides", &filename);
	mu_assert ("temporary slide deck", fd >= 0);
	close (fd);
	mu_assert_true (r_file_dump (filename, (const ut8 *)"# Slide\n--label:start\n--gotokey:x:start\nabcdef\n", -1, false), "write slide deck");
	const char *keys[] = { "hhhllllllq", ":q" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (keys); i++) {
		RCore *core = r_core_new ();
		RCons *cons = core->cons;
		r_config_set_b (core->config, "scr.interactive", true);
		cons->force_columns = 40;
		cons->force_rows = 10;
		cons->context->noflush = true;
		cons->vtmode = 2;
		r_cons_enable_mouse (cons, i == 0);
		cons->event_resize = slides_resize;
		cons->event_data = core;
		cons->user_fgets = slides_prompt_eof;
		r_line_set_prompt (cons->line, "original> ");
		mu_assert_true (r_cons_readpush (cons, keys[i], strlen (keys[i])), "queue slide keys");
		r_core_visual_slides (core, filename);
		mu_assert_true (r_config_get_b (core->config, "scr.interactive"), "restore interactive mode after exit");
		mu_assert_eq (cons->mouse, i == 0, "restore saved mouse state");
		mu_assert_true (cons->event_resize == slides_resize, "restore resize callback");
		mu_assert_ptreq (cons->event_data, core, "restore resize data");
		mu_assert_streq (cons->line->state.prompt, "original> ", "restore command prompt");
		if (i == 0) {
			char *output = strdup (r_cons_get_buffer (cons, NULL));
			r_str_ansi_strip (output);
			mu_assert_notnull (strstr (output, "\nbcdef"), "moving left at zero does not delay scrolling right");
			free (output);
		} else {
			mu_assert_eq (cons->input_state.readbuffer_length, 1, "prompt EOF exits without reading another key");
		}
		r_cons_enable_mouse (cons, false);
		r_core_free (core);
	}
	r_file_rm (filename);
	free (filename);
	mu_end;
}

#if R2__UNIX__
bool test_slides_eof(void) {
	char *filename = NULL;
	int fd = r_file_mkstemp ("r2-slides-eof", &filename);
	mu_assert ("temporary empty slide deck", fd >= 0);
	close (fd);
	int input[2];
	mu_assert_eq (pipe (input), 0, "create EOF input");
	close (input[1]);
	int saved_stdin = dup (STDIN_FILENO);
	mu_assert ("save stdin", saved_stdin >= 0);
	mu_assert ("redirect stdin", dup2 (input[0], STDIN_FILENO) >= 0);
	close (input[0]);
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "scr.interactive", true);
	core->cons->context->noflush = true;
	core->cons->event_resize = slides_resize;
	core->cons->event_data = core;
	r_core_visual_slides (core, filename);
	dup2 (saved_stdin, STDIN_FILENO);
	close (saved_stdin);
	mu_assert_true (r_config_get_b (core->config, "scr.interactive"), "EOF restores interactive mode");
	mu_assert_true (core->cons->event_resize == slides_resize, "EOF restores resize callback");
	mu_assert_ptreq (core->cons->event_data, core, "EOF restores resize data");
	r_core_free (core);
	r_file_rm (filename);
	free (filename);
	mu_end;
}
#endif

int all_tests(void) {
	mu_run_test (test_slides_load_failure);
	mu_run_test (test_slides_cleanup);
#if R2__UNIX__
	mu_run_test (test_slides_eof);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
