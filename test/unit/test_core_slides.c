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
	const char *keys[] = { "hhhllllllq", ":q", "/q" };
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

bool test_slides_mouse_wheel(void) {
	char *filename = NULL;
	int fd = r_file_mkstemp ("r2-slides-wheel", &filename);
	mu_assert ("temporary slide deck", fd >= 0);
	close (fd);
	mu_assert_true (r_file_dump (filename, (const ut8 *)"# Slide\none\ntwo\nthree\nfour\nfive\nsix\n", -1, false), "write slide deck");
	RCore *core = r_core_new ();
	RCons *cons = core->cons;
	r_config_set_b (core->config, "scr.interactive", true);
	cons->force_columns = 40;
	cons->force_rows = 4;
	cons->context->noflush = true;
	char *down = r_str_repeat ("\x1b[<65;1;1M", 8);
	char *up = r_str_repeat ("\x1b[<64;1;1M", 8);
	char *keys = r_str_newf ("%s%sq", down, up);
	mu_assert_true (r_cons_readpush (cons, keys, strlen (keys)), "queue wheel events");
	free (keys);
	free (up);
	free (down);
	r_core_visual_slides (core, filename);
	char *output = strdup (r_cons_get_buffer (cons, NULL));
	r_str_ansi_strip (output);
	char *scrolled = strstr (output, "     five");
	mu_assert_notnull (scrolled, "wheel down reveals content below the screen");
	mu_assert_notnull (strstr (scrolled, "     one"), "wheel up returns to earlier slide content");
	mu_assert_false (cons->mouse, "restore disabled mouse reporting after wheel navigation");
	free (output);
	r_core_free (core);
	r_file_rm (filename);
	free (filename);
	mu_end;
}

bool test_slides_footer(void) {
	char *filename = NULL;
	int fd = r_file_mkstemp ("r2-slides-footer", &filename);
	mu_assert ("temporary slide deck", fd >= 0);
	close (fd);
	mu_assert_true (r_file_dump (filename, (const ut8 *)"# First\n--font=plain\n# Last\n--font=plain\n", -1, false), "write slide deck");
	const int widths[] = { 1, 6, 7, 8, 20, 80, 160 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (widths); i++) {
		RCore *core = r_core_new ();
		RCons *cons = core->cons;
		r_config_set_b (core->config, "scr.interactive", true);
		r_config_set_b (core->config, "scr.utf8", false);
		r_config_set_i (core->config, "scr.color", 0);
		cons->force_columns = widths[i];
		cons->force_rows = 10;
		cons->context->noflush = true;
		int flags = core->print->flags;
		mu_assert_true (r_cons_readpush (cons, "nNq", 3), "queue slide navigation");
		r_core_visual_slides (core, filename);
		mu_assert_eq (core->print->flags, flags, "footer preserves print flags");
		char *output = strdup (r_cons_get_buffer (cons, NULL));
		r_str_ansi_strip (output);
		if (widths[i] >= 7) {
			int cells = widths[i] - 6;
			char *filled = r_str_repeat ("#", cells);
			char *bar = r_str_newf ("[%s]2/2", filled);
			mu_assert_notnull (strstr (output, bar), "progress bar fills footer width beside counter");
			free (bar);
			free (filled);
		} else {
			mu_assert_null (strchr (output, '['), "omit progress bar when counter needs the space");
		}
		if (widths[i] >= 3) {
			mu_assert_notnull (strstr (output, "1/2"), "first slide counter remains visible");
			mu_assert_notnull (strstr (output, "2/2"), "last slide counter remains visible");
		}
		free (output);
		r_core_free (core);
	}
	r_file_rm (filename);
	free (filename);
	mu_end;
}

static int slides_count_transitions(const char *output, const char *sequence) {
	int count = 0;
	while ((output = strstr (output, sequence))) {
		count++;
		output += strlen (sequence);
	}
	return count;
}

bool test_slides_transitions(void) {
	char *filename = NULL;
	int fd = r_file_mkstemp ("r2-slides-transitions", &filename);
	mu_assert ("temporary slide deck", fd >= 0);
	close (fd);
	const char *deck = "# First\n--font=plain\n`f first_draws=first_draws+1`\none\n"
		"# Last\n--font=plain\n`f last_draws=last_draws+1`\ntwo\n";
	mu_assert_true (r_file_dump (filename, (const ut8 *)deck, -1, false), "write slide deck");
	int i;
	for (i = 0; i < 4; i++) {
		char *capture = NULL;
		fd = r_file_mkstemp ("r2-slides-output", &capture);
		mu_assert ("temporary output capture", fd >= 0);
		RCore *core = r_core_new ();
		RCons *cons = core->cons;
		r_config_set_b (core->config, "scr.interactive", true);
		r_config_set_b (core->config, "scr.demo", i != 0);
		r_config_set_i (core->config, "scr.color", 0);
		cons->force_columns = 40;
		cons->force_rows = i == 2? 3: 10;
		cons->vtmode = 2;
		r_flag_set (core->flags, "first_draws", 0, 1);
		r_flag_set (core->flags, "last_draws", 0, 1);
		int saved_fdout = cons->fdout;
		cons->fdout = fd;
		const char *keys = i == 3? "2nNq": "NnnNq";
		mu_assert_true (r_cons_readpush (cons, keys, strlen (keys)), "queue slide transitions and boundary navigation");
		r_core_visual_slides (core, filename);
		cons->fdout = saved_fdout;
		close (fd);
		char *output = r_file_slurp (capture, NULL);
		mu_assert_notnull (output, "read captured transitions");
		if (i == 1 || i == 3) {
			mu_assert_eq (slides_count_transitions (output, "\x1b[1;9r"), 2, "animate only actual slide changes");
			mu_assert_notnull (strstr (output, "\x1b[1S"), "forward navigation scrolls up");
			mu_assert_notnull (strstr (output, "\x1b[1T"), "backward navigation scrolls down");
			mu_assert_eq (slides_count_transitions (output, "\x1b[r"), 2, "restore scrolling region after each transition");
		} else {
			mu_assert_null (strstr (output, "\x1b[1;"), "disabled demo and small screens redraw without animation");
		}
		if (i != 3) {
			RFlagItem *first = r_flag_get (core->flags, "first_draws");
			RFlagItem *last = r_flag_get (core->flags, "last_draws");
			mu_assert_notnull (first, "first slide command executed");
			mu_assert_notnull (last, "last slide command executed");
			mu_assert_eq (first->addr, 3, "first slide commands execute once per refresh");
			mu_assert_eq (last->addr, 2, "last slide commands execute once per refresh");
		}
		free (output);
		r_core_free (core);
		r_file_rm (capture);
		free (capture);
	}
	r_file_rm (filename);
	free (filename);
	mu_end;
}

static const char *slides_search_word;
static RCore *slides_search_core;
static bool slides_search_highlight;
static bool slides_search_executed;

static int slides_search_prompt(RCons *cons, char *buf, int len) {
	slides_search_highlight |= !strcmp (r_config_get (slides_search_core->config, "scr.highlight"), slides_search_word);
	slides_search_executed |= r_flag_get (slides_search_core->flags, "indexed_offscreen") != NULL;
	return snprintf (buf, len, "%s", slides_search_word);
}

bool test_slides_search(void) {
	char *filename = NULL;
	int fd = r_file_mkstemp ("r2-slides-search", &filename);
	mu_assert ("temporary search deck", fd >= 0);
	close (fd);
	const char *deck = "# needle\n--font=plain\nneedle needle\n"
		"# Skip\n`f indexed_offscreen`\n"
		"# End\n```text\n# needle\n```\none\ntwo\nthree\nfour\nfive\nneedle\n";
	mu_assert_true (r_file_dump (filename, (const ut8 *)deck, -1, false), "write search deck");
	const char *words[] = { "needle", "absent", "", "needle", "needle" };
	const char *keys[] = { "/nnnnpNP n/q nq", "/npq nq", "/nq", "2/nnnpqq", "/\x12nqq" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (words); i++) {
		RCore *core = r_core_new ();
		RCons *cons = core->cons;
		r_config_set_b (core->config, "scr.interactive", true);
		r_config_set_i (core->config, "scr.color", 0);
		cons->force_columns = 40;
		cons->force_rows = 5;
		cons->context->noflush = true;
		cons->vtmode = 2;
		cons->user_fgets = slides_search_prompt;
		slides_search_word = words[i];
		slides_search_core = core;
		slides_search_highlight = false;
		slides_search_executed = false;
		r_line_set_prompt (cons->line, "original> ");
		mu_assert_true (r_cons_readpush (cons, keys[i], strlen (keys[i])), "queue search and navigation keys");
		r_core_visual_slides (core, filename);
		char *output = strdup (r_cons_get_buffer (cons, NULL));
		r_str_ansi_strip (output);
		if (i == 0) {
			const char *counters[] = { "[1/5] 1/3", "[2/5] 1/3", "[3/5] 1/3", "[4/5] 3/3", "[5/5] 3/3",
				"[4/5] 3/3", "[3/5] 1/3", "[4/5] 3/3", "[5/5] 3/3", "[1/5] 1/3" };
			const char *at = output;
			size_t j;
			for (j = 0; j < R_ARRAY_SIZE (counters); j++) {
				at = strstr (at, counters[j]);
				mu_assert_notnull (at, "navigate individual matches in both directions and wrap");
				at += strlen (counters[j]);
			}
			mu_assert_notnull (strstr (at, "2/3"), "q restores normal page navigation");
			mu_assert_true (slides_search_highlight, "search sets scr.highlight");
			mu_assert_false (slides_search_executed, "indexing does not execute offscreen commands");
			mu_assert_notnull (strstr (output, "     needle"), "scroll to the hit below the viewport");
		} else if (i == 1) {
			mu_assert_notnull (strstr (output, "[0/0] 1/3"), "show no matches without changing page");
		} else if (i == 2) {
			mu_assert_null (strstr (output, "[0/0]"), "empty query leaves search mode");
		} else {
			mu_assert_notnull (strstr (output, "[2/5] 1/3"), "two-page mode and reload retain individual hit navigation");
		}
		mu_assert_streq (r_config_get (core->config, "scr.highlight"), "", "q clears search highlight");
		mu_assert_streq (cons->line->state.prompt, "original> ", "restore prompt after search");
		mu_assert_eq (cons->input_state.readbuffer_length, 0, "q cancels search before exiting slides");
		free (output);
		r_core_free (core);
	}
	r_file_rm (filename);
	free (filename);
	mu_end;
}

#if R2__UNIX__
static bool slides_mouse_enabled_on_read;

static void *slides_check_mouse(void *user) {
	RCore *core = user;
	slides_mouse_enabled_on_read = core->cons->mouse;
	return NULL;
}

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
	core->cons->cb_sleep_begin = slides_check_mouse;
	core->cons->cb_sleep_end = NULL;
	r_core_visual_slides (core, filename);
	mu_assert_true (slides_mouse_enabled_on_read, "enable mouse reporting while reading slide input");
	r_config_set_b (core->config, "scr.wheel", false);
	r_core_visual_slides (core, filename);
	mu_assert_false (slides_mouse_enabled_on_read, "honor disabled wheel reporting");
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
	mu_run_test (test_slides_mouse_wheel);
	mu_run_test (test_slides_footer);
	mu_run_test (test_slides_transitions);
	mu_run_test (test_slides_search);
#if R2__UNIX__
	mu_run_test (test_slides_eof);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
