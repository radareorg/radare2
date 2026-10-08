#include <r_cons.h>
#include <r_util/r_time.h>
#include "minunit.h"

bool test_r_cons(void) {
	// NOTE: not initializing a value here results in UB
	ut8 r = 0, g = 0, b = 0, a = 0;

	// all these strdup are for asan/valgrind to have some exact bounds to work with

	char *foo = strdup ("___"); // should crash in asan mode
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);

	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 0, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// old school
	foo = strdup ("\x1b[32mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[32mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("32mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 0, "red color");
	mu_assert_eq (g, 127, "green color");
	mu_assert_eq (b, 0, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// 256
	foo = strdup ("\x1b[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 255, "red color");
	mu_assert_eq (g, 135, "green color");
	mu_assert_eq (b, 255, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// 24 bit
	foo = strdup ("\x1b[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	foo = strdup ("38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);
	mu_assert_eq (r, 42, "red color");
	mu_assert_eq (g, 13, "green color");
	mu_assert_eq (b, 37, "blue color");
	mu_assert_eq (a, 0, "alpha color");

	// no over-read
	foo = strdup ("38;2");
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);

	foo = strdup ("38;5");
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);

	foo = strdup ("3");
	r_str_html_rgbparse (foo, &r, &g, &b, &a);
	free (foo);

	mu_end;
}

bool test_cons_to_html(void) {
	char *html;

	html = r_str_html_strip ("\x1b[32mhello\x1b[0m", NULL);
	mu_assert_streq_free (html, "<span style='color:#0f0'>hello</span>", "Simple font color");

	html = r_str_html_strip ("\x1b[31mhello\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00'>hello</span>abc", "Simple font color2");

	html = r_str_html_strip ("\x1b[31mhe\x1b[44mllo\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00'>he</span><span style='color:#f00;background-color:#00f'>llo</span>abc", "Color and background");

	html = r_str_html_strip ("\x1b[44mhe\x1b[31mllo\x1b[0mabc", NULL);
	mu_assert_streq_free (html, "<span style='background-color:#00f'>he</span><span style='color:#f00;background-color:#00f'>llo</span>abc", "Background and color");

	html = r_str_html_strip ("AA\x1b[31mBB\x1b[32mCC\x1b[0mDD", NULL);
	mu_assert_streq_free (html, "AA<span style='color:#f00'>BB</span><span style='color:#0f0'>CC</span>DD", "Switch color");

	html = r_str_html_strip ("AA\x1b[31mBB\x1b[32m\x1b[41mCC\x1b[0mDD", NULL);
	mu_assert_streq_free (html, "AA<span style='color:#f00'>BB</span><span style='color:#0f0;background-color:#f00'>CC</span>DD", "Multiple changes");

	html = r_str_html_strip ("\x1b[33m0x0005d01\x1b[0m \x1b[36mand\x1b[36m foo", NULL);
	mu_assert_streq_free (html, "<span style='color:#ff0'>0x0005d01</span>&nbsp;<span style='color:#aaf'>and</span><span style='color:#aaf'>&nbsp;foo</span>", "Space and reset");

	html = r_str_html_strip ("\x1b[33mAAAA\x1b[7mBBBB\x1b[33mBBB\x1b[0mCCC", NULL);
	mu_assert_streq_free (html, "<span style='color:#ff0'>AAAA</span>"
				    "<span style='color:#ff0;text-decoration:underline overline'>BBBB</span>"
				    "<span style='color:#ff0;text-decoration:underline overline'>BBB</span>CCC",
		"Invert");

	html = r_str_html_strip ("\x1b[33mAAAA\x1b[7mBBBB\x1b[33mBBB\x1b[27mCCC", NULL);
	mu_assert_streq_free (html, "<span style='color:#ff0'>AAAA</span>"
				    "<span style='color:#ff0;text-decoration:underline overline'>BBBB</span>"
				    "<span style='color:#ff0;text-decoration:underline overline'>BBB</span><span style='color:#ff0'>CCC</span>",
		"Invert rest");

	html = r_str_html_strip ("\x1b[41m\x1b[31mBB\x1b[39mCC", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00;background-color:#f00'>BB</span>"
		"<span style='background-color:#f00'>CC</span>", "Default font color color");

	html = r_str_html_strip ("\x1b[41m\x1b[31mBB\x1b[49mCC", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00;background-color:#f00'>BB</span><span style='color:#f00'>CC</span>", "Default background color");

	// standalone bold
	html = r_str_html_strip ("\x1b[1mBOLD\x1b[0m", NULL);
	mu_assert_streq_free (html, "<span style='font-weight:bold'>BOLD</span>", "Standalone bold");

	// bold + separate color
	html = r_str_html_strip ("\x1b[1m\x1b[31mBOLD\x1b[0m", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00;font-weight:bold'>BOLD</span>", "Bold then color");

	// bold prefix in combined sequence
	html = r_str_html_strip ("\x1b[1;31mBOLD\x1b[0m", NULL);
	mu_assert_streq_free (html, "<span style='color:#f00;font-weight:bold'>BOLD</span>", "Bold combined with color");

	mu_end;
}

bool test_cons_child_isolation(void) {
	RCons *parent = r_cons_new ();
	mu_assert_notnull (parent, "parent console");
	parent->columns = 123;
	parent->use_utf8 = true;
	parent->context->color_mode = COLOR_MODE_16;
	r_cons_rainbow_new (parent, 2);
	r_cons_print (parent, "parent");
	r_cons_context_break (parent->context);

	RCons *child = r_cons_new_child (parent);
	mu_assert_notnull (child, "child console");
	mu_assert_notnull (parent->terminal, "parent is terminal attached");
	mu_assert_null (child->terminal, "child is terminal detached");
	mu_assert ("different console", child != parent);
	mu_assert ("different context", child->context != parent->context);
	mu_assert ("different context stack", child->ctx_stack != parent->ctx_stack);
	mu_assert ("different lock", child->lock != parent->lock);
	mu_assert ("different line editor", child->line != parent->line);
	mu_assert_eq (child->columns, 123, "inherit columns");
	mu_assert_true (child->use_utf8, "inherit utf8");
	mu_assert_true (child->is_embedded, "capture child does not use process-wide signals");
	mu_assert_eq (child->context->color_mode, COLOR_MODE_16, "inherit color mode");
	mu_assert_null (child->context->pal.rainbow, "child starts without a rainbow");
	mu_assert_eq (child->context->pal.rainbow_sz, 0, "child rainbow size is consistent");
	mu_assert_eq (child->context->buffer_len, 0, "child starts empty");
	mu_assert_false (child->context->breaked, "child starts unbroken");
	mu_assert_true (child->context->noflush, "child captures flushes");

	parent->context->breaked = false;
	r_cons_print (child, "child");
	mu_assert_streq (parent->context->buffer, "parent", "parent output stays isolated");
	mu_assert_streq (child->context->buffer, "child", "child owns its output");
	child->context->color_mode = COLOR_MODE_DISABLED;
	r_cons_context_break (child->context);
	mu_assert_eq (parent->context->color_mode, COLOR_MODE_16, "child settings stay isolated");
	mu_assert_false (parent->context->breaked, "child break stays isolated");

	r_cons_free (child);
	r_cons_free (parent);
	mu_end;
}

typedef struct {
	RCons *cons;
	char byte;
	size_t count;
} ConsWriter;

static RThreadFunctionRet cons_writer(RThread *thread) {
	ConsWriter *writer = thread->user;
	size_t i;
	for (i = 0; i < writer->count; i++) {
		r_cons_write (writer->cons, &writer->byte, 1);
	}
	return R_TH_STOP;
}

static bool cons_buffer_is(const char *buffer, size_t size, char byte) {
	size_t i;
	for (i = 0; i < size; i++) {
		if (buffer[i] != byte) {
			return false;
		}
	}
	return true;
}

bool test_cons_child_concurrent_merge(void) {
	RCons *parent = r_cons_new ();
	RCons *left = r_cons_new_child (parent);
	RCons *right = r_cons_new_child (parent);
	mu_assert_notnull (left, "left child");
	mu_assert_notnull (right, "right child");
	ConsWriter left_writer = {
		.cons = left,
		.byte = 'L',
		.count = 4096
	};
	ConsWriter right_writer = {
		.cons = right,
		.byte = 'R',
		.count = 4096
	};
	RThread *left_thread = r_th_new (cons_writer, &left_writer, 0);
	RThread *right_thread = r_th_new (cons_writer, &right_writer, 0);
	mu_assert_notnull (left_thread, "left thread");
	mu_assert_notnull (right_thread, "right thread");
	mu_assert_true (r_th_start (left_thread), "start left");
	mu_assert_true (r_th_start (right_thread), "start right");
	r_th_wait (left_thread);
	r_th_wait (right_thread);

	size_t left_size;
	size_t right_size;
	const char *left_output = r_cons_get_buffer (left, &left_size);
	const char *right_output = r_cons_get_buffer (right, &right_size);
	mu_assert_eq (left_size, left_writer.count, "left output size");
	mu_assert_eq (right_size, right_writer.count, "right output size");
	mu_assert_true (cons_buffer_is (left_output, left_size, 'L'), "left output contents");
	mu_assert_true (cons_buffer_is (right_output, right_size, 'R'), "right output contents");

	left->context->color_mode = COLOR_MODE_16;
	mu_assert_true (r_cons_merge_output (parent, left), "merge left");
	mu_assert_true (r_cons_merge_output (parent, right), "merge right");
	mu_assert_eq (left->context->buffer_len, 0, "left drained");
	mu_assert_eq (right->context->buffer_len, 0, "right drained");
	mu_assert_eq (parent->context->buffer_len, left_size + right_size, "merged output size");
	mu_assert_eq (parent->context->color_mode, COLOR_MODE_DISABLED, "settings do not merge");
	mu_assert_true (cons_buffer_is (parent->context->buffer, left_size, 'L'), "merged left contents");
	mu_assert_true (cons_buffer_is (parent->context->buffer + left_size, right_size, 'R'), "merged right contents");

	const ut8 binary[] = { 'A', 0, 'B' };
	r_cons_reset (parent);
	mu_assert_true (r_cons_write (left, binary, sizeof (binary)), "write binary output");
	mu_assert_true (r_cons_merge_output (parent, left), "merge binary output");
	mu_assert_eq (parent->context->buffer_len, sizeof (binary), "binary output size");
	mu_assert_memeq ((const ut8 *)parent->context->buffer, binary, sizeof (binary), "binary output contents");

	r_th_free (left_thread);
	r_th_free (right_thread);
	r_cons_free (left);
	r_cons_free (right);
	r_cons_free (parent);
	mu_end;
}

bool test_cons_multiple_roots_same_thread(void) {
	mu_assert_false (r_cons_is_initialized (), "thread starts without a current console");
	RCons *first = r_cons_new ();
	RCons *second = r_cons_new ();
	mu_assert_notnull (first->terminal, "first root is terminal attached");
	mu_assert_notnull (second->terminal, "second root is terminal attached");
	mu_assert_ptreq (r_cons_singleton (), second, "newest root is current");
#if R2__UNIX__ && !__wasi__
	r_cons_break_push (second, NULL, NULL);
	raise (SIGINT);
	mu_assert_false (first->context->breaked, "SIGINT leaves the previous root untouched");
	mu_assert_true (second->context->breaked, "SIGINT breaks the current root");
	r_cons_break_end (second);
#endif
	mu_assert_ptreq (r_cons_global (first), first, "explicitly switch current root");

	r_cons_free (first);
	mu_assert_ptreq (r_cons_singleton (), second, "freeing current root restores previous root");
	r_cons_print (second, "second");
	size_t size;
	char *output = r_cons_drain (second, &size);
	mu_assert_eq (size, 6, "remaining root output size");
	mu_assert_memeq ((const ut8 *)output, (const ut8 *)"second", size, "remaining root output");
	free (output);

	r_cons_free (second);
	mu_assert_false (r_cons_is_initialized (), "freeing current root clears thread state");
	mu_end;
}

bool test_cons_empty_drain_reuses_buffer(void) {
	RCons *cons = r_cons_new ();
	mu_assert_true (r_cons_write (cons, "x", 1), "allocate console buffer");
	char *buffer = cons->context->buffer;
	const size_t capacity = cons->context->buffer_sz;
	r_cons_reset (cons);

	size_t size = SIZE_MAX;
	char *output = r_cons_drain (cons, &size);
	mu_assert_null (output, "empty drain returns NULL");
	mu_assert_eq (size, 0, "empty drain reports zero bytes");
	mu_assert_ptreq (cons->context->buffer, buffer, "empty drain retains the buffer");
	mu_assert_eq (cons->context->buffer_sz, capacity, "empty drain retains buffer capacity");

	mu_assert_true (r_cons_write (cons, "y", 1), "retained buffer remains writable");
	mu_assert_ptreq (cons->context->buffer, buffer, "next write reuses the buffer");
	r_cons_free (cons);
	mu_end;
}

bool test_cons_output_chunks(void) {
	RCons *cons = r_cons_new ();
	char *filename = NULL;
	int fd = r_file_mkstemp ("r2-cons-output", &filename);
	mu_assert ("temporary output file", fd >= 0);
	cons->fdout = fd;
	cons->context->is_interactive = false;
	const size_t length = 2 * 64 * 1024 + 3;
	char *buffer = malloc (length);
	mu_assert_notnull (buffer, "output buffer");
	size_t i;
	for (i = 0; i < length; i++) {
		buffer[i] = i % 256;
	}
	mu_assert_true (r_cons_write (cons, buffer, length), "buffer binary output");
	r_cons_flush (cons);
	mu_assert_eq (cons->context->buffer_len, 0, "flush drains all chunks");

	cons->columns = 2;
	cons->rows = 1;
	cons->break_lines = false;
	char cropped[] = "abcdef\n";
	r_cons_visual_write (cons, cropped);
	close (fd);
	size_t output_length;
	char *output = r_file_slurp (filename, &output_length);
	r_file_rm (filename);
	free (filename);
	mu_assert_notnull (output, "read flushed output");
	const char suffix[] = "ab" R_CONS_CLEAR_FROM_CURSOR_TO_END Color_RESET;
	mu_assert_eq (output_length, length + sizeof (suffix) - 1, "all chunks and clear sequence are written");
	mu_assert_memeq ((const ut8 *)output, (const ut8 *)buffer, length, "chunk boundaries preserve binary output");
	mu_assert_memeq ((const ut8 *)output + length, (const ut8 *)suffix, sizeof (suffix) - 1, "clipping writes the complete clear sequence");
	free (buffer);
	free (output);
	r_cons_free (cons);
	mu_end;
}

typedef struct {
	RThreadSemaphore *ready;
	RThreadSemaphore *release;
	bool ok;
} ConsRootThread;

static RThreadFunctionRet cons_root_thread(RThread *thread) {
	ConsRootThread *state = thread->user;
	RCons *cons = r_cons_new ();
	state->ok = cons->terminal && r_cons_singleton () == cons;
	r_th_sem_post (state->ready);
	r_th_sem_wait (state->release);
	state->ok = state->ok && r_cons_singleton () == cons;
	r_cons_free (cons);
	state->ok = state->ok && !r_cons_is_initialized ();
	return R_TH_STOP;
}

bool test_cons_multiple_roots_across_threads(void) {
	RThreadSemaphore *ready = r_th_sem_new (0);
	RThreadSemaphore *release = r_th_sem_new (0);
	mu_assert_notnull (ready, "ready semaphore");
	mu_assert_notnull (release, "release semaphore");
	ConsRootThread left_state = {
		.ready = ready,
		.release = release
	};
	ConsRootThread right_state = {
		.ready = ready,
		.release = release
	};
	RThread *left = r_th_new (cons_root_thread, &left_state, 0);
	RThread *right = r_th_new (cons_root_thread, &right_state, 0);
	mu_assert_notnull (left, "left root thread");
	mu_assert_notnull (right, "right root thread");
	mu_assert_true (r_th_start (left), "start left root thread");
	mu_assert_true (r_th_start (right), "start right root thread");
	r_th_sem_wait (ready);
	r_th_sem_wait (ready);
	r_th_sem_post (release);
	r_th_sem_post (release);
	r_th_wait (left);
	r_th_wait (right);
	mu_assert_true (left_state.ok, "left thread keeps its current console");
	mu_assert_true (right_state.ok, "right thread keeps its current console");
	mu_assert_false (r_cons_is_initialized (), "worker consoles do not affect main thread");

	r_th_free (left);
	r_th_free (right);
	r_th_sem_free (ready);
	r_th_sem_free (release);
	mu_end;
}

bool test_cons_timeout_keeps_earliest_deadline(void) {
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "r_cons_new()");

	r_cons_break_timeout (cons, 10);
	const ut64 first_deadline = cons->timeout;
	mu_assert ("first timeout set", first_deadline > 0);

	r_cons_break_timeout (cons, 100);
	mu_assert_eq (cons->timeout, first_deadline, "longer nested timeout must not extend deadline");

	r_cons_break_timeout (cons, 1);
	mu_assert ("shorter nested timeout must tighten deadline", cons->timeout < first_deadline);

	r_cons_free (cons);
	mu_end;
}

bool test_cons_timeout_does_not_restart_expired_deadline(void) {
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "r_cons_new()");

	cons->timeout = r_time_now_mono () - 1;
	cons->otimeout = 1;
	r_cons_break_timeout (cons, 100);
	mu_assert ("expired timeout must stay expired", cons->timeout < r_time_now_mono ());

	r_cons_free (cons);
	mu_end;
}

bool test_cons_json_path_grep_buffer(void) {
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "r_cons_new()");

	const char *json = "{\"name\":\"radare2\"}\n";
	mu_assert ("write json", r_cons_write (cons, json, strlen (json)));
	cons->context->grep.json = true;
	cons->context->grep.json_path = strdup ("name");
	r_cons_grepbuf (cons);
	mu_assert_streq (cons->context->buffer, "radare2\n", "JSON path result");
	mu_assert_null (cons->context->grep.json_path, "JSON path must be released");

	r_cons_reset (cons);
	mu_assert ("write json again", r_cons_write (cons, json, strlen (json)));
	char *buffer = cons->context->buffer;
	cons->context->grep.json = true;
	cons->context->grep.json_path = strdup ("missing");
	r_cons_grepbuf (cons);
	mu_assert_ptreq (cons->context->buffer, buffer, "missing JSON path must preserve buffer");
	mu_assert_streq (cons->context->buffer, json, "missing JSON path contents");

	r_cons_free (cons);
	mu_end;
}

bool test_cons_grep_icase_does_not_mutate_word(void) {
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "r_cons_new()");

	r_cons_grep_expression (cons, "+FoO");
	RConsGrepWord *gw = r_list_first (cons->context->grep.strings);
	mu_assert_notnull (gw, "grep word");
	char line[] = "foo";
	mu_assert_eq (r_cons_grep_line (cons, line, 3), 3, "case-insensitive grep");
	mu_assert_streq (gw->str, "FoO", "grep matching must not mutate words");

	r_cons_free (cons);
	mu_end;
}

static const RCoreHelpMessage test_help_message = {
	"Usage: h", "", "help test",
	"ha", "", "first command",
	"hab", "", "second command",
	NULL
};

bool test_cons_cmd_help_uses_context_color(void) {
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "r_cons_new()");

	r_cons_cmd_help (cons, test_help_message);
	mu_assert_notnull (cons->context->buffer, "plain help output");
	mu_assert_null (strstr (cons->context->buffer, "\x1b["), "disabled color mode must not emit ANSI");

	r_cons_reset (cons);
	cons->context->color_mode = COLOR_MODE_16;
	r_cons_pal_reload (cons);
	r_cons_cmd_help (cons, test_help_message);
	mu_assert_notnull (strstr (cons->context->buffer, "\x1b["), "enabled color mode must emit ANSI");

	r_cons_push (cons);
	mu_assert_eq (cons->context->color_mode, COLOR_MODE_16, "child context must inherit color mode");
	r_cons_cmd_help (cons, test_help_message);
	mu_assert_notnull (strstr (cons->context->buffer, "\x1b["), "child help must use inherited color mode");
	r_cons_pop (cons);

	r_cons_free (cons);
	mu_end;
}

bool test_cons_push_inherits_last_output(void) {
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "r_cons_new()");
	RConsContext *parent = cons->context;
	parent->lastOutput = strdup ("previous");
	parent->lastLength = 8;

	r_cons_push (cons);
	mu_assert ("child owns last output", cons->context->lastOutput != parent->lastOutput);
	r_cons_last (cons);
	mu_assert_eq (cons->context->buffer_len, 8, "child sees last output");
	mu_assert_memeq ((const ut8 *)cons->context->buffer,
		(const ut8 *)"previous", 8, "child last output");
	r_cons_pop (cons);

	mu_assert_ptreq (cons->context, parent, "pop restores parent");
	mu_assert_memeq ((const ut8 *)parent->lastOutput,
		(const ut8 *)"previous", 8, "parent keeps last output");
	r_cons_free (cons);
	mu_end;
}

bool test_cons_cmd_help_match(void) {
	RCons *cons = r_cons_new ();
	mu_assert_notnull (cons, "r_cons_new()");

	mu_assert_eq (r_cons_cmd_help_match (cons, test_help_message, "ha", 0, true), 1, "exact help match");
	mu_assert_notnull (strstr (cons->context->buffer, "first command"), "exact match output");
	mu_assert_null (strstr (cons->context->buffer, "second command"), "exact match must exclude longer commands");

	r_cons_reset (cons);
	mu_assert_eq (r_cons_cmd_help_match (cons, test_help_message, "ha", 0, false), 2, "contains help match");
	mu_assert_notnull (strstr (cons->context->buffer, "first command"), "contains first match");
	mu_assert_notnull (strstr (cons->context->buffer, "second command"), "contains second match");

	r_cons_reset (cons);
	mu_assert_eq (r_cons_cmd_help_match (cons, test_help_message, "ha", 'b', true), 1, "spec help match");
	mu_assert_null (strstr (cons->context->buffer, "first command"), "spec match must exclude base command");
	mu_assert_notnull (strstr (cons->context->buffer, "second command"), "spec match output");

	r_cons_free (cons);
	mu_end;
}

bool test_cons_canvas_attribute_lifetime(void) {
	RCons *cons = r_cons_new ();
	cons->use_utf8 = false;
	RConsCanvas *canvas = r_cons_canvas_new (cons, 8, 2, 0);
	mu_assert_notnull (canvas, "canvas");
	canvas->color = true;
	char *color = strdup (Color_RED);
	RCanvasLineStyle style = {
		.color = LINE_TRUE,
		.symbol = LINE_NONE,
		.ansicolor = color
	};
	r_cons_canvas_line_square (canvas, 0, 0, 7, 0, &style);
	free (color);
	const char *attribute = r_cons_canvas_attribute_at (canvas, 0, 0);
	mu_assert_streq (attribute, Color_RED, "custom color survives its input");
	int x;
	for (x = 1; x < 8; x++) {
		mu_assert_ptreq (r_cons_canvas_attribute_at (canvas, x, 0), attribute, "line cells share one color");
	}
	char *output = r_cons_canvas_tostring (canvas);
	mu_assert_streq_free (output, Color_RED "." Color_RED "-" Color_RED "-" Color_RED "-"
		Color_RED "-" Color_RED "-" Color_RED "-" Color_RED ".\n", "colored line output");

	r_cons_canvas_clear (canvas, R_CONS_CANVAS_FLAG_DEFAULT);
	mu_assert_streq (attribute, Color_RED, "clearing attributes retains pooled strings");
	color = strdup (Color_BLUE);
	canvas->attr = color;
	r_cons_canvas_write_at (canvas, "a", 0, 0);
	free (color);
	mu_assert_streq (r_cons_canvas_attribute_at (canvas, 0, 0), Color_BLUE, "direct attribute is retained");

	r_cons_canvas_background (canvas, Color_BGBLUE);
	r_cons_canvas_write_at (canvas, "b\nc", 1, 0);
	r_cons_canvas_background (canvas, Color_BGRED);
	mu_assert_streq (r_cons_canvas_attribute_at (canvas, 1, 0), Color_BGBLUE, "newline retains the old background");
	mu_assert_streq (r_cons_canvas_attribute_at (canvas, 1, 1), Color_BGBLUE, "next row retains the old background");

	r_cons_canvas_clear (canvas, R_CONS_CANVAS_FLAG_DEFAULT);
	cons->context->color_mode = COLOR_MODE_16;
	r_cons_pal_reload (cons);
	char *palette_color = strdup (cons->context->pal.graph_true);
	style.ansicolor = NULL;
	r_cons_canvas_line_square (canvas, 0, 0, 7, 0, &style);
	cons->context->color_mode = COLOR_MODE_256;
	r_cons_pal_reload (cons);
	mu_assert_streq (r_cons_canvas_attribute_at (canvas, 0, 0), palette_color, "palette reload retains existing colors");
	free (palette_color);
	r_cons_canvas_free (canvas);
	r_cons_free (cons);
	mu_end;
}

bool test_cons_canvas_long_attribute(void) {
	RCons *cons = r_cons_new ();
	RConsCanvas *canvas = r_cons_canvas_new (cons, 1, 1, 0);
	mu_assert_notnull (canvas, "canvas");
	canvas->color = true;
	RStrBuf *text = r_strbuf_new (NULL);
	int i;
	for (i = 0; i < 100; i++) {
		r_strbuf_append (text, Color_RED);
	}
	r_strbuf_append (text, "x");
	r_cons_canvas_write (canvas, r_strbuf_get (text));
	char *output = r_cons_canvas_tostring (canvas);
	mu_assert_streq_free (output, r_strbuf_get (text), "output includes the complete ANSI attribute");
	r_strbuf_free (text);
	r_cons_canvas_free (canvas);
	r_cons_free (cons);
	mu_end;
}

bool test_cons_canvas_vertical_clipping(void) {
	RCons *cons = r_cons_new ();
	const int endpoints[][2] = {
		{ -100, 100 }, { -100, -90 }, { 20, 30 }, { -1, -1 }, { 3, 3 }, { 0, 2 }
	};
	const char *units[] = { RUNECODESTR_LINE_VERT, "┊", "╵" };
	int utf8, dot_style, shift, edge;
	for (utf8 = 0; utf8 < 2; utf8++) {
		cons->use_utf8 = utf8;
		cons->dotted_lines = true;
		for (dot_style = DOT_STYLE_NORMAL; dot_style <= DOT_STYLE_BACKEDGE; dot_style++) {
			for (shift = 0; shift < 2; shift++) {
				for (edge = 0; edge < R_ARRAY_SIZE (endpoints); edge++) {
					int flags = utf8? R_CONS_CANVAS_FLAG_UTF8: 0;
					RConsCanvas *canvas = r_cons_canvas_new (cons, 8, 5, flags);
					RConsCanvas *reference = r_cons_canvas_new (cons, 8, 5, flags);
					mu_assert_notnull (canvas, "clipped canvas");
					mu_assert_notnull (reference, "reference canvas");
					canvas->linemode = true;
					canvas->color = reference->color = true;
					canvas->sx = reference->sx = -shift;
					canvas->sy = reference->sy = -3 * shift;
					RCanvasLineStyle style = {
						.color = LINE_NONE,
						.symbol = LINE_NONE,
						.dot_style = dot_style,
						.ansicolor = Color_GREEN
					};
					int y = endpoints[edge][0], y2 = endpoints[edge][1];
					r_cons_canvas_line_square_defined (canvas, 3, y, 3, y2, &style, 0, true);
					reference->attr = Color_GREEN;
					int row;
					for (row = y + 1; row <= y2 + 1; row++) {
						r_cons_canvas_write_at (reference, utf8? units[dot_style]: "|", 3, row);
					}
					char *output = r_cons_canvas_tostring (canvas);
					char *expected = r_cons_canvas_tostring (reference);
					mu_assert_streq (output, expected, "vertical clipping preserves cells and colors");
					free (output);
					free (expected);
					r_cons_canvas_free (canvas);
					r_cons_canvas_free (reference);
				}
			}
		}
	}
	r_cons_free (cons);
	mu_end;
}

bool test_cons_canvas_large_output(void) {
	RConsCanvas *canvas = r_cons_canvas_new (NULL, 8191, 8192, 0);
	mu_assert_notnull (canvas, "large canvas");
	r_cons_canvas_fill (canvas, 0, 0, canvas->w, canvas->h, 'x');
	char *output = r_cons_canvas_tostring (canvas);
	mu_assert_notnull (output, "large serialized canvas");
	const ut64 length = (ut64)(canvas->w + 1) * canvas->h - 1;
	mu_assert_eq (strlen (output), length, "large output length");
	mu_assert_eq (output[0], 'x', "first output cell");
	mu_assert_eq (output[canvas->w], '\n', "row separator");
	mu_assert_eq (output[length - 1], 'x', "last output cell");
	free (output);
	r_cons_canvas_free (canvas);
	mu_end;
}

bool test_cons_canvas_dimension_bounds(void) {
	mu_assert_null (r_cons_canvas_new (NULL, ST32_MAX, 1, 0), "row capacity must fit int");
	RConsCanvas *canvas = r_cons_canvas_new (NULL, 1, 1, 0);
	mu_assert_notnull (canvas, "canvas");
	mu_assert_false (r_cons_canvas_resize (canvas, ST32_MAX, 1), "reject overflowing row capacity");
	r_cons_canvas_write (canvas, "x");
	char *output = r_cons_canvas_tostring (canvas);
	mu_assert_streq_free (output, "x", "rejected resize preserves the canvas");
	r_cons_canvas_free (canvas);
	mu_end;
}

bool test_cons_canvas_resize_reuses_rows(void) {
	RConsCanvas *canvas = r_cons_canvas_new (NULL, 4, 2, 0);
	RConsCanvas *reference = r_cons_canvas_new (NULL, 4, 2, 0);
	mu_assert_notnull (canvas, "canvas");
	mu_assert_notnull (reference, "reference canvas");
	r_cons_canvas_write_at (canvas, "\xe2\x94\x80\xe2\x94\x80", 0, 0);
	r_cons_canvas_write_at (canvas, "z", 1, 1);
	mu_assert_true (canvas->blen[0] > canvas->w, "utf8 expands the row bytes");
	char *row = canvas->b[0];
	mu_assert_true (r_cons_canvas_resize (canvas, 4, 2), "same size resize");
	mu_assert_ptreq (canvas->b[0], row, "same size resize reuses rows");
	mu_assert_eq (canvas->blen[0], canvas->w, "row length is reset");
	mu_assert_eq (canvas->x, 0, "cursor x is reset");
	mu_assert_eq (canvas->y, 0, "cursor y is reset");
	r_cons_canvas_write_at (canvas, "ab", 0, 0);
	r_cons_canvas_write_at (reference, "ab", 0, 0);
	char *output = r_cons_canvas_tostring (canvas);
	char *expected = r_cons_canvas_tostring (reference);
	mu_assert_streq (output, expected, "reused canvas matches a fresh one");
	free (output);
	free (expected);
	r_cons_canvas_free (canvas);
	r_cons_canvas_free (reference);
	mu_end;
}

bool test_cons_canvas_many_attributes(void) {
	RCons *cons = r_cons_new ();
	RConsCanvas *canvas = r_cons_canvas_new (cons, 300, 2, 0);
	mu_assert_notnull (canvas, "canvas");
	canvas->color = true;
	int x;
	for (x = 0; x < 300; x++) {
		char *s = r_str_newf ("\x1b[38;2;%d;%d;0mx", x % 256, x / 256);
		r_cons_canvas_write_at (canvas, s, x, 0);
		free (s);
	}
	for (x = 0; x < 300; x++) {
		char *expected = r_str_newf ("\x1b[38;2;%d;%d;0m", x % 256, x / 256);
		mu_assert_streq (r_cons_canvas_attribute_at (canvas, x, 0), expected, "each cell keeps its own style past 255 styles");
		free (expected);
	}
	char *output = r_cons_canvas_tostring (canvas);
	mu_assert_true (r_str_startswith (output, "\x1b[38;2;0;0;0mx\x1b[38;2;1;0;0mx"), "serialized styles");
	mu_assert_notnull (strstr (output, "\x1b[38;2;43;1;0mx"), "serialized wide style");
	free (output);
	r_cons_canvas_write_at (canvas, "y", 5, 0);
	mu_assert_streq (r_cons_canvas_attribute_at (canvas, 5, 0), "\x1b[38;2;43;1;0m", "plain write uses the current style");
	r_cons_canvas_clear (canvas, R_CONS_CANVAS_FLAG_DEFAULT);
	mu_assert_null (r_cons_canvas_attribute_at (canvas, 299, 0), "clear removes styles");
	mu_assert_true (r_cons_canvas_resize (canvas, 4, 1), "resize");
	mu_assert_null (r_cons_canvas_attribute_at (canvas, 0, 0), "resize removes styles");
	r_cons_canvas_free (canvas);
	r_cons_free (cons);
	mu_end;
}

bool test_cons_canvas_print_rows(void) {
	RCons *cons = r_cons_new ();
	RConsCanvas *canvas = r_cons_canvas_new (cons, 6, 6, 0);
	mu_assert_notnull (canvas, "canvas");
	canvas->color = true;
	r_cons_canvas_write_at (canvas, Color_RED "a", 0, 0);
	r_cons_canvas_write_at (canvas, "\t", 2, 1);
	r_cons_canvas_write_at (canvas, Color_BLUE "b \t", 1, 2);
	r_cons_canvas_write_at (canvas, "\t", 0, 4);
	char *expected = r_cons_canvas_tostring (canvas);
	mu_assert_notnull (expected, "serialized canvas");
	size_t len;
	r_cons_reset (cons);
	r_cons_canvas_print (canvas);
	mu_assert_streq (r_cons_get_buffer (cons, &len), expected, "print streams every row");
	r_str_trim_tail (expected);
	r_cons_reset (cons);
	r_cons_canvas_print_region (canvas);
	mu_assert_streq (r_cons_get_buffer (cons, &len), expected, "print_region trims only the output tail");
	free (expected);
	r_cons_canvas_clear (canvas, R_CONS_CANVAS_FLAG_DEFAULT);
	r_cons_reset (cons);
	r_cons_canvas_print_region (canvas);
	const char *empty = r_cons_get_buffer (cons, &len);
	mu_assert_true (!empty || !*empty, "blank canvas prints nothing");
	r_cons_canvas_free (canvas);
	r_cons_free (cons);
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_cons);
	mu_run_test (test_cons_to_html);
	mu_run_test (test_cons_child_isolation);
	mu_run_test (test_cons_child_concurrent_merge);
	mu_run_test (test_cons_multiple_roots_same_thread);
	mu_run_test (test_cons_empty_drain_reuses_buffer);
	mu_run_test (test_cons_output_chunks);
	mu_run_test (test_cons_multiple_roots_across_threads);
	mu_run_test (test_cons_timeout_keeps_earliest_deadline);
	mu_run_test (test_cons_timeout_does_not_restart_expired_deadline);
	mu_run_test (test_cons_json_path_grep_buffer);
	mu_run_test (test_cons_grep_icase_does_not_mutate_word);
	mu_run_test (test_cons_cmd_help_uses_context_color);
	mu_run_test (test_cons_push_inherits_last_output);
	mu_run_test (test_cons_cmd_help_match);
	mu_run_test (test_cons_canvas_attribute_lifetime);
	mu_run_test (test_cons_canvas_long_attribute);
	mu_run_test (test_cons_canvas_vertical_clipping);
	mu_run_test (test_cons_canvas_large_output);
	mu_run_test (test_cons_canvas_dimension_bounds);
	mu_run_test (test_cons_canvas_resize_reuses_rows);
	mu_run_test (test_cons_canvas_many_attributes);
	mu_run_test (test_cons_canvas_print_rows);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
