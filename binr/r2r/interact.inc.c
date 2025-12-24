/* radare - LGPL - Copyright 2020-2025 - pancake, thestr4ng3r */

#include "r2r.h"

// After editing a test, fix the line numbers previously saved for all the other tests
static void fixup_tests(RVecR2RTestResultInfoPtr *results, const char *edited_file, ut64 start_line, st64 delta) {
	R2RTestResultInfo **it;
	R_VEC_FOREACH (results, it) {
		R2RTestResultInfo *result = *it;
		if (result->test->type != R2R_TEST_TYPE_CMD && result->test->type != R2R_TEST_TYPE_LEAK) {
			continue;
		}
		if (result->test->path != edited_file) { // this works because all the paths come from the string pool
			continue;
		}
		R2RCmdTest *test = result->test->cmd_test;
		test->run_line += delta;

#define DO_KEY_STR(key, field) \
	if (test->field.value) { \
		if (test->field.line_begin >= start_line) { \
			test->field.line_begin += delta; \
		} \
		if (test->field.line_end >= start_line) { \
			test->field.line_end += delta; \
		} \
	}

#define DO_KEY_BOOL(key, field) \
	if (test->field.set && test->field.line >= start_line) { \
		test->field.line += delta; \
	}

#define DO_KEY_NUM(key, field) \
	if (test->field.set && test->field.line >= start_line) { \
		test->field.line += delta; \
	}

		R2R_CMD_TEST_FOREACH_RECORD (DO_KEY_STR, DO_KEY_BOOL, DO_KEY_NUM)
#undef DO_KEY_STR
#undef DO_KEY_BOOL
#undef DO_KEY_NUM
	}
}


static char *format_cmd_kv(const char *key, const char *val) {
	if (strchr (val, '\n')) {
		if (strstr (val, "EOF")) {
			R_LOG_TODO ("Value cannot contain multiline text with 'EOF'");
		}
		return r_str_newf ("%s=<<EOF\n%sEOF", key, val);
	}
	return r_str_newf ("%s=%s", key, val);
}
static char *replace_lines(const char *src, size_t from, size_t to, const char *news) {
	const char *begin = src;
	size_t line = 1;
	while (line < from) {
		begin = strchr (begin, '\n');
		if (!begin) {
			return NULL;
		}
		begin++;
		line++;
	}

	const char *end = begin;
	while (line < to) {
		end = strchr (end, '\n');
		if (!end) {
			break;
		}
		end++;
		line++;
	}

	char *data = r_str_ndup (src, begin - src);
	char *res = r_str_newf ("%s%s\n%s", data, news, end? end: "");
	free (data);
	return res;
}

static char *replace_cmd_kv(const char *path, const char *content, size_t line_begin, size_t line_end, const char *key, const char *value, RVecR2RTestResultInfoPtr *fixup_results) {
	char *kv = format_cmd_kv (key, value);
	if (!kv) {
		return NULL;
	}
	size_t kv_lines = r_str_char_count (kv, '\n') + 1;
	char *newc = replace_lines (content, line_begin, line_end, kv);
	free (kv);
	if (!newc) {
		return NULL;
	}
	size_t lines_before = line_end - line_begin;
	st64 delta = (st64)kv_lines - (st64)lines_before;
	if (line_end == line_begin) {
		delta++;
	}
	fixup_tests (fixup_results, path, line_end, delta);
	return newc;
}

static void replace_cmd_kv_file(const char *path, ut64 line_begin, ut64 line_end, const char *key, const char *value, RVecR2RTestResultInfoPtr *fixup_results) {
	char *content = r_file_slurp (path, NULL);
	if (!content) {
		R_LOG_ERROR ("Failed to read file \"%s\"", path);
		return;
	}
	char *newc = replace_cmd_kv (path, content, line_begin, line_end, key, value, fixup_results);
	free (content);
	if (!newc) {
		return;
	}
	if (r_file_dump (path, (const ut8 *)newc, -1, false)) {
#if R2__UNIX__ && !(__wasi__ || __EMSCRIPTEN__)
		sync ();
#endif
	} else {
		R_LOG_ERROR ("Failed to write file \"%s\"", path);
	}
	free (newc);
}

static void interact_break(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results) {
	R_RETURN_IF_FAIL (result->test->type == R2R_TEST_TYPE_CMD || result->test->type == R2R_TEST_TYPE_LEAK);
	R2RCmdTest *test = result->test->cmd_test;
	ut64 line_begin, line_end;
	if (test->broken.set) {
		line_begin = test->broken.set;
		line_end = line_begin + 1;
	} else {
		line_begin = line_end = test->run_line;
	}
	replace_cmd_kv_file (result->test->path, line_begin, line_end, "BROKEN", "1", fixup_results);
}

static void interact_commands(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results) {
	R_RETURN_IF_FAIL (result->test->type == R2R_TEST_TYPE_CMD || result->test->type == R2R_TEST_TYPE_LEAK);
	R2RCmdTest *test = result->test->cmd_test;
	if (!test->cmds.value) {
		return;
	}
	char *name = NULL;
	int fd = r_file_mkstemp ("r2r-cmds", &name);
	if (fd == -1) {
		free (name);
		R_LOG_ERROR ("Failed to open tmp file");
		return;
	}
	size_t cmds_sz = strlen (test->cmds.value);
	if (write (fd, test->cmds.value, cmds_sz) != cmds_sz) {
		R_LOG_ERROR ("Failed to write to tmp file");
		free (name);
		close (fd);
		return;
	}
	close (fd);

	char *editor = r_sys_getenv ("EDITOR");
	if (!editor || !*editor) {
		free (editor);
		editor = strdup ("vim");
		if (!editor) {
			free (name);
			return;
		}
	}
	r_sys_cmdf ("%s '%s'", editor, name);
	free (editor);

	char *newcmds = r_file_slurp (name, NULL);
	if (!newcmds) {
		R_LOG_ERROR ("Failed to read edited command file");
		free (name);
		return;
	}
	r_str_trim (newcmds);

	// if it's multiline we want exactly one trailing newline
	if (strchr (newcmds, '\n')) {
		char *tmp = newcmds;
		newcmds = r_str_newf ("%s\n", newcmds);
		free (tmp);
		if (!newcmds) {
			free (name);
			return;
		}
	}

	replace_cmd_kv_file (result->test->path, test->cmds.line_begin, test->cmds.line_end, "CMDS", newcmds, fixup_results);
	free (name);
	free (newcmds);
}

static void interact_fix(R2RTestResultInfo *result, RVecR2RTestResultInfoPtr *fixup_results) {
	R_RETURN_IF_FAIL (result->test->type == R2R_TEST_TYPE_CMD || result->test->type == R2R_TEST_TYPE_LEAK);
	R2RCmdTest *test = result->test->cmd_test;
	R2RProcessOutput *out = result->proc_out;
	if (test->expect.value && out->out) {
		replace_cmd_kv_file (result->test->path,
			test->expect.line_begin, test->expect.line_end,
			"EXPECT", out->out, fixup_results);
	}
	if (test->expect_err.value && out->err) {
		replace_cmd_kv_file (result->test->path,
			test->expect_err.line_begin, test->expect_err.line_end,
			"EXPECT_ERR", out->err, fixup_results);
	}
}

static void interact_diffchar(R2RTestResultInfo *result) {
	if (result->test->type != R2R_TEST_TYPE_CMD && result->test->type != R2R_TEST_TYPE_LEAK) {
		return;
	}
	const char *actual = result->proc_out->out;
	const char *expected = result->test->cmd_test->expect.value;
	const char *regexp_out = result->test->cmd_test->regexp_out.value;
	printf ("-- stdout\n");
	print_diff (actual, expected, true, regexp_out);
}

static void interact(R2RState *state) {
	R2RTestResultInfo **it;
	RVecR2RTestResultInfoPtr failed_results;
	RVecR2RTestResultInfoPtr_init (&failed_results);
	R_VEC_FOREACH (&state->results, it) {
		R2RTestResultInfo *result = *it;
		if (result->result == R2R_TEST_RESULT_FAILED) {
			RVecR2RTestResultInfoPtr_push_back (&failed_results, &result);
		}
	}
	if (RVecR2RTestResultInfoPtr_empty (&failed_results)) {
		goto beach;
	}

	bool use_fancy_stuff = !r_cons_is_windows ();
#if R2__WINDOWS__
	// XXX move to rcons
	(void)SetConsoleOutputCP (65001); // UTF-8
#endif
	printf ("\n");
	printf ("#####################\n");
	const size_t failed = RVecR2RTestResultInfoPtr_length (&failed_results);
	if (use_fancy_stuff) {
		printf (" %zu failed test(s)" R_UTF8_POLICE_CARS_REVOLVING_LIGHT "\n", failed);
	} else {
		printf (" %zu failed test(s)\n", failed);
	}
	bool always_fix = false;

	R_VEC_FOREACH (&failed_results, it) {
		R2RTestResultInfo *result = *it;
		if (result->test->type != R2R_TEST_TYPE_CMD && result->test->type != R2R_TEST_TYPE_LEAK) {
			// TODO: other types of tests (asm, json, fuzz)
			continue;
		}
		printf ("#####################\n\n");
		print_result_diff (&state->run_config, result);
	menu:
		if (use_fancy_stuff) {
			printf ("Wat do?    "
			"(f)ix " R_UTF8_WHITE_HEAVY_CHECK_MARK R_UTF8_VS16 R_UTF8_VS16 R_UTF8_VS16 "  "
			"(F)ixAll " R_UTF8_WHITE_HEAVY_CHECK_MARK R_UTF8_VS16 R_UTF8_VS16 R_UTF8_VS16 "  "
			"(i)gnore " R_UTF8_SEE_NO_EVIL_MONKEY "  "
			"(b)roken " R_UTF8_SKULL_AND_CROSSBONES R_UTF8_VS16 R_UTF8_VS16 R_UTF8_VS16 "  "
			"(c)ommands " R_UTF8_KEYBOARD R_UTF8_VS16 "  "
			"(d)iffchar " R_UTF8_LEFT_POINTING_MAGNIFYING_GLASS "  "
			"(q)uit " R_UTF8_DOOR "\n");
		} else {
			printf ("Wat do?  (f)ix  (F)ixAll  (i)gnore  (b)roken  (c)ommands  (d)iffchar  (q)uit\n");
		}
		char buf[32] = { 0 };
		if (always_fix) {
			printf ("> f\n");
			fflush (stdout);
			r_str_ncpy (buf, "f", sizeof (buf));
		} else {
			printf ("> ");
			fflush (stdout);
			if (!fgets (buf, sizeof (buf) - 1, stdin)) {
				break;
			}
			r_str_trim (buf);
			if (buf[1]) {
				// LOL
				goto menu;
			}
		}
		if (buf[0] == 'F') {
			always_fix = true;
			buf[0] = 'f';
		}
		switch (buf[0]) {
		case 'f':
			if (result->run_failed || result->proc_out->ret != 0) {
				printf ("This test has failed too hard to be fixed.\n");
				goto menu;
			}
			interact_fix (result, &failed_results);
			break;
		case 'i':
			// do nothing on purpose
			break;
		case 'b':
			interact_break (result, &failed_results);
			break;
		case 'c':
			interact_commands (result, &failed_results);
			break;
		case 'd':
			interact_diffchar (result);
			goto menu;
		case 'q':
			goto beach;
		default:
			goto menu;
		}
	}

beach:
	RVecR2RTestResultInfoPtr_fini (&failed_results);
}
