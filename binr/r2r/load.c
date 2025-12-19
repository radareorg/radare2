/* radare - LGPL - Copyright 2020-2025 - pancake, thestr4ng3r */

#undef R_LOG_ORIGIN
#define R_LOG_ORIGIN "r2r.load"

#include "r2r.h"

#define LINEFMT "%s, line %" PFMT64u ": "

R_API R2RCmdTest *r2r_cmd_test_new(void) {
	return R_NEW0 (R2RCmdTest);
}

R_API void r2r_cmd_test_free(R2RCmdTest *test) {
	if (!test) {
		return;
	}
#define DO_KEY_STR(key, field) free(test->field.value);
	R2R_CMD_TEST_FOREACH_RECORD (DO_KEY_STR, R2R_CMD_TEST_FOREACH_RECORD_NOP, R2R_CMD_TEST_FOREACH_RECORD_NOP)
#undef DO_KEY_STR
	free (test);
}

static char *readline(char *buf, size_t *linesz) {
	R_RETURN_VAL_IF_FAIL (buf && linesz, NULL);
	char *end = strchr (buf, '\n');
	if (end) {
		size_t len = end - buf;
		*end = '\0';
		if (len > 0 && buf[len - 1] == '\r') {
			buf[len - 1] = '\0';
			len--;
		}
		*linesz = len;
		return end + 1;
	}
	*linesz = strlen (buf);
	return NULL;
}

// read the (possibly multiline) string value of some key in the file
// e.g. for
//
// 0    CMDS=<<EOF
// 1    Hello
// 2    World
// 3    EOF
// 4    ...
//
// if nextline is at the beginning of line 1,"
// read_string_val (&nextline, "<<EOF\0")
// will return "Hello\nWorld\n" with nextline being at the beginning of line 4 afterwards.
static char *read_string_val(char **nextline, const char *val, ut64 *linenum) {
	if (val[0] == '\'') {
		size_t len = strlen (val);
		if (len > 1 && val[len - 1] == '\'') {
			R_LOG_ERROR ("Invalid string syntax, use <<EOF instead of '...'");
			return NULL;
		}
	}
	if (val[0] == '<' && val[1] == '<') {
		// <<EOF syntax
		const char *endtoken = val + 2;
		if (!*endtoken) {
			R_LOG_ERROR ("Missing opening end token after <<");
			return NULL;
		}
		RStrBuf *sb = r_strbuf_new (NULL);
		r_strbuf_reserve (sb, 8192);
		char *line = *nextline;
		size_t linesz = 0;
		while (line) {
			*nextline = readline (line, &linesz);
			(*linenum)++;
			char *end = strstr (line, endtoken);
			if (end != line) {
				// Require the EOF to be at the beginning of the line.
				// This means makes it impossible to write multiline tests without a trailing newline.
				// This requirement could be lifted later if necessary.
				end = NULL;
			}
			if (end) {
				*end = '\0';
			}
			r_strbuf_append (sb, line);
			if (end) {
				return r_strbuf_drain (sb);
			}
			r_strbuf_append (sb, "\n");
			line = *nextline;
		}
		R_LOG_ERROR ("Missing closing end token %s", endtoken);
		r_strbuf_free (sb);
		return NULL;
	}

	return strdup (val);
}

R_API RVecR2RCmdTestPtr *r2r_load_cmd_test_file(const char *file) {
	char *contents = r_file_slurp (file, NULL);
	if (!contents) {
		R_LOG_ERROR ("Failed to open %s", file);
		return NULL;
	}

	RVecR2RCmdTestPtr *ret = RVecR2RCmdTestPtr_new ();
	if (!ret) {
		free (contents);
		return NULL;
	}
	R2RCmdTest *test = r2r_cmd_test_new ();

	ut64 linenum = 0;
	char *line = contents;
	size_t linesz;
	char *nextline;
	do {
		nextline = readline (line, &linesz);
		linenum++;
		if (!linesz) {
			continue;
		}
		if (*line == '#') {
			continue;
		}
		char *val = strchr (line, '=');
		if (val) {
			*val = '\0';
			val++;
		}

		// RUN is the only cmd without value
		if (!strcmp (line, "NORUN")) {
			// dont run this test, like if it was commented out
			continue;
		}
		if (!strcmp (line, "RUN")) {
			test->run_line = linenum;
			if (!test->cmds.value) {
				R_LOG_ERROR (LINEFMT ": Test without CMDS key", file, linenum);
				goto fail;
			}
			if (! (test->expect.value || test->expect_err.value)) {
				if (! (test->regexp_out.value || test->regexp_err.value)) {
					R_LOG_ERROR (LINEFMT ": Test without EXPECT or EXPECT_ERR key, missing EOF?", file, linenum);
					goto fail;
				}
			}
			RVecR2RCmdTestPtr_push_back (ret, &test);
			test = r2r_cmd_test_new ();
			if (!test) {
				goto beach;
			}
			continue;
		}

#define DO_KEY_STR(key, field) \
	if (!strcmp (line, key)) { \
		if (test->field.value) { \
			free (test->field.value); \
			R_LOG_WARN (LINEFMT ": Duplicate key \"%s\"", file, linenum, key); \
		} \
		if (!val) { \
			R_LOG_ERROR (LINEFMT ": No value for key \"%s\"", file, linenum, key); \
			goto fail; \
		} \
		test->field.line_begin = linenum; \
		test->field.value = read_string_val (&nextline, val, &linenum); \
		test->field.line_end = linenum + 1; \
		if (!test->field.value) { \
			R_LOG_ERROR (LINEFMT ": Failed to read value for key \"%s\"", file, linenum, key); \
			goto fail; \
		} \
		continue; \
	}

#define DO_KEY_BOOL(key, field) \
	if (!strcmp (line, key)) { \
		if (test->field.value) { \
			R_LOG_WARN (LINEFMT ": Duplicate key \"%s\"", file, linenum, key); \
		} \
		test->field.set = true; \
		if (!val) { \
			R_LOG_ERROR (LINEFMT ": No value for key \"%s\"", file, linenum, key); \
			goto fail; \
		} \
		/* Strip comment */ \
		char *cmt = strchr (val, '#'); \
		if (cmt) { \
			*cmt = '\0'; \
			cmt--; \
			while (cmt > val && *cmt == ' ') { \
				*cmt = '\0'; \
				cmt--; \
			} \
		} \
		if (!strcmp (val, "1")) { \
			test->field.value = true; \
		} else if (!strcmp (val, "0")) { \
			test->field.value = false; \
		} else { \
			R_LOG_ERROR (LINEFMT ": Invalid value \"%s\" for boolean key \"%s\", only \"1\" or \"0\" allowed", file, linenum, val, key); \
			goto fail; \
		} \
		continue; \
	}

#define DO_KEY_NUM(key, field) \
	if (!strcmp (line, key)) { \
		if (test->field.value) { \
			R_LOG_WARN (LINEFMT ": Duplicate key \"%s\"", file, linenum, key); \
		} \
		test->field.set = true; \
		if (!val) { \
			R_LOG_ERROR (LINEFMT ": No value for key \"%s\"", file, linenum, key); \
			goto fail; \
		} \
		/* Strip comment */ \
		char *cmt = strchr (val, '#'); \
		if (cmt) { \
			*cmt = '\0'; \
			cmt--; \
			while (cmt > val && *cmt == ' ') { \
				*cmt = '\0'; \
				cmt--; \
			} \
		} \
		char *endval; \
		test->field.value = strtol (val, &endval, 0); \
		if (!endval || *endval) { \
			R_LOG_ERROR (LINEFMT ": Invalid value \"%s\" for numeric key \"%s\", only numbers allowed", file, linenum, val, key); \
			goto fail; \
		} \
		continue; \
	}

		R2R_CMD_TEST_FOREACH_RECORD (DO_KEY_STR, DO_KEY_BOOL, DO_KEY_NUM)
#undef DO_KEY_STR
#undef DO_KEY_BOOL
#undef DO_KEY_NUM

		R_LOG_ERROR (LINEFMT ": Unknown key \"%s\"", file, linenum, line);
		break;
	} while ((line = nextline));
beach:
	free (contents);

	if (test && (test->name.value || test->cmds.value || test->expect.value)) {
		R_LOG_WARN ("found test tokens at the end of \"%s\" without RUN", file);
	}
	r2r_cmd_test_free (test);
	return ret;
fail:
	r2r_cmd_test_free (test);
	test = NULL;
	RVecR2RCmdTestPtr_free (ret);
	ret = NULL;
	goto beach;
}

R_API void r2r_asm_test_free(R2RAsmTest *test) {
	if (test != NULL) {
		free (test->disasm);
		free (test->bytes);
		free (test);
	}
}

static bool parse_asm_path(const char *path, RStrConstPool *strpool, const char **arch_out, const char **cpuout, int *bitsout) {
	RList *file_tokens = r_str_split_duplist (path, R_SYS_DIR, true);
	if (r_list_empty (file_tokens)) {
		r_list_free (file_tokens);
		return false;
	}

	// Possibilities:
	// arm
	// arm_32
	// arm_cortex_32

	char *arch = r_list_last (file_tokens);
	if (!*arch) {
		r_list_free (file_tokens);
		return false;
	}
	char *second = strchr (arch, '_');
	if (second) {
		*second = '\0';
		second++;
		char *third = strchr (second, '_');
		if (third) {
			*third = '\0';
			third++;
			*cpuout = r_str_constpool_get (strpool, second);
			*bitsout = atoi (third);
		} else {
			*cpuout = NULL;
			*bitsout = atoi (second);
		}
	} else {
		*cpuout = NULL;
		*bitsout = 0;
	}
	*arch_out = r_str_constpool_get (strpool, arch);
	r_list_free (file_tokens);
	return true;
}

R_API RVecR2RAsmTestPtr *r2r_load_asm_test_file(RStrConstPool *strpool, const char *file) {
	const char *arch;
	const char *cpu;
	int bits;
	if (!parse_asm_path (file, strpool, &arch, &cpu, &bits)) {
		R_LOG_ERROR ("Failed to parse arch/cpu/bits from path %s", file);
		return NULL;
	}

	char *contents = r_file_slurp (file, NULL);
	if (!contents) {
		R_LOG_ERROR ("Failed to open file \"%s\"", file);
		return NULL;
	}

	RVecR2RAsmTestPtr *ret = RVecR2RAsmTestPtr_new ();
	if (!ret) {
		return NULL;
	}

	ut64 linenum = 0;
	char *line = contents;
	size_t linesz;
	char *nextline;
	do {
		nextline = readline (line, &linesz);
		linenum++;
		if (!linesz) {
			continue;
		}
		if (*line == '#') {
			continue;
		}

		int mode = 0;
		while (*line && *line != ' ') {
			switch (*line) {
			case 'a':
				mode |= R2R_ASM_TEST_MODE_ASSEMBLE;
				break;
			case 'd':
				mode |= R2R_ASM_TEST_MODE_DISASSEMBLE;
				break;
			case 'E':
				mode |= R2R_ASM_TEST_MODE_BIG_ENDIAN;
				break;
			case 'B':
				mode |= R2R_ASM_TEST_MODE_BROKEN;
				break;
			default:
				R_LOG_WARN (LINEFMT ": Invalid mode char '%c'", file, linenum, *line);
				goto fail;
			}
			line++;
		}
		if (! (mode & R2R_ASM_TEST_MODE_ASSEMBLE) && ! (mode & R2R_ASM_TEST_MODE_DISASSEMBLE)) {
			R_LOG_WARN (LINEFMT "Mode specifies neither assemble nor disassemble", file, linenum);
			continue;
		}

		char *disasm = strchr (line, '"');
		if (!disasm) {
			R_LOG_ERROR (LINEFMT ": Expected \" to begin disassembly", file, linenum);
			goto fail;
		}
		disasm++;
		char *hex = strchr (disasm, '"');
		if (!hex) {
			R_LOG_ERROR (LINEFMT ": Expected \" to end disassembly", file, linenum);
			goto fail;
		}
		*hex = '\0';
		hex = (char *)r_str_trim_head_ro (hex + 1);
		r_str_trim (disasm);

		char *offset = strchr (hex, ' ');
		if (offset) {
			*offset = '\0';
			offset++;
		}

		size_t hexlen = strlen (hex);
		if (!hexlen) {
			R_LOG_ERROR (LINEFMT ": Expected hex chars", file, linenum);
			goto fail;
		}
		ut8 *bytes = malloc (hexlen);
		if (!bytes) {
			break;
		}
		int bytesz = r_hex_str2bin (hex, bytes);
		if (bytesz == 0) {
			R_LOG_ERROR (LINEFMT "Expected hex chars", file, linenum);
			goto fail;
		}
		if (bytesz < 0) {
			R_LOG_ERROR (LINEFMT ": Odd number of hex chars: %s", file, linenum, hex);
			goto fail;
		}

		R2RAsmTest *test = R_NEW0 (R2RAsmTest);
		test->line = linenum;
		test->bits = bits;
		test->arch = arch;
		test->cpu = cpu;
		test->mode = mode;
		test->offset = offset? (ut64)strtoull (offset, NULL, 0): 0;
		test->disasm = strdup (disasm);
		test->bytes = bytes;
		test->bytes_size = (size_t)bytesz;
		RVecR2RAsmTestPtr_push_back (ret, &test);
	} while ((line = nextline));
beach:
	free (contents);
	return ret;
fail:
	RVecR2RAsmTestPtr_free (ret);
	ret = NULL;
	goto beach;
}

R_API void r2r_json_test_free(R2RJsonTest *test) {
	if (R_LIKELY (test)) {
		free (test->cmd);
		free (test);
	}
}

R_API RVecR2RJsonTestPtr *r2r_load_json_test_file(const char *file) {
	char *contents = r_file_slurp (file, NULL);
	if (!contents) {
		R_LOG_ERROR ("Failed to open %s", file);
		return NULL;
	}

	RVecR2RJsonTestPtr *ret = RVecR2RJsonTestPtr_new ();
	if (!ret) {
		free (contents);
		return NULL;
	}

	ut64 linenum = 0;
	char *line = contents;
	size_t linesz;
	char *nextline;
	do {
		nextline = readline (line, &linesz);
		linenum++;
		if (!linesz) {
			continue;
		}
		if (*line == '#') {
			continue;
		}

		char *broken_token = strstr (line, "BROKEN");
		if (broken_token) {
			*broken_token = '\0';
		}

		r_str_trim (line);
		if (!*line) {
			// empty line
			continue;
		}

		R2RJsonTest *test = R_NEW0 (R2RJsonTest);
		test->line = linenum;
		test->cmd = strdup (line);
		if (!test->cmd) {
			r2r_json_test_free (test);
			break;
		}
		test->broken = broken_token? true: false;
		RVecR2RJsonTestPtr_push_back (ret, &test);
	} while ((line = nextline));

	free (contents);
	return ret;
}

static R2RTest *r2r_test_new(R2RTestType type, const char *path, void *specific_test, bool load_plugins) {
	R2RTest *test = R_NEW (R2RTest);
	test->type = type;
	test->path = path;
	switch (type) {
	case R2R_TEST_TYPE_CMD:
		test->cmd_test = specific_test;
		test->cmd_test->load_plugins = load_plugins;
		break;
	case R2R_TEST_TYPE_ASM:
		test->asm_test = specific_test;
		break;
	case R2R_TEST_TYPE_JSON:
		test->json_test = specific_test;
		test->json_test->load_plugins = load_plugins;
		break;
	case R2R_TEST_TYPE_LEAK:
		test->cmd_test = specific_test;
		test->cmd_test->load_plugins = load_plugins;
		break;
	case R2R_TEST_TYPE_FUZZ:
		break;
	}
	return test;
}

R_API void r2r_test_free(R2RTest *test) {
	if (!test) {
		return;
	}
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		r2r_cmd_test_free (test->cmd_test);
		break;
	case R2R_TEST_TYPE_ASM:
		r2r_asm_test_free (test->asm_test);
		break;
	case R2R_TEST_TYPE_JSON:
		r2r_json_test_free (test->json_test);
		break;
	case R2R_TEST_TYPE_LEAK:
		r2r_cmd_test_free (test->cmd_test);
		break;
	case R2R_TEST_TYPE_FUZZ:
		break;
	}
	free (test);
}

R_API R2RTestDatabase *R_NONNULL r2r_test_database_new(void) {
	R2RTestDatabase *db = R_NEW (R2RTestDatabase);
	RVecR2RTestPtr_init (&db->tests);
	r_str_constpool_init (&db->strpool);
	return db;
}

R_API void r2r_test_database_free(R2RTestDatabase *db) {
	if (!db) {
		return;
	}
	R2RTest **it;
	R_VEC_FOREACH (&db->tests, it) {
		r2r_test_free (*it);
	}
	RVecR2RTestPtr_fini (&db->tests);
	r_str_constpool_fini (&db->strpool);
	free (db);
}

R_IPI const char *getarchos(void);

static R2RTestFrom test_type_for_path(const char *path) {
	R2RTestFrom res = { 0 };
	res.load_plugins = false;
	if (strstr (path, R_SYS_DIR "asm" R_SYS_DIR)) {
		res.type = R2R_TEST_TYPE_ASM;
	} else if (strstr (path, R_SYS_DIR "json" R_SYS_DIR)) {
		res.type = R2R_TEST_TYPE_JSON;
	} else if (strstr (path, R_SYS_DIR "leak" R_SYS_DIR)) {
		res.type = R2R_TEST_TYPE_LEAK;
	} else {
		if (strstr (path, R_SYS_DIR "extras" R_SYS_DIR)) {
			res.load_plugins = true;
		}
		res.type = R2R_TEST_TYPE_CMD;
	}
	res.archos = false;
	if ((strstr (path, R_SYS_DIR "archos" R_SYS_DIR) || !strcmp (path, "archos")) &&
	    strcmp (path + strlen (path) - strlen (getarchos ()), getarchos ())) {
		res.archos = true;
	}
	return res;
}

static bool database_load(R2RTestDatabase *db, const char *path, int depth, bool skip_json_tests, bool skip_leak_tests) {
#if WANT_V35 == 0
	R2RTestToSkip v35_tests_to_skip[] = {
		{ "asm", "arm.v35_64" },
		{ "esil", "arm_64" },
		{ "tools", "rasm2" },
	};
#endif
	if (depth <= 0) {
		R_LOG_ERROR ("Directories for loading tests too deep: %s", path);
		return false;
	}
	R2RTestFrom test_from = test_type_for_path (path);
	if (r_file_is_directory (path)) {
		const char *archos = getarchos ();
		RList *dir = r_sys_dir (path);
		if (!dir) {
			return false;
		}
		RListIter *it;
		const char *subname;
		const bool skip_archos = r_sys_getenv_asbool ("R2R_SKIP_ARCHOS");
		const bool skip_asm = r_sys_getenv_asbool ("R2R_SKIP_ASM");
		bool ret = true;
		r_list_foreach (dir, it, subname) {
			if (*subname == '.') {
				continue;
			}
			if (!strcmp (subname, "extras")) {
				// Only load "extras" dirs if explicitly specified
				R_LOG_WARN ("Skipping %s" R_SYS_DIR "%s because it requires additional dependencies", shortpath (path), subname);
				continue;
			}
#if WANT_V35 == 0
			bool skip = false;
			size_t i = 0;
			for (; i < sizeof (v35_tests_to_skip) / sizeof (R2RTestToSkip); i++) {
				R2RTestToSkip test = v35_tests_to_skip[i];
				char *testdir = r_str_newf (R_SYS_DIR "%s", test.dir);
				bool is_dir = r_str_endswith (path, testdir);
				free (testdir);
				if (is_dir) {
					if (!strcmp (subname, test.name)) {
						R_LOG_WARN ("Skipping test %s" R_SYS_DIR "%s because it requires arm.v35", shortpath (path), subname);
						skip = true;
						break;
					}
				}
			}
			if (skip) {
				continue;
			}
#endif
			if (skip_asm && test_from.type == R2R_TEST_TYPE_ASM) {
				R_LOG_INFO ("R2R_SKIP_ASM: Skipping %s", shortpath (path));
				continue;
			}
			if (test_from.archos && (skip_archos || strcmp (subname, archos))) {
				R_LOG_INFO ("Skipping %s" R_SYS_DIR "%s because it does not match the current platform \"%s\"", shortpath (path), subname, archos);
				continue;
			}
			char *subpath = r_file_new (path, subname, NULL);
			ret = database_load (db, subpath, depth - 1, skip_json_tests, skip_leak_tests);
			free (subpath);
			if (!ret) {
				break;
			}
		}
		r_list_free (dir);
		return ret;
	}

	if (!r_file_exists (path)) {
		R_LOG_ERROR ("Path \"%s\" does not exist", path);
		return false;
	}

	// Not a directory but exists, load a file
	const char *pooled_path = r_str_constpool_get (&db->strpool, path);
	R2RTestFrom tff = test_type_for_path (path);
	if (skip_json_tests && tff.type == R2R_TEST_TYPE_JSON) {
		return true;
	}
	if (skip_leak_tests && tff.type == R2R_TEST_TYPE_LEAK) {
		return true;
	}
	switch (tff.type) {
	case R2R_TEST_TYPE_CMD:
		{
			RVecR2RCmdTestPtr *cmd_tests = r2r_load_cmd_test_file (path);
			if (!cmd_tests) {
				return false;
			}
			R2RCmdTest **it;
			R_VEC_FOREACH (cmd_tests, it) {
				R2RTest *test = r2r_test_new (R2R_TEST_TYPE_CMD, pooled_path, *it, tff.load_plugins);
				RVecR2RTestPtr_push_back (&db->tests, &test);
			}
			RVecR2RCmdTestPtr_free (cmd_tests);
			break;
		}
	case R2R_TEST_TYPE_ASM:
		{
			RVecR2RAsmTestPtr *asm_tests = r2r_load_asm_test_file (&db->strpool, path);
			if (!asm_tests) {
				return false;
			}
			R2RAsmTest **it;
			R_VEC_FOREACH (asm_tests, it) {
				R2RTest *test = r2r_test_new (R2R_TEST_TYPE_ASM, pooled_path, *it, false);
				RVecR2RTestPtr_push_back (&db->tests, &test);
			}
			RVecR2RAsmTestPtr_free (asm_tests);
			break;
		}
	case R2R_TEST_TYPE_JSON:
		{
			RVecR2RJsonTestPtr *json_tests = r2r_load_json_test_file (path);
			if (!json_tests) {
				return false;
			}
			R2RJsonTest **it;
			R_VEC_FOREACH (json_tests, it) {
				R2RTest *test = r2r_test_new (R2R_TEST_TYPE_JSON, pooled_path, *it, tff.load_plugins);
				RVecR2RTestPtr_push_back (&db->tests, &test);
			}
			RVecR2RJsonTestPtr_free (json_tests);
			break;
		}
	case R2R_TEST_TYPE_LEAK:
		{
			RVecR2RCmdTestPtr *cmd_tests = r2r_load_cmd_test_file (path);
			if (!cmd_tests) {
				return false;
			}
			R2RCmdTest **it;
			R_VEC_FOREACH (cmd_tests, it) {
				R2RTest *test = r2r_test_new (R2R_TEST_TYPE_LEAK, pooled_path, *it, tff.load_plugins);
				RVecR2RTestPtr_push_back (&db->tests, &test);
			}
			RVecR2RCmdTestPtr_free (cmd_tests);
			break;
		}
	case R2R_TEST_TYPE_FUZZ:
		// shouldn't come here, fuzz tests are loaded differently
		break;
	}

	return true;
}

R_API bool r2r_test_database_load(R2RTestDatabase *db, const char *path, bool skip_json_tests, bool skip_leak_tests) {
	return database_load (db, path, 4, skip_json_tests, skip_leak_tests);
}

static void database_load_fuzz_file(R2RTestDatabase *db, const char *path, const char *file) {
	R2RTest *test = r2r_test_new (R2R_TEST_TYPE_FUZZ, r_str_constpool_get (&db->strpool, file), NULL, false);
	RVecR2RTestPtr_push_back (&db->tests, &test);
}

R_API bool r2r_test_database_load_fuzz(R2RTestDatabase *db, const char *path) {
	if (r_file_is_directory (path)) {
		RList *dir = r_sys_dir (path);
		if (!dir) {
			return false;
		}
		RListIter *it;
		const char *subname;
		r_list_foreach (dir, it, subname) {
			if (*subname == '.') {
				continue;
			}
			char *subpath = r_file_new (path, subname, NULL);
			if (!r_file_is_directory (subpath)) {
				database_load_fuzz_file (db, path, subpath);
			}
			free (subpath);
		}
		r_list_free (dir);
		return true;
	}
	if (!r_file_exists (path)) {
		R_LOG_ERROR ("Path \"%s\" does not exist", path);
		return false;
	}
	database_load_fuzz_file (db, path, path);
	return true;
}
