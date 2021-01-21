/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

#include <assert.h>

#define LINEFMT "%s, line %"PFMT64u": "

R_API R2RCmdTest *r2r_cmd_test_new(void) {
	return R_NEW0 (R2RCmdTest);
}

R_API void r2r_cmd_test_free(R2RCmdTest *test) {
	if (!test) {
		return;
	}
#define DO_KEY_STR(key, field) free (test->field.value);
	R2R_CMD_TEST_FOREACH_RECORD(DO_KEY_STR, R2R_CMD_TEST_FOREACH_RECORD_NOP, R2R_CMD_TEST_FOREACH_RECORD_NOP)
#undef DO_KEY_STR
	free (test);
}

static char *readline(char *buf, size_t *linesz) {
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
	} else {
		*linesz = strlen (buf);
		return NULL;
	}
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
// if nextline is at the beginning of line 1,
// read_string_val(&nextline, "<<EOF\0")
// will return "Hello\nWorld\n" with nextline being at the beginning of line 4 afterwards.
static char *read_string_val(char **nextline, const char *val, ut64 *linenum) {
	if (val[0] == '\'') {
		size_t len = strlen (val);
		if (len > 1 && val[len - 1] == '\'') {
			eprintf ("Error: Invalid string syntax, use <<EOF instead of '...'\n");
			return NULL;
		}
	}
	if (val[0] == '<' && val[1] == '<') {
		// <<EOF syntax
		const char *endtoken = val + 2;
		if (!*endtoken) {
			eprintf ("Error: Missing opening end token after <<\n");
			return NULL;
		}
		if (strcmp (endtoken, "EOF") != 0) {
			// In case there will be strings containing "EOF" inside of them, this requirement
			// can be weakened to only apply for strings which do not contain "EOF".
			eprintf ("Error: End token must be \"EOF\", got \"%s\" instead.", endtoken);
			return NULL;
		}
		RStrBuf *buf = r_strbuf_new ("");
		char *line = *nextline;
		size_t linesz = 0;
		do {
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
			r_strbuf_append (buf, line);
			if (end) {
				return r_strbuf_drain (buf);
			} else {
				r_strbuf_append (buf, "\n");
			}
		} while ((line = *nextline));
		eprintf ("Error: Missing closing end token %s\n", endtoken);
		r_strbuf_free (buf);
		return NULL;
	}

	return strdup (val);
}

R_API RPVector *r2r_load_cmd_test_file(const char *file) {
	char *contents = r_file_slurp (file, NULL);
	if (!contents) {
		eprintf ("Failed to open file \"%s\"\n", file);
		return NULL;
	}

	RPVector *ret = r_pvector_new (NULL);
	if (!ret) {
		free (contents);
		return NULL;
	}
	R2RCmdTest *test = r2r_cmd_test_new ();
	if (!test) {
		free (contents);
		r_pvector_free (ret);
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
		char *val = strchr (line, '=');
		if (val) {
			*val = '\0';
			val++;
		}

		// RUN is the only cmd without value
		if (strcmp (line, "RUN") == 0) {
			test->run_line = linenum;
			if (!test->cmds.value) {
				eprintf (LINEFMT "Error: Test without CMDS key\n", file, linenum);
				goto fail;
			}
			if (!(test->expect.value || test->expect_err.value)) {
				if (!(test->regexp_out.value || test->regexp_err.value)) {
					eprintf (LINEFMT "Error: Test without EXPECT or EXPECT_ERR key"
						 " (did you forget an EOF?)\n", file, linenum);
					goto fail;
				}
			}
			r_pvector_push (ret, test);
			test = r2r_cmd_test_new ();
			if (!test) {
				goto beach;
			}
			continue;
		}

#define DO_KEY_STR(key, field) \
		if (strcmp (line, key) == 0) { \
			if (test->field.value) { \
				free (test->field.value); \
				eprintf (LINEFMT "Warning: Duplicate key \"%s\"\n", file, linenum, key); \
			} \
			if (!val) { \
				eprintf (LINEFMT "Error: No value for key \"%s\"\n", file, linenum, key); \
				goto fail; \
			} \
			test->field.line_begin = linenum; \
			test->field.value = read_string_val (&nextline, val, &linenum); \
			test->field.line_end = linenum + 1; \
			if (!test->field.value) { \
				eprintf (LINEFMT "Error: Failed to read value for key \"%s\"\n", file, linenum, key); \
				goto fail; \
			} \
			continue; \
		}

#define DO_KEY_BOOL(key, field) \
		if (strcmp (line, key) == 0) { \
			if (test->field.value) { \
				eprintf (LINEFMT "Warning: Duplicate key \"%s\"\n", file, linenum, key); \
			} \
			test->field.set = true; \
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
				eprintf (LINEFMT "Error: Invalid value \"%s\" for boolean key \"%s\", only \"1\" or \"0\" allowed.\n", file, linenum, val, key); \
				goto fail; \
			} \
			continue; \
		}

#define DO_KEY_NUM(key, field) \
		if (strcmp (line, key) == 0) { \
			if (test->field.value) { \
				eprintf (LINEFMT "Warning: Duplicate key \"%s\"\n", file, linenum, key); \
			} \
			test->field.set = true; \
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
				eprintf (LINEFMT "Error: Invalid value \"%s\" for numeric key \"%s\", only numbers allowed.\n", file, linenum, val, key); \
				goto fail; \
			} \
			continue; \
		}

		R2R_CMD_TEST_FOREACH_RECORD(DO_KEY_STR, DO_KEY_BOOL, DO_KEY_NUM)
#undef DO_KEY_STR
#undef DO_KEY_BOOL
#undef DO_KEY_NUM

		eprintf (LINEFMT "Unknown key \"%s\".\n", file, linenum, line);
	} while ((line = nextline));
beach:
	free (contents);

	if (test && (test->name.value || test->cmds.value || test->expect.value)) {
		eprintf ("Warning: found test tokens at the end of \"%s\" without RUN.\n", file);
	}
	r2r_cmd_test_free (test);
	return ret;
fail:
	r2r_cmd_test_free (test);
	test = NULL;
	r_pvector_free (ret);
	ret = NULL;
	goto beach;
}

R_API R2RAsmTest *r2r_asm_test_new(void) {
	return R_NEW0 (R2RAsmTest);
}

R_API void r2r_asm_test_free(R2RAsmTest *test) {
	if (!test) {
		return;
	}
	free (test->disasm);
	free (test->bytes);
	free (test);
}

static bool parse_asm_path(const char *path, RStrConstPool *strpool, const char **arch_out, const char **cpuout, int *bitsout) {
	RList *file_tokens = r_str_split_duplist (path, R_SYS_DIR, true);
	if (!file_tokens || r_list_empty (file_tokens)) {
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

R_API RPVector *r2r_load_asm_test_file(RStrConstPool *strpool, const char *file) {
	const char *arch;
	const char *cpu;
	int bits;
	if (!parse_asm_path (file, strpool, &arch, &cpu, &bits)) {
		eprintf ("Failed to parse arch/cpu/bits from path %s\n", file);
		return NULL;
	}

	char *contents = r_file_slurp (file, NULL);
	if (!contents) {
		eprintf ("Failed to open file \"%s\"\n", file);
		return NULL;
	}

	RPVector *ret = r_pvector_new (NULL);
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
				eprintf (LINEFMT "Warning: Invalid mode char '%c'\n", file, linenum, *line);
				goto fail;
			}
			line++;
		}
		if (!(mode & R2R_ASM_TEST_MODE_ASSEMBLE) && !(mode & R2R_ASM_TEST_MODE_DISASSEMBLE)) {
			eprintf (LINEFMT "Warning: Mode specifies neither assemble nor disassemble.\n", file, linenum);
			continue;
		}

		char *disasm = strchr (line, '"');
		if (!disasm) {
			eprintf (LINEFMT "Error: Expected \" to begin disassembly.\n", file, linenum);
			goto fail;
		}
		disasm++;
		char *hex = strchr (disasm, '"');
		if (!hex) {
			eprintf (LINEFMT "Error: Expected \" to end disassembly.\n", file, linenum);
			goto fail;
		}
		*hex = '\0';
		hex++;
		r_str_trim (disasm);

		while (*hex && *hex == ' ') {
			hex++;
		}

		char *offset = strchr (hex, ' ');
		if (offset) {
			*offset = '\0';
			offset++;
		}

		size_t hexlen = strlen (hex);
		if (!hexlen) {
			eprintf (LINEFMT "Error: Expected hex chars.\n", file, linenum);
			goto fail;
		}
		ut8 *bytes = malloc (hexlen);
		if (!bytes) {
			break;
		}
		int bytesz = r_hex_str2bin (hex, bytes);
		if (bytesz == 0) {
			eprintf (LINEFMT "Error: Expected hex chars.\n", file, linenum);
			goto fail;
		}
		if (bytesz < 0) {
			eprintf (LINEFMT "Error: Odd number of hex chars: %s\n", file, linenum, hex);
			goto fail;
		}

		R2RAsmTest *test = r2r_asm_test_new ();
		if (!test) {
			free (bytes);
			goto fail;
		}
		test->line = linenum;
		test->bits = bits;
		test->arch = arch;
		test->cpu = cpu;
		test->mode = mode;
		test->offset = offset ? (ut64)strtoull (offset, NULL, 0) : 0;
		test->disasm = strdup (disasm);
		test->bytes = bytes;
		test->bytes_size = (size_t)bytesz;
		r_pvector_push (ret, test);
	} while ((line = nextline));

beach:
	free (contents);
	return ret;
fail:
	r_pvector_free (ret);
	ret = NULL;
	goto beach;
}

R_API R2RJsonTest *r2r_json_test_new(void) {
	return R_NEW0 (R2RJsonTest);
}

R_API void r2r_json_test_free(R2RJsonTest *test) {
	if (!test) {
		return;
	}
	free (test->cmd);
	free (test);
}

R_API RPVector *r2r_load_json_test_file(const char *file) {
	char *contents = r_file_slurp (file, NULL);
	if (!contents) {
		eprintf ("Failed to open file \"%s\"\n", file);
		return NULL;
	}

	RPVector *ret = r_pvector_new (NULL);
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

		R2RJsonTest *test = r2r_json_test_new ();
		if (!test) {
			break;
		}
		test->line = linenum;
		test->cmd = strdup (line);
		if (!test->cmd) {
			r2r_json_test_free (test);
			break;
		}
		test->broken = broken_token ? true : false;
		r_pvector_push (ret, test);
	} while ((line = nextline));

	free (contents);
	return ret;
}

R_API void r2r_fuzz_test_free(R2RFuzzTest *test) {
	if (!test) {
		return;
	}
	free (test->file);
	free (test);
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
	case R2R_TEST_TYPE_FUZZ:
		r2r_fuzz_test_free (test->fuzz_test);
		break;
	}
	free (test);
}

R_API R2RTestDatabase *r2r_test_database_new(void) {
	R2RTestDatabase *db = R_NEW (R2RTestDatabase);
	if (!db) {
		return NULL;
	}
	r_pvector_init (&db->tests, (RPVectorFree)r2r_test_free);
	r_str_constpool_init (&db->strpool);
	return db;
}

R_API void r2r_test_database_free(R2RTestDatabase *db) {
	if (!db) {
		return;
	}
	r_pvector_clear (&db->tests);
	r_str_constpool_fini (&db->strpool);
	free (db);
}

static R2RTestType test_type_for_path(const char *path, bool *load_plugins) {
	R2RTestType ret = R2R_TEST_TYPE_CMD;
	char *pathdup = strdup (path);
	RList *tokens = r_str_split_list (pathdup, R_SYS_DIR, 0);
	if (!tokens) {
		return ret;
	}
	if (!r_list_empty (tokens)) {
		r_list_pop (tokens);
	}
	RListIter *it;
	char *token;
	*load_plugins = false;
	r_list_foreach (tokens, it, token) {
		if (!strcmp (token, "asm")) {
			ret = R2R_TEST_TYPE_ASM;
			continue;
		}
		if (!strcmp (token, "json")) {
			ret = R2R_TEST_TYPE_JSON;
			continue;
		}
		if (!strcmp (token, "extras")) {
			*load_plugins = true;
		}
	}
	r_list_free (tokens);
	free (pathdup);
	return ret;
}

static bool database_load(R2RTestDatabase *db, const char *path, int depth) {
	if (depth <= 0) {
		eprintf ("Directories for loading tests too deep: %s\n", path);
		return false;
	}
	if (r_file_is_directory (path)) {
		RList *dir = r_sys_dir (path);
		if (!dir) {
			return false;
		}
		RListIter *it;
		const char *subname;
		RStrBuf subpath;
		r_strbuf_init (&subpath);
		bool ret = true;
		r_list_foreach (dir, it, subname) {
			if (*subname == '.') {
				continue;
			}
			if (!strcmp (subname, "extras")) {
				// Only load "extras" dirs if explicitly specified
				eprintf ("Skipping %s"R_SYS_DIR"%s because it requires additional dependencies.\n", path, subname);
				continue;
			}
			if ((!strcmp (path, "archos") || r_str_endswith (path, R_SYS_DIR"archos"))
				&& strcmp (subname, R2R_ARCH_OS)) {
				eprintf ("Skipping %s"R_SYS_DIR"%s because it does not match the current platform.\n", path, subname);
				continue;
			}
			r_strbuf_setf (&subpath, "%s%s%s", path, R_SYS_DIR, subname);
			if (!database_load (db, r_strbuf_get (&subpath), depth - 1)) {
				ret = false;
				break;
			}
		}
		r_strbuf_fini (&subpath);
		r_list_free (dir);
		return ret;
	}

	if (!r_file_exists (path)) {
		eprintf ("Path \"%s\" does not exist\n", path);
		return false;
	}

	// Not a directory but exists, load a file
	const char *pooled_path = r_str_constpool_get (&db->strpool, path);
	bool load_plugins = false;
	R2RTestType test_type = test_type_for_path (path, &load_plugins);
	switch (test_type) {
	case R2R_TEST_TYPE_CMD: {
		RPVector *cmd_tests = r2r_load_cmd_test_file (path);
		if (!cmd_tests) {
			return false;
		}
		void **it;
		r_pvector_foreach (cmd_tests, it) {
			R2RTest *test = R_NEW (R2RTest);
			if (!test) {
				continue;
			}
			test->type = R2R_TEST_TYPE_CMD;
			test->path = pooled_path;
			test->cmd_test = *it;
			test->cmd_test->load_plugins = load_plugins;
			r_pvector_push (&db->tests, test);
		}
		r_pvector_free (cmd_tests);
		break;
	}
	case R2R_TEST_TYPE_ASM: {
		RPVector *asm_tests = r2r_load_asm_test_file (&db->strpool, path);
		if (!asm_tests) {
			return false;
		}
		void **it;
		r_pvector_foreach (asm_tests, it) {
			R2RTest *test = R_NEW (R2RTest);
			if (!test) {
				continue;
			}
			test->type = R2R_TEST_TYPE_ASM;
			test->path = pooled_path;
			test->asm_test = *it;
			r_pvector_push (&db->tests, test);
		}
		r_pvector_free (asm_tests);
		break;
	}
	case R2R_TEST_TYPE_JSON: {
		RPVector *json_tests = r2r_load_json_test_file (path);
		if (!json_tests) {
			return false;
		}
		void **it;
		r_pvector_foreach (json_tests, it) {
			R2RTest *test = R_NEW (R2RTest);
			if (!test) {
				continue;
			}
			test->type = R2R_TEST_TYPE_JSON;
			test->path = pooled_path;
			test->json_test = *it;
			test->json_test->load_plugins = load_plugins;
			r_pvector_push (&db->tests, test);
		}
		r_pvector_free (json_tests);
		break;
	}
	case R2R_TEST_TYPE_FUZZ:
		// shouldn't come here, fuzz tests are loaded differently
		break;
	}

	return true;
}

R_API bool r2r_test_database_load(R2RTestDatabase *db, const char *path) {
	return database_load (db, path, 4);
}

static void database_load_fuzz_file(R2RTestDatabase *db, const char *path, const char *file) {
	R2RFuzzTest *fuzz_test = R_NEW (R2RFuzzTest);
	if (!fuzz_test) {
		return;
	}
	fuzz_test->file = strdup (file);
	if (!fuzz_test->file) {
		free (fuzz_test);
		return;
	}
	R2RTest *test = R_NEW (R2RTest);
	if (!test) {
		free (fuzz_test->file);
		free (fuzz_test);
		return;
	}
	test->type = R2R_TEST_TYPE_FUZZ;
	test->fuzz_test = fuzz_test;
	test->path = r_str_constpool_get (&db->strpool, path);
	r_pvector_push (&db->tests, test);
}

R_API bool r2r_test_database_load_fuzz(R2RTestDatabase *db, const char *path) {
	if (r_file_is_directory (path)) {
		RList *dir = r_sys_dir (path);
		if (!dir) {
			return false;
		}
		RListIter *it;
		const char *subname;
		RStrBuf subpath;
		r_strbuf_init (&subpath);
		bool ret = true;
		r_list_foreach (dir, it, subname) {
			if (*subname == '.') {
				continue;
			}
			r_strbuf_setf (&subpath, "%s%s%s", path, R_SYS_DIR, subname);
			if (r_file_is_directory (r_strbuf_get (&subpath))) {
				// only load 1 level deep
				continue;
			}
			database_load_fuzz_file (db, path, r_strbuf_get (&subpath));
		}
		r_strbuf_fini (&subpath);
		r_list_free (dir);
		return ret;
	}

	if (!r_file_exists (path)) {
		eprintf ("Path \"%s\" does not exist\n", path);
		return false;
	}

	// Just a single file
	database_load_fuzz_file (db, path, path);
	return true;
}
