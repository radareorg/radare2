/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

#include <assert.h>

#define LINEFMT "%s, line %"PFMT64u": "

R_API R2RCmdTest *r2r_cmd_test_new() {
	return R_NEW0 (R2RCmdTest);
}

R_API void r2r_cmd_test_free(R2RCmdTest *test) {
	if (!test) {
		return;
	}
#define DO_KEY_STR(key, field) free (test->field.value);
	R2R_CMD_TEST_FOREACH_RECORD(DO_KEY_STR, R2R_CMD_TEST_FOREACH_RECORD_NOP)
#undef DO_KEY_STR
	free (test);
}

static char *readline(char *buf, size_t *linesz) {
	char *end = strchr (buf, '\n');
	if (end) {
		*end = '\0';
		*linesz = end - buf;
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
		eprintf ("Error: Invalid string syntax, use <<EOF instead of '...'\n");
		return NULL;
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

	RPVector *ret = r_pvector_new ((RPVectorFree)r2r_cmd_test_free);
	if (!ret) {
		return NULL;
	}
	R2RCmdTest *test = r2r_cmd_test_new ();
	if (!test) {
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
		char *val = strchr (line, '=');
		if (val) {
			*val = '\0';
			val++;
		}

		// RUN is the only cmd without value
		if (strcmp (line, "RUN") == 0) {
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
			test->field.line_begin = linenum; \
			test->field.value = read_string_val (&nextline, val, &linenum); \
			test->field.line_end = linenum; \
			if (!test->field.value) { \
				eprintf (LINEFMT "Error: Failed to read value for key \"%s\"\n", file, linenum, key); \
			} \
			continue; \
		}

#define DO_KEY_BOOL(key, field) \
		if (strcmp (line, key) == 0) { \
			if (test->field.value) { \
				eprintf (LINEFMT "Warning: Duplicate key \"%s\"\n", file, linenum, key); \
			} \
			if (strcmp (val, "1") != 0) { \
				eprintf (LINEFMT "Error: Invalid value for boolean key \"%s\", only \"1\" allowed.\n", file, linenum, key); \
			} \
			continue; \
		}

		R2R_CMD_TEST_FOREACH_RECORD(DO_KEY_STR, DO_KEY_BOOL)
#undef DO_KEY_STR
#undef DO_KEY_BOOL

		eprintf (LINEFMT "Unknown key \"%s\".\n", file, linenum, line);
	} while ((line = nextline));
beach:
	free (contents);

	if (test && (test->name.value || test->cmds.value || test->expect.value)) {
		eprintf ("Warning: found test tokens at the end of \"%s\" without RUN.\n", file);
	}
	r2r_cmd_test_free (test);
	return ret;
}

static void r2r_test_free(R2RTest *test) {
	if (!test) {
		return;
	}
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		r2r_cmd_test_free (test->cmd_test);
		break;
	default:
		assert (false); // TODO: other types
	}
}

R_API R2RTestDatabase *r2r_test_database_new() {
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

static R2RTestType test_type_for_path(const char *path) {
	return R2R_TEST_TYPE_CMD;
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
	R2RTestType test_type = test_type_for_path (path);
	switch (test_type) {
	case R2R_TEST_TYPE_CMD: {
		RPVector *cmd_tests = r2r_load_cmd_test_file (path);
		if (!cmd_tests) {
			return false;
		}
		cmd_tests->v.free = NULL;
		cmd_tests->v.free_user = NULL;
		void **it;
		r_pvector_foreach (cmd_tests, it) {
			R2RTest *test = R_NEW (R2RTest);
			if (!test) {
				continue;
			}
			test->type = R2R_TEST_TYPE_CMD;
			test->path = pooled_path;
			test->cmd_test = *it;
			r_pvector_push (&db->tests, test);
		}
		r_pvector_free (cmd_tests);
		break;
	}
	default:
		assert (false); // TODO: other types
	}

	return true;
}

R_API bool r2r_test_database_load(R2RTestDatabase *db, const char *path) {
	return database_load (db, path, 4);
}
