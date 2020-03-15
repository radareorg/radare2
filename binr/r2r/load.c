/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

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
// if f is at the beginning of line 1,
// read_string_val(f, "<<EOF\0")
// will return "Hello\nWorld\n" with f being at the beginning of line 4 afterwards.
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
