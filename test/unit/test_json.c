/*
 * Copyright (c) 2013 Yaroslav Stavnichiy <yarosla@gmail.com>
 *
 * This file is part of NXJSON.
 *
 * NXJSON is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * NXJSON is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with NXJSON. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "nxjson.h"

#define ERROR(msg, p) fprintf(stderr, "ERROR: " msg " %s\n", (p));

static char *load_file(const char *filepath) {
	struct stat st;
	if (stat (filepath, &st) == -1) {
		// ERROR("can't find file", filepath);
		return 0;
	}
	int fd = open (filepath, O_RDONLY);
	if (fd == -1) {
		ERROR("can't open file", filepath);
		return 0;
	}
	char *text = malloc (st.st_size + 1); // this is not going to be freed
	if (st.st_size != read (fd, text, st.st_size)) {
		ERROR("can't read file", filepath);
		close (fd);
		return 0;
	}
	close (fd);
	text[st.st_size] = '\0';
	return text;
}

static int save_file(const char *filepath, const char *text) {
	int fd = open (filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		ERROR("can't open file", filepath);
		return -1;
	}
	int length = strlen (text);
	if (length != write (fd, text, length)) {
		ERROR("can't write file", filepath);
		close (fd);
		return -1;
	}
	close (fd);
	return 0;
}

static void dump(const nx_json *json, char *out, char **end, int indent) {
	if (!json) {
		*end = out;
		return;
	}
	int i;
	for (i = 0; i < indent; i++) *out++ = ' ';
	if (json->key) {
		strcpy (out, json->key);
		out += strlen (json->key);
		*out++ = ':';
	}
	switch (json->type) {
	case NX_JSON_NULL:
		strcpy (out, "null");
		out += 4;
		break;
	case NX_JSON_OBJECT:
		*out++ = '{';
		*out++ = '\n';
		{
			nx_json *js = json->children.first;
			for (js = json->children.first; js; js = js->next) {
				dump (js, out, &out, indent + 2);
			}
		}
		for (i = 0; i < indent; i++) *out++ = ' ';
		*out++ = '}';
		break;
	case NX_JSON_ARRAY:
		*out++ = '[';
		*out++ = '\n';
		{
			nx_json *js = json->children.first;
			for (js = json->children.first; js; js = js->next) {
				dump (js, out, &out, indent + 2);
			}
		}
		for (i = 0; i < indent; i++) *out++ = ' ';
		*out++ = ']';
		break;
	case NX_JSON_STRING:
		*out++ = '"';
		strcpy (out, json->text_value);
		out += strlen (json->text_value);
		*out++ = '"';
		break;
	case NX_JSON_INTEGER:
		out += sprintf (out, "%lld", (long long) json->num.s_value);
		break;
	case NX_JSON_DOUBLE:
		out += sprintf (out, "%le", json->num.dbl_value);
		break;
	case NX_JSON_BOOL:
		*out++ = json->num.s_value ? 'T' : 'F';
		break;
	default:
		strcpy (out, "????");
		out += 4;
		break;
	}
	*out++ = '\n';
	*end = out;
}

#define FMT_PASSED "\x1b[32m[%03d] PASSED\x1b[0m\n"
#define FMT_FAILED "\x1b[31m[%03d] FAILED\x1b[0m\n"

static int run_test(int test_number, char *input, const char *expected_output) {
	int input_length = strlen (input);
	const nx_json *json = nx_json_parse_utf8 (input);
	if (!json) {
		if (!expected_output) {
			printf (FMT_PASSED, test_number);
			return 1;
		} else {
			printf (FMT_FAILED, test_number);
			return 0;
		}
	}
	char *buf = malloc (input_length * 32 + 4000000); // hope this will be large enough; depends on nesting & indenting
	char *p = buf;
	dump (json, p, &p, 0);
	nx_json_free (json);
	*p = '\0';

	char fname[32];
	sprintf (fname, "tests/%03d.result", test_number);
	save_file (fname, buf);

	if (!expected_output) {
		printf (FMT_FAILED, test_number);
		free (buf);
		return 0;
	}
	if (!strcmp (buf, expected_output)) {
		printf (FMT_PASSED, test_number);
		free (buf);
		return 1;
	} else {
		printf (FMT_FAILED, test_number);
		free (buf);
		return 0;
	}
}

static int run_tests() {
	char infile[32];
	char expfile[32];
	int i, total = 0, passed = 0;
	for (i = 1; i < 100; i++) {
		sprintf (infile, "tests/%03d.json", i);
		sprintf (expfile, "tests/%03d.expected", i);
		char *input = load_file (infile);
		if (!input) break;
		char *expected_output = load_file (expfile);
		passed += run_test (i, input, expected_output);
		total++;
		free (input);
		free (expected_output);
	}
	printf ("\nPASSED %d OUT OF %d\n", passed, total);
	return passed == total;
}

int main() {
	return run_tests () ? 0 : 1;
}
