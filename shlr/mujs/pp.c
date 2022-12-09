/* Pretty-print input source by emitting parse tree back as syntax.
 * with no flags: pretty-printed source
 * with -m: minified source with line breaks
 * with -mm: minified source without line breaks
 * with -s: s-expression syntax tree
 */

#include <stdio.h>

#include "jsi.h"
#include "jsparse.h"

static void js_ppstring(js_State *J, const char *filename, const char *source, int minify)
{
	js_Ast *P;
	if (js_try(J)) {
		jsP_freeparse(J);
		js_throw(J);
	}
	P = jsP_parse(J, filename, source);
	if (minify > 2)
		jsP_dumplist(J, P);
	else
		jsP_dumpsyntax(J, P, minify);
	jsP_freeparse(J);
	js_endtry(J);
}

void js_ppfile(js_State *J, const char *filename, int minify)
{
	FILE * volatile f = NULL;
	char * volatile s = NULL;
	int n, t;

	if (js_try(J)) {
		js_free(J, s);
		if (f) fclose(f);
		js_throw(J);
	}

	f = fopen(filename, "rb");
	if (!f) {
		js_error(J, "cannot open file: '%s'", filename);
	}

	if (fseek(f, 0, SEEK_END) < 0) {
		js_error(J, "cannot seek in file: '%s'", filename);
	}

	n = ftell(f);
	if (n < 0) {
		js_error(J, "cannot tell in file: '%s'", filename);
	}

	if (fseek(f, 0, SEEK_SET) < 0) {
		js_error(J, "cannot seek in file: '%s'", filename);
	}

	s = js_malloc(J, n + 1); /* add space for string terminator */
	if (!s) {
		js_error(J, "cannot allocate storage for file contents: '%s'", filename);
	}

	t = fread(s, 1, (size_t)n, f);
	if (t != n) {
		js_error(J, "cannot read data from file: '%s'", filename);
	}

	s[n] = 0; /* zero-terminate string containing file data */

	js_ppstring(J, filename, s, minify);

	js_endtry(J);
	js_free(J, s);
	fclose(f);
}

int
main(int argc, char **argv)
{
	js_State *J;
	int minify = 0;
	int i;

	J = js_newstate(NULL, NULL, 0);

	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "-m"))
			minify = 1;
		else if (!strcmp(argv[i], "-mm"))
			minify = 2;
		else if (!strcmp(argv[i], "-s"))
			minify = 3;
		else {
			if (js_try(J)) {
				js_report(J, js_trystring(J, -1, "Error"));
				js_pop(J, 1);
				continue;
			}
			js_ppfile(J, argv[i], minify);
			js_endtry(J);
		}
	}

	js_gc(J, 0);
	js_freestate(J);

	return 0;
}
