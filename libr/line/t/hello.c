#include "r_line.h"

static const char *myargv[4] = { "fontana", "fonticulo", "funebre", NULL };

static int complete (void *pline) {
	RLine *line = (RLine*) pline;
	line->completion.argc = 3;
	line->completion.argv = (const char **)myargv;
	return 0;
}

int main() {
	const char *str;
	RLine *line = r_line_new ();
	r_cons_new ();
	line->completion.run = (RLineCallback) complete;
#if 0
	if (!r_line_init ()) {
		printf ("Cannot initizalize r_line\n");
		return 0;
	}
#endif
	for (;;) {
		str = r_line_readline (0, NULL);
		if (str == NULL) // catch eof
			break;
		printf ("%s\n", str);
		r_line_hist_add (str);
	}
	r_line_free ();
	return 0;
}
