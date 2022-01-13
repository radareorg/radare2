#include <stdio.h>
#include <string.h>
#include <r_core.h>

static int r2stuff(RThread *th) {
	r_cons_thready ();
	RCore *core = r_core_new ();
	int i;
	for (i = 0; i < 10; i++) {
		// printf ("%d\n", i);
		char *a = r_core_cmd_str (core, "?e hello");
		if (a && strcmp (a, "hello\n")) {
			eprintf ("(%s)\n", a);
			exit (1);
		}
 		free (r_core_cmd_str (core, "af-*;af; pd 4"));
		free (a);
	}
	r_core_free (core);
	return 0;
}

int main() {
	RThread *a = r_th_new (r2stuff, NULL, 0);
	RThread *b = r_th_new (r2stuff, NULL, 0); // if 0 then crash happens in r_cons initialization /o\

	r_th_start (a, true);
	r_th_start (b, true);
	r_th_wait (a);
	r_th_wait (b);

	r_th_free (a);
	r_th_free (b);
	return 0;
}
