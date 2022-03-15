/* radare - LGPL - Copyright 2012-2021 - pancake */

#include <r_main.h>
#include <r_util.h>

R_LIB_VERSION(r_main);

static RMain foo[] = {
	{ "r2pm", r_main_r2pm },
	{ "rax2", r_main_rax2 },
	{ "radiff2", r_main_radiff2 },
	{ "rafind2", r_main_rafind2 },
	{ "rarun2", r_main_rarun2 },
	{ "rasm2", r_main_rasm2 },
	{ "ragg2", r_main_ragg2 },
	{ "rabin2", r_main_rabin2 },
	{ "radare2", r_main_radare2 },
	{ "r2", r_main_radare2 },
	{ NULL, NULL }
};

R_API RMain *r_main_new(const char *name) {
	size_t i = 0;
	while (foo[i].name) {
		if (r_str_startswith (name, foo[i].name)) {
			RMain *m = R_NEW0 (RMain);
			if (m) {
				m->name = strdup (foo[i].name);
				m->main = foo[i].main;
			}
			return m;
		}
		i++;
	}
	return NULL;
}

R_API void r_main_free(RMain *m) {
	free (m);
}

R_API int r_main_run(RMain *m, int argc, const char **argv) {
	r_return_val_if_fail (m && m->main, -1);
	return m->main (argc, argv);
}

R_API int r_main_version_print(const char *progname) {
	char *s = r_str_version (progname);
	if (s) {
		printf ("%s\n", s);
		free (s);
	}
	return 0;
}
