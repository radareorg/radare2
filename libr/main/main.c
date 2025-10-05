/* radare - LGPL - Copyright 2012-2025 - pancake */

#include <r_main.h>

R_LIB_VERSION(r_main);

static const RMain foo[] = {
	{ "r2pm", r_main_r2pm },
	{ "rax2", r_main_rax2 },
	{ "radiff2", r_main_radiff2 },
	{ "rafind2", r_main_rafind2 },
	{ "ravc2", r_main_ravc2 },
	{ "rarun2", r_main_rarun2 },
	{ "rafs2", r_main_rafs2 },
	{ "rasm2", r_main_rasm2 },
	{ "ragg2", r_main_ragg2 },
	{ "rapatch2", r_main_rapatch2 },
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
			m->name = strdup (foo[i].name);
			m->main = foo[i].main;
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
	R_RETURN_VAL_IF_FAIL (m && m->main, -1);
	return m->main (argc, argv);
}

R_API int r_main_version_print(const char *progname, int mode) {
	PJ *pj;
	switch (mode) {
	case 'j':
	case 'J':
		pj = pj_new ();
		pj_o (pj);
		pj_ks (pj, "name", progname);
		pj_ks (pj, "version", R2_VERSION);
		pj_ks (pj, "birth", R2_BIRTH);
		pj_ks (pj, "commit", R2_GITTIP);
		pj_ki (pj, "commits", R2_VERSION_COMMIT);
		pj_ks (pj, "license", "LGPLv3");
		pj_ks (pj, "tap", R2_GITTAP);
		pj_ko (pj, "semver");
		pj_ki (pj, "major", R2_VERSION_MAJOR);
		pj_ki (pj, "minor", R2_VERSION_MINOR);
		pj_ki (pj, "patch", R2_VERSION_MINOR);
		pj_end (pj);
		pj_end (pj);
		char *s = pj_drain (pj);
		printf ("%s\n", s);
		free (s);
		break;
	case 'q':
		printf ("%s\n", R2_VERSION);
		// mainr2_fini (&mr);
		break;
	default:
		{
			char *s = r_str_version (progname);
			if (s) {
				printf ("%s\n", s);
				free (s);
			}
		}
		break;
	}
	return 0;
}
