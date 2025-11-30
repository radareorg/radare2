/* radare - LGPL - Copyright 2012-2025 - pancake */

#include <r_main.h>
#include <r_userconf.h>
#include <r_util.h>
#include <ctype.h>
#include <string.h>

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
  { "rahash2", r_main_rahash2 },
	{ NULL, NULL }
};

R_API RMain *r_main_new(const char *name) {
	size_t i = 0;
	while (foo[i].name) {
		if (r_str_startswith (name, foo[i].name)) {
			RMain *m = R_NEW0 (RMain);
			m->name = foo[i].name;
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

R_API bool r_main_r2_build_flags(char **out_cflags, char **out_ldflags) {
	R_RETURN_VAL_IF_FAIL (out_cflags && out_ldflags, false);
	*out_cflags = NULL;
	*out_ldflags = NULL;
#if R2__WINDOWS__
	char *libdir = r_str_r2_prefix (R2_LIBDIR);
	char *incdir = r_str_r2_prefix (R2_INCDIR);
#else
	char *libdir = strdup (R2_LIBDIR);
	char *incdir = strdup (R2_INCDIR);
#endif
	if (!libdir || !incdir) {
		free (libdir);
		free (incdir);
		return false;
	}
	if (!*out_cflags) {
		*out_cflags = r_str_newf ("-I%s", incdir);
	}
	if (!*out_ldflags) {
		RStrBuf *sb = r_strbuf_new ("");
		const char *libs_default[] = {
			"-lr_core",
			"-lr_config",
			"-lr_debug",
			"-lr_bin",
			"-lr_lang",
			"-lr_anal",
			"-lr_bp",
			"-lr_egg",
			"-lr_asm",
			"-lr_flag",
			"-lr_search",
			"-lr_syscall",
			"-lr_fs",
			"-lr_io",
			"-lr_socket",
			"-lr_cons",
			"-lr_magic",
			"-lr_muta",
			"-lr_arch",
			"-lr_esil",
			"-lr_reg",
			"-lr_util",
			NULL
		};
		if (sb) {
			r_strbuf_appendf (sb, "-L%s", libdir);
			int i = 0;
			while (libs_default[i]) {
				r_strbuf_appendf (sb, " %s", libs_default[i]);
				i++;
			}
#if R2__UNIX__ && !__APPLE__
			r_strbuf_append (sb, " -ldl");
#endif
			*out_ldflags = r_strbuf_drain (sb);
		}
	}
	if (!*out_cflags) {
		*out_cflags = strdup ("");
	}
	if (!*out_ldflags) {
		*out_ldflags = strdup ("");
	}
	free (libdir);
	free (incdir);
	return true;
}
