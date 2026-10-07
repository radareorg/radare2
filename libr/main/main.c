/* radare - LGPL - Copyright 2012-2026 - pancake */

#include <r_main.h>
#include <r_userconf.h>
#include <r_lib.h>
#include "main_private.h"

R_LIB_VERSION(r_main);

R_IPI RCons *r_main_cons_new(RCons *parent) {
	return parent? parent: r_cons_new ();
}

R_IPI void r_main_cons_free(RCons *parent, RCons *cons) {
	if (cons && cons != parent) {
		r_cons_free (cons);
	}
}

R_IPI void r_main_cons_flush(RCons *parent, RCons *cons) {
	if (parent) {
		if (cons != parent) {
			r_cons_merge_output (parent, cons);
		}
	} else {
		r_cons_flush (cons);
	}
}

R_IPI st64 r_main_write(RCons *cons, const void *buf, size_t len) {
	if (cons) {
		return !len || r_cons_write (cons, buf, len)? len: -1;
	}
	return write (1, buf, len);
}

R_IPI RCons *r_main_cons_open(RCons *parent, int fd) {
	RCons *previous = r_cons_global (NULL);
	RCons *cons = parent? r_cons_new_child (parent): r_cons_new ();
	r_cons_global (previous);
	if (cons) {
		cons->fdout = fd;
		cons->context->noflush = true;
	}
	return cons;
}

R_IPI bool r_main_cons_close(RCons *cons) {
	bool success = true;
	if (cons) {
		size_t size;
		char *output = r_cons_drain (cons, &size);
		success = !size || write (cons->fdout, output, size) == size;
		free (output);
		if (close (cons->fdout) == -1) {
			success = false;
		}
		r_cons_free (cons);
	}
	if (!success) {
		R_LOG_ERROR ("Failed to write output file");
	}
	return success;
}

R_IPI RPrint *r_main_print_new(RCons *cons) {
	RPrint *print = r_print_new ();
	if (cons) {
		r_cons_bind (cons, &print->consb);
	}
	return print;
}

R_IPI bool r_main_core_init(RCons *parent, RCore *core) {
	if (!parent) {
		return r_core_init (core);
	}
	core->cons = r_cons_new_child (parent);
	if (!core->cons) {
		return false;
	}
	char *core_env = r_sys_getenv ("R2CORE");
	const bool initialized = r_core_init (core);
	r_sys_setenv ("R2CORE", core_env);
	free (core_env);
	return initialized;
}

R_IPI RCore *r_main_core_new(RCons *parent) {
	RCore *core = R_NEW0 (RCore);
	if (!r_main_core_init (parent, core)) {
		free (core);
		return NULL;
	}
	return core;
}

R_IPI void r_main_core_fini(RCons *parent, RCore *core) {
	if (parent && core->cons != parent) {
		r_cons_merge_output (parent, core->cons);
	}
	r_core_fini (core);
}

R_IPI void r_main_core_free(RCons *parent, RCore *core) {
	if (core) {
		r_main_core_fini (parent, core);
		free (core);
	}
}

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
	{ "rahash2", r_main_rahash2 },
	{ "rabin2", r_main_rabin2 },
	{ "radare2", r_main_radare2 },
	{ "r2", r_main_radare2 },
	{ NULL, NULL }
};

R_API RMain *r_main_new(const char *name) {
	size_t i = 0;
	while (foo[i].name) {
		const RMain *entry = &foo[i];
		if (r_str_startswith (name, entry->name)) {
			RMain *m = R_NEW0 (RMain);
			m->name = entry->name;
			m->main = entry->main;
			return m;
		}
		i++;
	}
	return NULL;
}

R_API void r_main_free(RMain *m) {
	free (m);
}

R_API int r_main_run(RMain *m, RCons *cons, int argc, const char **argv) {
	R_RETURN_VAL_IF_FAIL (m && m->main, -1);
	return m->main (cons, argc, argv);
}

R_API int r_main_version_print(RCons *main_cons, const char *progname, int mode) {
	PJ *pj;
	switch (mode) {
	case 'j':
	case 'J':
		pj = pj_new ();
		pj_o (pj);
		pj_ks (pj, "name", progname);
		pj_ks (pj, "version", R2_VERSION);
		pj_ki (pj, "abiversion", R2_ABIVERSION);
		pj_ks (pj, "birth", R2_BIRTH);
		pj_ks (pj, "commit", R2_GITTIP);
		pj_ki (pj, "commits", R2_VERSION_COMMIT);
		pj_ks (pj, "license", "LGPLv3");
		pj_ks (pj, "tap", R2_GITTAP);
		pj_ko (pj, "semver");
		pj_ki (pj, "major", R2_VERSION_MAJOR);
		pj_ki (pj, "minor", R2_VERSION_MINOR);
		pj_ki (pj, "patch", R2_VERSION_PATCH);
		pj_end (pj);
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_printf (main_cons, "%s\n", s);
		free (s);
		break;
	case 'q':
		r_cons_printf (main_cons, "%s\n", R2_VERSION);
		// mainr2_fini (&mr);
		break;
	default:
		{
			char *s = r_str_version (progname);
			if (s) {
				r_cons_printf (main_cons, "%s\n", s);
				free (s);
			}
		}
		break;
	}
	return 0;
}

#define LIBSTRING \
	"-lr_core -lr_config -lr_debug -lr_bin -lr_lang -lr_anal " \
	"-lr_bp -lr_egg -lr_asm -lr_flag -lr_search -lr_syscall " \
	"-lr_fs -lr_io -lr_socket -lr_cons -lr_magic -lr_muta " \
	"-lr_arch -lr_esil -lr_reg -lr_util"
R_API bool r_main_buildflags(char **out_cflags, char **out_ldflags, char **out_libs) {
	R_RETURN_VAL_IF_FAIL (out_cflags && out_ldflags && out_libs, false);
	*out_cflags = NULL;
	*out_ldflags = NULL;
	*out_libs = NULL;
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
	*out_cflags = r_str_newf ("-I%s", incdir);
	*out_ldflags = r_str_newf ("-L%s", libdir);
#if R2__UNIX__ && !__APPLE__
	*out_libs = strdup (LIBSTRING" -ldl");
#else
	*out_libs = strdup (LIBSTRING);
#endif
	free (libdir);
	free (incdir);
	return true;
}
