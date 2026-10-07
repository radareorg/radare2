/* radare - LGPL - Copyright 2012-2026 - pancake */

#include <r_main.h>
#include <r_userconf.h>
#include <r_lib.h>
#include "main_private.h"

R_LIB_VERSION(r_main);

R_IPI RCons *r_main_cons(void) {
	if (!r_cons_is_initialized ()) {
		return NULL;
	}
	char *value = r_sys_getenv ("R2CONS");
	void *ptr = NULL;
	if (value) {
		sscanf (value, "%p", &ptr);
	}
	free (value);
	return ptr;
}

R_IPI RCons *r_main_cons_new(void) {
	RCons *cons = r_main_cons ();
	return cons? cons: r_cons_new ();
}

R_IPI void r_main_cons_free(RCons *cons) {
	if (cons && cons != r_main_cons ()) {
		r_cons_free (cons);
	}
}

R_IPI void r_main_cons_flush(RCons *cons) {
	RCons *parent = r_main_cons ();
	if (parent) {
		if (cons != parent) {
			r_cons_merge_output (parent, cons);
		}
	} else {
		r_cons_flush (cons);
	}
}

R_IPI int r_main_printf(RCons *cons, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	int ret = 0;
	if (cons) {
		r_cons_printf_list (cons, format, ap);
	} else {
		ret = vprintf (format, ap);
	}
	va_end (ap);
	return ret;
}

R_IPI st64 r_main_write(RCons *cons, const void *buf, size_t len) {
	if (cons) {
		return !len || r_cons_write (cons, buf, len)? len: -1;
	}
	return write (1, buf, len);
}

R_IPI int r_main_gprintf(const char *format, ...) {
	RCons *cons = r_main_cons ();
	if (!cons) {
		cons = r_cons_global (NULL);
	}
	va_list ap;
	va_start (ap, format);
	r_cons_printf_list (cons, format, ap);
	va_end (ap);
	return 0;
}

R_IPI RPrint *r_main_print_new(void) {
	RPrint *print = r_print_new ();
	RCons *cons = r_main_cons ();
	if (cons) {
		r_cons_bind (cons, &print->consb);
	}
	return print;
}

R_IPI bool r_main_core_init(RCore *core) {
	RCons *parent = r_main_cons ();
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

R_IPI RCore *r_main_core_new(void) {
	RCore *core = R_NEW0 (RCore);
	if (!r_main_core_init (core)) {
		free (core);
		return NULL;
	}
	return core;
}

R_IPI void r_main_core_fini(RCore *core) {
	RCons *parent = r_main_cons ();
	if (parent && core->cons != parent) {
		r_cons_merge_output (parent, core->cons);
	}
	r_core_fini (core);
}

R_IPI void r_main_core_free(RCore *core) {
	if (core) {
		r_main_core_fini (core);
		free (core);
	}
}

static int main_invoke(RMainCallback callback, int argc, const char **argv) {
	RCons *previous_cons = r_cons_global (NULL);
	RCons *cons = r_main_cons ();
	char *previous_env = r_sys_getenv ("R2CONS");
	char *previous_core = r_sys_getenv ("R2CORE");
	bool noflush = false;
#if !__wasi__
	int stdout_fd = -1;
#endif
	if (cons) {
#if !__wasi__
		fflush (stdout);
		stdout_fd = dup (1);
		if (stdout_fd == -1) {
			free (previous_env);
			free (previous_core);
			return 1;
		}
#endif
		noflush = cons->context->noflush;
		cons->context->noflush = true;
	} else {
		// Ignore inherited console pointers in standalone tools.
		r_sys_setenv ("R2CONS", NULL);
	}
	int ret = callback (argc, argv);
#if !__wasi__
	if (stdout_fd != -1) {
		fflush (stdout);
		dup2 (stdout_fd, 1);
		close (stdout_fd);
	}
#endif
	if (cons) {
		cons->context->noflush = noflush;
		r_cons_global (previous_cons);
	}
	r_sys_setenv ("R2CONS", previous_env);
	r_sys_setenv ("R2CORE", previous_core);
	free (previous_env);
	free (previous_core);
	return ret;
}

#define MAIN_WRAPPER(name) \
	R_IPI int r_main_##name##_impl(int argc, const char **argv); \
	R_API int r_main_##name(int argc, const char **argv) { \
		return main_invoke (r_main_##name##_impl, argc, argv); \
	}

MAIN_WRAPPER (r2pm)
MAIN_WRAPPER (rax2)
MAIN_WRAPPER (radiff2)
MAIN_WRAPPER (rafind2)
MAIN_WRAPPER (ravc2)
MAIN_WRAPPER (rarun2)
MAIN_WRAPPER (rafs2)
MAIN_WRAPPER (rasm2)
MAIN_WRAPPER (ragg2)
MAIN_WRAPPER (rapatch2)
MAIN_WRAPPER (rahash2)
MAIN_WRAPPER (rabin2)
MAIN_WRAPPER (radare2)
MAIN_WRAPPER (r2agent)
MAIN_WRAPPER (rasign2)

#undef MAIN_WRAPPER

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

R_API int r_main_run(RMain *m, int argc, const char **argv) {
	R_RETURN_VAL_IF_FAIL (m && m->main, -1);
	return m->main (argc, argv);
}

R_API int r_main_version_print(const char *progname, int mode) {
	RCons *main_cons = r_main_cons ();
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
		r_main_printf (main_cons, "%s\n", s);
		free (s);
		break;
	case 'q':
		r_main_printf (main_cons, "%s\n", R2_VERSION);
		// mainr2_fini (&mr);
		break;
	default:
		{
			char *s = r_str_version (progname);
			if (s) {
				r_main_printf (main_cons, "%s\n", s);
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
