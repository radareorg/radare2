/* radare - LGPL - Copyright 2011-2017 pancake */
/* vala extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static bool lang_vala_file(RLang *lang, const char *file, bool silent) {
	void *lib;
	char *p, name[512], buf[512];
	char *vapidir, *srcdir, *libname;
	int len;

	if (strlen (file) > 500) {
		return false;
	}
	if (!strstr (file, ".vala")) {
		sprintf (name, "%s.vala", file);
	} else {
		strcpy (name, file);
	}
	if (!r_file_exists (name)) {
		eprintf ("file not found (%s)\n", name);
		return false;
	}

	srcdir = strdup (file);
	p = (char*)r_str_lchr (srcdir, '/');
	if (p) {
		*p = 0;
		libname = strdup (p+1);
		if (*file!='/') {
			strcpy (srcdir, ".");
		}
	} else {
		libname = strdup (file);
		strcpy (srcdir, ".");
	}
	r_sys_setenv ("PKG_CONFIG_PATH", R2_LIBDIR"/pkgconfig");
	vapidir = r_sys_getenv ("VAPIDIR");
	char *tail = silent?  " > /dev/null 2>&1": "";
	char *src = r_file_slurp (name, NULL);
	const char *pkgs = "";
	const char *libs = "";
	if (src) {
		if (strstr (src, "using Json;")) {
			pkgs = "--pkg json-glib-1.0";
			libs = "json-glib-1.0";
		}
		free (src);
	}
	// const char *pkgs = "";
	if (vapidir) {
		if (*vapidir) {
			len = snprintf (buf, sizeof (buf), "valac --disable-warnings -d %s --vapidir=%s --pkg r_core %s -C %s %s",
				srcdir, vapidir, pkgs, name, tail);
			if (len >= sizeof (buf)) {
				free (vapidir);
				free (srcdir);
				free (libname);
				return false;
			}
		}
		free (vapidir);
	} else {
		len = snprintf (buf, sizeof (buf) - 1, "valac --disable-warnings -d %s %s --pkg r_core -C %s %s", srcdir, pkgs, name, tail);
		if (len >= sizeof (buf)) {
			free (srcdir);
			free (libname);
			return false;
		}
	}
	free (srcdir);
	if (r_sandbox_system (buf, 1) != 0) {
		free (libname);
		return false;
	}
	p = strstr (name, ".vala");
	if (p) {
		*p = 0;
	}
	p = strstr (name, ".gs");
	if (p) {
		*p = 0;
	}
	// TODO: use CC environ if possible
	len = snprintf (buf, sizeof (buf), "gcc -fPIC -shared %s.c -o lib%s." R_LIB_EXT
		" $(pkg-config --cflags --libs r_core gobject-2.0 %s)", name, libname, libs);
	if (len >= sizeof (buf) || r_sandbox_system (buf, 1) != 0) {
		free (libname);
		return false;
	}

	len = snprintf (buf, sizeof (buf), "./lib%s." R_LIB_EXT, libname);
	free (libname);
	if (len >= sizeof (buf)) {
		return false;
	}

	lib = r_lib_dl_open (buf);
	if (lib) {
		void (*fcn) (RCore *);
		fcn = r_lib_dl_sym (lib, "entry");
		if (fcn) {
			fcn (lang->user);
		} else {
			eprintf ("Cannot find 'entry' symbol in library\n");
		}
		r_lib_dl_close (lib);
	} else {
		eprintf ("Cannot open library\n");
	}
	r_file_rm (buf); // remove lib
	len = snprintf (buf, sizeof (buf), "%s.c", name); // remove .c
	if (len >= sizeof (buf)) {
		return false;
	}

	r_file_rm (buf);
	return 0;
}

static bool vala_run_file(RLang *lang, const char *file) {
	return lang_vala_file(lang, file, false);
}

static bool lang_vala_init(void *user) {
	// TODO: check if "valac" is found in path
	return true;
}

static bool lang_vala_run(RLang *lang, const char *code, int len) {
	bool silent = !strncmp (code, "-s", 2);
	FILE *fd = r_sandbox_fopen (".tmp.vala", "w");
	if (fd) {
		if (silent) {
			code += 2;
		}
		fputs ("using Radare;\n\npublic static void entry(RCore core) {\n", fd);
		fputs (code, fd);
		fputs (";\n}\n", fd);
		fclose (fd);
		lang_vala_file (lang, ".tmp.vala", silent);
		r_file_rm (".tmp.vala");
		return true;
	}
	eprintf ("Cannot open .tmp.vala\n");
	return false;
}

static RLangPlugin r_lang_plugin_vala = {
	.name = "vala",
	.ext = "vala",
	.license = "LGPL",
	.desc = "Vala language extension",
	.run = lang_vala_run,
	.init = (void*)lang_vala_init,
	.run_file = (void*)vala_run_file,
};
