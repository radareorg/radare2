/* radare - LGPL - Copyright 2011-2023 pancake */

#include <r_lang.h>

static bool lang_vala_file(RLangSession *s, const char *file, bool silent) {
	char *name = (!strstr (file, ".vala")) ? r_str_newf ("%s.vala", file) : strdup (file);
	if (!name || !r_file_exists (name)) {
		R_LOG_ERROR ("file not found (%s)", name);
		free (name);
		return false;
	}
	char *srcdir = strdup (file);
	char *p = (char*)r_str_lchr (srcdir, '/');
	char *libname;
	if (p) {
		*p = 0;
		libname = strdup (p + 1);
		if (*file != '/') {
			strcpy (srcdir, ".");
		}
	} else {
		libname = strdup (file);
		strcpy (srcdir, ".");
	}
	r_sys_setenv ("PKG_CONFIG_PATH", R2_LIBDIR"/pkgconfig");
#if R2__WINDOWS__
	const char *tail = silent?  " >NUL 2>NUL": "";
#else
	const char *tail = silent?  " > /dev/null 2>&1": "";
#endif
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
	char *cmdbuf = NULL;
	char *vapidir = r_sys_getenv ("VAPIDIR");
	if (R_STR_ISNOTEMPTY (vapidir)) {
		cmdbuf = r_str_newf ("valac --disable-warnings -d %s --vapidir=%s --pkg r_core %s -C %s %s",
			srcdir, vapidir, pkgs, name, tail);
	} else {
		cmdbuf = r_str_newf ("valac --disable-warnings -d %s %s --pkg r_core -C %s %s", srcdir, pkgs, name, tail);
	}
	R_FREE (vapidir);
	free (srcdir);
	if (!cmdbuf || r_sandbox_system (cmdbuf, 1) != 0) {
		free (name);
		free (libname);
		free (cmdbuf);
		return false;
	}
	free (cmdbuf);
	p = strstr (name, ".vala");
	if (p) {
		*p = 0;
	}
	p = strstr (name, ".gs");
	if (p) {
		*p = 0;
	}
	char *cc = r_sys_getenv ("CC");
	if (R_STR_ISEMPTY (cc)) {
		free (cc);
		cc = strdup ("gcc");
	}
	cmdbuf = r_str_newf ("%s -fPIC -shared %s.c -o lib%s." R_LIB_EXT
		" $(pkg-config --cflags --libs r_core gobject-2.0 %s)", cc, name, libname, libs);
	R_FREE (cc);
	if (r_sandbox_system (cmdbuf, 1) != 0) {
		free (libname);
		free (name);
		free (cmdbuf);
		return false;
	}
	free (cmdbuf);
	cmdbuf = r_str_newf ("./lib%s." R_LIB_EXT, libname);
	free (libname);

	void *lib = r_lib_dl_open (cmdbuf, false);
	if (lib) {
		void (*fcn) (RCore *) = r_lib_dl_sym (lib, "entry");
		if (fcn) {
			fcn (s->lang->user);
		} else {
			R_LOG_ERROR ("Cannot find 'entry' symbol in library");
		}
		r_lib_dl_close (lib);
	} else {
		R_LOG_ERROR ("Cannot open library");
	}
	r_file_rm (cmdbuf); // remove lib
	free (cmdbuf);
	cmdbuf = r_str_newf ("%s.c", name);
	free (name);
	r_file_rm (cmdbuf);
	free (cmdbuf);
	return 0;
}

static bool vala_run_file(RLangSession *s, const char *file) {
	return lang_vala_file (s, file, false);
}

static bool lang_vala_init(RLangSession *s) {
	char *valac = r_file_path ("valac");
	bool found = (valac && *valac != 'v');
	free (valac);
	return found;
}

static bool lang_vala_run(RLangSession *s, const char *code, int len) {
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
		lang_vala_file (s, ".tmp.vala", silent);
		r_file_rm (".tmp.vala");
		return true;
	}
	R_LOG_ERROR ("Cannot open .tmp.vala");
	return false;
}

static RLangPlugin r_lang_plugin_vala = {
	.meta = {
		.name = "vala",
		.author = "pancake",
		.license = "LGPL-3.0-only",
		.desc = "Vala language extension",
	},
	.ext = "vala",
	.run = lang_vala_run,
	.init = lang_vala_init,
	.run_file = (void*)vala_run_file,
};
