/* radare - LGPL - Copyright 2011-2014 pancake */
/* vala extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_vala_file(RLang *lang, const char *file) {
	void *lib;
	char *p, name[512], buf[512];
	char *vapidir, *srcdir, *libname;

	if (strlen (file)>500)
		return R_FALSE;
	if (!strstr (file, ".vala"))
		sprintf (name, "%s.vala", file);
	else strcpy (name, file);
	if (!r_file_exists (name)) {
		eprintf ("file not found (%s)\n", name);
		return R_FALSE;
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
	vapidir = r_sys_getenv ("VAPIDIR");
	if (vapidir) {
		if (*vapidir) {
			snprintf (buf, sizeof (buf)-1, "valac -d %s --vapidir=%s --pkg r_core -C %s",
				srcdir, vapidir, name);
		}
		free (vapidir);
	} else snprintf (buf, sizeof(buf)-1, "valac -d %s --pkg r_core -C %s", srcdir, name);
	free (srcdir);
	if (system (buf) != 0) {
		free (libname);
		return R_FALSE;
	}
	p = strstr (name, ".vala"); if (p) *p=0;
	p = strstr (name, ".gs"); if (p) *p=0;
	// TODO: use CC environ if possible
	snprintf (buf, sizeof (buf), "gcc -fPIC -shared %s.c -o lib%s."R_LIB_EXT
		" $(pkg-config --cflags --libs r_core gobject-2.0)", name, libname);
	if (system (buf) != 0) {
		free (libname);
		return R_FALSE;
	}

	snprintf (buf, sizeof (buf), "./lib%s."R_LIB_EXT, libname);
	free (libname);
	lib = r_lib_dl_open (buf);
	if (lib!= NULL) {
		void (*fcn)(RCore *);
		fcn = r_lib_dl_sym (lib, "entry");
		if (fcn) fcn (lang->user);
		else eprintf ("Cannot find 'entry' symbol in library\n");
		r_lib_dl_close (lib);
	} else eprintf ("Cannot open library\n");
	r_file_rm (buf); // remove lib
	sprintf (buf, "%s.c", name); // remove .c
	r_file_rm (buf);
	return 0;
}

static int lang_vala_init(void *user) {
	// TODO: check if "valac" is found in path
	return R_TRUE;
}

static int lang_vala_run(RLang *lang, const char *code, int len) {
	FILE *fd = fopen (".tmp.vala", "w");
	if (fd) {
		fputs ("using Radare;\n\npublic static void entry(RCore core) {\n", fd);
		fputs (code, fd);
		fputs (";\n}\n", fd);
		fclose (fd);
		lang_vala_file (lang, ".tmp.vala");
		r_file_rm (".tmp.vala");
	} else eprintf ("Cannot open .tmp.vala\n");
	return R_TRUE;
}

static struct r_lang_plugin_t r_lang_plugin_vala = {
	.name = "vala",
	.ext = "vala",
	.desc = "VALA language extension",
	.help = NULL,
	.run = lang_vala_run,
	.init = (void*)lang_vala_init,
	.fini = NULL,
	.run_file = (void*)lang_vala_file,
	.set_argv = NULL,
};
