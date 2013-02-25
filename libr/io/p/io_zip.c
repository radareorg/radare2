/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>

// TODO: escape quotes?
// TODO: add support for directories
static inline int chkfn (const char *p) {
	return !!!(strchr (p, '\''));
}

static int __plugin_open(RIO *io, const char *file) {
	if (!memcmp (file, "zip://", 6) && file[6])
		return R_TRUE;
	if (!memcmp (file, "apk://", 6) && file[6])
		return R_TRUE;
	return R_FALSE;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char *d, *d2, *p, *str, cmd[1024];
	if (__plugin_open (io, file)) {
		if (!memcmp (file, "apk://", 6)) {
			int l = strlen (file+6);
			str = malloc (l+32);
			strcpy (str, file+6);
			strcpy (str+l, "//classes.dex");
		} else str = strdup (file+6);

		d = r_file_temp ("zipdir");
		p = (char *)r_str_casestr (str, "//");
		if (p && p[2]) {
			*p++ = 0;
			if (r_sys_rmkdir (d)) {
				d2 = strdup (d);
				d2 = r_str_concat (d2, "/");
				d2 = r_str_concat (d2, p+1);
				snprintf (cmd, sizeof (cmd), "unzip -o '%s' '%s' -d '%s'",
					str, p+1, d);
				if (chkfn (str) && chkfn (p+1) && chkfn (d)) 
					if (system (cmd) == 0)
						r_io_redirect (io, d2);
				free (d2);
			} else eprintf ("Cannot create temporary directory\n");
		} else {
			// XXX ugly as hell
			snprintf (cmd, sizeof (cmd), "unzip -l '%s' |grep -e '[0-9][0-9]-[0-9][0-9]'| awk '{print $4}'", str);
			if (chkfn (str) && system (cmd) != 0)
				eprintf ("Use zip://<path-to-zip>//<path-inside-zip>\n");
		}
		eprintf ("Remove '%s' manually\n", d);
		free (str);
		free (d);
		return NULL;
	}
	r_io_redirect (io, NULL);
	return NULL;
}

struct r_io_plugin_t r_io_plugin_zip = {
	.name = "zip",
        .desc = "Open files inside zip apk://foo.apk or zip://foo.apk/classes.dex",
        .open = __open,
        .plugin_open = __plugin_open,
	.lseek = NULL,
	.system = NULL,
	.debug = (void *)1,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_zip
};
#endif
