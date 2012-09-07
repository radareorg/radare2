/* radare - LGPL - Copyright 2012 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>

static int __plugin_open(RIO *io, const char *file) {
	if (!memcmp (file, "zip://", 6) && file[6])
		return R_TRUE;
	return R_FALSE;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char *p, *str, cmd[1024];
	if (__plugin_open (io, file)) {
		str = strdup (file+6);
		p = (char *)r_str_casestr (str, "//");
		if (p && p[2]) {
			*p++ = 0;
// TODO: escape quotes
// TODO: add support for directories
			snprintf (cmd, sizeof (cmd), "unzip -o '%s' '%s'", str, p+1);
			if (system (cmd) == 0)
				r_io_redirect (io, p+1);
		} else {
			snprintf (cmd, sizeof (cmd), "unzip -l '%s' |grep -e '[0-9][0-9]-[0-9][0-9]'| awk '{print $4}'", str);
			if (system (cmd) != 0)
				eprintf ("Use zip://<path-to-zip>//<path-inside-zip>\n");
		}
		free (str);
		return NULL;
	}
	r_io_redirect (io, NULL);
	return NULL;
}

struct r_io_plugin_t r_io_plugin_zip = {
	.name = "zip",
        .desc = "Open files inside zip archives zip://whatsapp.apk/classes.dex",
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
