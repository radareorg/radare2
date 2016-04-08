/* radare - LGPL - Copyright 2009-2015 nibble */

#include <stdio.h>
#include <stdlib.h>

#include "parse_mreplace/mreplace.h"

#include <r_lib.h>
#include <r_parse.h>

#if __UNIX__

struct mreplace_t {
	char *data;
	char *search;
	char *replace;
};

static int parse(RParse *p, const char *data, char *str) {
	const struct mreplace_t *sdata = (struct mreplace_t*)data;
	char *buf = treplace (sdata->data, sdata->search, sdata->replace);
	memcpy (str, buf, R_PARSE_STRLEN);
	free (buf);
	return true;
}

static int assemble(RParse *p, char *data, char *str) {
	char *ptr = strchr (str, '=');
	if (ptr) {
		*ptr = '\0';
		sprintf (data, "mov %s, %s", str, ptr+1);
	} else strcpy (data, str);
	return true;
}

static bool varsub(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
#if USE_VARSUBS
	char *ptr, *ptr2;
	int i;
	strncpy (str, data, len);
	for (i = 0; i < R_ANAL_VARSUBS; i++)
		if (f->varsubs[i].pat[0] != '\0' && f->varsubs[i].sub[0] != '\0' &&
			(ptr = strstr (data, f->varsubs[i].pat))) {
				*ptr = '\0';
				ptr2 = ptr + strlen (f->varsubs[i].pat);
				snprintf (str, len, "%s%s%s", data, f->varsubs[i].sub, ptr2);
		}
	return true;
#else
	strncpy (str, data, len);
	return false;
#endif
}

RParsePlugin r_parse_plugin_mreplace = {
	.name = "mreplace",
	.desc = "mreplace parsing plugin",
	.parse = &parse,
	.assemble = &assemble,
	.varsub = &varsub,
};

#else
struct r_parse_plugin_t r_parse_plugin_mreplace = {
	.name = "mreplace",
	.desc = "mreplace parsing plugin (NOT SUPPORTED FOR THIS PLATFORM)",
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_mreplace,
	.version = R2_VERSION
};
#endif
