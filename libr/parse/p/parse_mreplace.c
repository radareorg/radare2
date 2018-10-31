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
	} else {
		strcpy (data, str);
	}
	return true;
}

static bool varsub(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	strncpy (str, data, len);
	return false;
}

RParsePlugin r_parse_plugin_mreplace = {
	.name = "mreplace",
	.desc = "mreplace parsing plugin",
	.parse = &parse,
	.assemble = &assemble,
	.varsub = &varsub,
};

#else
RParsePlugin r_parse_plugin_mreplace = {
	.name = "mreplace",
	.desc = "mreplace parsing plugin (NOT SUPPORTED FOR THIS PLATFORM)",
};
#endif

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_mreplace,
	.version = R2_VERSION
};
#endif
