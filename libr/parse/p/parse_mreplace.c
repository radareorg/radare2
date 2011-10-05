/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

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

static int parse(struct r_parse_t *p, void *data, char *str) {
	struct mreplace_t *sdata = (struct mreplace_t*)data;
	char *buf = treplace (sdata->data, sdata->search, sdata->replace);
	memcpy (str, buf, R_PARSE_STRLEN);
	free (buf);
	return R_TRUE;
}

struct r_parse_plugin_t r_parse_plugin_mreplace = {
	.name = "mreplace",
	.desc = "mreplace parsing plugin",
	.init = NULL,
	.fini = NULL,
	.parse = &parse,
	.assemble = NULL,
	.filter = NULL
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
	.data = &r_parse_plugin_mreplace
};
#endif
