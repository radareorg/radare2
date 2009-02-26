/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdlib.h>

#include "mreplace/mreplace.h"

#include <r_lib.h>
#include <r_parse.h>


struct mreplace_t {
	char *data;
	char *search;
	char *replace;
};

static int parse(struct r_parse_t *p, void *data, char *str)
{
	struct mreplace_t *sdata = (struct mreplace_t*)data;
	char *buf = NULL;
	buf = treplace(sdata->data, sdata->search, sdata->replace);
	memcpy(str, buf, R_PARSE_STRLEN);
	if (buf != NULL)
		free(buf);

	return R_TRUE;
}

static struct r_parse_handle_t r_parse_plugin_parse_mreplace = {
	.name = "parse_mreplace",
	.desc = "mreplace parsing plugin",
	.init = NULL,
	.fini = NULL,
	.parse = &parse,
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_parse_mreplace
};
