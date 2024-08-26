/* radare - LGPL - Copyright 2024 - pancake */

#include <r_parse.h>

RParsePlugin r_parse_plugin_null_pseudo = {
	.name = "null.pseudo",
	.desc = "pseudo nothing",
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_null_pseudo,
	.version = R2_VERSION
};
#endif
