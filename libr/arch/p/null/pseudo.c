/* radare - LGPL - Copyright 2024 - pancake */

#include <r_parse.h>

RParsePlugin r_parse_plugin_null_pseudo = {
	.meta = {
		.name = "null.pseudo",
		.desc = "pseudo nothing",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	}
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_null_pseudo,
	.version = R2_VERSION
};
#endif
