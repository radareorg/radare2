/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>


static int parse(RParse *p, const char *data, char *str) {
	// Intentationally left blank
	// because it's not yet implemented
	return false;
}

RParsePlugin r_parse_plugin_pickle_pseudo = {
	.name = "pickle.pseudo",
	.desc = "Pickle pseudo syntax",
	.parse = parse, // parse actually converts the string into asm.pseudo
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_pickle_pseudo,
	.version = R2_VERSION
};
#endif
