/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_asm.h>

// x86-specific AT&T to Intel parser plugin
// Uses the generic r_str_att2intel() from libr/util/str_att.c

static char *parse(RAsmPluginSession *aps, const char *data) {
	return r_str_att2intel (data);
}

// Public API wrapper for backwards compatibility
R_API char *r_asm_att2intel(const char *att_str) {
	return r_str_att2intel (att_str);
}

RAsmPlugin r_asm_plugin_att2intel = {
	.meta = {
		.name = "att2intel",
		.desc = "AT&T to Intel syntax converter",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_att2intel,
	.version = R2_VERSION
};
#endif
