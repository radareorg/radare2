/* radare - LGPLv3 - Copyright 2014 Jody Frankowski */
/* This file holds help messages relative functions */

#include <r_core.h>

R_API void r_core_cmd_help(const RCore *core, const char *help[]) {
	r_cons_cmd_help (help, core->print->flags & R_PRINT_FLAGS_COLOR);
}
