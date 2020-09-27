/* radare - LGPL - Copyright 2019 - deroad */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

static char* get_fcn_name(RAnal *anal, ut32 fcn_id) {
	r_cons_push ();
	char *s = anal->coreb.cmdstrf (anal->coreb.core, "is~FUNC[6:%u]", fcn_id);
	r_cons_pop ();
	if (s) {
		size_t namelen = strlen (s);
		s[namelen - 1] = 0;
	}
	return s;
}

static bool subvar(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	char *fcn_name = NULL;
	str[0] = 0;
	if (!strncmp (data, "call ", 5)) {
		ut32 fcn_id = (ut32) r_num_get (NULL, data + 5);
		if (!(fcn_name = get_fcn_name (p->analb.anal, fcn_id))) {
			return false;
		}
		snprintf (str, len, "call sym.%s", fcn_name);
		free (fcn_name);
		return true;
	}
	return false;
}

RParsePlugin r_parse_plugin_wasm_pseudo = {
	.name = "wasm.pseudo",
	.desc = "WASM pseudo syntax",
	.subvar = &subvar,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_wasm_pseudo,
	.version = R2_VERSION
};
#endif
