/* radare - LGPL - Copyright 2015-2023 - inisider, pancake */

#include <r_bin.h>
#include "./microsoft.h"

R_API char *r_bin_demangle_msvc(const char *str) {
	char *out = NULL;
	SDemangler *mangler = 0;

	create_demangler (&mangler);
	if (!mangler) {
		return NULL;
	}
	if (init_demangler (mangler, (char *)str) == eDemanglerErrOK) {
		mangler->demangle (mangler, &out/*demangled_name*/);
	}
	free_demangler (mangler);
	return out;
}
