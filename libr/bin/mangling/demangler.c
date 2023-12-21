/* radare - LGPL - Copyright 2015-2023 - inisider */

#include <r_types.h>
#include "microsoft.h"

typedef enum EManglingType {
	eManglingMicrosoft = 0,
	eManglingUnsupported,
	eManglingUnknown,
	eManglingTypeMax
} EManglingType;

static EManglingType get_mangling_type(const char *sym) {
	EManglingType mangling_type = eManglingUnsupported;
	if (sym == 0) {
		mangling_type = eManglingUnknown;
		goto get_mangling_type_err;
	}
	const char sym0 = *sym;
	if (sym0 == '.' || sym0 == '?') {
		mangling_type = eManglingMicrosoft;
	}

get_mangling_type_err:
	return mangling_type;
}

EDemanglerErr create_demangler(SDemangler **demangler) {
	EDemanglerErr err = eDemanglerErrOK;
	SDemangler *sd = R_NEW0 (SDemangler);
	*demangler = sd;
	if (!*demangler) {
		err = eDemanglerErrMemoryAllocation;
		goto create_demagler_err;
	}
	sd->demangle = 0;
	sd->symbol = 0;
	sd->abbr_types = r_list_newf (free);
	sd->abbr_names = r_list_newf (free);
create_demagler_err:
	return err;
}

///////////////////////////////////////////////////////////////////////////////
EDemanglerErr init_demangler(SDemangler *demangler, char *sym) {
	EManglingType mangling_type = eManglingUnsupported;
	EDemanglerErr err = eDemanglerErrOK;

	// !!! sequence in this array need to be same as in EManglingType enum !!!
	demangle_func demangle_funcs[] = {
		microsoft_demangle,	// Microsoft demangling function
		0,					// Unsupported demangling
		0					// Unknown demangling
	};

	if (demangler == 0) {
		err =  eDemanglerErrMemoryAllocation;
		goto init_demangler_err;
	}

	mangling_type = get_mangling_type(sym);
	switch (mangling_type) {
	case eManglingUnsupported:
		err = eDemanglerErrUnsupportedMangling;
		break;
	case eManglingUnknown:
		err = eDemanglerErrUnknown;
		break;
	default:
		break;
	}

	if (err != eDemanglerErrOK) {
		goto init_demangler_err;
	}

	demangler->symbol = strdup(sym);
	demangler->demangle = demangle_funcs[mangling_type];

init_demangler_err:
	return err;
}

void free_demangler(SDemangler *sd) {
	r_list_free (sd->abbr_types);
	r_list_free (sd->abbr_names);
	free (sd->symbol);
	free (sd);
}
