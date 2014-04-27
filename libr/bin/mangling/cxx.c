/* radare - LGPL - Copyright 2013 - pancake */

#include <r_bin.h>

R_API int r_bin_lang_cxx(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RBinSymbol *sym;
	RListIter *iter;
	int hascxx = R_FALSE;
	const char *lib;

	if (!info)
		return R_FALSE;
	r_list_foreach (o->libs, iter, lib) {
		if (strstr (lib, "stdc++")) {
			hascxx = R_TRUE;
			info->lang = "cxx";
			break;
		}
	}
	if (!hascxx)
	r_list_foreach (o->symbols, iter, sym) {
		if (!strncmp (sym->name, "__Z", 3)) {
			hascxx = R_TRUE;
			info->lang = "cxx";
			break;
		}
	}
	return hascxx;
}
