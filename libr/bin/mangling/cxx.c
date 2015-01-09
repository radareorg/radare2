/* radare - LGPL - Copyright 2013-2015 - pancake */

#include <r_bin.h>

static int is_cxx_symbol (const char *name) {
	if (!strncmp (name, "_Z", 2)) 
		return 1;
	if (!strncmp (name, "__Z", 3))
		return 1;
	return 0;
}

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
			break;
		}
	}
	if (!hascxx) {
		r_list_foreach (o->symbols, iter, sym) {
			if (is_cxx_symbol (sym->name)) {
				hascxx = R_TRUE;
				break;
			}
		}
	}
	if (hascxx)
		info->lang = "cxx";
	return hascxx;
}
