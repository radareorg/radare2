/* radare - LGPL - Copyright 2015 - inisider */

#include <r_bin.h>

///////////////////////////////////////////////////////////////////////////////
static int is_cxx_symbol (const char *name) {
	if (*name == '?')
		return 1;
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
R_API int r_bin_lang_msvc(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RBinSymbol *sym;
	RListIter *iter;
	int hascxx = R_FALSE;

	if (!info)
		return R_FALSE;

	if (!hascxx) {
		r_list_foreach (o->symbols, iter, sym) {
			if (is_cxx_symbol (sym->name)) {
				hascxx = R_TRUE;
				break;
			}
		}
	}

	if (hascxx)
		info->lang = "msvc";

	return hascxx;
}
