/* radare - LGPL - Copyright 2013-2015 - pancake */

#include <r_bin.h>

R_API int r_bin_lang_swift(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RBinSymbol *sym;
	RListIter *iter;
	int haslang = R_FALSE;

	if (!info)
		return R_FALSE;
	r_list_foreach (o->symbols, iter, sym) {
		if (strstr (sym->name, "swift_release")) {
			haslang = R_TRUE;
			info->lang = "swift";
			break;
		}
	}
	return haslang;
}
