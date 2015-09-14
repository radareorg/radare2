/* radare - LGPL - Copyright 2013-2015 - pancake */

#include <r_bin.h>

R_API int r_bin_lang_swift(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RBinSymbol *sym;
	RListIter *iter;
	_Bool haslang = false;

	if (info) {
		r_list_foreach (o->symbols, iter, sym) {
			if (strstr (sym->name, "swift_release")) {
				haslang = true;
				info->lang = "swift";
				break;
			}
		}
	}
	return (int)haslang;
}
