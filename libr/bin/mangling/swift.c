/* radare - LGPL - Copyright 2013-2016 - pancake */

#include <r_bin.h>

R_API bool r_bin_lang_swift(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RBinSymbol *sym;
	RListIter *iter;
	if (info) {
		r_list_foreach (o->symbols, iter, sym) {
			if (strstr (sym->name, "swift_once")) {
				info->lang = "swift";
				return true;
			}
		}
	}
	return false;
}
