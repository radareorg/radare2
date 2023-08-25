/* radare - LGPL - Copyright 2013-2023 - pancake */

#include <r_bin.h>

R_IPI bool r_bin_lang_swift(RBinFile *bf) {
	if (!bf || !bf->bo) {
		return false;
	}
	RBinObject *bo = bf->bo;
	RBinInfo *info = bo->info;
	RBinSymbol *sym;
	RListIter *iter;
	if (info) {
		if (bo->symbols) {
			r_list_foreach (bo->symbols, iter, sym) {
				if (sym->name && strstr (sym->name, "swift_once")) {
					info->lang = "swift";
					return true;
				}
			}
		} else {
			R_VEC_FOREACH (&bo->symbols_vec, sym) {
				if (sym->name && strstr (sym->name, "swift_once")) {
					info->lang = "swift";
					return true;
				}
			}
		}
	}
	return false;
}
