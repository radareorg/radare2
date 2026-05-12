/* radare - LGPL - Copyright 2013-2023 - pancake */

#include <r_bin.h>

R_IPI bool r_bin_lang_swift(RBinFile *bf) {
	if (!bf || !bf->bo) {
		return false;
	}
	RBinObject *bo = bf->bo;
	RBinInfo *info = bo->info;
	if (!info) {
		return false;
	}
	RBinSymbol *sym;
	R_VEC_FOREACH (&bo->symbols_vec, sym) {
		const char *name = r_bin_name_tostring2 (sym->name, 'o');
		if (name) {
			if (r_str_startswith (name, "_$s")) {
				info->lang = "swift";
				return true;
			}
			if (strstr (name, "swift_once")) {
				info->lang = "swift";
				return true;
			}
		}
	}
	return false;
}
