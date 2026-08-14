/* radare - LGPL - Copyright 2013-2023 - pancake */

#include <r_bin.h>

R_IPI bool r_bin_lang_swift(RBinFile *bf) {
	if (!bf || !bf->bo || !R_VPACK_HAS (bf->bo->langs, R_BIN_LANG_SWIFT)) {
		return false;
	}
	if (bf->bo->info) {
		bf->bo->info->lang = "swift";
	}
	return true;
}
