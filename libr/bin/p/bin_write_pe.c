/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <r_types.h>
#include <r_bin.h>
#include "pe/pe.h"

static bool scn_perms(RBinFile *bf, const char *name, int perms) {
	return PE_(r_bin_pe_section_perms) (bf, name, perms);
}

#if !R_BIN_PE64
RBinWrite r_bin_write_pe = {
	.scn_perms = &scn_perms
};
#endif
