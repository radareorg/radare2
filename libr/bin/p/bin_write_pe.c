/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <r_types.h>
#include <r_bin.h>
#include "pe/pe.h"

static bool scn_perms(RBinFile *bf, const char *name, int perms) {
	return PE_(r_bin_pe_section_perms) (bf, name, perms);
}

static int checksum(RBinFile *bf, RStrBuf *report, bool fix) {
	RBinPEObj *pe = bf->bo->bin_obj;
	if (!pe || !pe->optional_header || !pe->nt_header_offset || pe->size >= 0x40000000) {
		return -1;
	}
	const ut64 paddr = pe->nt_header_offset + 4 + sizeof (PE_(image_file_header)) + 0x40;
	// most linkers leave the checksum unset, which is not a mismatch
	if (!fix && !PE_(bin_pe_get_claimed_checksum) (pe)) {
		r_strbuf_appendf (report, "pe 0x%08" PFMT64x " 00000000 unset\n", paddr);
		return 0;
	}
	ut8 computed[4];
	r_write_le32 (computed, PE_(bin_pe_get_actual_checksum) (pe));
	return !r_bin_wr_checksum_update (pe->b, report, "pe", paddr, computed, sizeof (computed), fix);
}

#if !R_BIN_PE64
RBinWrite r_bin_write_pe = {
	.scn_perms = &scn_perms,
	.checksum = &checksum,
};
#endif
