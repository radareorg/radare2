/* radare - LGPL - Copyright 2016-2019 - pancake */

#include <r_types.h>
#include <r_bin.h>
#include "mach0/mach0.h"

typedef struct machoPointers_t {
	size_t ncmds;
	size_t ncmds_off;
	size_t sizeofcmds;
	size_t sizeofcmds_off;
	size_t lastcmd_off;
} MachoPointers;

static MachoPointers findLastCommand(RBinFile *bf) {
	struct MACH0_(obj_t) *bin = bf->o->bin_obj;
	int i = 0;
	ut64 off;
	MachoPointers mp = {0};
	mp.ncmds = bin->hdr.ncmds;
	mp.ncmds_off = 0x10;
	mp.sizeofcmds = bin->hdr.sizeofcmds;
	mp.sizeofcmds_off = 0x14;
	
	for (i = 0, off = 0x20 + bin->header_at; i < mp.ncmds; i++) {
		ut32 loadc[2] = {0};
		r_buf_read_at (bin->b, off, (ut8*)&loadc, sizeof (loadc));
		//r_buf_seek (bin->b, off, R_BUF_SET);
		int len = loadc[1]; // r_buf_read_le32 (loadc[1]); // bin->b); // 
		if (len < 1) {
			eprintf ("Error: read (lc) at 0x%08"PFMT64x"\n", off);
			break;
		}
		int size = r_read_ble32 (&loadc[1], bin->big_endian);
		off += size;
	}
	mp.lastcmd_off = off;
	return mp;
}

static const uint8_t sample_dylib[56] = {
	0x0c, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x18, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x0a, 0xca, 0x04,
	0x00, 0x00, 0x01, 0x00, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c,
	0x69, 0x62, 0x2f, 0x6c, 0x69, 0x6f, 0x75, 0x74, 0x69, 0x6c,
	0x2e, 0x64, 0x79, 0x6c, 0x69, 0x62, 0x00, 0x6c, 0x69, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool MACH0_(write_addlib)(RBinFile *bf, const char *lib) {
	MachoPointers mp = findLastCommand (bf);
	size_t size_of_lib = 56;

	ut32 ncmds = mp.ncmds + 1;
	r_buf_write_at (bf->buf, mp.ncmds_off, (const ut8*)&ncmds, sizeof (ncmds));

	ut32 sizeofcmds = mp.sizeofcmds + size_of_lib; // , &ncmds, sizeof (ncmds));
	r_buf_write_at (bf->buf, mp.sizeofcmds_off, (ut8*)&sizeofcmds, sizeof (sizeofcmds));

	size_t lib_len = strlen (lib);
	if (lib_len > 22) {
		eprintf ("Warning: Adjusting cmdsize too long libname\n");
		size_of_lib += lib_len + 1 - 22;
		size_of_lib += 8 - (size_of_lib % 8);
	}

	const size_t sample_dylib_name_off = 24;
	r_buf_write_at (bf->buf, mp.lastcmd_off, sample_dylib, 56);
	r_buf_write_at (bf->buf, mp.lastcmd_off + 4, (const ut8*)&size_of_lib, 4);
	r_buf_write_at (bf->buf, mp.lastcmd_off + sample_dylib_name_off, (const ut8*)lib, lib_len + 1);
	return true;
}

static bool addlib(RBinFile *bf, const char *lib) {
	return MACH0_(write_addlib) (bf, lib);
}

#if !R_BIN_MACH064
RBinWrite r_bin_write_mach0 = {
#if 0
	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
	.rpath_del = &rpath_del,
	.entry = &chentry,
#endif
	.addlib = &addlib,
};
#endif
