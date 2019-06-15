/* radare - LGPL - Copyright 2016-2019 - pancake */

#include <r_types.h>
#include <r_bin.h>
#include "mach0/mach0.h"

static size_t findLastCommand(RBinFile *bf) {
	struct MACH0_(obj_t) *bin = bf->o->bin_obj;
	int i = 0;
	ut64 off;
	for (i = 0, off = sizeof (struct MACH0_(mach_header)) + bin->header_at; \
			i < bin->hdr.ncmds; i++) {
		ut32 loadc[2] = {0};
		eprintf ("off %d 0x%llx\n", i, off);
		r_buf_read_at (bin->b, off, &loadc, sizeof (loadc));
		eprintf ("off - 0x%llx\n", loadc[0]);
		eprintf ("off - 0x%llx\n", loadc[1]);
		//r_buf_seek (bin->b, off, R_BUF_SET);
		int len = r_buf_read_le32 (&loadc + 8); // bin->b); // 
eprintf ("%d\n", len);
		if (len < 1) {
			eprintf ("Error: read (lc) at 0x%08"PFMT64x"\n", off);
			return false;
		}
		off += r_read_ble32 (&loadc[4], bin->big_endian);
	}
	eprintf ("___ (0x%x) __\n", off);
}

static bool MACH0_(write_addlib)(RBinFile *bf, const char *lib) {
	struct MACH0_(obj_t) *obj = bf->o->bin_obj;
	size_t lastCommandOffset = findLastCommand (bf);
eprintf ("NCMDS = %d\n", obj->hdr.ncmds);
	eprintf ("TODO: addlib\n");
	return false;
}

static bool addlib(RBinFile *bf, const char *lib) {
	bool ret = MACH0_(write_addlib) (bf, lib);

	//r_buf_free (bf->buf);
	//bf->buf = obj->b;
	//obj->b = NULL;
	return ret;
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
