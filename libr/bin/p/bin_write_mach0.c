/* radare - LGPL - Copyright 2016 - pancake */

#include <r_types.h>
#include <r_bin.h>
#include "mach0/mach0.h"

static bool MACH0_(write_addlib)(struct MACH0_(obj_t) *obj, const char *lib) {
	eprintf ("TODO\n");
	return false;
}

static bool addlib(RBinFile *arch, const char *lib) {
	struct MACH0_(obj_t) *obj = arch->o->bin_obj;
	bool ret = MACH0_(write_addlib) (arch->o->bin_obj, lib);
	r_buf_free (arch->buf);
	arch->buf = obj->b;
	obj->b = NULL;
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
