/* radare - LGPL - Copyright 2009-2016 - pancake, nibble */

#include <r_types.h>
#include <r_bin.h>
#include "pe/pe.h"

static bool scn_perms(RBinFile *arch, const char *name, int perms) {
	struct PE_(r_bin_pe_obj_t) *obj = arch->o->bin_obj;
	int ret = PE_(r_bin_pe_section_perms) (arch->o->bin_obj, name, perms);
	r_buf_free (arch->buf);
	arch->buf = obj->b;
	obj->b = NULL;
	return ret;
}

RBinWrite r_bin_write_pe = {
//	.scn_resize = &scn_resize,
	.scn_perms = &scn_perms,
};