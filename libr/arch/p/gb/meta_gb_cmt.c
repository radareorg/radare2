/* radare - LGPL - Copyright 2013 - condret */

#include <r_io.h>
#include <r_anal.h>

void meta_gb_bankswitch_cmt(RArchSession *as, ut64 addr, ut16 ldarg) {
	if (0x1fff <ldarg && ldarg < 0x4000 && addr < 0x4000) {
		// XXX r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "Bankswitch");
	}
	if (0x6000 > ldarg && ldarg > 0x3fff) {
		// XXX r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "Ramswitch");
	}
}
