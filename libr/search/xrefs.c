/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_search.h"
//#include <regex.h>

R_API int r_search_xrefs_update(void *s, ut64 from, const ut8 *buf, size_t len) {
//	ut8 code[1024];
//	ut8 mask[1024];
	int count = 0;
	//get_delta_for(
	//if (r_mem_cmp_mask(buf, code, mask, 4)) {
	//}
	return count;
}

#if 0

struct r_xrefs_arch_t {
	int align; // if arch requires align we can skip invalid addresses
	int bigendian;
	ut64 baseaddr;
	ut64 targetaddr; // the addr we are looking for
};

the xrefs plugin will have a callback:

 - size of opcode to skip in bytes (mips/arm=4 f.ex)
 int r_xrefs_x86(ut64 addr, int bigendian, ut64 baseaddr)
 {
	// check for calls, branches..and calculate target address
 }

Options we need to configure xrefs search plugin:
 - endian
 - base address
 - target address
 - from/to (defined as max for the maximum branch distance)
 - architecture profile ()
 - TODO: ensure we are pointing to a function if following a 'call'
 - we need per-arch plugins

#endif
