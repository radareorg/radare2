/* radare2 - LGPL - Copyright */

#ifndef R_MIPS_UTILS_H
#define R_MIPS_UTILS_H

#include <r_endian.h>
#include <r_arch.h>
#include <r_bin.h>

static inline ut64 mips_read_ptr_at(RBin *bin, ut64 addr, bool be, int bits) {
	const int ptrsz = bits == 64 ? 8 : 4;
	ut8 v[8] = {0};
	if (!bin || bin->iob.read_at (bin->iob.io, addr, v, ptrsz) != ptrsz) {
		return UT64_MAX;
	}
	return ptrsz == 8 ? r_read_ble64 (v, be) : r_read_ble32 (v, be);
}

// esil for the unaligned lwl/lwr/ldl/ldr loads and swl/swr/sdl/sdr stores
static inline void mips_esil_unaligned(RStrBuf *esil, const RArchConfig *cfg, const char *addr, const char *rt, int w, bool left, bool store) {
	const char *mask = (w == 8)? "0xffffffffffffffff": "0xffffffff";
	const char *align = (w == 8)? "0xfffffffffffffff8": "0xfffffffffffffffc";
	const bool sx = !store && w == 4 && cfg->bits == 64;
	// a le cpu counts the addressed byte from the other end of the word
	char *sh = (R_ARCH_CONFIG_IS_BIG_ENDIAN (cfg) == left)
		? r_str_newf ("3,%s,%d,&,<<", addr, w - 1)
		: r_str_newf ("3,%s,%d,&,%d,-,<<", addr, w - 1, w - 1);
	char *mem = r_str_newf ("%s,%s,&,[%d]", addr, align, w);
	if (store && left) {
		r_strbuf_appendf (esil, "%s,%s,>>,%s,^,%s,&,%s,%s,%s,&,>>,|,%s,%s,&,=[%d]",
			sh, mask, mask, mem, sh, mask, rt, addr, align, w);
	} else if (store) {
		r_strbuf_appendf (esil, "%s,%s,%s,&,<<,1,%s,1,<<,-,%s,&,|,%s,%s,&,=[%d]",
			sh, mask, rt, sh, mem, addr, align, w);
	} else if (left) {
		r_strbuf_appendf (esil, "%s%s,%s,<<,%s,&,1,%s,1,<<,-,%s,&,|,%s%s,=",
			sx? "32,": "", sh, mem, mask, sh, rt, sx? "~,": "", rt);
	} else {
		r_strbuf_appendf (esil, "%s%s,%s,>>,%s,%s,%s,>>,^,%s,&,|,%s%s,=",
			sx? "32,": "", sh, mem, mask, sh, mask, rt, sx? "~,": "", rt);
	}
	free (sh);
	free (mem);
}

#endif
