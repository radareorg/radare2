/* radare - LGPL - Copyright 2015-2026 - pancake, phix33 */

#include <r_core.h>
#include "pseudo.h"

static ut64 find_nextop(RCore *core, ut64 addr) {
	RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT);
	if (op && (int)op->size > 0) {
		return addr + op->size;
	}
	const int minopsz = r_arch_info (core->anal->arch, R_ARCH_INFO_MINOP_SIZE);
	// Check for possible integer overflow
	if (UT64_MAX - (ut64)minopsz < addr) {
		return UT64_MAX;
	}
	return addr + minopsz;
}

// problematic for non-linear functions
// TODO: resort all lines from the decompiler by offset and then use that as guide
static ut64 find_endfunc(RCore *core, ut64 addr) {
	ut64 res = UT64_MAX;
	RList *funcs = r_anal_get_functions_in (core->anal, addr);
	if (funcs) {
		RAnalFunction *f = (RAnalFunction *)r_list_get_n (funcs, 0);
		if (f) {
			res = r_anal_function_max_addr (f);
		}
		r_list_free (funcs);
	}
	return res;
}
static ut64 find_nextfunc(RCore *core, ut64 addr, int range) {
	while (range-- > 0) {
#if 0
		RList *funcs = r_anal_get_functions_in (core->anal, addr);
		if (funcs) {
			RAnalFunction *f = r_list_get_n (funcs, 0);
			if (f) {
				return addr;
			}
		}
#else
		RAnalFunction *f = r_anal_get_function_at (core->anal, addr);
		if (f) {
			return addr;
		}
#endif
		addr = find_nextop (core, addr);
	}
	return UT64_MAX;
}

static void linear_pseudo(RCore *core, const char *arg) {
	int rows = (int)r_num_math (core->num, arg);
	int h;
	r_cons_get_size (core->cons, &h);
	if (rows < 1) {
		rows = h;
	}
	char *offpos = NULL;
	int lines = 0;
	RStrBuf *sb = r_strbuf_new ("");
	ut64 nextaddr = UT64_MAX;
	ut64 initial_addr = core->addr;
	ut64 addr = initial_addr;
repeat:;
	offpos = NULL;
	char *cur = r_core_cmd_str (core, "pdco");
	if (cur) {
		// we have a function, but we need to find the
		// current offset inside the output of the decompiler
		int retries = 10;
	repeat_inside:;
		char *off = r_str_newf ("0x%08" PFMT64x, addr);
		offpos = strstr (cur, off);
		if (!offpos) {
			addr = find_nextop (core, addr);
			if (retries > 0) {
				retries--;
				free (off);
				off = r_str_newf ("0x%08" PFMT64x, addr);
				goto repeat_inside;
			}
			R_FREE (cur);
		}
		R_FREE (off);
	}
	if (offpos) {
		while (offpos > cur) {
			if (*offpos == '\n') {
				offpos++;
				break;
			}
			offpos--;
		}
		r_strbuf_append (sb, offpos);
		lines += r_str_char_count (offpos, '\n');
#if 0
		char *lastoff = r_str_rstr (offpos, "0x");
		nextaddr = r_num_get (core->num, lastoff);
#else
		ut64 eof = find_endfunc (core, addr);
		if (eof != UT64_MAX) {
			nextaddr = find_nextop (core, eof);
		}
#endif
	} else {
		nextaddr = addr;
	}
	free (cur);
	cur = NULL;
	ut64 nextfunc = find_nextfunc (core, nextaddr, 128);
	if (lines < rows) {
		if (nextfunc == UT64_MAX) {
			char *res = r_core_cmd_strf (core, "pd %d @0x%08" PFMT64x "@e:asm.lines=0@e:asm.pseudo=true@e:asm.bytes=0@e:emu.str=true", rows - lines, addr);
			r_strbuf_append (sb, res);
			free (res);
		} else {
			char *res = r_core_cmd_strf (core, "pD %" PFMT64d " @0x%08" PFMT64x "@e:asm.lines=0@e:asm.pseudo=true@e:asm.bytes=0@e:emu.str=true", nextfunc - addr, addr);
			r_strbuf_append (sb, res);
			lines += r_str_char_count (res, '\n');
			free (res);
			addr = nextfunc;
			r_core_seek (core, nextfunc, true);
			goto repeat;
		}
	}
	char *s = r_strbuf_drain (sb);
	r_cons_print (core->cons, s);
	free (s);
	r_core_seek (core, initial_addr, true);
}


static bool r_cmd_pseudo_call(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (!core) {
		return false;
	}
	if (!r_str_startswith (input, "pdc") && !r_str_startswith (input, "pDc")) {
		return false;
	}
	if (input[3] == 'l') { // "pdcl"
		linear_pseudo (core, input + 4);
	} else {
		pdc_decompile (core, input + 3);
	}
	return true;
}

RCorePlugin r_core_plugin_pseudo = {
	.meta = {
		.name = "pseudo",
		.desc = "pdc pseudo decompiler",
		.license = "LGPL-3.0-only",
		.author = "pancake",
	},
	.call = r_cmd_pseudo_call,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_pseudo,
	.version = R2_VERSION
};
#endif
