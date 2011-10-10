/* radare - LGPL - Copyright 2011 // pancake<nopcode.org> */
#include <r_core.h>

R_API void r_core_hack_help(RCore *core) {
	eprintf ("wao [op] ; performs a modification on current opcode\n"
		" nop          : replace current opcode with\n"
		" jz           : make current opcode conditional (zero)\n"
		" jnz          : make current opcode conditional (not zero)\n"
		" un-cjmp      : remove conditional operation to branch\n"
		" swap-cjmp    : swap conditional branch\n"
		"NOTE: those operations are only implemented for x86 atm. (TODO)\n");
}

// TODO: needs refactoring to make it cross-architecture
R_API int r_core_hack(RCore *core, const char *op) {
	ut8 *b = core->block;
	RAnalOp analop;
	if (!r_anal_op (core->anal, &analop, core->offset, core->block, core->blocksize)) {
 		eprintf ("anal op fail\n");
		return R_FALSE;
	}
	if (!strcmp (op, "nop")) {
		int nopsize = 1; // XXX x86 only
		const char *nopcode = "90"; // XXX x86 only
		int len = analop.length;
		if (len%nopsize) {
			eprintf ("Invalid nopcode length\n");
			return R_FALSE;
		}
		r_cons_puts ("wx ");
		do r_cons_puts (nopcode);
		while (len-=nopsize);
		r_cons_puts ("\n");
		return R_TRUE;
	} else
	if (!strcmp (op, "jz")) {
		if (b[0] == 0x75) {
			r_cons_puts ("wx 74\n");
			return R_TRUE;
		} else eprintf ("Current opcode is not conditional\n");
	} else
	if (!strcmp (op, "jnz")) {
		if (b[0] == 0x74) {
			r_cons_puts ("wx 75\n");
			return R_TRUE;
		} else eprintf ("Current opcode is not conditional\n");
		return R_TRUE;
	} else
	if (!strcmp (op, "un-cjmp")) {
		if (b[0] >= 0x70 && b[0] <= 0x7f) {
			r_cons_puts ("wx eb\n");
			return R_TRUE;
		} else eprintf ("Current opcode is not conditional\n");
	} else
	if (!strcmp (op, "swap-cjmp")) {
		if (b[0] == 0x74)
			r_cons_puts ("wx 75\n");
		else
		if (b[0] == 0x75)
			r_cons_puts ("wx 74\n");
		else eprintf ("Invalid opcode\n");
		// XXX. add support for jb, jg, jl, ..
	} else eprintf ("Invalid operation\n");
	return R_FALSE;
}
