/* radare - LGPL - Copyright 2011-2012 - pancake */

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

R_API int r_core_hack_x86(RCore *core, const char *op, RAnalOp *analop) {
	ut8 *b = core->block;
	if (!strcmp (op, "nop")) {
		int nopsize = 1;
		const char *nopcode = "90";
		int len = analop->size;
		if (len%nopsize) {
			eprintf ("Invalid nopcode size\n");
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

// TODO: needs refactoring to make it cross-architecture
R_API int r_core_hack(RCore *core, const char *op) {
	RAnalOp analop;
	if (!strstr (r_config_get (core->config, "asm.arch"), "x86"))
		eprintf ("TODO: write hacks are only for x86\n");
	if (!r_anal_op (core->anal, &analop, core->offset, core->block, core->blocksize)) {
 		eprintf ("anal op fail\n");
		return R_FALSE;
	}
	return r_core_hack_x86 (core, op, &analop);
}
