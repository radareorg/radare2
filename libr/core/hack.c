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

R_API int r_core_hack_arm(RCore *core, const char *op, RAnalOp *analop) {
	int bits = core->assembler->bits;
	ut8 *b = core->block;
	if (!strcmp (op, "nop")) {
		int nopsize = (bits==16)? 2: 4;
		const char *nopcode = (bits==16)? "\x00\xbf":"\x00\x00\xa0\xe1";
		int len = analop->size;
		if (len%nopsize) {
			eprintf ("Invalid nopcode size\n");
			return R_FALSE;
		}
		r_cons_puts ("wx ");
		do r_cons_puts (nopcode);
		while (len -= nopsize);
		r_cons_puts ("\n");
		return R_TRUE;
	} else
	if (!strcmp (op, "jz")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb9: // CBNZ
				r_cons_printf ("wx b1 @@ $$+1\n"); //CBZ
				break;
			case 0xbb: // CBNZ
				r_cons_printf ("wx b3 @@ $$+1\n"); //CBZ
				break;
			case 0xd1: // BNE
				r_cons_printf ("wx d0 @@ $$+1\n"); //BEQ
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				break;
			}
		} else {
			eprintf ("ARM jz hack not supported\n");
		}
	} else
	if (!strcmp (op, "jnz")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
				r_cons_printf ("wx b9 @@ $$+1\n"); //CBNZ
				break;
			case 0xb3: // CBZ
				r_cons_printf ("wx bb @@ $$+1\n"); //CBNZ
				break;
			case 0xd0: // BEQ
				r_cons_printf ("wx d1 @@ $$+1\n"); //BNE
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				break;
			}
		} else {
			eprintf ("ARM jz hack not supported\n");
		}
	} else
	if (!strcmp (op, "un-cjmp")) {
		// TODO: drop conditional bit instead of that hack
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
			case 0xb3: // CBZ
			case 0xd0: // BEQ
			case 0xb9: // CBNZ
			case 0xbb: // CBNZ
			case 0xd1: // BNE
				r_cons_printf ("wx e0 @@ $$+1\n"); //BEQ
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				break;
			}
		} else {
			eprintf ("ARM jz hack not supported\n");
		}
	} else
	if (!strcmp (op, "swap-cjmp")) {
		eprintf ("TODO: use jnz or jz\n");
	} else eprintf ("Invalid operation\n");
	return R_FALSE;
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
	int (*hack)(RCore *core, const char *op, RAnalOp *analop) = NULL;
	int ret = R_FALSE;
	RAnalOp analop;
	const char *asmarch = r_config_get (core->config, "asm.arch");
	if (strstr (asmarch, "x86")) {
		hack = r_core_hack_x86;
	} else if (strstr (asmarch, "arm")) {
		hack = r_core_hack_arm;
	} else {
		eprintf ("TODO: write hacks are only for x86\n");
	}
	if (hack) {
		if (!r_anal_op (core->anal, &analop, core->offset,
				core->block, core->blocksize)) {
			eprintf ("anal op fail\n");
			return R_FALSE;
		}
		ret = hack (core, op, &analop);
	}
	return ret;
}
