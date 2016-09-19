/* radare - LGPL - Copyright 2011-2012 - pancake */

#include <r_core.h>

/* We can not use some kind of structure type with
 * a string for each case, because some architectures (like ARM)
 * have several modes/alignement requirements.
 */

void r_core_hack_help(const RCore *core) {
	const char* help_msg[] = {
		"wao", " [op]", "performs a modification on current opcode",
		"wao", " nop", "nop current opcode",
		"wao", " jz", "make current opcode conditional (zero)",
		"wao", " jnz", "make current opcode conditional (not zero)",
		"wao", " ret1", "make the current opcode return 1",
		"wao", " ret0", "make the current opcode return 0",
		"wao", " retn", "make the current opcode return -1",
		"wao", " un-cjmp", "remove conditional operation to branch",
		"wao", " trap", "make the current opcode a trap",
		"wao", " swap-cjmp", "swap conditional branch",
		"NOTE:", "", "those operations are only implemented for x86 and arm atm.", //TODO
		NULL
	};
	r_core_cmd_help(core, help_msg);
}

R_API int r_core_hack_arm(RCore *core, const char *op, const RAnalOp *analop) {
	const int bits = core->assembler->bits;
	const ut8 *b = core->block;

	if (!strcmp (op, "nop")) {
		const int nopsize = (bits==16)? 2: 4;
		const char *nopcode = (bits==16)? "00bf":"0000a0e1";
		const int len = analop->size;
		char* str;
		int i;

		if (len % nopsize) {
			eprintf ("Invalid nopcode size\n");
			return false;
		}

		str = malloc (len*2 + 1);
		for (i=0; i<len; i+=nopsize)
			memcpy (str+i*2, nopcode, nopsize*2);
		str[len*2] = '\0';
		r_core_cmdf (core, "wx %s\n", str);
		free (str);
	} else if (!strcmp (op, "trap")) {
		const char* trapcode = (bits==16)? "bebe": "fedeffe7";
		r_core_cmdf (core, "wx %s\n", trapcode);
	} else if (!strcmp (op, "jz")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb9: // CBNZ
				r_core_cmd0 (core, "wx b1 @@ $$+1\n"); //CBZ
				break;
			case 0xbb: // CBNZ
				r_core_cmd0 (core, "wx b3 @@ $$+1\n"); //CBZ
				break;
			case 0xd1: // BNE
				r_core_cmd0 (core, "wx d0 @@ $$+1\n"); //BEQ
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				return false;
			}
		} else {
			eprintf ("ARM jz hack not supported\n");
			return false;
		}
	} else if (!strcmp (op, "jnz")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
				r_core_cmd0 (core, "wx b9 @@ $$+1\n"); //CBNZ
				break;
			case 0xb3: // CBZ
				r_core_cmd0 (core, "wx bb @@ $$+1\n"); //CBNZ
				break;
			case 0xd0: // BEQ
				r_core_cmd0 (core, "wx d1 @@ $$+1\n"); //BNE
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				return false;
			}
		} else {
			eprintf ("ARM jnz hack not supported\n");
			return false;
		}
	} else if (!strcmp (op, "un-cjmp")) {
		// TODO: drop conditional bit instead of that hack
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
			case 0xb3: // CBZ
			case 0xd0: // BEQ
			case 0xb9: // CBNZ
			case 0xbb: // CBNZ
			case 0xd1: // BNE
				r_core_cmd0 (core, "wx e0 @@ $$+1\n"); //BEQ
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				return false;
			}
		} else {
			eprintf ("ARM un-cjmp hack not supported\n");
			return false;
		}
	} else if (!strcmp (op, "swap-cjmp")) {
		eprintf ("TODO: use jnz or jz\n");
		return false;
	} else if (!strcmp (op, "ret1")) {
		if (bits == 16)
			r_core_cmd0 (core, "wx 01207047 @@ $$+1\n"); // mov r0, 1; bx lr
		else
			r_core_cmd0 (core, "wx 0100b0e31eff2fe1 @@ $$+1\n"); // movs r0, 1; bx lr
	} else if (!strcmp (op, "ret0")) {
		if (bits == 16)
			r_core_cmd0 (core, "wx 00207047 @@ $$+1\n"); // mov r0, 0; bx lr
		else
			r_core_cmd0 (core, "wx 0000a0e31eff2fe1 @@ $$+1\n"); // movs r0, 0; bx lr
	} else if (!strcmp (op, "retn")) {
		if (bits == 16)
			r_core_cmd0 (core, "wx ff207047 @@ $$+1\n"); // mov r0, -1; bx lr
		else
			r_core_cmd0 (core, "wx ff00a0e31eff2fe1 @@ $$+1\n"); // movs r0, -1; bx lr
	} else {
		eprintf ("Invalid operation\n");
		return false;
	}
	return true;
}

R_API int r_core_hack_x86(RCore *core, const char *op, const RAnalOp *analop) {
	const ut8 *b = core->block;
	const int size = analop->size;
	if (!strcmp (op, "nop")) {
		if (size * 2 + 1 < size) return false;
		char *str = malloc (size * 2 + 1);
		if (!str) return false;
		int i;
		for (i = 0; i < size; i++)
			memcpy(str + (i * 2), "90", 2);
		str[size*2] = '\0';
		r_core_cmdf(core, "wx %s\n", str);
		free(str);
	} else if (!strcmp (op, "trap")) {
		r_core_cmd0 (core, "wx cc\n");
	} else if (!strcmp (op, "jz")) {
		if (b[0] == 0x75) {
			r_core_cmd0 (core, "wx 74\n");
		} else {
			eprintf ("Current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp (op, "jnz")) {
		if (b[0] == 0x74) {
			r_core_cmd0 (core, "wx 75\n");
		} else {
			eprintf ("Current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp (op, "un-cjmp")) {
		if (b[0] >= 0x70 && b[0] <= 0x7f) {
			r_core_cmd0 (core, "wx eb\n");
		} else {
			eprintf ("Current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp (op, "swap-cjmp")) {
		if (b[0] < 0x80 && b[0] >= 0x70){ // jo, jno, jb, jae, je, jne, jbe, ja, js, jns
			r_core_cmdf (core, "wx %x\n", (b[0]%2)? b[0] - 1: b[0] + 1);
		} else {
			eprintf ("Invalid opcode\n");
			return false;
		}
	} else if (!strcmp (op, "ret1")) {
		r_core_cmd0 (core, "wx c20100\n");
	} else if (!strcmp (op, "ret0")) {
		r_core_cmd0 (core, "wx c20000\n");
	} else if (!strcmp (op, "retn")) {
		r_core_cmd0 (core, "wx c2ffff\n");
	} else {
		eprintf ("Invalid operation\n");
		return false;
	}
	return true;
}

R_API int r_core_hack(RCore *core, const char *op) {
	int (*hack)(RCore *core, const char *op, const RAnalOp *analop) = NULL;
	const char *asmarch = r_config_get (core->config, "asm.arch");
	if (!asmarch) return false;
	RAnalOp analop;

	if (strstr (asmarch, "x86")) {
		hack = r_core_hack_x86;
	} else if (strstr (asmarch, "arm")) {
		hack = r_core_hack_arm;
	} else {
		eprintf ("TODO: write hacks are only for x86\n");
	}
	if (hack) {
		if (!r_anal_op (core->anal, &analop, core->offset, core->block, core->blocksize)) {
			eprintf ("anal op fail\n");
			return false;
		}
		return hack (core, op, &analop);
	}
	return false;
}
