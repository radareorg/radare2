/* radare - LGPL - Copyright 2011-2023 - pancake */

#include <r_core.h>

/* We can not use some kind of structure type with
 * a string for each case, because some architectures (like ARM)
 * have several modes/alignment requirements.
 */

static bool r_core_hack_riscv(RCore *core, const char *op, const RAnalOp *analop) {
	// TODO honor analop->size
	if (!strcmp (op, "nop")) {
		if (analop->size < 2) {
			R_LOG_ERROR ("Can't nop <4 byte instructions");
			return false;
		}
		if (analop->size < 4) {
			r_core_cmd0 (core, "wx 0100");
		} else {
			r_core_cmd0 (core, "wx 13000000");
		}
		return true;
	}
	if (!strcmp (op, "jinf")) {
		if (analop->size < 2) {
			R_LOG_ERROR ("Minimum jinf is 2 byte");
			return false;
		}
		r_core_cmd0 (core, "wx 01a0");
		return true;
	}
	R_LOG_ERROR ("Unsupported operation '%s'", op);
	return false;
}

static bool r_core_hack_dalvik(RCore *core, const char *op, const RAnalOp *analop) {
	if (!strcmp (op, "nop")) {
		r_core_cmdf (core, "wx 0000");
	} else if (!strcmp (op, "ret2")) {
		r_core_cmdf (core, "wx 12200f00"); // mov v0, 2;ret v0
	} else if (!strcmp (op, "jinf")) {
		r_core_cmd0 (core, "wx 2800");
	} else if (!strcmp (op, "ret1")) {
		r_core_cmdf (core, "wx 12100f00"); // mov v0, 1;ret v0
	} else if (!strcmp (op, "ret0")) {
		r_core_cmdf (core, "wx 12000f00"); // mov v0, 0;ret v0
	} else {
		R_LOG_ERROR ("Unsupported operation '%s'", op);
		return false;
	}
	return true;
}

R_API bool r_core_hack_arm64(RCore *core, const char *op, const RAnalOp *analop) {
	if (!strcmp (op, "nop")) {
		r_core_cmdf (core, "wx 1f2003d5");
	} else if (!strcmp (op, "ret")) {
		r_core_cmdf (core, "wx c0035fd6t");
	} else if (!strcmp (op, "trap")) {
		r_core_cmdf (core, "wx 000020d4");
	} else if (!strcmp (op, "jz") || !strcmp (op, "je")) {
		R_LOG_ERROR ("ARM jz hack not supported");
		return false;
	} else if (!strcmp (op, "jinf")) {
		r_core_cmdf (core, "wx 00000014");
	} else if (!strcmp (op, "jnz") || !strcmp (op, "jne")) {
		R_LOG_ERROR ("ARM jnz hack not supported");
		return false;
	} else if (!strcmp (op, "nocj")) {
		R_LOG_ERROR ("ARM jnz hack not supported");
		return false;
	} else if (!strcmp (op, "recj")) {
		if (analop->size < 4) {
			return false;
		}
		const ut8 *buf = analop->bytes;
		if (!buf) {
			buf = core->block;
		}
		switch (*buf) {
		case 0x4c: // bgt -> ble
			r_core_cmd_call (core, "wx 4d");
			break;
		case 0x4d: // ble -> bgt
			r_core_cmd_call (core, "wx 4c");
			break;
		default:
			switch (buf[3]) {
			case 0x34: // cbz
			case 0xb4: // cbz
				r_core_cmdf (core, "wx 35 @ $$+3");
				break;
			case 0x35: // cbnz
				r_core_cmdf (core, "wx b4 @ $$+3");
				break;
			default:
				R_LOG_ERROR ("TODO: unsupported instruction to toggle conditional jump");
				return false;
			}
			break;
		}
	} else if (!strcmp (op, "ret1")) {
		r_core_cmdf (core, "wa mov x0, 1,,ret");
	} else if (!strcmp (op, "ret0")) {
		r_core_cmdf (core, "wa mov x0, 0,,ret");
	} else if (!strcmp (op, "retn")) {
		r_core_cmdf (core, "wa mov x0, -1,,ret");
	} else {
		R_LOG_ERROR ("Invalid operation '%s'", op);
		return false;
	}
	return true;
}
R_API bool r_core_hack_arm(RCore *core, const char *op, const RAnalOp *analop) {
	const int bits = core->rasm->config->bits;
	const ut8 *b = core->block;

	if (!strcmp (op, "nop")) {
		const int nopsize = (bits == 16)? 2: 4;
		const char *nopcode = (bits == 16)? "00bf":"0000a0e1";
		const int len = analop->size;
		int i;

		if (len % nopsize) {
			R_LOG_ERROR ("Invalid nopcode size");
			return false;
		}

		char *str = calloc (len + 1, 2);
		if (!str) {
			return false;
		}
		for (i = 0; i < len; i += nopsize) {
			memcpy (str + i * 2, nopcode, nopsize * 2);
		}
		str[len * 2] = '\0';
		r_core_cmdf (core, "wx %s", str);
		free (str);
	} else if (!strcmp (op, "jinf")) {
		r_core_cmdf (core, "wx %s", (bits==16)? "fee7": "feffffea");
	} else if (!strcmp (op, "trap")) {
		const char* trapcode = (bits==16)? "bebe": "fedeffe7";
		r_core_cmdf (core, "wx %s", trapcode);
	} else if (!strcmp (op, "jz") || !strcmp (op, "je")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb9: // CBNZ
				r_core_cmd0 (core, "wx b1 @ $$+1"); //CBZ
				break;
			case 0xbb: // CBNZ
				r_core_cmd0 (core, "wx b3 @ $$+1"); //CBZ
				break;
			case 0xd1: // BNE
				r_core_cmd0 (core, "wx d0 @ $$+1"); //BEQ
				break;
			default:
				R_LOG_ERROR ("Current opcode is not conditional");
				return false;
			}
		} else {
			R_LOG_ERROR ("ARM jz hack not supported");
			return false;
		}
	} else if (!strcmp (op, "jnz") || !strcmp (op, "jne")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
				r_core_cmd0 (core, "wx b9 @ $$+1"); //CBNZ
				break;
			case 0xb3: // CBZ
				r_core_cmd0 (core, "wx bb @ $$+1"); //CBNZ
				break;
			case 0xd0: // BEQ
				r_core_cmd0 (core, "wx d1 @ $$+1"); //BNE
				break;
			default:
				R_LOG_ERROR ("Current opcode is not conditional");
				return false;
			}
		} else {
			R_LOG_ERROR ("ARM jnz hack not supported");
			return false;
		}
	} else if (!strcmp (op, "nocj")) {
		// TODO: drop conditional bit instead of that hack
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
			case 0xb3: // CBZ
			case 0xd0: // BEQ
			case 0xb9: // CBNZ
			case 0xbb: // CBNZ
			case 0xd1: // BNE
				r_core_cmd0 (core, "wx e0 @ $$+1"); //BEQ
				break;
			default:
				R_LOG_ERROR ("Current opcode is not conditional");
				return false;
			}
		} else {
			R_LOG_ERROR ("ARM un-cjmp hack not supported");
			return false;
		}
	} else if (!strcmp (op, "recj")) {
		R_LOG_ERROR ("TODO: use jnz or jz");
		return false;
	} else if (!strcmp (op, "ret1")) {
		if (bits == 16) {
			r_core_cmd0 (core, "wx 01207047"); // mov r0, 1; bx lr
		} else {
			r_core_cmd0 (core, "wx 0100b0e31eff2fe1"); // movs r0, 1; bx lr
		}
	} else if (!strcmp (op, "ret0")) {
		if (bits == 16) {
			r_core_cmd0 (core, "wx 00207047"); // mov r0, 0; bx lr
		} else {
			r_core_cmd0 (core, "wx 0000a0e31eff2fe1"); // movs r0, 0; bx lr
		}
	} else if (!strcmp (op, "retn")) {
		if (bits == 16) {
			r_core_cmd0 (core, "wx ff207047"); // mov r0, -1; bx lr
		} else {
			r_core_cmd0 (core, "wx ff00a0e31eff2fe1"); // movs r0, -1; bx lr
		}
	} else {
		R_LOG_ERROR ("Invalid operation");
		return false;
	}
	return true;
}

R_API bool r_core_hack_x86(RCore *core, const char *op, const RAnalOp *analop) {
	const ut8 *b = core->block;
	int i, size = analop->size;
	if (!strcmp (op, "nop")) {
		if (size * 2 + 1 < size) {
			return false;
		}
		char *str = malloc (size * 2 + 1);
		if (!str) {
			return false;
		}
		for (i = 0; i < size; i++) {
			memcpy (str + (i * 2), "90", 2);
		}
		str[size*2] = '\0';
		r_core_cmdf (core, "wx %s", str);
		free (str);
	} else if (!strcmp (op, "trap")) {
		r_core_cmd0 (core, "wx cc");
	} else if (!strcmp (op, "jz") || !strcmp (op, "je")) {
		if (b[0] == 0x75) {
			r_core_cmd0 (core, "wx 74");
		} else {
			R_LOG_ERROR ("Current opcode is not conditional");
			return false;
		}
	} else if (!strcmp (op, "jinf")) {
		r_core_cmd0 (core, "wx ebfe");
	} else if (!strcmp (op, "jnz") || !strcmp (op, "jne")) {
		if (b[0] == 0x74) {
			r_core_cmd0 (core, "wx 75");
		} else {
			R_LOG_ERROR ("Current opcode is not conditional");
			return false;
		}
	} else if (!strcmp (op, "nocj")) {
		if (*b == 0xf) {
			r_core_cmd0 (core, "wx 90e9");
		} else if (b[0] >= 0x70 && b[0] <= 0x7f) {
			r_core_cmd0 (core, "wx eb");
		} else {
			R_LOG_ERROR ("Current opcode is not conditional");
			return false;
		}
	} else if (!strcmp (op, "recj")) {
		int is_near = (*b == 0xf);
		if (b[0] < 0x80 && b[0] >= 0x70) { // short jmps: jo, jno, jb, jae, je, jne, jbe, ja, js, jns
				r_core_cmdf (core, "wx %x", (b[0]%2)? b[0] - 1: b[0] + 1);
		} else if (is_near && b[1] < 0x90 && b[1] >= 0x80) { // near jmps: jo, jno, jb, jae, je, jne, jbe, ja, js, jns
				r_core_cmdf (core, "wx 0f%x", (b[1]%2)? b[1] - 1: b[1] + 1);
		} else {
			R_LOG_ERROR ("Invalid conditional jump opcode");
			return false;
		}
	} else if (!strcmp (op, "ret1")) {
		r_core_cmd0 (core, "wx c20100");
	} else if (!strcmp (op, "ret0")) {
		r_core_cmd0 (core, "wx c20000");
	} else if (!strcmp (op, "retn")) {
		r_core_cmd0 (core, "wx c2ffff");
	} else {
		R_LOG_ERROR ("Invalid operation '%s'", op);
		return false;
	}
	return true;
}

R_API bool r_core_hack(RCore *core, const char *op) {
	r_return_val_if_fail (core && op, false);
	bool (*hack)(RCore *core, const char *op, const RAnalOp *analop) = NULL;
	const char *asmarch = r_config_get (core->config, "asm.arch");
	const int asmbits = core->rasm->config->bits;
	const bool doseek = (*op == '+');
	if (doseek) {
		op++;
	}

	if (!asmarch) {
		return false;
	}
	if (core->blocksize < 4) {
		return false;
	}
#if R2_600
	// R2_590 TODO: call RArch.patch() if available, otherwise just do this hack until all anal plugs are moved to arch
	// r_arch_patch (aop, 0);
	RArchSession *acur = R_UNWRAP3 (core, rasm, acur);
	if (acur && acur->plugin->patch) {
		RAnalOp *aop = r_anal_op_new ();
		r_anal_op_set_mnemonic (aop, core->offset, op);
		r_anal_op_set_bytes (aop, core->offset, r_mem_dup (core->block, core->blocksize), core->blocksize);
#if 0
		r_arch_session_patch (core->anal->arch, aop, 0);
#endif
		bool res = acur->plugin->patch (acur, aop, 0);
		if (res) {
			// ... r_io_write_at ()
		}
		r_anal_op_free (aop);
		return res;
	}
#endif
	if (strstr (asmarch, "x86")) {
		hack = r_core_hack_x86;
	} else if (strstr (asmarch, "dalvik")) {
		hack = r_core_hack_dalvik;
	} else if (strstr (asmarch, "riscv")) {
		hack = r_core_hack_riscv;
	} else if (strstr (asmarch, "arm")) {
		if (asmbits == 64) {
			hack = r_core_hack_arm64;
		} else {
			hack = r_core_hack_arm;
		}
	} else {
		R_LOG_WARN ("Write hacks are only implemented for x86, arm32, arm64 and dalvik");
	}
	if (hack) {
		RAnalOp aop = {0};
		aop.addr = core->offset;
		r_anal_op_set_bytes (&aop, core->offset, core->block, 4);
		// TODO: use r_arch_decode
		if (!r_anal_op (core->anal, &aop, core->offset, core->block, core->blocksize, R_ARCH_OP_MASK_BASIC)) {
			R_LOG_ERROR ("anal op fail");
			return false;
		}
		bool res = hack (core, op, &aop);
		if (doseek) {
			r_core_seek (core, core->offset + aop.size, 1);
		}
		return res;
	}
	return false;
}
