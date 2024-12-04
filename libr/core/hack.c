/* radare - LGPL - Copyright 2011-2024 - pancake */

#include <r_core.h>

static bool r_core_hack_riscv(RCore *core, const RAnalOp *analop, const char *op, int mode) {
	const char *cmd = NULL;
	// TODO honor analop->size
	if (!strcmp (op, "nop")) {
		if (analop->size < 2) {
			R_LOG_ERROR ("Can't nop <4 byte instructions");
			return false;
		}
		if (analop->size < 4) {
			cmd = "wx 0100";
		} else {
		       cmd = "wx 13000000";
		}
	} else if (!strcmp (op, "jinf")) {
		if (analop->size < 2) {
			R_LOG_ERROR ("Minimum jinf is 2 byte");
			return false;
		}
		cmd = "wx 01a0";
	}
	if (cmd) {
		switch (mode) {
		case '*': r_cons_println (cmd); break;
		case 'l': r_cons_printf ("%d\n", (int)(strlen (cmd) - 3)/2); break;
		default: r_core_cmd0 (core, cmd); break;
		}
		return true;
	}
	R_LOG_ERROR ("Unsupported operation '%s'", op);
	return false;
}

static bool r_core_hack_dalvik(RCore *core, const RAnalOp *analop, const char *op, int mode) {
	const char *cmd = NULL;
	if (!strcmp (op, "nop")) {
		cmd = "wx 0000";
	} else if (!strcmp (op, "ret2")) {
		cmd = "wx 12200f00"; // mov v0, 2;ret v0
	} else if (!strcmp (op, "jinf")) {
		cmd = "wx 2800";
	} else if (!strcmp (op, "ret1")) {
		cmd = "wx 12100f00"; // mov v0, 1;ret v0
	} else if (!strcmp (op, "ret0")) {
		cmd = "wx 12000f00"; // mov v0, 0;ret v0
	}
	if (cmd) {
		switch (mode) {
		case '*': r_cons_println (cmd); break;
		case 'l': r_cons_printf ("%d\n", (int)(strlen (cmd) - 3)/2); break;
		default: r_core_cmd0 (core, cmd); break;
		}
		return true;
	}
	R_LOG_ERROR ("Unsupported operation '%s'", op);
	return false;
}

R_API bool r_core_hack_arm64(RCore *core, const RAnalOp *analop, const char *op, int mode) {
	const char *cmd = NULL;
	if (!strcmp (op, "nop")) {
		cmd = "wx 1f2003d5";
	} else if (!strcmp (op, "ret")) {
		cmd = "wx c0035fd6t";
	} else if (!strcmp (op, "trap")) {
		cmd = "wx 000020d4";
	} else if (!strcmp (op, "jz") || !strcmp (op, "je")) {
		R_LOG_ERROR ("ARM jz hack not supported");
	} else if (!strcmp (op, "jinf")) {
		cmd = "wx 00000014";
	} else if (!strcmp (op, "jnz") || !strcmp (op, "jne")) {
		R_LOG_ERROR ("ARM jnz hack not supported");
	} else if (!strcmp (op, "nocj")) {
		R_LOG_ERROR ("ARM jnz hack not supported");
	} else if (!strcmp (op, "recj")) {
		if (analop->size < 4) {
			R_LOG_ERROR ("can't fit 4 bytes in here");
			return false;
		}
		const ut8 *buf = analop->bytes;
		if (!buf) {
			buf = core->block;
		}
		switch (*buf) {
		case 0x4c: // bgt -> ble
			cmd = "wx 4d";
			break;
		case 0x4d: // ble -> bgt
			cmd = "wx 4c";
			break;
		default:
			switch (buf[3]) {
			case 0x36: // tbz
				cmd = "wx 37 @ $$+3";
				break;
			case 0x37: // tbnz
				cmd = "wx 36 @ $$+3";
				break;
			case 0x34: // cbz
			case 0xb4: // cbz
				cmd = "wx 35 @ $$+3";
				break;
			case 0x35: // cbnz
				cmd = "wx b4 @ $$+3";
				break;
			}
			break;
		}
	} else if (!strcmp (op, "ret1")) {
		cmd = "'wa mov x0, 1,,ret";
	} else if (!strcmp (op, "ret0")) {
		cmd = "'wa mov x0, 0,,ret";
	} else if (!strcmp (op, "retn")) {
		cmd = "'wa mov x0, -1,,ret";
	}
	if (cmd) {
		switch (mode) {
		case '*': r_cons_println (cmd); break;
		case 'l': r_cons_println ("4"); break;
		default: r_core_cmd0 (core, cmd); break;
		}
		return true;
	}
	R_LOG_ERROR ("Invalid operation '%s'", op);
	return false;
}

R_API bool r_core_hack_arm(RCore *core, const RAnalOp *analop, const char *op, int mode) {
	const int bits = core->rasm->config->bits;
	const ut8 *b = core->block;
	char *hcmd = NULL;
	const char *cmd = NULL;

	if (!strcmp (op, "nop")) {
		const int nopsize = (bits == 16)? 2: 4;
		const char *nopcode = (bits == 16)? "00bf":"0000a0e1";
		const int len = analop->size;
		int i;

		if (len % nopsize) {
			R_LOG_ERROR ("Invalid nopcode size");
			return false;
		}
		hcmd = calloc (len + 8, 2);
		if (R_LIKELY (hcmd)) {
			strcpy (hcmd, "wx ");
			int n = 3;
			for (i = 0; i < len; i += nopsize) {
				memcpy (hcmd + n + i * 2, nopcode, nopsize * 2);
			}
			hcmd[n + (len * 2)] = '\0';
			cmd = hcmd;
		}
	} else if (!strcmp (op, "jinf")) {
		hcmd = r_str_newf ("wx %s", (bits==16)? "fee7": "feffffea");
		cmd = hcmd;
	} else if (!strcmp (op, "trap")) {
		const char* trapcode = (bits==16)? "bebe": "fedeffe7";
		hcmd = r_str_newf ("wx %s", trapcode);
		cmd = hcmd;
	} else if (!strcmp (op, "jz") || !strcmp (op, "je")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb9: // CBNZ
				cmd = "wx b1 @ $$+1"; //CBZ
				break;
			case 0xbb: // CBNZ
				cmd = "wx b3 @ $$+1"; //CBZ
				break;
			case 0xd1: // BNE
				cmd = "wx d0 @ $$+1"; //BEQ
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
				cmd = "wx b9 @ $$+1"; //CBNZ
				break;
			case 0xb3: // CBZ
				cmd = "wx bb @ $$+1"; //CBNZ
				break;
			case 0xd0: // BEQ
				cmd = "wx d1 @ $$+1"; //BNE
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
				cmd = "wx e0 @ $$+1"; //BEQ
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
			cmd = "wx 01207047"; // mov r0, 1; bx lr
		} else {
			cmd = "wx 0100b0e31eff2fe1"; // movs r0, 1; bx lr
		}
	} else if (!strcmp (op, "ret0")) {
		if (bits == 16) {
			cmd = "wx 00207047"; // mov r0, 0; bx lr
		} else {
			cmd = "wx 0000a0e31eff2fe1"; // movs r0, 0; bx lr
		}
	} else if (!strcmp (op, "retn")) {
		if (bits == 16) {
			cmd = "wx ff207047"; // mov r0, -1; bx lr
		} else {
			cmd = "wx ff00a0e31eff2fe1"; // movs r0, -1; bx lr
		}
	} else {
		R_LOG_ERROR ("Invalid operation");
		return false;
	}
	if (cmd) {
		switch (mode) {
		case '*': r_cons_println (cmd); break;
		case 'l': r_cons_printf ("%d\n", (int)(strlen (cmd) - 3)/2); break;
		default: r_core_cmd_call (core, cmd); break;
		}
		free (hcmd);
		return true;
	}
	free (hcmd);
	return false;
}

R_API bool r_core_hack_x86(RCore *core, const RAnalOp *analop, const char *op, int mode) {
	const ut8 *b = core->block;
	int i, size = analop->size;
	char *hcmd = NULL;
	const char *cmd = NULL;
	if (!strcmp (op, "nop")) {
		if (size * 2 + 1 < size) {
			R_LOG_ERROR ("Cant fit a nop in here");
			return false;
		}
		char *hcmd = malloc ((size * 2) + 5);
		if (!hcmd) {
			return false;
		}
		strcpy (hcmd, "wx ");
		for (i = 0; i < size; i++) {
			memcpy (hcmd + 3 + (i * 2), "90", 2);
		}
		cmd = hcmd;
		hcmd[3 + (size * 2)] = '\0';
	} else if (!strcmp (op, "trap")) {
		cmd = "wx cc";
	} else if (!strcmp (op, "jz") || !strcmp (op, "je")) {
		if (b[0] == 0x75) {
			cmd = "wx 74";
		} else {
			R_LOG_ERROR ("Current opcode is not conditional");
		}
	} else if (!strcmp (op, "jinf")) {
		cmd = "wx ebfe";
	} else if (!strcmp (op, "jnz") || !strcmp (op, "jne")) {
		if (b[0] == 0x74) {
			cmd = "wx 75";
		} else {
			R_LOG_ERROR ("Current opcode is not conditional");
		}
	} else if (!strcmp (op, "nocj")) {
		if (*b == 0xf) {
			cmd = "wx 90e9";
		} else if (b[0] >= 0x70 && b[0] <= 0x7f) {
			cmd = "wx eb";
		} else {
			R_LOG_ERROR ("Current opcode is not conditional");
		}
	} else if (!strcmp (op, "recj")) {
		int is_near = (*b == 0xf);
		if (b[0] < 0x80 && b[0] >= 0x70) { // short jmps: jo, jno, jb, jae, je, jne, jbe, ja, js, jns
			cmd = hcmd = r_str_newf ("wx %x", (b[0]%2)? b[0] - 1: b[0] + 1);
		} else if (is_near && b[1] < 0x90 && b[1] >= 0x80) { // near jmps: jo, jno, jb, jae, je, jne, jbe, ja, js, jns
			cmd = hcmd = r_str_newf ("wx 0f%x", (b[1]%2)? b[1] - 1: b[1] + 1);
		} else {
			R_LOG_ERROR ("Invalid conditional jump opcode");
		}
	} else if (!strcmp (op, "ret1")) {
		cmd = "wx c20100";
	} else if (!strcmp (op, "ret0")) {
		cmd = "wx c20000";
	} else if (!strcmp (op, "retn")) {
		cmd = "wx c2ffff";
	} else {
		R_LOG_ERROR ("Invalid operation '%s'", op);
	}
	if (cmd) {
		switch (mode) {
		case '*': r_cons_println (cmd); break;
		case 'l': r_cons_printf ("%d\n", (int)(strlen (cmd) - 3)/2); break;
		default: r_core_cmd0 (core, cmd); break;
		}
		free (hcmd);
		return true;
	}
	free (hcmd);
	return true;
}

R_API bool r_core_hack(RCore *core, const char *op, int mode) {
	R_RETURN_VAL_IF_FAIL (core && op, false);
	bool (*hack)(RCore *core, const RAnalOp *analop, const char *op, int mode) = NULL;
	const char *asmarch = r_config_get (core->config, "asm.arch");
	const int asmbits = core->rasm->config->bits;
	const bool doseek = (*op == '+');
	if (doseek) {
		op++;
		mode = *op;
	}

	if (!asmarch) {
		return false;
	}
	if (core->blocksize < 4) {
		return false;
	}
#if 0
	// R2_600 TODO: call RArch.patch() if available, otherwise just do this hack until all anal plugs are moved to arch
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
		RAnalOp aop = { .addr = core->offset };
		r_anal_op_set_bytes (&aop, core->offset, core->block, 4);
		// TODO: use r_arch_decode
		if (!r_anal_op (core->anal, &aop, core->offset, core->block, core->blocksize, R_ARCH_OP_MASK_BASIC)) {
			R_LOG_ERROR ("anal op fail");
			r_anal_op_fini (&aop);
			return false;
		}
		r_anal_op_fini (&aop);
		bool res = hack (core, &aop, op, mode);
		if (doseek) {
			r_core_seek (core, core->offset + aop.size, 1);
		}
		return res;
	}
	return false;
}
