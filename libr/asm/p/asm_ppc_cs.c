/* radare2 - LGPL - Copyright 2014-2015 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include "../arch/ppc/libvle/vle.h"

static csh handle = 0;

static bool the_end(void *p) {
	if (handle) {
		cs_close (&handle);
		handle = 0;
	}
	return true;
}

static int decompile_vle(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	vle_t* instr = 0;
	vle_handle handle = {0};
	if (len < 2) {
		return -1;
	}
	if (!vle_init (&handle, buf, len) && (instr = vle_next (&handle))) {
		op->size = instr->size;
		vle_snprint (op->buf_asm, R_ASM_BUFSIZE, a->pc, instr);
		vle_free (instr);
	} else {
		strcpy (op->buf_asm, "invalid");
		op->size = 2;
		return -1;
	}
	return op->size;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	static int omode = -1, obits = -1;
	int n, ret;
	ut64 off = a->pc;
	cs_insn* insn;
	int mode = (a->bits == 64) ? CS_MODE_64 : (a->bits == 32) ? CS_MODE_32 : 0;
	mode |= a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;

	if (a->cpu && strncmp (a->cpu, "vle", 3) == 0) {
		// vle is big-endian only
		if (!a->big_endian) {
			return -1;
		}
		ret = decompile_vle (a, op, buf, len);
		if (ret >= 0) {
			return op->size;
		}
	}
	if (mode != omode || a->bits != obits) {
		cs_close (&handle);
		handle = 0;
		omode = mode;
		obits = a->bits;
	}
	if (handle == 0) {
		ret = cs_open (CS_ARCH_PPC, mode, &handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
	}
	op->size = 4;
	op->buf_asm[0] = 0;
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);

	n = cs_disasm (handle, (const ut8*) buf, len, off, 1, &insn);
	op->size = 4;
	if (n > 0 && insn->size > 0) {
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
				insn->mnemonic, insn->op_str[0] ? " " : "",
				insn->op_str);
		cs_free (insn, n);
		return op->size;
	}
	//op->size = -1;
	cs_free (insn, n);
	return 4;
}

RAsmPlugin r_asm_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "Capstone PowerPC disassembler",
	.license = "BSD",
	.arch = "ppc",
	.cpus = "ppc,vle",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.fini = the_end,
	.disassemble = &disassemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ppc_cs,
	.version = R2_VERSION
};
#endif
