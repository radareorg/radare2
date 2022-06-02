/* radare2 - LGPL - Copyright 2022 - terorie */

#include <r_anal.h>
#include <r_lib.h>

#include <capstone/capstone.h>
#if CS_API_MAJOR >= 5

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	static R_TH_LOCAL csh handle = 0;
	static R_TH_LOCAL int omode = -1;
	static R_TH_LOCAL int obits = 32;
	cs_insn *insn = NULL;
	int mode = (a->config->bits == 32)? CS_MODE_BPF_CLASSIC: CS_MODE_BPF_EXTENDED;
	int n, ret;
	mode |= (a->config->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (mode != omode || a->config->bits != obits) {
		if (handle != 0) {
			cs_close (&handle);
			handle = 0; // unnecessary
		}
		omode = mode;
		obits = a->config->bits;
	}
	op->size = 8;
	op->addr = addr;
	if (handle == 0) {
		ret = cs_open (CS_ARCH_BPF, mode, &handle);
		if (ret != CS_ERR_OK) {
			handle = 0;
			return -1;
		}
	}

	n = cs_disasm (handle, (ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
	} else {
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic,
				insn->op_str[0]? " ": "",
				insn->op_str);
		}
		op->size = insn->size;
		op->id = insn->id;
		cs_free (insn, n);
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_bpf_cs = {
	.name = "bpf.cs",
	.desc = "Capstone BPF arch plugin",
	.license = "BSD",
	.author = "terorie",
	.arch = "bpf",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.bits = 32 | 64,
	.op = &analop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bpf_cs,
	.version = R2_VERSION
};
#endif

#else
RAnalPlugin r_anal_plugin_bpf_cs = {0};
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.version = R2_VERSION
};
#endif
#endif
