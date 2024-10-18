/* radare - LGPL-3.0-only - Copyright 2016-2024 - FXTi, pancake */

#include <r_arch.h>
#include "pyc_dis.h"

static int pyversion_toi(const char *version) {
	if (version) {
		char vstr[32];
		char *v = (char *)&vstr;
		for (;*version; version++) {
			if (isdigit (*version)) {
				*v++ = *version;
			}
			if (v == vstr + 2) {
				break;
			}
		}
		*v++ = '0';
		*v = 0;
		if (*vstr) {
			return atoi (vstr);
		}
	}
	return 360; // default version
}

static bool disassemble(RArchSession *s, RAnalOp *op, RArchDecodeMask mask, int pyversion) {
	RBin *bin = s->arch->binb.bin;
	RBinPlugin *plugin = bin && bin->cur && bin->cur->bo? bin->cur->bo->plugin: NULL;
	RList *shared = (plugin && !strcmp (plugin->meta.name, "pyc"))?
		bin->cur->bo->bin_obj: NULL;
	RList *cobjs = NULL;
	RList *interned_table = NULL;
	if (shared) {
		cobjs = r_list_get_n (shared, 0);
		interned_table = r_list_get_n (shared, 1);
	}
	pyc_opcodes *ops = s->data;
	if (!ops || !pyc_opcodes_equal (ops, s->config->cpu)) {
		ops = get_opcode_by_version (s->config->cpu);
		if (!ops) {
			ops = get_opcode_by_version ("v3.9.0");
			if (!ops) {
				return false;
			}
		}
		ops->bits = s->config->bits;
	}
	s->data = ops;
	int r = r_pyc_disasm (op, op->bytes, cobjs, interned_table, op->addr, ops);
	op->size = r;
	return r > 0;
}

static int archinfo(RArchSession *as, ut32 query) {
	switch (query) {
	case R_ARCH_INFO_INVOP_SIZE:
	case R_ARCH_INFO_MINOP_SIZE:
		{
			int pyversion = pyversion_toi (as->config->cpu);
			return (pyversion < 370)? 1: 2;
		}
	case R_ARCH_INFO_MAXOP_SIZE:
		{
			int pyversion = pyversion_toi (as->config->cpu);
			return (pyversion < 370)? 3: 2;
		}
	default:
		return -1;
	case R_ARCH_INFO_ISVM:
		return R_ARCH_INFO_ISVM;
	}
}

static char *regs(RArchSession *as) {
	return strdup (
		"=PC    pc\n"
		"=BP    bp\n"
		"=SP    sp\n"
		"=SN    a0\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"=A2    a2\n"
		"=A3    a3\n"
		"=R0    r0\n"
		"gpr    a0  .32  0   0\n"
		"gpr    a1  .32  4   0\n"
		"gpr    a2  .32  8   0\n"
		"gpr    a3  .32 12   0\n"
		"gpr    r0  .32 16   0\n"
		"gpr    sp  .32 20   0\n" // stack pointer
		"gpr    pc  .32 24   0\n" // program counter
		"gpr    bp  .32 28   0\n" // base pointer // unused
	);
}

static RList *get_pyc_code_obj(RArchSession *as) {
	RBin *b = as->arch->binb.bin;
	RBinPlugin *plugin = b->cur && b->cur->bo? b->cur->bo->plugin: NULL;
	bool is_pyc = (plugin && strcmp (plugin->meta.name, "pyc") == 0);
	return is_pyc? b->cur->bo->bin_obj: NULL;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	RList *pyobj = get_pyc_code_obj (as);
	if (!pyobj) {
		return false;
	}
	const ut64 addr = op->addr;
	const ut8 *data = op->bytes;
	const size_t data_len = op->size;
	RList *cobjs = r_list_get_n (pyobj, 0);
	RListIter *iter = NULL;
	pyc_code_object *func = NULL, *t = NULL;
	r_list_foreach (cobjs, iter, t) {
		if (R_BETWEEN (t->start_offset, addr, t->end_offset - 1)) {
			func = t;
			break;
		}
	}
	if (!func) {
		return false;
	}
	const int pyversion = pyversion_toi (as->config->cpu);
	bool is_python36 = pyversion == 370; // < 370; // XXX this looks wrong

	if (mask & R_ARCH_OP_MASK_DISASM) {
		disassemble (as, op, mask, pyversion);
	}
	ut64 func_base = func->start_offset;
	ut32 extended_arg = 0, oparg = 0;
	ut8 op_code = data[0];
	op->sign = true;
	op->type = R_ANAL_OP_TYPE_ILL;
	op->id = op_code;

	pyc_opcodes *ops = as->data;
	if (!ops || !pyc_opcodes_equal (ops, as->config->cpu)) {
		if (!(ops = get_opcode_by_version (as->config->cpu))) {
			return false;
		}
	}
	pyc_opcode_object *op_obj = &ops->opcodes[op_code];
	if (!op_obj->op_name) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 1;
		goto beach;
	}

	op->size = is_python36? 2: ((op_code >= ops->have_argument)? 3: 1);
	if (op_code >= ops->have_argument) {
		if (is_python36) {
			if (data_len > 1) {
				oparg = data[1] + extended_arg;
			}
		} else {
			if (data_len > 2) {
				oparg = data[1] + data[2] * 256 + extended_arg;
			}
		}
	}

	if (op_obj->type & HASJABS) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = func_base + oparg;

		if (op_obj->type & HASCONDITION) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + ((is_python36)? 2: 3);
		}
	} else if (op_obj->type & HASJREL) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + oparg + ((is_python36)? 2: 3);
		op->fail = addr + ((is_python36)? 2: 3);

		if (op_obj->type & HASCONDITION) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			// op->fail = addr + ((is_python36)? 2: 3);
		}
	} else if (op_obj->type & HASCOMPARE) {
		op->type = R_ANAL_OP_TYPE_CMP;
	}
	anal_pyc_op (op, op_obj, oparg);
beach:
	return op->size > 0;
}

static bool finish(RArchSession *s) {
	pyc_opcodes *ops = s->data;
	if (ops) {
		free_opcode (ops);
		s->data = NULL;
	}
	return true;
}

const RArchPlugin r_arch_plugin_pyc = {
	.meta = {
		.name = "pyc",
		.author = "fxti",
		.desc = "Python bytecode analysis plugin",
		.license = "LGPL-3.0-only",
	},
	.arch = "pyc",
	.bits = R_SYS_BITS_PACK1 (32),
	.info = archinfo,
	.regs = regs,
	.decode = &decode,
	.fini = &finish,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_pyc,
	.version = R2_VERSION
};
#endif
