/* radare - LGPL3 - Copyright 2016-2022 - FXTi */

#include <r_lib.h>
#include <r_anal.h>
#include "../../asm/arch/pyc/pyc_dis.h"

static R_TH_LOCAL pyc_opcodes *ops = NULL;

static int disassemble(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	RList *shared = NULL;

	RBin *bin = a->binb.bin;

	RBinPlugin *plugin = bin && bin->cur && bin->cur->o? bin->cur->o->plugin: NULL;

	if (plugin) {
		if (!strcmp (plugin->name, "pyc")) {
			shared = bin->cur->o->bin_obj;
		}
	}
	RList *cobjs = NULL;
	RList *interned_table = NULL;
	if (shared) {
		cobjs = r_list_get_n (shared, 0);
		interned_table = r_list_get_n (shared, 1);
	}
	if (!ops || !pyc_opcodes_equal (ops, a->config->cpu)) {
		ops = get_opcode_by_version (a->config->cpu);
		if (!ops) {
			ops = get_opcode_by_version ("v3.9.0");
			if (!ops) {
				return 0;
			}
		}
		ops->bits = a->config->bits;
	}
	int r = r_pyc_disasm (op, buf, cobjs, interned_table, addr, ops);
	op->size = r;
	return r;
}

static int archinfo(RAnal *anal, int query) {
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return (anal->config->bits == 16)? 1: 2;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return (anal->config->bits == 16)? 3: 2;
	default:
		return -1;
	}
}

static char *get_reg_profile(RAnal *anal) {
	return strdup (
		"=PC    pc\n"
		"=BP    bp\n"
		"=SP    sp\n"
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

static bool set_reg_profile(RAnal *anal) {
	char *rp = get_reg_profile (anal);
	if (rp) {
		bool b = r_reg_set_profile_string (anal->reg, rp);
		free (rp);
		return b;
	}
	return false;
}

static RList *get_pyc_code_obj(RAnal *anal) {
	RBin *b = anal->binb.bin;
	RBinPlugin *plugin = b->cur && b->cur->o? b->cur->o->plugin: NULL;
	bool is_pyc = (plugin && strcmp (plugin->name, "pyc") == 0);
	return is_pyc? b->cur->o->bin_obj: NULL;
}

static int pyc_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	RList *pyobj = get_pyc_code_obj (a);
	if (!pyobj) {
		return -1;
	}
	RList *cobjs = r_list_get_n (pyobj, 0);
	RListIter *iter = NULL;
	pyc_code_object *func = NULL, *t = NULL;
	r_list_foreach (cobjs, iter, t) {
		if (R_BETWEEN (t->start_offset, addr, t->end_offset - 1)) { // addr in [start_offset, end_offset)
			func = t;
			break;
		}
	}
	if (!func) {
		return -1;
	}

	if (mask & R_ARCH_OP_MASK_DISASM) {
		disassemble (a, op, addr, data, len);
	}
	ut64 func_base = func->start_offset;
	ut32 extended_arg = 0, oparg = 0;
	ut8 op_code = data[0];
	op->addr = addr;
	op->sign = true;
	op->type = R_ANAL_OP_TYPE_ILL;
	op->id = op_code;

	if (!ops || !pyc_opcodes_equal (ops, a->config->cpu)) {
		if (!(ops = get_opcode_by_version (a->config->cpu))) {
			return -1;
		}
	}
	int bits = a->config->bits;
	bool is_python36 = bits == 8;
	pyc_opcode_object *op_obj = &ops->opcodes[op_code];
	if (!op_obj->op_name) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 1;
		goto anal_end;
	}

	op->size = is_python36? 2: ((op_code >= ops->have_argument)? 3: 1);

	if (op_code >= ops->have_argument) {
		if (!is_python36) {
			oparg = data[1] + data[2] * 256 + extended_arg;
		} else {
			oparg = data[1] + extended_arg;
		}
	}

	if (op_obj->type & HASJABS) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = func_base + oparg;

		if (op_obj->type & HASCONDITION) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + ((is_python36)? 2: 3);
		}
		goto anal_end;
	}
	if (op_obj->type & HASJREL) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + oparg + ((is_python36)? 2: 3);
		op->fail = addr + ((is_python36)? 2: 3);

		if (op_obj->type & HASCONDITION) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			//op->fail = addr + ((is_python36)? 2: 3);
		}
		//goto anal_end;
	}

	if (op_obj->type & HASCOMPARE) {
		op->type = R_ANAL_OP_TYPE_CMP;
		goto anal_end;
	}

	anal_pyc_op (op, op_obj, oparg);

anal_end:
	//free_opcode (ops);
	return op->size;
}

static int finish(void *user) {
	if (ops) {
		free_opcode (ops);
		ops = NULL;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_pyc = {
	.name = "pyc",
	.desc = "Python bytecode analysis plugin",
	.license = "LGPL3",
	.arch = "pyc",
	.bits = 32,
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.set_reg_profile = &set_reg_profile,
	.op = &pyc_op,
	.esil = false,
	.fini = &finish,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_pyc,
	.version = R2_VERSION
};
#endif
