/* radare - LGPL3 - Copyright 2016-2020 - FXTi */

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "../../asm/arch/pyc/pyc_dis.h"

static pyc_opcodes *ops = NULL;

static int archinfo(RAnal *anal, int query) {
	if (!strcmp (anal->cpu, "x86")) {
		return -1;
	}

	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return (anal->bits == 16)? 1: 2;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return (anal->bits == 16)? 3: 2;
	default:
		return -1;
	}
}

static char *get_reg_profile(RAnal *anal) {
	return strdup (
		"=PC    pc\n"
		"=BP    bp\n"
		"=SP    sp\n"
		"=A0    sp\n"
		"gpr    sp  .32 0   0\n" // stack pointer
		"gpr    pc  .32 4   0\n" // program counter
		"gpr    bp  .32 8   0\n" // base pointer // unused
	);
}

static RList *get_pyc_code_obj(RAnal *anal) {
	RBin *b = anal->binb.bin;
	RBinPlugin *plugin = b->cur && b->cur->o? b->cur->o->plugin: NULL;
	bool is_pyc = (plugin && strcmp (plugin->name, "pyc") == 0);
	return is_pyc? b->cur->o->bin_obj: NULL;
}

static int pyc_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	RList *cobjs = r_list_get_n (get_pyc_code_obj (a), 0);
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

	ut64 func_base = func->start_offset;
	ut32 extended_arg = 0, oparg = 0;
	ut8 op_code = data[0];
	op->addr = addr;
	op->sign = true;
	op->type = R_ANAL_OP_TYPE_ILL;
	op->id = op_code;

	if (!ops || !pyc_opcodes_equal (ops, a->cpu)) {
		if (!(ops = get_opcode_by_version (a->cpu))) {
			return -1;
		}
	}
	bool is_python36 = a->bits == 8;
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
		extended_arg = 0;
		if (op_code == ops->extended_arg) {
			extended_arg = is_python36? (oparg << 8): (oparg * 65536);
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
	.bits = 16 | 8, // Partially agree with this
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
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
