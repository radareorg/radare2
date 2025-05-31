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

static pyc_opcodes *get_pyc_opcodes(RArchSession *s) {
	pyc_opcodes *ops = s->data;
	if (!ops || !pyc_opcodes_equal (ops, s->config->cpu)) {
		ops = get_opcode_by_version (s->config->cpu);
		ops = ops? ops: get_opcode_by_version ("v3.9.0");
		if (ops) {
			ops->bits = s->config->bits;
		}
		s->data = ops;
	}
	return ops;
}

static RList *get_pyc_code_obj(RArchSession *as) {
	RBin *b = as->arch->binb.bin;
	RBinPlugin *plugin = b->cur && b->cur->bo? b->cur->bo->plugin: NULL;
	bool is_pyc = (plugin && strcmp (plugin->meta.name, "pyc") == 0);
	return is_pyc? b->cur->bo->bin_obj: NULL;
}

static inline pyc_code_object *get_func(ut64 pc, RList *pyobj) {
	// XXX use better data structures
	RList *cobjs = pyobj? r_list_get_n (pyobj, 0): NULL;
	if (cobjs) {
		pyc_code_object *t;
		RListIter *iter;
		r_list_foreach (cobjs, iter, t) {
			if (R_BETWEEN (t->start_offset, pc, t->end_offset - 1)) {
				return t;
			}
		}
	}
	return NULL;
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

static inline bool simple_parse_op(RAnalOp *op, size_t *oloc, py_simple_op *so) {
	size_t loc = *oloc;
	if (loc + 1 > op->size) {
		return false;
	}

	so->opcode = op->bytes[loc++];
	if (so->opcode >= so->have_arg) {
		if (loc + so->argsize > op->size) {
			return false;
		}
		so->arg = op->bytes[loc++];
		if (so->argsize == 2) {
			so->arg += op->bytes[loc++] << 8;
		}
	} else if (so->argsize == 1) {
		// python > 3.6 opcodes have empty arguments of size 1
		loc++;
		if (loc > op->size) {
			return false;
		}
	}

	*oloc = loc;
	return true;
}

// Parses instruction with ext if needed. If this returns 0, you should still run simple_parse_op.
static inline size_t parse_op(RAnalOp *op, py_simple_op *so) {
	size_t loc = 0;
	ut32 ext = 0;

	int i, loops = so->argsize == 2? 1: 3;
	for (i = 0; i < loops; i++) {
		if (!simple_parse_op (op, &loc, so)) {
			return 0;
		}

		// extended op, so we add it's arg to the next arg
		if (so->opcode == so->extop) {
			ext += so->arg;
			ext = ext << (8 * so->argsize);
		} else {
			break;
		}
	}

	// no extention encoutered, just return op
	if (i == 0) {
		return loc;
	}

	// on the first non-extended opcode, it should have an argument
	if (so->opcode >= so->have_arg) {
		so->arg += ext;
		return loc;
	};

	// just returned the extended instruction then...
	loc = 0;
	return simple_parse_op (op, &loc, so)? loc: 0;
}

static bool pyc_decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const int pyversion = pyversion_toi (as->config->cpu);
	RList *pyobj = get_pyc_code_obj (as);
	pyc_opcodes *ops = get_pyc_opcodes (as);
	pyc_code_object *func = get_func (op->addr, pyobj);
	if (!func || !ops) {
		return false;
	}

	py_simple_op so = { 0 };
	// python <= 3.6 has opcode len 1 or 3 see https://docs.python.org/3/library/dis.html#opcode-HAVE_ARGUMENT
	so.argsize = pyversion <= 360? 2: 1;
	so.have_arg = ops->have_argument;
	so.extop = ops->extended_arg;
	int size = parse_op (op, &so);
	pyc_opcode_object *op_obj = &ops->opcodes[so.opcode];
	if (!size || !op_obj) {
		return false;
	}
	op->size = size;

	if (mask & R_ARCH_OP_MASK_DISASM) {
		RList *interned_table = r_list_get_n (pyobj, 1);
		r_pyc_disasm (op, func, interned_table, ops, &so);
	}
	ut64 func_base = func->start_offset;
	op->sign = true;
	op->type = R_ANAL_OP_TYPE_ILL;
	op->id = so.opcode;

	if (op_obj->type & HASJABS) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = func_base + so.arg;

		if (op_obj->type & HASCONDITION) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = op->addr + size;
		}
	} else if (op_obj->type & HASJREL) {
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr + so.arg + size;
		op->fail = op->addr + size;

		if (op_obj->type & HASCONDITION) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			// op->fail = addr + ((py36_lens)? 2: 3);
		}
	} else if (op_obj->type & HASCOMPARE) {
		op->type = R_ANAL_OP_TYPE_CMP;
	}
	anal_pyc_op (op, op_obj, so.arg);
	return true;
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
		.desc = "Python bytecode (1.0 .. 3.9)",
		.license = "LGPL-3.0-only",
	},
	.arch = "pyc",
	.bits = R_SYS_BITS_PACK1 (32),
	.info = archinfo,
	.regs = regs,
	.decode = &pyc_decode,
	.fini = &finish,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_pyc,
	.version = R2_VERSION
};
#endif
