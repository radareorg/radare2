/*
 *
 * Copyright 2015 - mrmacete <mrmacete@protonmail.ch>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "bpf.h"

#define EMIT_CJMP(op, addr, f)\
	(op)->type = R_ANAL_OP_TYPE_CJMP;\
	(op)->jump = (addr) + 8 + (st8) (f)->jt * 8;\
	(op)->fail = (addr) + 8 + (st8) (f)->jf * 8;

#define EMIT_LOAD(op, addr, size)\
	(op)->type = R_ANAL_OP_TYPE_LOAD;\
	(op)->ptr = (addr);\
	(op)->ptrsize = (size);

#define NEW_SRC_DST(op)\
	(op)->src[0] = r_anal_value_new ();\
	(op)->dst = r_anal_value_new ();

#define SET_REG_SRC_DST(op, _src, _dst)\
	NEW_SRC_DST ((op));\
	(op)->src[0]->reg = r_reg_get (anal->reg, (_src), R_REG_TYPE_GPR);\
	(op)->dst->reg = r_reg_get (anal->reg, (_dst), R_REG_TYPE_GPR);

#define SET_REG_DST_IMM(op, _dst, _imm)\
	NEW_SRC_DST ((op));\
	(op)->dst->reg = r_reg_get (anal->reg, (_dst), R_REG_TYPE_GPR);\
	(op)->src[0]->imm = (_imm);

#define SET_A_SRC(op)\
	(op)->src[0] = r_anal_value_new ();\
	(op)->src[0]->reg = r_reg_get (anal->reg, "A", R_REG_TYPE_GPR);

#define SET_A_DST(op)\
	(op)->dst = r_anal_value_new ();\
	(op)->dst->reg = r_reg_get (anal->reg, "A", R_REG_TYPE_GPR);

#define INSIDE_M(k) ((k) >= 0 && (k) <= 16)

static bool bpf_int_exit(RAnalEsil *esil, ut32 interrupt, void *user);
RAnalEsilInterruptHandler ih = { 0, NULL, NULL, &bpf_int_exit, NULL };

static const char *M[] = {
	"M[0]",
	"M[1]",
	"M[2]",
	"M[3]",
	"M[4]",
	"M[5]",
	"M[6]",
	"M[7]",
	"M[8]",
	"M[9]",
	"M[10]",
	"M[11]",
	"M[12]",
	"M[13]",
	"M[14]",
	"M[15]"
};

static int bpf_anal(RAnal *anal, RAnalOp *op, ut64 addr,
	const ut8 *data, int len) {
	RBpfSockFilter *f = (RBpfSockFilter *)data;
	memset (op, '\0', sizeof (RAnalOp));
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = 8;
	op->addr = addr;

	r_strbuf_init (&op->esil);

	switch (f->code) {
	case BPF_RET | BPF_A:
		op->type = R_ANAL_OP_TYPE_RET;
		esilprintf (op, "A,R0,=,0,$");
		break;
	case BPF_RET | BPF_K:
	case BPF_RET | BPF_X:
		op->type = R_ANAL_OP_TYPE_RET;
		if (BPF_SRC (f->code) == BPF_K) {
			esilprintf (op, "%" PFMT64d ",R0,=,0,$", f->k);
		} else if (BPF_SRC (f->code) == BPF_X) {
			esilprintf (op, "X,R0,=,0,$");
		}
		break;
	case BPF_MISC_TAX:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "A", "X");
		esilprintf (op, "A,X,=");
		break;
	case BPF_MISC_TXA:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "X", "A");
		esilprintf (op, "X,A,=");
		break;
	case BPF_ST:
		if (INSIDE_M (f->k)) {
			op->type = R_ANAL_OP_TYPE_MOV;
			SET_REG_SRC_DST (op, "A", M[f->k]);
			esilprintf (op, "A,M[%" PFMT64d "],=", f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_STX:
		if (INSIDE_M (f->k)) {
			op->type = R_ANAL_OP_TYPE_MOV;
			SET_REG_SRC_DST (op, "X", M[f->k]);
			esilprintf (op, "X,M[%" PFMT64d "],=", f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_LD_W | BPF_LEN:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "len", "A");
		esilprintf (op, "len,A,=", f->k);
		break;
	case BPF_LDX | BPF_LEN:
		op->type = R_ANAL_OP_TYPE_MOV;
		SET_REG_SRC_DST (op, "len", "X");
		esilprintf (op, "len,X,=", f->k);
		break;
	case BPF_LD_W | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 4);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,R0,=,0,$,BREAK,},%" PFMT64d ",[4],A,=",
			f->k + 4, op->ptr);
		break;
	case BPF_LD_H | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 2);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,R0,=,0,$,BREAK,},"
			"%" PFMT64d ",[2],A,=",
			f->k + 2, op->ptr);
		break;
	case BPF_LD_B | BPF_ABS:
		EMIT_LOAD (op, anal->gp + f->k, 1);
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",>,?{,0,R0,=,0,$,BREAK,},"
			"%" PFMT64d ",[1],A,=",
			f->k + 1, op->ptr);
		break;
	case BPF_LD_W | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 4;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",X,+,0xffffffff,&,>,?{,0,R0,=,0,$,BREAK,},"
			"%" PFMT64d ",X,+,0xffffffff,&,[4],A,=",
			(st32)f->k + 4, anal->gp + (st32)f->k);
		break;
	case BPF_LD_H | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 2;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",X,+,0xffffffff,&,>,?{,0,R0,=,0,$,BREAK,},"
			"%" PFMT64d ",X,+,0xffffffff,&,[2],A,=",
			(st32)f->k + 2, anal->gp + (st32)f->k);
		break;
	case BPF_LD_B | BPF_IND:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 1;
		SET_A_DST (op);
		esilprintf (op,
			"len,%" PFMT64d ",X,+,0xffffffff,&,>,?{,0,R0,=,0,$,BREAK,},"
			"%" PFMT64d ",X,+,0xffffffff,&,[1],A,=",
			(st32)f->k + 1, anal->gp + (st32)f->k);
		break;
	case BPF_LD | BPF_IMM:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->val = f->k;
		SET_REG_DST_IMM (op, "A", f->k);
		esilprintf (op, "0x%08" PFMT64x ",A,=", f->k);
		break;
	case BPF_LDX | BPF_IMM:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->val = f->k;
		SET_REG_DST_IMM (op, "X", f->k);
		esilprintf (op, "0x%08" PFMT64x ",X,=", f->k);
		break;
	case BPF_LDX_B | BPF_MSH:
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->ptrsize = 1;
		op->ptr = anal->gp + f->k;
		SET_A_DST (op);
		esilprintf (op, "%" PFMT64d ",[1],0xf,&,4,*,X,=", op->ptr);
		break;
	case BPF_LD | BPF_MEM:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (INSIDE_M (f->k)) {
			SET_REG_SRC_DST (op, M[f->k], "A");
			esilprintf (op, "M[%" PFMT64d "],A,=", f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_LDX | BPF_MEM:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (INSIDE_M (f->k)) {
			SET_REG_SRC_DST (op, M[f->k], "X");
			esilprintf (op, "M[%" PFMT64d "],X,=", f->k);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_JMP_JA:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + 8 + f->k * 8;
		esilprintf (op, "%" PFMT64d ",pc,=", op->jump);

		break;
	case BPF_JMP_JGT | BPF_X:
	case BPF_JMP_JGT | BPF_K:
		EMIT_CJMP (op, addr, f);
		op->cond = R_ANAL_COND_GT;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",A,>,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else if (BPF_SRC (f->code) == BPF_X) {
			esilprintf (op,
				"X,A,>,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->jump, op->fail);
		} else {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		break;
	case BPF_JMP_JGE | BPF_X:
	case BPF_JMP_JGE | BPF_K:
		EMIT_CJMP (op, addr, f);
		op->cond = R_ANAL_COND_GE;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",A,>=,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"X,A,>=,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->jump, op->fail);
		}
		break;
	case BPF_JMP_JEQ | BPF_X:
	case BPF_JMP_JEQ | BPF_K:
		EMIT_CJMP (op, addr, f);
		op->cond = R_ANAL_COND_EQ;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",A,==,$z,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"X,A,==,$z,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->jump, op->fail);
		}
		break;
	case BPF_JMP_JSET | BPF_X:
	case BPF_JMP_JSET | BPF_K:
		EMIT_CJMP (op, addr, f);
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			esilprintf (op,
				"%" PFMT64d ",A,&,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		} else {
			esilprintf (op,
				"X,A,&,!,?{,%" PFMT64d ",pc,=,BREAK,},%" PFMT64d ",pc,=",
				op->val, op->jump, op->fail);
		}
		break;
	case BPF_ALU_NEG:
		op->type = R_ANAL_OP_TYPE_NOT;
		esilprintf (op, "A,0,-,A,=");
		SET_REG_SRC_DST (op, "A", "A");
		break;
	case BPF_ALU_LSH | BPF_X:
	case BPF_ALU_LSH | BPF_K:
		op->type = R_ANAL_OP_TYPE_SHL;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", f->k);
			esilprintf (op, "%" PFMT64d ",A,<<=", f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,<<=");
		}
		break;
	case BPF_ALU_RSH | BPF_X:
	case BPF_ALU_RSH | BPF_K:
		op->type = R_ANAL_OP_TYPE_SHR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", f->k);
			esilprintf (op, "%" PFMT64d ",A,>>=", f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,>>=");
		}
		break;
	case BPF_ALU_ADD | BPF_X:
	case BPF_ALU_ADD | BPF_K:
		op->type = R_ANAL_OP_TYPE_ADD;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", op->val);
			esilprintf (op, "%" PFMT64d ",A,+=", op->val);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,+=");
		}
		break;
	case BPF_ALU_SUB | BPF_X:
	case BPF_ALU_SUB | BPF_K:
		op->type = R_ANAL_OP_TYPE_SUB;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", op->val);
			esilprintf (op, "%" PFMT64d ",A,-=", op->val);

		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,-=");
		}
		break;
	case BPF_ALU_MUL | BPF_X:
	case BPF_ALU_MUL | BPF_K:
		op->type = R_ANAL_OP_TYPE_MUL;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", f->k);
			esilprintf (op, "%" PFMT64d ",A,*=", f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,*=");
		}
		break;
	case BPF_ALU_DIV | BPF_X:
	case BPF_ALU_DIV | BPF_K:
		op->type = R_ANAL_OP_TYPE_DIV;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", f->k);
			if (f->k == 0) {
				esilprintf (op, "0,R0,=,0,$");
			} else {
				esilprintf (op, "%" PFMT64d ",A,/=", f->k);
			}
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "0,X,==,$z,?{,0,R0,=,0,$,BREAK,},X,A,/=");
		}
		break;
	case BPF_ALU_MOD | BPF_X:
	case BPF_ALU_MOD | BPF_K:
		op->type = R_ANAL_OP_TYPE_MOD;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", f->k);
			if (f->k == 0) {
				esilprintf (op, "0,R0,=,0,$");
			} else {
				esilprintf (op, "%" PFMT64d ",A,%%=", f->k);
			}
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "0,X,==,$z,?{,0,R0,=,0,$,BREAK,},X,A,%%=");
		}
		break;
	case BPF_ALU_AND | BPF_X:
	case BPF_ALU_AND | BPF_K:
		op->type = R_ANAL_OP_TYPE_AND;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", f->k);
			esilprintf (op, "%" PFMT64d ",A,&=", f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,&=");
		}
		break;
	case BPF_ALU_OR | BPF_X:
	case BPF_ALU_OR | BPF_K:
		op->type = R_ANAL_OP_TYPE_OR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", f->k);
			esilprintf (op, "%" PFMT64d ",A,|=", f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,|,A,=");
		}
		break;
	case BPF_ALU_XOR | BPF_X:
	case BPF_ALU_XOR | BPF_K:
		op->type = R_ANAL_OP_TYPE_XOR;
		if (BPF_SRC (f->code) == BPF_K) {
			op->val = f->k;
			SET_REG_DST_IMM (op, "A", f->k);
			esilprintf (op, "%" PFMT64d ",A,^=", f->k);
		} else {
			SET_REG_SRC_DST (op, "X", "A");
			esilprintf (op, "X,A,^=");
		}
		break;
	default:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	}

	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC    pc\n"
		"gpr    A        .32 0    0\n"
		"gpr    X        .32 4    0\n"
		"gpr    M[0]     .32 8    0\n"
		"gpr    M[1]     .32 12   0\n"
		"gpr    M[2]     .32 16   0\n"
		"gpr    M[3]     .32 20   0\n"
		"gpr    M[4]     .32 24   0\n"
		"gpr    M[5]     .32 28   0\n"
		"gpr    M[6]     .32 32   0\n"
		"gpr    M[7]     .32 36   0\n"
		"gpr    M[8]     .32 40   0\n"
		"gpr    M[9]     .32 44   0\n"
		"gpr    M[10]    .32 48   0\n"
		"gpr    M[11]    .32 52   0\n"
		"gpr    M[12]    .32 56   0\n"
		"gpr    M[13]    .32 60   0\n"
		"gpr    M[14]    .32 64   0\n"
		"gpr    M[15]    .32 68   0\n"
		"gpr    pc       .32 72   0\n"
		"gpr    len      .32 76   0\n"
		"gpr    R0       .32 80   0\n"
		"gpr    R1       .32 84   0\n"
		"gpr    R2       .32 88   0\n"
		"gpr    R3       .32 92   0\n"
		"gpr    R4       .32 96   0\n"
		"gpr    R5       .32 100  0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

static bool bpf_int_exit(RAnalEsil *esil, ut32 interrupt, void *user) {
	int syscall;
	ut64 r0;
	if (!esil || (interrupt != 0x0))
		return false;
	r_anal_esil_reg_read (esil, "R0", &r0, NULL);
	if (r0 == 0) {
		esil->anal->cb_printf ("; BPF result: DROP value: %d\n", (int)r0);
		eprintf ("BPF result: DROP value: %d\n", (int)r0);
	} else {
		esil->anal->cb_printf ("; BPF result: ACCEPT value: %d\n", (int)r0);
		eprintf ("BPF result: ACCEPT value: %d\n", (int)r0);
	}
	return true;
}

static int esil_bpf_init(RAnalEsil *esil) {
	if (!esil)
		return false;
	RAnalEsilInterrupt *intr = r_anal_esil_interrupt_new (esil, 0, &ih);
	r_anal_esil_set_interrupt (esil, intr);
	return true;
}

static int esil_bpf_fini(RAnalEsil *esil) {
	return true;
}

struct r_anal_plugin_t r_anal_plugin_bpf = {
	.name = "bpf",
	.desc = "Berkely packet filter analysis plugin",
	.license = "GPLv2",
	.arch = "bpf",
	.bits = 32,
	.esil = true,
	.init = NULL,
	.fini = NULL,
	.reset_counter = NULL,
	.archinfo = NULL,
	.op = &bpf_anal,
	.bb = NULL,
	.fcn = NULL,
	.analyze_fns = NULL,
	.op_from_buffer = NULL,
	.bb_from_buffer = NULL,
	.fn_from_buffer = NULL,
	.analysis_algorithm = NULL,
	.set_reg_profile = &set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL,
	.pre_anal = NULL,
	.pre_anal_fn_cb = NULL,
	.pre_anal_op_cb = NULL,
	.post_anal_op_cb = NULL,
	.pre_anal_bb_cb = NULL,
	.post_anal_bb_cb = NULL,
	.post_anal_fn_cb = NULL,
	.post_anal = NULL,
	.revisit_bb_anal = NULL,
	.cmd_ext = NULL,
	.esil_init = &esil_bpf_init,
	.esil_post_loop = NULL,
	.esil_trap = NULL,
	.esil_fini = &esil_bpf_fini
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bpf,
	.version = R2_VERSION
};
#endif
