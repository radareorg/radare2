/* radare - LGPL - Copyright 2009-2012 - nibble */

#include <r_lib.h>
#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "udis86/types.h"
#include "udis86/extern.h"

static st64 getval(ud_operand_t *op) {
	int bits = op->size;
	switch (bits) {
	case 8: return (char)op->lval.sbyte;
	case 16: return (short) op->lval.uword;
	case 32: return op->lval.udword;
	case 64: return op->lval.uqword;
	}
	return 0LL;
}

int x86_udis86_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int oplen;
	struct ud u;
	ud_init (&u);
	ud_set_pc (&u, addr);
	ud_set_mode (&u, anal->bits);
	ud_set_syntax (&u, NULL);
	ud_set_input_buffer (&u, data, len);
	ud_disassemble (&u);
	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->jump = op->fail = -1;
	op->ref = op->value = -1;
	oplen = op->length = ud_insn_len (&u);
	switch (u.mnemonic) {
	case UD_Ijmp:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + oplen + getval (&u.operand[0]);
		break;
	case UD_Ijz:
	case UD_Ijnz:
	case UD_Ijb:
	case UD_Ijbe:
	case UD_Ija:
	case UD_Ijs:
	case UD_Ijns:
	case UD_Ijo:
	case UD_Ijno:
	case UD_Ijp:
	case UD_Ijnp:
	case UD_Ijl:
	case UD_Ijge:
	case UD_Ijle:
	case UD_Ijg:
	case UD_Ijcxz:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + oplen + getval (&u.operand[0]);
		op->fail = addr+oplen;
		break;
	case UD_Icall:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = oplen + getval (&u.operand[0]);
		op->fail = addr+oplen;
		break;
	case UD_Iret:
	case UD_Iretf:
	case UD_Isysret:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case UD_Isyscall:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	default:
		break;
	}
	return oplen;
}

static int set_reg_profile(RAnal *anal) {
	/* XXX Dupped Profiles */
	if (anal->bits == 32)
#if __WINDOWS__
		return r_reg_set_profile_string (anal->reg,
				"=pc	eip\n"
				"=sp	esp\n"
				"=bp	ebp\n"
				"=a0	eax\n"
				"=a1	ebx\n"
				"=a2	ecx\n"
				"=a3	edi\n"
				"drx	dr0	.32	4	0\n"
				"drx	dr1	.32	8	0\n"
				"drx	dr2	.32	12	0\n"
				"drx	dr3	.32	16	0\n"
				"drx	dr6	.32	20	0\n"
				"drx	dr7	.32	24	0\n"
				/* floating save area 4+4+4+4+4+4+4+80+4 = 112 */
				"seg	gs	.32	132	0\n"
				"seg	fs	.32	136	0\n"
				"seg	es	.32	140	0\n"
				"seg	ds	.32	144	0\n"
				"gpr	edi	.32	156	0\n"
				"gpr	esi	.32	160	0\n"
				"gpr	ebx	.32	164	0\n"
				"gpr	edx	.32	168	0\n"
				"gpr	ecx	.32	172	0\n"
				"gpr	eax	.32	176	0\n"
				"gpr	ebp	.32	180	0\n"
				"gpr	esp	.32	196	0\n"
				"gpr	eip	.32	184	0\n"
				"seg	cs	.32	184	0\n"
				"seg	ds	.32	152	0\n"
				"seg	gs	.32	140	0\n"
				"seg	fs	.32	144	0\n"
				"gpr	eflags	.32	192	0	c1p.a.zstido.n.rv\n" // XXX must be flg
				"seg	ss	.32	200	0\n"
				/* +512 bytes for maximum supoprted extension extended registers */
				);
#else
		return r_reg_set_profile_string (anal->reg,
				"=pc	eip\n"
				"=sp	esp\n"
				"=bp	ebp\n"
				"=a0	eax\n"
				"=a1	ebx\n"
				"=a2	ecx\n"
				"=a3	edi\n"
				"gpr	eip	.32	48	0\n"
				"gpr	ip	.16	48	0\n"
				"gpr	oeax	.32	44	0\n"
				"gpr	eax	.32	24	0\n"
				"gpr	ax	.16	24	0\n"
				"gpr	ah	.8	24	0\n"
				"gpr	al	.8	25	0\n"
				"gpr	ebx	.32	0	0\n"
				"gpr	bx	.16	0	0\n"
				"gpr	bh	.8	0	0\n"
				"gpr	bl	.8	1	0\n"
				"gpr	ecx	.32	4	0\n"
				"gpr	cx	.16	4	0\n"
				"gpr	ch	.8	4	0\n"
				"gpr	cl	.8	5	0\n"
				"gpr	edx	.32	8	0\n"
				"gpr	dx	.16	8	0\n"
				"gpr	dh	.8	8	0\n"
				"gpr	dl	.8	9	0\n"
				"gpr	esp	.32	60	0\n"
				"gpr	sp	.16	60	0\n"
				"gpr	ebp	.32	20	0\n"
				"gpr	bp	.16	20	0\n"
				"gpr	esi	.32	12	0\n"
				"gpr	si	.16	12	0\n"
				"gpr	edi	.32	16	0\n"
				"gpr	di	.16	16	0\n"
				"seg	xfs	.32	36	0\n"
				"seg	xgs	.32	40	0\n"
				"seg	xcs	.32	52	0\n"
				"seg	cs	.16	52	0\n"
				"seg	xss	.32	52	0\n"
				"gpr	eflags	.32	56	0	c1p.a.zstido.n.rv\n"
				"gpr	flags	.16	56	0\n"
				"flg	carry	.1	.448	0\n"
				"flg	flag_p	.1	.449	0\n"
				"flg	flag_a	.1	.450	0\n"
				"flg	zero	.1	.451	0\n"
				"flg	sign	.1	.452	0\n"
				"flg	flag_t	.1	.453	0\n"
				"flg	flag_i	.1	.454	0\n"
				"flg	flag_d	.1	.455	0\n"
				"flg	flag_o	.1	.456	0\n"
				"flg	flag_r	.1	.457	0\n"
				"drx	dr0	.32	0	0\n"
				"drx	dr1	.32	4	0\n"
				"drx	dr2	.32	8	0\n"
				"drx	dr3	.32	12	0\n"
				//"drx	dr4	.32	16	0\n"
				//"drx	dr5	.32	20	0\n"
				"drx	dr6	.32	24	0\n"
				"drx	dr7	.32	28	0\n");
#endif
	else return r_reg_set_profile_string (anal->reg,
				"=pc	rip\n"
				"=sp	rsp\n"
				"=bp	rbp\n"
				"=a0	rax\n"
				"=a1	rbx\n"
				"=a2	rcx\n"
				"=a3	rdx\n"
				"# no profile defined for x86-64\n"
				"gpr	r15	.64	0	0\n"
				"gpr	r14	.64	8	0\n"
				"gpr	r13	.64	16	0\n"
				"gpr	r12	.64	24	0\n"
				"gpr	rbp	.64	32	0\n"
				"gpr	ebp	.32	32	0\n"
				"gpr	rbx	.64	40	0\n"
				"gpr	ebx	.32	40	0\n"
				"gpr	r11	.64	48	0\n"
				"gpr	r10	.64	56	0\n"
				"gpr	r9	.64	64	0\n"
				"gpr	r8	.64	72	0\n"
				"gpr	rax	.64	80	0\n"
				"gpr	eax	.32	80	0\n"
				"gpr	rcx	.64	88	0\n"
				"gpr	ecx	.32	88	0\n"
				"gpr	rdx	.64	96	0\n"
				"gpr	edx	.32	96	0\n"
				"gpr	rsi	.64	104	0\n"
				"gpr	esi	.32	104	0\n"
				"gpr	rdi	.64	112	0\n"
				"gpr	edi	.32	112	0\n"
				"gpr	oeax	.64	120	0\n"
				"gpr	rip	.64	128	0\n"
				"seg	cs	.64	136	0\n"
				//"flg	eflags	.64	144	0\n"
				"gpr	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
				"gpr	rsp	.64	152	0\n"
				"seg	ss	.64	160	0\n"
				"seg	fs_base	.64	168	0\n"
				"seg	gs_base	.64	176	0\n"
				"seg	ds	.64	184	0\n"
				"seg	es	.64	192	0\n"
				"seg	fs	.64	200	0\n"
				"seg	gs	.64	208	0\n"
				"drx	dr0	.32	0	0\n"
				"drx	dr1	.32	4	0\n"
				"drx	dr2	.32	8	0\n"
				"drx	dr3	.32	12	0\n"
				"drx	dr6	.32	24	0\n"
				"drx	dr7	.32	28	0\n");
}

struct r_anal_plugin_t r_anal_plugin_x86_udis86 = {
	.name = "x86.udis86",
	.desc = "X86 analysis plugin (udis86 backend)",
	.arch = R_SYS_ARCH_X86,
	.bits = 16|32|64,
	.init = NULL,
	.fini = NULL,
	.op = &x86_udis86_op,
	.set_reg_profile = &set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_udis86
};
#endif
