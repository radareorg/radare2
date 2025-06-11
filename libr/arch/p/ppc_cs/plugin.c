/* radare2 - LGPL - Copyright 2013-2024 - pancake */

#include <r_arch.h>
#include <r_esil.h>
#include <capstone/capstone.h>
#include <capstone/ppc.h>
#include "../ppc/libvle/vle.h"
#include "../ppc/libps/libps.h"

#define SPR_HID0 0x3f0 /* Hardware Implementation Register 0 */
#define SPR_HID1 0x3f1 /* Hardware Implementation Register 1 */
#define SPR_HID2 0x3f3 /* Hardware Implementation Register 2 */
#define SPR_HID4 0x3f4 /* Hardware Implementation Register 4 */
#define SPR_HID5 0x3f6 /* Hardware Implementation Register 5 */
#define SPR_HID6 0x3f9 /* Hardware Implementation Register 6 */

struct Getarg {
	csh handle;
	cs_insn *insn;
	int bits;
};

#define INSOPS insn->detail->ppc.op_count
#define INSOP(n) insn->detail->ppc.operands[n]
#define IMM(x) (ut64)(insn->detail->ppc.operands[x].imm)

#ifndef PFMT32x
#define PFMT32x "lx"
#endif

// * cs6 - compatibility *
#if CS_API_MAJOR < 6
#define BC() insn->detail->ppc.bc
#else
#define BC() insn->detail->ppc.bc.pred_cr

#define PPC_INS_CMP PPC_INS_ALIAS_CMP
#define PPC_INS_CMPI PPC_INS_ALIAS_CMPI
#define PPC_INS_MR PPC_INS_ALIAS_MR
#define PPC_INS_LI PPC_INS_ALIAS_LI
#define PPC_INS_LIS PPC_INS_ALIAS_LIS
#define PPC_INS_CLRLWI PPC_INS_ALIAS_CLRLWI
#define PPC_INS_LWSYNC PPC_INS_ALIAS_LWSYNC
#define PPC_INS_PTESYNC PPC_INS_ALIAS_PTESYNC
#define PPC_INS_SUB PPC_INS_ALIAS_SUB
#define PPC_INS_SUBC PPC_INS_ALIAS_SUBC
#define PPC_INS_CRCLR PPC_INS_ALIAS_CRCLR
#define PPC_INS_CRSET PPC_INS_ALIAS_CRSET
#define PPC_INS_CRMOVE PPC_INS_ALIAS_CRMOVE
#define PPC_INS_CRNOT PPC_INS_ALIAS_CRNOT
#define PPC_INS_BNE PPC_INS_ALIAS_BNE
#define PPC_INS_BNEA PPC_INS_ALIAS_BNEA
#define PPC_INS_BNECTR PPC_INS_ALIAS_BNECTR
#define PPC_INS_BNECTRL PPC_INS_ALIAS_BNECTRL
#define PPC_INS_BNEL PPC_INS_ALIAS_BNEL
#define PPC_INS_BNELA PPC_INS_ALIAS_BNELA
#define PPC_INS_BNELR PPC_INS_ALIAS_BNELR
#define PPC_INS_BNELRL PPC_INS_ALIAS_BNELRL
#define PPC_INS_BNG PPC_INS_ALIAS_BNG
#define PPC_INS_BNGA PPC_INS_ALIAS_BNGA
#define PPC_INS_BNGCTR PPC_INS_ALIAS_BNGCTR
#define PPC_INS_BNGCTRL PPC_INS_ALIAS_BNGCTRL
#define PPC_INS_BNGL PPC_INS_ALIAS_BNGL
#define PPC_INS_BNGLA PPC_INS_ALIAS_BNGLA
#define PPC_INS_BNGLR PPC_INS_ALIAS_BNGLR
#define PPC_INS_BNGLRL PPC_INS_ALIAS_BNGLRL
#define PPC_INS_BNL PPC_INS_ALIAS_BNL
#define PPC_INS_BNLA PPC_INS_ALIAS_BNLA
#define PPC_INS_BNLCTR PPC_INS_ALIAS_BNLCTR
#define PPC_INS_BNLCTRL PPC_INS_ALIAS_BNLCTRL
#define PPC_INS_BNLL PPC_INS_ALIAS_BNLL
#define PPC_INS_BNLLA PPC_INS_ALIAS_BNLLA
#define PPC_INS_BNLLR PPC_INS_ALIAS_BNLLR
#define PPC_INS_BNLLRL PPC_INS_ALIAS_BNLLRL
#define PPC_INS_BNS PPC_INS_ALIAS_BNS
#define PPC_INS_BNSA PPC_INS_ALIAS_BNSA
#define PPC_INS_BNSCTR PPC_INS_ALIAS_BNSCTR
#define PPC_INS_BNSCTRL PPC_INS_ALIAS_BNSCTRL
#define PPC_INS_BNSL PPC_INS_ALIAS_BNSL
#define PPC_INS_BNSLA PPC_INS_ALIAS_BNSLA
#define PPC_INS_BNSLR PPC_INS_ALIAS_BNSLR
#define PPC_INS_BNSLRL PPC_INS_ALIAS_BNSLRL
#define PPC_INS_BNU PPC_INS_ALIAS_BNU
#define PPC_INS_BNUA PPC_INS_ALIAS_BNUA
#define PPC_INS_BNUCTR PPC_INS_ALIAS_BNUCTR
#define PPC_INS_BNUCTRL PPC_INS_ALIAS_BNUCTRL
#define PPC_INS_BNUL PPC_INS_ALIAS_BNUL
#define PPC_INS_BNULA PPC_INS_ALIAS_BNULA
#define PPC_INS_BNULR PPC_INS_ALIAS_BNULR
#define PPC_INS_BNULR PPC_INS_ALIAS_BNULR
#define PPC_INS_BNULRL PPC_INS_ALIAS_BNULRL
#define PPC_INS_BT PPC_INS_ALIAS_BT
#define PPC_INS_BF PPC_INS_ALIAS_BF
#define PPC_INS_BDNZ PPC_INS_ALIAS_BDNZ
#define PPC_INS_BDNZA PPC_INS_ALIAS_BDNZA
#define PPC_INS_BDNZL PPC_INS_ALIAS_BDNZL
#define PPC_INS_BDNZLA PPC_INS_ALIAS_BDNZLA
#define PPC_INS_BDNZLR PPC_INS_ALIAS_BDNZLR
#define PPC_INS_BDZ PPC_INS_ALIAS_BDZ
#define PPC_INS_BDZA PPC_INS_ALIAS_BDZA
#define PPC_INS_BDZL PPC_INS_ALIAS_BDZL
#define PPC_INS_BDZLA PPC_INS_ALIAS_BDZLA
#define PPC_INS_BDZLR PPC_INS_ALIAS_BDZLR
#define PPC_INS_BDZLRL PPC_INS_ALIAS_BDZLRL
#define PPC_INS_BDZLRL PPC_INS_ALIAS_BDZLRL
#define PPC_INS_MFPVR PPC_INS_ALIAS_MFPVR
#define PPC_INS_MFDCCR PPC_INS_ALIAS_MFDCCR
#define PPC_INS_MFICCR PPC_INS_ALIAS_MFICCR
#define PPC_INS_MFDEAR PPC_INS_ALIAS_MFDEAR
#define PPC_INS_MTDCCR PPC_INS_ALIAS_MTDCCR
#define PPC_INS_MTICCR PPC_INS_ALIAS_MTICCR
#define PPC_INS_MTDEAR PPC_INS_ALIAS_MTDEAR
#define PPC_INS_CLRLDI PPC_INS_ALIAS_CLRLDI
#define PPC_INS_ROTLDI PPC_INS_ALIAS_ROTLDI
#define PPC_INS_BDNZLRL PPC_INS_ALIAS_BDNZLRL

#define PPC_BC_LT PPC_PRED_LT
#define PPC_BC_LE PPC_PRED_LE
#define PPC_BC_EQ PPC_PRED_EQ
#define PPC_BC_GE PPC_PRED_GE
#define PPC_BC_GT PPC_PRED_GT
#define PPC_BC_NE PPC_PRED_NE
#define PPC_BC_INVALID PPC_PRED_INVALID
#define PPC_BC_NS PPC_PRED_NS
#define PPC_BC_SO PPC_PRED_SO
#endif
// ***********************

typedef struct plugin_data_t PluginData;
static const char* getspr(PluginData *pd, struct Getarg *gop, int n);
static char *getarg2(PluginData *pd, struct Getarg *gop, int n, const char *setstr);

static ut64 mask64(ut64 mb, ut64 me) {
	ut64 maskmb = UT64_MAX >> mb;
	ut64 maskme = UT64_MAX << (63 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

static ut32 mask32(ut32 mb, ut32 me) {
	ut32 maskmb = UT32_MAX >> mb;
	ut32 maskme = UT32_MAX << (31 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

#define cmaskbuf_SIZEOF 32
static const char* cmask64(char *cmaskbuf, const char *mb_c, const char *me_c) {
	ut64 mb = 0;
	ut64 me = 0;
	if (mb_c) {
		mb = strtol (mb_c, NULL, 16);
	}
	if (me_c) {
		me = strtol (me_c, NULL, 16);
	}
	snprintf (cmaskbuf, cmaskbuf_SIZEOF, "0x%"PFMT64x, mask64 (mb, me));
	return cmaskbuf;
}

static const char* cmask32(char *cmaskbuf, const char *mb_c, const char *me_c) {
	ut32 mb = mb_c? strtol (mb_c, NULL, 16): 0;
	ut32 me = me_c? strtol (me_c, NULL, 16): 0;
	snprintf (cmaskbuf, cmaskbuf_SIZEOF, "0x%"PFMT32x, mask32 (mb, me));
	return cmaskbuf;
}

static ut64 getarg(struct Getarg *gop, int n) {
	ut64 value = 0;
	cs_insn *insn = gop->insn;
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return 0;
	}

	op = INSOP (n);
	switch (op.type) {
	case PPC_OP_INVALID:
		break;
	case PPC_OP_REG:
		value = op.reg;
		break;
	case PPC_OP_IMM:
		value = (ut64) op.imm;
		break;
	case PPC_OP_MEM:
		value = op.mem.disp + op.mem.base;
		break;
#if CS_API_MAJOR < 6
	case PPC_OP_CRX: // Condition Register field
		value = (ut64) op.imm;
		break;
#endif
	}
	return value;
}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_ppc *x = &insn->detail->ppc;
	for (i = 0; i < x->op_count; i++) {
		cs_ppc_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case PPC_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case PPC_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case PPC_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base != PPC_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			pj_ki (pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

#define PPCSPR(n) getspr(pd, &gop, n)
#define ARG(n) getarg2(pd, &gop, n, "")
#define ARG2(n,m) getarg2(pd, &gop, n, m)

static char *regs(RArchSession *as) {
	if (as->config->bits == 32) {
		const char *p =
			"=PC	pc\n"
			"=SP	r1\n"
			"=BP	r31\n"
			"=SR	srr1\n" // status register ??
			"=SN	r3\n" // also for ret
			"=R0	r3\n" // ret
			"=A0	r3\n" // also for ret
			"=A1	r4\n"
			"=A2	r5\n"
			"=A3	r6\n"
			"=A4	r7\n"
			"=A5	r8\n"
			"=A6	r6\n"
			"gpr	srr0   .32 0   0\n"
			"gpr	srr1   .32 4   0\n"
			"gpr	r0   .32 8   0\n"
			"gpr	r1   .32 12  0\n"
			"gpr	r2   .32 16  0\n"
			"gpr	r3   .32 20  0\n"
			"gpr	r4   .32 24  0\n"
			"gpr	r5   .32 28  0\n"
			"gpr	r6   .32 32  0\n"
			"gpr	r7   .32 36  0\n"
			"gpr	r8   .32 40  0\n"
			"gpr	r9   .32 44  0\n"
			"gpr	r10 .32 48  0\n"
			"gpr	r11 .32 52  0\n"
			"gpr	r12 .32 56  0\n"
			"gpr	r13 .32 60  0\n"
			"gpr	r14 .32 64  0\n"
			"gpr	r15 .32 68  0\n"
			"gpr	r16 .32 72  0\n"
			"gpr	r17 .32 76  0\n"
			"gpr	r18 .32 80  0\n"
			"gpr	r19 .32 84  0\n"
			"gpr	r20 .32 88  0\n"
			"gpr	r21 .32 92  0\n"
			"gpr	r22 .32 96  0\n"
			"gpr	r23 .32 100 0\n"
			"gpr	r24 .32 104 0\n"
			"gpr	r25 .32 108 0\n"
			"gpr	r26 .32 112 0\n"
			"gpr	r27 .32 116 0\n"
			"gpr	r28 .32 120 0\n"
			"gpr	r29 .32 124 0\n"
			"gpr	r30 .32 128 0\n"
			"gpr	r31 .32 132 0\n"
			"gpr	lr   .32 136 0\n"
			"gpr	ctr .32 140 0\n"
			"gpr	msr .32 144 0\n"
			"gpr	pc   .32 148 0\n"
			"gpr	cr  .64 152 0\n"
			"gpr	cr0 .8  152 0\n"
			"gpr	cr1 .8  153 0\n"
			"gpr	cr2 .8  154 0\n"
			"gpr	cr3 .8  155 0\n"
			"gpr	cr4 .8  156 0\n"
			"gpr	cr5 .8  157 0\n"
			"gpr	cr6 .8  158 0\n"
			"gpr	cr7 .8  159 0\n"
			"gpr	xer .32 160 0\n"
			"gpr	mq   .32 164 0\n"
			"gpr	fpscr  .32 168 0\n"
			"gpr	vrsave .32 172 0\n"
			"gpr	pvr .32 176 0\n"
			"gpr	dccr   .32 180 0\n"
			"gpr	iccr   .32 184 0\n"
			"gpr	dear   .32 188 0\n"
			"gpr	hid0   .32 192 0\n"
			"gpr	hid1   .32 196 0\n"
			"gpr	hid2   .32 200 0\n"
			"gpr	hid3   .32 204 0\n"
			"gpr	hid4   .32 208 0\n"
			"gpr	hid5   .32 212 0\n"
			"gpr	hid6   .32 216 0\n"
			"gpr	ibat0  .64 220 0\n"
			"gpr	ibat1  .64 228 0\n"
			"gpr	ibat2  .64 236 0\n"
			"gpr	ibat3  .64 244 0\n"
			"gpr	ibat0l .32 220 0\n"
			"gpr	ibat1l .32 228 0\n"
			"gpr	ibat2l .32 236 0\n"
			"gpr	ibat3l .32 244 0\n"
			"gpr	ibat0u .32 224 0\n"
			"gpr	ibat1u .32 232 0\n"
			"gpr	ibat2u .32 240 0\n"
			"gpr	ibat3u .32 248 0\n"
			"gpr	dbat0  .64 256 0\n"
			"gpr	dbat1  .64 264 0\n"
			"gpr	dbat2  .64 272 0\n"
			"gpr	dbat3  .64 280 0\n"
			"gpr	dbat0l .32 256 0\n"
			"gpr	dbat1l .32 264 0\n"
			"gpr	dbat2l .32 272 0\n"
			"gpr	dbat3l .32 280 0\n"
			"gpr	dbat0u .32 260 0\n"
			"gpr	dbat1u .32 268 0\n"
			"gpr	dbat2u .32 276 0\n"
			"gpr	dbat3u .32 284 0\n"
			"gpr	mask   .32 288 0\n";
		return strdup (p);
	}

	const char *p =
		"=PC	pc\n"
		"=SP	r1\n"
		"=BP	r31\n"
		"=SR	srr1\n" // status register ??
		"=SN	r0\n" // also for ret
		"=R0	r3\n" // ret
		"=A0	r3\n" // also for ret
		"=A1	r4\n"
		"=A2	r5\n"
		"=A3	r6\n"
		"=A4	r7\n"
		"=A5	r8\n"
		"=A6	r6\n"
		"gpr	srr0   .64 0   0\n"
		"gpr	srr1   .64 8   0\n"
		"gpr	r0   .64 16  0\n"
		"gpr	r1   .64 24  0\n"
		"gpr	r2   .64 32  0\n"
		"gpr	r3   .64 40  0\n"
		"gpr	r4   .64 48  0\n"
		"gpr	r5   .64 56  0\n"
		"gpr	r6   .64 64  0\n"
		"gpr	r7   .64 72  0\n"
		"gpr	r8   .64 80  0\n"
		"gpr	r9   .64 88  0\n"
		"gpr	r10 .64 96  0\n"
		"gpr	r11 .64 104 0\n"
		"gpr	r12 .64 112 0\n"
		"gpr	r13 .64 120 0\n"
		"gpr	r14 .64 128 0\n"
		"gpr	r15 .64 136 0\n"
		"gpr	r16 .64 144 0\n"
		"gpr	r17 .64 152 0\n"
		"gpr	r18 .64 160 0\n"
		"gpr	r19 .64 168 0\n"
		"gpr	r20 .64 176 0\n"
		"gpr	r21 .64 184 0\n"
		"gpr	r22 .64 192 0\n"
		"gpr	r23 .64 200 0\n"
		"gpr	r24 .64 208 0\n"
		"gpr	r25 .64 216 0\n"
		"gpr	r26 .64 224 0\n"
		"gpr	r27 .64 232 0\n"
		"gpr	r28 .64 240 0\n"
		"gpr	r29 .64 248 0\n"
		"gpr	r30 .64 256 0\n"
		"gpr	r31 .64 264 0\n"
		"gpr	lr   .64 272 0\n"
		"gpr	ctr .64 280 0\n"
		"gpr	msr .64 288 0\n"
		"gpr	pc   .64 296 0\n"
		"gpr	cr  .64 304 0\n"
		"gpr	cr0 .8  304 0\n"
		"gpr	cr1 .8  305 0\n"
		"gpr	cr2 .8  306 0\n"
		"gpr	cr3 .8  307 0\n"
		"gpr	cr4 .8  308 0\n"
		"gpr	cr5 .8  309 0\n"
		"gpr	cr6 .8  310 0\n"
		"gpr	cr7 .8  311 0\n"
		"gpr	xer .64 312 0\n"
		"gpr	mq   .64 320 0\n"
		"gpr	fpscr  .64 328 0\n"
		"gpr	vrsave .64 336 0\n"
		"gpr	pvr .64 344 0\n"
		"gpr	dccr   .32 352 0\n"
		"gpr	iccr   .32 356 0\n"
		"gpr	dear   .32 360 0\n"
		"gpr	hid0   .64 364 0\n"
		"gpr	hid1   .64 372 0\n"
		"gpr	hid2   .64 380 0\n"
		"gpr	hid3   .64 388 0\n"
		"gpr	hid4   .64 396 0\n"
		"gpr	hid5   .64 404 0\n"
		"gpr	hid6   .64 412 0\n"
		"gpr	ibat0  .64 420 0\n"
		"gpr	ibat1  .64 428 0\n"
		"gpr	ibat2  .64 436 0\n"
		"gpr	ibat3  .64 444 0\n"
		"gpr	ibat0l .32 420 0\n"
		"gpr	ibat1l .32 428 0\n"
		"gpr	ibat2l .32 436 0\n"
		"gpr	ibat3l .32 444 0\n"
		"gpr	ibat0u .32 424 0\n"
		"gpr	ibat1u .32 432 0\n"
		"gpr	ibat2u .32 440 0\n"
		"gpr	ibat3u .32 448 0\n"
		"gpr	dbat0  .64 456 0\n"
		"gpr	dbat1  .64 464 0\n"
		"gpr	dbat2  .64 472 0\n"
		"gpr	dbat3  .64 480 0\n"
		"gpr	dbat0l .32 456 0\n"
		"gpr	dbat1l .32 464 0\n"
		"gpr	dbat2l .32 472 0\n"
		"gpr	dbat3l .32 480 0\n"
		"gpr	dbat0u .32 460 0\n"
		"gpr	dbat1u .32 468 0\n"
		"gpr	dbat2u .32 476 0\n"
		"gpr	dbat3u .32 484 0\n"
		"gpr	mask   .64 488 0\n"; //not a real register used on complex functions
	return strdup (p);
}

static int analop_vle(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	vle_t* instr = NULL;
	vle_handle handle = {0};
	op->size = 2;
	if (len > 1 && !vle_init (&handle, buf, len) && (instr = vle_next (&handle))) {
		op->size = instr->size;
		op->type = instr->anal_op;
		//op->id = instr->type;

		switch (op->type) {
		case R_ANAL_OP_TYPE_ILL:
			break;
		case R_ANAL_OP_TYPE_ADD:
			break;
		case R_ANAL_OP_TYPE_AND:
			break;
		case R_ANAL_OP_TYPE_CALL:
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CCALL:
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CJMP:
			op->cond = instr->cond; //R_ANAL_CONDTYPE_NE;
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CMP:
			break;
		case R_ANAL_OP_TYPE_JMP:
			op->jump = addr + instr->fields[instr->n - 1].value;
			break;
		case R_ANAL_OP_TYPE_LOAD:
			break;
		case R_ANAL_OP_TYPE_MOV:
			break;
		case R_ANAL_OP_TYPE_MUL:
			break;
		case R_ANAL_OP_TYPE_NOT:
			break;
		case R_ANAL_OP_TYPE_OR:
			break;
		case R_ANAL_OP_TYPE_ROR:
			break;
		case R_ANAL_OP_TYPE_ROL:
			break;
		case R_ANAL_OP_TYPE_RCALL:
			op->eob = true;
			break;
		case R_ANAL_OP_TYPE_RET:
			op->eob = true;
			break;
		case R_ANAL_OP_TYPE_RJMP:
			break;
		case R_ANAL_OP_TYPE_SHL:
			break;
		case R_ANAL_OP_TYPE_SHR:
			break;
		case R_ANAL_OP_TYPE_STORE:
			break;
		case R_ANAL_OP_TYPE_SUB:
			break;
		case R_ANAL_OP_TYPE_SWI:
			break;
		case R_ANAL_OP_TYPE_SYNC:
			break;
		case R_ANAL_OP_TYPE_TRAP:
			break;
		case R_ANAL_OP_TYPE_XOR:
			break;
		default:
			//eprintf ("Missing an R_ANAL_OP_TYPE (%"PFMT64u")\n", op->type);
			break;
		}
		vle_free (instr);
		return op->size;
	}
	return -1;
}

static const char *parse_reg_name(csh handle, cs_insn *insn, int reg_num) {
	switch (INSOP (reg_num).type) {
	case PPC_OP_REG:
		return cs_reg_name (handle, INSOP (reg_num).reg);
	case PPC_OP_MEM:
		if (INSOP (reg_num).mem.base != PPC_REG_INVALID) {
			return cs_reg_name (handle, INSOP (reg_num).mem.base);
		}
		break;
	default:
		break;
	}
	return NULL;
}

static void create_src_dst(RAnalOp *op) {
	r_vector_push (&op->srcs, NULL);
	r_vector_push (&op->srcs, NULL);
	r_vector_push (&op->srcs, NULL);
	r_vector_push (&op->dsts, NULL);
}

static void set_src_dst(RAnalValue *val, csh *handle, cs_insn *insn, int x) {
	cs_ppc_op ppcop = INSOP (x);
	val->reg = parse_reg_name (*handle, insn, x);
	switch (ppcop.type) {
	case PPC_OP_REG:
		break;
	case PPC_OP_MEM:
		val->delta = ppcop.mem.disp;
		break;
	case PPC_OP_IMM:
		val->imm = ppcop.imm;
		break;
	default:
		break;
	}
}

static void op_fillval(RAnalOp *op, csh handle, cs_insn *insn) {
	create_src_dst (op);
	RAnalValue *src0 = r_vector_index_ptr (&op->srcs, 0);
	RAnalValue *src1 = r_vector_index_ptr (&op->srcs, 1);
	RAnalValue *src2 = r_vector_index_ptr (&op->srcs, 2);
	RAnalValue *dst = r_vector_index_ptr (&op->dsts, 0);
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_CMP:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_NOR:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_CAST:
		set_src_dst (src2, &handle, insn, 3);
		set_src_dst (src1, &handle, insn, 2);
		set_src_dst (src0, &handle, insn, 1);
		set_src_dst (dst, &handle, insn, 0);
		break;
	case R_ANAL_OP_TYPE_STORE:
		set_src_dst (dst, &handle, insn, 1);
		set_src_dst (src0, &handle, insn, 0);
		break;
	}
}

static char *shrink(char *op) {
	if (!op) {
		return NULL;
	}
	size_t len = strlen(op);
	if (!len) {
		return NULL;
	}
	op[len - 1] = 0;
	return op;
}

#undef PPC
#define CSINC PPC
#if 0
#define CSINC_MODE \
	((as->config->bits == 64) ? CS_MODE_64 : (as->config->bits == 32) ? CS_MODE_32 : 0) \
	| (R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN)
#else
#define CSINC_MODE \
	((as->config->bits == 64) ? CS_MODE_64 : (as->config->bits == 32) ? CS_MODE_32 : 0)
#endif
#include "../capstone.inc.c"

typedef struct plugin_data_t {
	CapstonePluginData cpd;
	char cspr[16];
	char words[8][64];
} PluginData;

static const char* getspr(PluginData *pd, struct Getarg *gop, int n) {
	ut32 spr = 0;
	if (n < 0 || n >= 8) {
		return NULL;
	}
	spr = getarg (gop, 0);
	switch (spr) {
	case SPR_HID0:
		return "hid0";
	case SPR_HID1:
		return "hid1";
	case SPR_HID2:
		return "hid2";
	case SPR_HID4:
		return "hid4";
	case SPR_HID5:
		return "hid5";
	case SPR_HID6:
		return "hid6";
	default:
		snprintf (pd->cspr, sizeof (pd->cspr), "spr_%u", spr);
		break;
	}
	return pd->cspr;
}

static char *getarg2(PluginData *pd, struct Getarg *gop, int n, const char *setstr) {
	cs_insn *insn = gop->insn;
	csh handle = gop->handle;
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return NULL;
	}
	op = INSOP (n);
	switch (op.type) {
	case PPC_OP_INVALID:
		pd->words[n][0] = '\0';
		//strcpy (pd->words[n], "invalid");
		break;
	case PPC_OP_REG:
		snprintf (pd->words[n], sizeof (pd->words[n]),
				"%s%s", cs_reg_name (handle, op.reg), setstr);
		break;
	case PPC_OP_IMM:
		snprintf (pd->words[n], sizeof (pd->words[n]),
				"0x%"PFMT64x"%s", (ut64) op.imm, setstr);
		break;
	case PPC_OP_MEM:
		snprintf (pd->words[n], sizeof (pd->words[n]),
				"%"PFMT64d",%s,+,%s",
				(ut64) op.mem.disp,
				cs_reg_name (handle, op.mem.base), setstr);
		break;
#if CS_API_MAJOR < 6
	case PPC_OP_CRX: // Condition Register field
		snprintf (pd->words[n], sizeof (pd->words[n]),
				"%"PFMT64d"%s", (ut64) op.imm, setstr);
		break;
#endif
	}
	return pd->words[n];
}


static int decompile_vle(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	vle_t* instr = 0;
	vle_handle handle = {0};
	if (len < 2) {
		return -1;
	}
	if (!vle_init (&handle, buf, len) && (instr = vle_next (&handle))) {
		op->size = instr->size;
		char buf_asm[64];
		vle_snprint (buf_asm, sizeof (buf_asm), addr, instr);
		op->mnemonic = strdup (buf_asm);
		vle_free (instr);
	} else {
		op->mnemonic = strdup ("invalid");
		op->size = 2;
		return -1;
	}
	return op->size;
}

static int decompile_ps(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ppcps_t instr = {0};
	if (len < 4) {
		eprintf ("not eno\n");
		return -1;
	}
	op->size = 4;
	const ut32 data = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	if (libps_decode (data, &instr) < 1) {
		return -1;
	}
	char buf_asm[64] = {0};
	libps_snprint (buf_asm, sizeof (buf_asm), addr, &instr);
	op->mnemonic = strdup (buf_asm);
	// eprintf ("Mnemonic (%s)\n", buf_asm);
	return op->size;
}

static csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static void swap4(ut8 *buf) {
	ut8 swap = buf[0];
	buf[0] = buf[3];
	buf[3] = swap;
	swap = buf[1];
	buf[1] = buf[2];
	buf[2] = swap;
}

static bool decode(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	ut8 *buf = op->bytes;
	const int len = op->size;
	char cmaskbuf[cmaskbuf_SIZEOF] = {0};
	csh handle = cs_handle_for_session (as);
	if (handle == 0 || len < 4) {
		return false;
	}

	int ret;
	cs_insn *insn;
	char *op1;

	PluginData *pd = as->data;
	const char *cpu = as->config->cpu;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	ut8 csbuf[4];
	memcpy (csbuf, buf, 4);
	if (be) {
		swap4 (csbuf);
	}
	// capstone-next
	int n = cs_disasm (handle, (const ut8*)csbuf, len, addr, 1, &insn);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		ret = -1;
		if (cpu && !strcmp (cpu, "vle")) {
			if (!be) {
				return false;
			}
			// vle is big-endian only
			ret = decompile_vle (as, op, addr, buf, len);
		} else if (cpu && !strcmp (cpu, "ps")) {
			// libps is big-endian only
			if (!be) {
				return false;
			}
			ret = decompile_ps (as, op, addr, buf, len);
		}
		if (ret < 1) {
			if (n > 0) {
				op->mnemonic = r_str_newf ("%s%s%s",
					insn->mnemonic,
					insn->op_str[0]? " ": "",
					insn->op_str);
			} else {
				op->mnemonic = strdup ("invalid");
			}
		}
	}
	if (cpu && !strcmp (cpu, "vle")) {
		// vle is big-endian only
		if (!be) {
			return false;
		}
		ret = analop_vle (as, op, addr, buf, len);
		if (ret >= 0) {
			return op->size > 0;
		}
	}

	op->size = 4;

	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		if (mask & R_ARCH_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		struct Getarg gop = {
			.handle = handle,
			.insn = insn,
			.bits = as->config->bits
		};
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
#if CS_API_MAJOR >= 4
		case PPC_INS_CMPB:
#endif
		case PPC_INS_CMPD:
		case PPC_INS_CMPDI:
		case PPC_INS_CMPLD:
		case PPC_INS_CMPLDI:
		case PPC_INS_CMPLW:
		case PPC_INS_CMPLWI:
		case PPC_INS_CMPW:
		case PPC_INS_CMPWI:
#if CS_API_MAJOR > 4
		case PPC_INS_CMP:
		case PPC_INS_CMPI:
#endif
			op->type = R_ANAL_OP_TYPE_CMP;
			op->sign = true;
			if (ARG (2)[0] == '\0') {
				esilprintf (op, "%s,%s,-,0xff,&,cr0,=", ARG (1), ARG (0));
			} else {
				esilprintf (op, "%s,%s,-,0xff,&,%s,=", ARG (2), ARG (1), ARG (0));
			}
			break;
		case PPC_INS_MFLR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "lr,%s,=", ARG (0));
			break;
		case PPC_INS_MTLR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,lr,=", ARG (0));
			break;
		case PPC_INS_MR:
			op->type = R_ANAL_OP_TYPE_RMOV;
			esilprintf (op, "%s,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_LI:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_LIS:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s0000,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_CLRLWI:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (1), cmask32 (cmaskbuf, ARG (2), "0x1F"), ARG (0));
			break;
		case PPC_INS_RLWINM:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,&,%s,=", ARG (2), ARG (1), cmask32 (cmaskbuf, ARG (3), ARG (4)), ARG (0));
			break;
		case PPC_INS_SC:
			op->type = R_ANAL_OP_TYPE_SWI;
			esilprintf (op, "0,$");
			break;
		case PPC_INS_EXTSB:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_MOV;
			if (as->config->bits == 64) {
				esilprintf (op, "%s,0x80,&,?{,0xFFFFFFFFFFFFFF00,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			} else {
				esilprintf (op, "%s,0x80,&,?{,0xFFFFFF00,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			}
			break;
		case PPC_INS_EXTSH:
			op->sign = true;
			if (as->config->bits == 64) {
				esilprintf (op, "%s,0x8000,&,?{,0xFFFFFFFFFFFF0000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			} else {
				esilprintf (op, "%s,0x8000,&,?{,0xFFFF0000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			}
			break;
		case PPC_INS_EXTSW:
			op->sign = true;
			esilprintf (op, "%s,0x80000000,&,?{,0xFFFFFFFF00000000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			break;
		case PPC_INS_SYNC:
		case PPC_INS_ISYNC:
		case PPC_INS_LWSYNC:
#if CS_API_MAJOR < 6
		case PPC_INS_MSYNC:
#endif
		case PPC_INS_PTESYNC:
		case PPC_INS_TLBSYNC:
		case PPC_INS_SLBIA:
		case PPC_INS_SLBIE:
		case PPC_INS_SLBMFEE:
		case PPC_INS_SLBMTE:
		case PPC_INS_EIEIO:
		case PPC_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			esilprintf (op, ",");
			break;
		case PPC_INS_STW:
		case PPC_INS_STWUX:
		case PPC_INS_STWX:
		case PPC_INS_STWCX:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[4]"));
			break;
		case PPC_INS_STWU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[4],%s=", ARG (0), op1, op1);
			if (strstr (op1, "r1")) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = -atoi (op1);
			}
			break;
		case PPC_INS_STWBRX:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case PPC_INS_STB:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[1]"));
			break;
		case PPC_INS_STBU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[1],%s=", ARG (0), op1, op1);
			break;
		case PPC_INS_STH:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[2]"));
			break;
		case PPC_INS_STHU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[2],%s=", ARG (0), op1, op1);
			break;
		case PPC_INS_STD:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[8]"));
			break;
		case PPC_INS_STDU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[8],%s=", ARG (0), op1, op1);
			break;
		case PPC_INS_LBZU:
		case PPC_INS_LBZUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,[1],%s,=,%s=", op1, ARG (0), op1);
			break;
		case PPC_INS_LBZ:
#if CS_API_MAJOR >= 4
		case PPC_INS_LBZCIX:
#endif
		case PPC_INS_LBZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[1]"), ARG (0));
			break;
		case PPC_INS_LD:
		case PPC_INS_LDARX:
#if CS_API_MAJOR >= 4
		case PPC_INS_LDCIX:
#endif
		case PPC_INS_LDU:
		case PPC_INS_LDUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,[8],%s,=,%s=", op1, ARG (0), op1);
			break;
		case PPC_INS_LDX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[8]"), ARG (0));
			break;
		case PPC_INS_LDBRX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case PPC_INS_LFD:
		case PPC_INS_LFDU:
		case PPC_INS_LFDUX:
		case PPC_INS_LFDX:
		case PPC_INS_LFIWAX:
		case PPC_INS_LFIWZX:
		case PPC_INS_LFS:
		case PPC_INS_LFSU:
		case PPC_INS_LFSUX:
		case PPC_INS_LFSX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[4]"), ARG (0));
			break;
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
		case PPC_INS_LHAUX:
		case PPC_INS_LHAX:
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,[2],%s,=,%s=", op1, ARG (0), op1);
			break;
		case PPC_INS_LHBRX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case PPC_INS_LWA:
		case PPC_INS_LWARX:
		case PPC_INS_LWAUX:
		case PPC_INS_LWAX:
		case PPC_INS_LWZ:
#if CS_API_MAJOR >= 4
		case PPC_INS_LWZCIX:
#endif
		case PPC_INS_LWZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[4]"), ARG (0));
			break;
		case PPC_INS_LWZU:
		case PPC_INS_LWZUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,[4],%s,=,%s=", op1, ARG (0), op1);
			break;
		case PPC_INS_LWBRX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case PPC_INS_SLW:
		case PPC_INS_SLWI:
			op->type = R_ANAL_OP_TYPE_SHL;
			esilprintf (op, "%s,%s,<<,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SRW:
		case PPC_INS_SRWI:
			op->type = R_ANAL_OP_TYPE_SHR;
			esilprintf (op, "%s,%s,>>,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MULLI:
			op->sign = true;
		case PPC_INS_MULLW:
		case PPC_INS_MULLD:
			op->type = R_ANAL_OP_TYPE_MUL;
			esilprintf (op, "%s,%s,*,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SUB:
		case PPC_INS_SUBC:
		case PPC_INS_SUBF:
		case PPC_INS_SUBFIC:
		case PPC_INS_SUBFZE:
			op->type = R_ANAL_OP_TYPE_SUB;
			esilprintf (op, "%s,%s,-,%s,=", ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_ADD:
		case PPC_INS_ADDI:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_CRCLR:
		case PPC_INS_CRSET:
		case PPC_INS_CRMOVE:
		case PPC_INS_CRXOR:
		case PPC_INS_CRNOR:
		case PPC_INS_CRNOT:
			// reset conditional bits
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case PPC_INS_ADDC:
		case PPC_INS_ADDIC:
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ADDIS:
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "16,%s,<<,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ADDE:
		case PPC_INS_ADDME:
		case PPC_INS_ADDZE:
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MTSPR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG (1), PPCSPR (0));
			break;
		case PPC_INS_BCTR: // switch table here
			op->type = R_ANAL_OP_TYPE_UJMP;
			esilprintf (op, "ctr,pc,=");
			break;
		case PPC_INS_BCTRL: // switch table here
			op->type = R_ANAL_OP_TYPE_CALL;
			esilprintf (op, "pc,lr,=,ctr,pc,=");
			break;
#if CS_VERSION_MAJOR >= 5
		case PPC_INS_BNE:
		case PPC_INS_BNEA:
		case PPC_INS_BNECTR:
		case PPC_INS_BNECTRL:
		case PPC_INS_BNEL:
		case PPC_INS_BNELA:
		case PPC_INS_BNELR:
		case PPC_INS_BNELRL:
		case PPC_INS_BNG:
		case PPC_INS_BNGA:
		case PPC_INS_BNGCTR:
		case PPC_INS_BNGCTRL:
		case PPC_INS_BNGL:
		case PPC_INS_BNGLA:
		case PPC_INS_BNGLR:
		case PPC_INS_BNGLRL:
		case PPC_INS_BNL:
		case PPC_INS_BNLA:
		case PPC_INS_BNLCTR:
		case PPC_INS_BNLCTRL:
		case PPC_INS_BNLL:
		case PPC_INS_BNLLA:
		case PPC_INS_BNLLR:
		case PPC_INS_BNLLRL:
		case PPC_INS_BNS:
		case PPC_INS_BNSA:
		case PPC_INS_BNSCTR:
		case PPC_INS_BNSCTRL:
		case PPC_INS_BNSL:
		case PPC_INS_BNSLA:
		case PPC_INS_BNSLR:
		case PPC_INS_BNSLRL:
		case PPC_INS_BNU:
		case PPC_INS_BNUA:
		case PPC_INS_BNUCTR:
		case PPC_INS_BNUCTRL:
		case PPC_INS_BNUL:
		case PPC_INS_BNULA:
		case PPC_INS_BNULR:
		case PPC_INS_BNULRL:
#endif
		case PPC_INS_B:
		case PPC_INS_BC:
		case PPC_INS_BA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = ARG (1)[0] == '\0' ? IMM (0) : IMM (1);
			op->fail = addr + op->size;
			switch (BC ()) {
			case PPC_BC_LT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,!,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0x80,%s,&,!,!,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_LE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,!,cr0,!,|,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0x80,%s,&,!,!,0,%s,!,|,?{,%s,pc,=,},", ARG (0), ARG (0), ARG (1));
				}
				break;
			case PPC_BC_EQ:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,!,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "%s,!,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_GE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,cr0,!,|,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0x80,%s,&,!,%s,!,|,?{,%s,pc,=,},", ARG (0), ARG (0), ARG (1));
				}
				break;
			case PPC_BC_GT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0x80,%s,&,!,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_NE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,!,!,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "%s,!,!,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_INVALID:
				op->type = R_ANAL_OP_TYPE_JMP;
				esilprintf (op, "%s,pc,=", ARG (0));
#if CS_API_MAJOR < 6
			case PPC_BC_UN: // unordered (cs6 - same as *_SO)
			case PPC_BC_NU: // not unordered (cs6 - same as *_NS)
#endif
			case PPC_BC_SO: // summary overflow
			case PPC_BC_NS: // not summary overflow
			default:
				break;
			}
			break;
		case PPC_INS_BT:
		case PPC_INS_BF:
			switch (insn->detail->ppc.operands[0].type) {
#if CS_API_MAJOR < 6
			case PPC_OP_CRX:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->fail = addr + op->size;
				break;
#endif
			case PPC_OP_REG:
				if (op->type == R_ANAL_OP_TYPE_CJMP) {
					op->type = R_ANAL_OP_TYPE_UCJMP;
				} else {
					op->type = R_ANAL_OP_TYPE_CJMP;
				}
				op->jump = IMM (1);
				op->fail = addr + op->size;
				//op->type = R_ANAL_OP_TYPE_UJMP;
			default:
				break;
			}
			break;
		case PPC_INS_BDNZ:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,!,?{,%s,pc,=,}", ARG (0));
			break;
#if CS_API_MAJOR < 6
		case PPC_INS_BDNZA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
#endif
		case PPC_INS_BDNZL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLR:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,!,?{,lr,pc,=,},");
			break;
		case PPC_INS_BDNZLRL:
			op->fail = addr + op->size;
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case PPC_INS_BDZ:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,?{,%s,pc,=,}", ARG (0));
			break;
#if CS_API_MAJOR < 6
		case PPC_INS_BDZA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
#endif
		case PPC_INS_BDZL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLR:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,?{,lr,pc,=,}");
			break;
		case PPC_INS_BDZLRL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			break;
		case PPC_INS_BLR:
		case PPC_INS_BLRL:
		case PPC_INS_BCLR:
		case PPC_INS_BCLRL:
			op->type = R_ANAL_OP_TYPE_CRET;		//I'm a condret
			op->fail = addr + op->size;
			switch (BC ()) {
			case PPC_BC_INVALID:
				op->type = R_ANAL_OP_TYPE_RET;
				esilprintf (op, "lr,pc,=");
				break;
			case PPC_BC_LT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,!,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0x80,%s,&,!,!,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_LE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,!,cr0,!,|,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0x80,%s,&,!,!,0,%s,!,|,?{,lr,pc,=,},", ARG (0), ARG (0));
				}
				break;
			case PPC_BC_EQ:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,!,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "%s,!,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_GE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,cr0,!,|,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0x80,%s,&,!,%s,!,|,?{,lr,pc,=,},", ARG (0), ARG (0));
				}
				break;
			case PPC_BC_GT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0x80,%s,&,!,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_NE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,!,!,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "%s,!,!,?{,lr,pc,=,},", ARG (0));
				}
				break;
#if CS_API_MAJOR < 6
			case PPC_BC_UN: // unordered (cs6 - same as *_SO)
			case PPC_BC_NU: // not unordered (cs6 - same as *_NS)
#endif
			case PPC_BC_SO: // summary overflow
			case PPC_BC_NS: // not summary overflow
			default:
				break;
			}
			break;
		case PPC_INS_NOR:
			op->type = R_ANAL_OP_TYPE_NOR;
			esilprintf (op, "%s,%s,|,!,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_XOR:
		case PPC_INS_XORI:
			op->type = R_ANAL_OP_TYPE_XOR;
			esilprintf (op, "%s,%s,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_XORIS:
			op->type = R_ANAL_OP_TYPE_XOR;
			esilprintf (op, "16,%s,<<,%s,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_DIVD:
		case PPC_INS_DIVW:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_DIV;
			esilprintf (op, "%s,%s,/,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_DIVDU:
		case PPC_INS_DIVWU:
			op->type = R_ANAL_OP_TYPE_DIV;
			esilprintf (op, "%s,%s,/,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_BL:
		case PPC_INS_BLA:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "pc,lr,=,%s,pc,=", ARG (0));
			break;
		case PPC_INS_TRAP:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case PPC_INS_AND:
		case PPC_INS_NAND:
		case PPC_INS_ANDI:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ANDIS:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "16,%s,<<,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_OR:
		case PPC_INS_ORI:
			op->type = R_ANAL_OP_TYPE_OR;
			esilprintf (op, "%s,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ORIS:
			op->type = R_ANAL_OP_TYPE_OR;
			esilprintf (op, "16,%s,<<,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MFPVR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "pvr,%s,=", ARG (0));
			break;
		case PPC_INS_MFSPR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", PPCSPR (1), ARG (0));
			break;
		case PPC_INS_MFCTR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "ctr,%s,=", ARG (0));
			break;
		case PPC_INS_MFDCCR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "dccr,%s,=", ARG (0));
			break;
		case PPC_INS_MFICCR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "iccr,%s,=", ARG (0));
			break;
		case PPC_INS_MFDEAR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "dear,%s,=", ARG (0));
			break;
		case PPC_INS_MFMSR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "msr,%s,=", ARG (0));
			break;
		case PPC_INS_MTCTR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,ctr,=", ARG (0));
			break;
		case PPC_INS_MTDCCR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,dccr,=", ARG (0));
			break;
		case PPC_INS_MTICCR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,iccr,=", ARG (0));
			break;
		case PPC_INS_MTDEAR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,dear,=", ARG (0));
			break;
		case PPC_INS_MTMSR:
		case PPC_INS_MTMSRD:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,msr,=", ARG (0));
			break;
			// Data Cache Block Zero
		case PPC_INS_DCBZ:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, ",=[128]"));
			break;
		case PPC_INS_CLRLDI:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (1), cmask64 (cmaskbuf, ARG (2), "0x3F"), ARG (0));
			break;
		case PPC_INS_ROTLDI:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_RLDCL:
		case PPC_INS_RLDICL:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,&,%s,=", ARG (2), ARG (1), cmask64 (cmaskbuf, ARG (3), "0x3F"), ARG (0));
			break;
		case PPC_INS_RLDCR:
		case PPC_INS_RLDICR:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,&,%s,=", ARG (2), ARG (1), cmask64 (cmaskbuf, 0, ARG (3)), ARG (0));
			break;
		}
		if (mask & R_ARCH_OP_MASK_VAL) {
			op_fillval (op, handle, insn);
		}
		if (!(mask & R_ARCH_OP_MASK_ESIL)) {
			r_strbuf_fini (&op->esil);
		}
		cs_free (insn, n);
	}
	return op->size > 0;
}

static int archinfo(RArchSession *as, ut32 q) {
	const char *cpu = as->config->cpu;
	if (cpu && !strncmp (cpu, "vle", 3)) {
		return 2;
	}
	return 4;
}

static RList *preludes(RArchSession *as) {
	RList *l = r_list_newf (free);
	r_list_append (l, r_str_newf ("7c0802a6"));
	return l;
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (PluginData);
	PluginData *pd = as->data;
	if (!r_arch_cs_init (as, &pd->cpd.cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	CapstonePluginData *cpd = as->data;
	cs_close (&cpd->cs_handle);
	R_FREE (as->data);
	return true;
}

const RArchPlugin r_arch_plugin_ppc_cs = {
	.meta = {
		.name = "ppc",
		.author = "pancake,deroad",
		.desc = "PowerPC +vle +ps (capstone)",
		.license = "Apache-2.0",
	},
	.arch = "ppc",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.cpus = "ppc,vle,ps",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.info = archinfo,
	.preludes = preludes,
	.decode = decode,
	.regs = regs,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_ppc_cs,
	.version = R2_VERSION
};
#endif
