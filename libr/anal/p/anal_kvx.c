/* radare - LGPL - Copyright 2022 - jmaselbas */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>

#include "kvx/kvx.h"

static const char *kvx_reg_profile = ""
	"=PC	pc\n"
	"=SP	r12\n"
	"=LR	ra\n"
	"=SN	r0\n"
	"=A0	r0\n"
	"=A1	r1\n"
	"=A2	r2\n"
	"=A3	r3\n"
	"=A4	r4\n"
	"=A5	r5\n"
	"=A6	r6\n"
	"=A7	r7\n"
	"=A8	r8\n"
	"=A9	r9\n"
	/* FIXME: alias of three char are not supported */
#if 0
	"=A10	r10\n"
	"=A11	r11\n"
#endif
	"=R0	r0\n"
	"gpr	r0	.64 0 0\n"
	"gpr	r1	.64 8 0\n"
	"gpr	r2	.64 16 0\n"
	"gpr	r3	.64 24 0\n"
	"gpr	r4	.64 32 0\n"
	"gpr	r5	.64 40 0\n"
	"gpr	r6	.64 48 0\n"
	"gpr	r7	.64 56 0\n"
	"gpr	r8	.64 64 0\n"
	"gpr	r9	.64 72 0\n"
	"gpr	r10	.64 80 0\n"
	"gpr	r11	.64 88 0\n"
	"gpr	r12	.64 96 0\n"
	"gpr	r13	.64 104 0\n"
	"gpr	r14	.64 112 0\n"
	"gpr	r15	.64 120 0\n"
	"gpr	r16	.64 128 0\n"
	"gpr	r17	.64 136 0\n"
	"gpr	r18	.64 144 0\n"
	"gpr	r19	.64 152 0\n"
	"gpr	r20	.64 160 0\n"
	"gpr	r21	.64 168 0\n"
	"gpr	r22	.64 176 0\n"
	"gpr	r23	.64 184 0\n"
	"gpr	r24	.64 192 0\n"
	"gpr	r25	.64 200 0\n"
	"gpr	r26	.64 208 0\n"
	"gpr	r27	.64 216 0\n"
	"gpr	r28	.64 224 0\n"
	"gpr	r29	.64 232 0\n"
	"gpr	r30	.64 240 0\n"
	"gpr	r31	.64 248 0\n"
	"gpr	r32	.64 256 0\n"
	"gpr	r33	.64 264 0\n"
	"gpr	r34	.64 272 0\n"
	"gpr	r35	.64 280 0\n"
	"gpr	r36	.64 288 0\n"
	"gpr	r37	.64 296 0\n"
	"gpr	r38	.64 304 0\n"
	"gpr	r39	.64 312 0\n"
	"gpr	r40	.64 320 0\n"
	"gpr	r41	.64 328 0\n"
	"gpr	r42	.64 336 0\n"
	"gpr	r43	.64 344 0\n"
	"gpr	r44	.64 352 0\n"
	"gpr	r45	.64 360 0\n"
	"gpr	r46	.64 368 0\n"
	"gpr	r47	.64 376 0\n"
	"gpr	r48	.64 384 0\n"
	"gpr	r49	.64 392 0\n"
	"gpr	r50	.64 400 0\n"
	"gpr	r51	.64 408 0\n"
	"gpr	r52	.64 416 0\n"
	"gpr	r53	.64 424 0\n"
	"gpr	r54	.64 432 0\n"
	"gpr	r55	.64 440 0\n"
	"gpr	r56	.64 448 0\n"
	"gpr	r57	.64 456 0\n"
	"gpr	r58	.64 464 0\n"
	"gpr	r59	.64 472 0\n"
	"gpr	r60	.64 480 0\n"
	"gpr	r61	.64 488 0\n"
	"gpr	r62	.64 496 0\n"
	"gpr	r63	.64 504 0\n"
	"gpr	r0r1	.128 0 0\n"
	"gpr	r2r3	.128 16 0\n"
	"gpr	r4r5	.128 32 0\n"
	"gpr	r6r7	.128 48 0\n"
	"gpr	r8r9	.128 64 0\n"
	"gpr	r10r11	.128 80 0\n"
	"gpr	r12r13	.128 96 0\n"
	"gpr	r14r15	.128 112 0\n"
	"gpr	r16r17	.128 128 0\n"
	"gpr	r18r19	.128 144 0\n"
	"gpr	r20r21	.128 160 0\n"
	"gpr	r22r23	.128 176 0\n"
	"gpr	r24r25	.128 192 0\n"
	"gpr	r26r27	.128 208 0\n"
	"gpr	r28r29	.128 224 0\n"
	"gpr	r30r31	.128 240 0\n"
	"gpr	r32r33	.128 256 0\n"
	"gpr	r34r35	.128 272 0\n"
	"gpr	r36r37	.128 288 0\n"
	"gpr	r38r39	.128 304 0\n"
	"gpr	r40r41	.128 320 0\n"
	"gpr	r42r43	.128 336 0\n"
	"gpr	r44r45	.128 352 0\n"
	"gpr	r46r47	.128 368 0\n"
	"gpr	r48r49	.128 384 0\n"
	"gpr	r50r51	.128 400 0\n"
	"gpr	r52r53	.128 416 0\n"
	"gpr	r54r55	.128 432 0\n"
	"gpr	r56r57	.128 448 0\n"
	"gpr	r58r59	.128 464 0\n"
	"gpr	r60r61	.128 480 0\n"
	"gpr	r62r63	.128 496 0\n"
	"gpr	r0r1r2r3	.256 0 0\n"
	"gpr	r4r5r6r7	.256 32 0\n"
	"gpr	r8r9r10r11	.256 64 0\n"
	"gpr	r12r13r14r15	.256 96 0\n"
	"gpr	r16r17r18r19	.256 128 0\n"
	"gpr	r20r21r22r23	.256 160 0\n"
	"gpr	r24r25r26r27	.256 192 0\n"
	"gpr	r28r29r30r31	.256 224 0\n"
	"gpr	r32r33r34r35	.256 256 0\n"
	"gpr	r36r37r38r39	.256 288 0\n"
	"gpr	r40r41r42r43	.256 320 0\n"
	"gpr	r44r45r46r47	.256 352 0\n"
	"gpr	r48r49r50r51	.256 384 0\n"
	"gpr	r52r53r54r55	.256 416 0\n"
	"gpr	r56r57r58r59	.256 448 0\n"
	"gpr	r60r61r62r63	.256 480 0\n"
	"gpr	pc	.64 512 0\n"
	"gpr	ps	.64 520 0\n"
	"gpr	pcr	.64 528 0\n"
	"gpr	ra	.64 536 0\n"
	"gpr	cs	.64 544 0\n"
	"gpr	csit	.64 552 0\n"
	"gpr	aespc	.64 560 0\n"
	"gpr	ls	.64 568 0\n"
	"gpr	le	.64 576 0\n"
	"gpr	lc	.64 584 0\n"
	"gpr	ipe	.64 592 0\n"
	"gpr	men	.64 600 0\n"
	"gpr	pmc	.64 608 0\n"
	"gpr	pm0	.64 616 0\n"
	"gpr	pm1	.64 624 0\n"
	"gpr	pm2	.64 632 0\n"
	"gpr	pm3	.64 640 0\n"
	"gpr	pmsa	.64 648 0\n"
	"gpr	tcr	.64 656 0\n"
	"gpr	t0v	.64 664 0\n"
	"gpr	t1v	.64 672 0\n"
	"gpr	t0r	.64 680 0\n"
	"gpr	t1r	.64 688 0\n"
	"gpr	wdv	.64 696 0\n"
	"gpr	wdr	.64 704 0\n"
	"gpr	ile	.64 712 0\n"
	"gpr	ill	.64 720 0\n"
	"gpr	ilr	.64 728 0\n"
	"gpr	mmc	.64 736 0\n"
	"gpr	tel	.64 744 0\n"
	"gpr	teh	.64 752 0\n"
	"gpr	syo	.64 768 0\n"
	"gpr	hto	.64 776 0\n"
	"gpr	ito	.64 784 0\n"
	"gpr	do	.64 792 0\n"
	"gpr	mo	.64 800 0\n"
	"gpr	pso	.64 808 0\n"
	"gpr	dc	.64 832 0\n"
	"gpr	dba0	.64 840 0\n"
	"gpr	dba1	.64 848 0\n"
	"gpr	dwa0	.64 856 0\n"
	"gpr	dwa1	.64 864 0\n"
	"gpr	mes	.64 872 0\n"
	"gpr	ws	.64 880 0\n"
	"gpr	spc_pl0	.64 1024 0\n"
	"gpr	spc_pl1	.64 1032 0\n"
	"gpr	spc_pl2	.64 1040 0\n"
	"gpr	spc_pl3	.64 1048 0\n"
	"gpr	sps_pl0	.64 1056 0\n"
	"gpr	sps_pl1	.64 1064 0\n"
	"gpr	sps_pl2	.64 1072 0\n"
	"gpr	sps_pl3	.64 1080 0\n"
	"gpr	ea_pl0	.64 1088 0\n"
	"gpr	ea_pl1	.64 1096 0\n"
	"gpr	ea_pl2	.64 1104 0\n"
	"gpr	ea_pl3	.64 1112 0\n"
	"gpr	ev_pl0	.64 1120 0\n"
	"gpr	ev_pl1	.64 1128 0\n"
	"gpr	ev_pl2	.64 1136 0\n"
	"gpr	ev_pl3	.64 1144 0\n"
	"gpr	sr_pl0	.64 1152 0\n"
	"gpr	sr_pl1	.64 1160 0\n"
	"gpr	sr_pl2	.64 1168 0\n"
	"gpr	sr_pl3	.64 1176 0\n"
	"gpr	es_pl0	.64 1184 0\n"
	"gpr	es_pl1	.64 1192 0\n"
	"gpr	es_pl2	.64 1200 0\n"
	"gpr	es_pl3	.64 1208 0\n"
	"gpr	syow	.64 1280 0\n"
	"gpr	htow	.64 1288 0\n"
	"gpr	itow	.64 1296 0\n"
	"gpr	dow	.64 1304 0\n"
	"gpr	mow	.64 1312 0\n"
	"gpr	psow	.64 1320 0\n"
	"gpr	spc	.64 1536 0\n"
	"gpr	sps	.64 1568 0\n"
	"gpr	ea	.64 1600 0\n"
	"gpr	ev	.64 1632 0\n"
	"gpr	sr	.64 1664 0\n"
	"gpr	es	.64 1696 0\n"
	;

/* The bundle store several instruction that cannot be disassembled
 * individually, but each instructions should be printed on it's own
 * line for readability. The function kvx_next_insn does all the magic
 * of figuring out if the next instruction is already decoded in this
 * bundle or if it needs to decode a new bundle */
static R_TH_LOCAL bundle_t bundle;

static int kvx_op(RAnal *anal, RArchOp *op, ut64 addr, const ut8 *b, int len, RArchOpMask mask) {
	char strasm[64];
	r_return_val_if_fail (anal && op, -1);

	if (addr % 4) {
		goto unaligned;
	}

	insn_t *insn = kvx_next_insn (&bundle, addr, b, len);
	if (!insn) {
		goto invalid;
	}
	op->addr = addr;
	op->size = insn->len * sizeof (ut32);

	if (insn->opc) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			kvx_instr_print (insn, addr, strasm, sizeof (strasm));
			op->mnemonic = strdup (strasm);
		}

		op->type = insn->opc->type;
		op->cond = insn->opc->cond;
		/* The delay slot is a bit abused here, it is used make each
		 * instructions in a bundle complet at the same address, for
		 * exemple branch isntruction comes first but will be effective
		 * at the end of the bundle, after the remaning instructions. */
		op->delay = insn->rem;
		if ((op->type & R_ARCH_OP_TYPE_CJMP) == R_ARCH_OP_TYPE_CJMP) {
			/* if fail goto next bundle */
			op->fail = bundle.addr + bundle.size;
		}
		if ((op->type & R_ARCH_OP_TYPE_JMP) == R_ARCH_OP_TYPE_JMP) {
			op->jump = kvx_instr_jump (insn, addr);
		}
		if ((op->type & R_ARCH_OP_TYPE_RET) == R_ARCH_OP_TYPE_RET) {
			op->eob = true;
		}
	} else {
		op->type = R_ARCH_OP_TYPE_UNK;
	}

	return op->size;

invalid:
	op->size = 4;
	return op->size;

unaligned:
	op->size = 4 - (addr % 4);
	return op->size;
}

static int kvx_archinfo(RAnal *anal, int query) {
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 4;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 12;
	case R_ANAL_ARCHINFO_ALIGN:
		return 4;
	case R_ANAL_ARCHINFO_DATA_ALIGN:
		return 0;
	default:
		return 0;
	}
}

static bool kvx_set_reg_profile(RAnal *anal) {
	return r_reg_set_profile_string (anal->reg, kvx_reg_profile);
}

RAnalPlugin r_anal_plugin_kvx = {
	.name = "kvx",
	.desc = "Kalray VLIW core analysis plugin",
	.arch = "kvx",
	.license = "GPL",
	.esil = false,
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.op = kvx_op,
	.archinfo = kvx_archinfo,
	.set_reg_profile = kvx_set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_kvx,
	.version = R2_VERSION
};
#endif
