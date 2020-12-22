/* radare2 - LGPL - Copyright 2015-2018 - oddcoder, thestr4ng3r, courk */

#include <r_types.h>
#include <r_anal.h>
#include <r_lib.h>

#include "../../asm/arch/pic/pic_midrange.h"

typedef struct _pic_midrange_op_args_val {
	ut16 f;
	ut16 k;
	ut8 d;
	ut8 m;
	ut8 n;
	ut8 b;
} PicMidrangeOpArgsVal;

typedef void (*pic_midrange_inst_handler_t) (RAnal *anal, RAnalOp *op,
					     ut64 addr,
					     PicMidrangeOpArgsVal *args);

typedef struct _pic_midrange_op_anal_info {
	PicMidrangeOpcode opcode;
	PicMidrangeOpArgs args;
	pic_midrange_inst_handler_t handler;
} PicMidrangeOpAnalInfo;

#define INST_HANDLER(OPCODE_NAME)                                            \
	static void _inst__##OPCODE_NAME (RAnal *anal, RAnalOp *op,          \
					  ut64 addr,                         \
					  PicMidrangeOpArgsVal *args)
#define INST_DECL(NAME, ARGS)                                                \
	{                                                                    \
		PIC_MIDRANGE_OPCODE_##NAME, PIC_MIDRANGE_OP_ARGS_##ARGS,     \
			_inst__##NAME                                        \
	}

#define e(frag) r_strbuf_append (&op->esil, frag)
#define ef(frag, ...) r_strbuf_appendf (&op->esil, frag, __VA_ARGS__)

#define PIC_MIDRANGE_ESIL_SRAM_START (1 << 16)
#define PIC_MIDRANGE_ESIL_CSTACK_TOP ((1 << 16) + (1 << 12))

#define PIC_MIDRANGE_ESIL_BSR_ADDR "bsr,0x80,*,0x%x,+,_sram,+"

#define PIC_MIDRANGE_ESIL_OPTION_ADDR "0x95,_sram,+"

#define PIC_MIDRANGE_ESIL_UPDATE_FLAGS                                       \
	"$z,z,:=,"                                                            \
	"7,$c,c,:=,"                                                           \
	"4,$c,dc,:=,"

#define PIC_MIDRANGE_ESIL_LW_OP(O)                                           \
	"0x%x,wreg," #O "=," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

#define PIC_MIDRANGE_ESIL_FWF_OP(O)                                          \
	"wreg," PIC_MIDRANGE_ESIL_BSR_ADDR "," #O                            \
	"=[1]," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

#define PIC_MIDRANGE_ESIL_WWF_OP(O)                                          \
	PIC_MIDRANGE_ESIL_BSR_ADDR                                           \
	",[1],"                                                              \
	"wreg," #O "=," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

#define PIC_MIDRANGE_ESIL_FWF_OP_C(O)                                        \
	"c,wreg,"                                                            \
	"+," PIC_MIDRANGE_ESIL_BSR_ADDR "," #O                               \
	"=[1]," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

#define PIC_MIDRANGE_ESIL_WWF_OP_C(O)                                        \
	"c," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1]," #O ","                       \
	"wreg," #O "=," PIC_MIDRANGE_ESIL_UPDATE_FLAGS

INST_HANDLER (NOP) {}

INST_HANDLER (RETFIE) {
	op->type = R_ANAL_OP_TYPE_RET;
}

INST_HANDLER (OPTION) {
	op->type = R_ANAL_OP_TYPE_STORE;
}

INST_HANDLER (TRIS) {
	op->type = R_ANAL_OP_TYPE_STORE;
}

INST_HANDLER (RETURN) {
	op->type = R_ANAL_OP_TYPE_RET;
	e ("0x1f,stkptr,==,$z,?{,BREAK,},");
	e ("_stack,stkptr,2,*,+,[2],2,*,pc,=,");
	e ("0x01,stkptr,-=,");
	e ("0xff,stkptr,==,$z,?{,0x1f,stkptr,=,},");
}

INST_HANDLER (CALL) {
	ut64 pclath;
	op->type = R_ANAL_OP_TYPE_CALL;
	r_anal_esil_reg_read (anal->esil, "pclath", &pclath, NULL);
	op->jump = 2 * (((pclath & 0x78) << 8) + args->k);
	ef ("8,pclath,0x78,&,<<,0x%x,+,2,*,pc,=,", args->k);
	e ("0x1f,stkptr,==,$z,?{,0xff,stkptr,=,},");
	e ("0x0f,stkptr,==,$z,?{,0xff,stkptr,=,},");
	e ("0x01,stkptr,+=,");
	ef ("0x%" PFMT64x ",_stack,stkptr,2,*,+,=[2],", (addr + 2) / 2);
}

INST_HANDLER (GOTO) {
	ut64 pclath;
	op->type = R_ANAL_OP_TYPE_JMP;
	r_anal_esil_reg_read (anal->esil, "pclath", &pclath, NULL);
	op->jump = 2 * (((pclath & 0x78) << 8) + args->k);
	ef ("8,pclath,0x78,&,<<,0x%x,+,2,*,pc,=,", args->k);
}

INST_HANDLER (BCF) {
	ut8 mask = ~(1 << args->b);
	ef (PIC_MIDRANGE_ESIL_BSR_ADDR
	    ",[1],0x%x,&," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],",
	    args->f, mask, args->f);
}

INST_HANDLER (BSF) {
	ut8 mask = (1 << args->b);
	ef (PIC_MIDRANGE_ESIL_BSR_ADDR
	    ",[1],0x%x,|," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],",
	    args->f, mask, args->f);
}

INST_HANDLER (BTFSC) {
	ut8 mask = (1 << args->b);
	op->type = R_ANAL_OP_TYPE_CJMP;
	op->jump = addr + 4;
	op->fail = addr + 2;
	ef (PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],0x%x,&,!,?{,0x%" PFMT64x ",pc,=,},",
	    args->f, mask, op->jump);
}

INST_HANDLER (BTFSS) {
	ut8 mask = (1 << args->b);
	op->type = R_ANAL_OP_TYPE_CJMP;
	op->jump = addr + 4;
	op->fail = addr + 2;
	ef (PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],0x%x,&,?{,0x%" PFMT64x ",pc,=,},", args->f,
	    mask, op->jump);
}

INST_HANDLER (BRA) {
	st16 branch = args->k;
	op->type = R_ANAL_OP_TYPE_JMP;
	branch |= ((branch & 0x100) ? 0xfe00 : 0);
	op->jump = addr + 2 * (branch + 1);
	ef ("%s0x%x,1,+,2,*,pc,+=,", branch < 0 ? "-" : "",
	    branch < 0 ? -branch : branch);
}

INST_HANDLER (BRW) {
	ut64 wreg;
	op->type = R_ANAL_OP_TYPE_UJMP;
	r_anal_esil_reg_read (anal->esil, "wreg", &wreg, NULL);
	op->jump = addr + 2 * (wreg + 1);
	e ("wreg,1,+,2,*,pc,+=,");
}

INST_HANDLER (CLR) {
	if (args->d) {
		ef ("0x00," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],", args->f);
	} else {
		e ("0x00,wreg,=,");
	}
	e ("1,z,=,");
}

INST_HANDLER (SUBWF) {
	op->type = R_ANAL_OP_TYPE_SUB;
	if (args->d) {
		ef (PIC_MIDRANGE_ESIL_FWF_OP (-), args->f);
	} else {
		ef (PIC_MIDRANGE_ESIL_WWF_OP (-), args->f);
		e ("wreg,0x00,-,wreg,=,c,!=,dc,!=,");
	}
}

INST_HANDLER (DECFSZ) {
	op->type = R_ANAL_OP_TYPE_CJMP;
	op->jump = addr + 4;
	op->fail = addr + 2;
	if (args->d) {
		ef ("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",-=[1],", args->f);
	} else {
		ef ("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],-,wreg,=,",
		    args->f);
	}
	ef (PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],!,?{,0x%" PFMT64x ",pc,=,},", args->f,
	    op->jump);
}

INST_HANDLER (INCFSZ) {
	op->type = R_ANAL_OP_TYPE_CJMP;
	op->jump = addr + 4;
	op->fail = addr + 2;
	if (args->d) {
		ef ("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",+=[1],", args->f);
	} else {
		ef ("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],+,wreg,=,",
		    args->f);
	}
	ef (PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],!,?{,0x%" PFMT64x ",pc,=,},", args->f,
	    op->jump);
}

INST_HANDLER (INCF) {
	op->type = R_ANAL_OP_TYPE_ADD;
	if (args->d) {
		ef ("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",+=[1],", args->f);
	} else {
		ef ("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],+,wreg,=,",
		    args->f);
	}
	e ("$z,z,:=,");
}

INST_HANDLER (DECF) {
	op->type = R_ANAL_OP_TYPE_SUB;
	if (args->d) {
		ef ("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",-=[1],", args->f);
	} else {
		ef ("0x01," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],-,wreg,=,",
		    args->f);
	}
	e ("$z,z,:=,");
}

INST_HANDLER (IORWF) {
	op->type = R_ANAL_OP_TYPE_OR;
	if (args->d) {
		ef (PIC_MIDRANGE_ESIL_FWF_OP (|), args->f);
	} else {
		ef (PIC_MIDRANGE_ESIL_WWF_OP (|), args->f);
	}
}

INST_HANDLER (ANDWF) {
	op->type = R_ANAL_OP_TYPE_AND;
	if (args->d) {
		ef (PIC_MIDRANGE_ESIL_FWF_OP (&), args->f);
	} else {
		ef (PIC_MIDRANGE_ESIL_WWF_OP (&), args->f);
	}
}

INST_HANDLER (XORWF) {
	op->type = R_ANAL_OP_TYPE_XOR;
	if (args->d) {
		ef (PIC_MIDRANGE_ESIL_FWF_OP (^), args->f);
	} else {
		ef (PIC_MIDRANGE_ESIL_WWF_OP (^), args->f);
	}
}

INST_HANDLER (ADDWF) {
	op->type = R_ANAL_OP_TYPE_ADD;
	if (args->d) {
		ef (PIC_MIDRANGE_ESIL_FWF_OP (+), args->f);
	} else {
		ef (PIC_MIDRANGE_ESIL_WWF_OP (+), args->f);
	}
}

INST_HANDLER (SUBLW) {
	op->type = R_ANAL_OP_TYPE_SUB;
	ef (PIC_MIDRANGE_ESIL_LW_OP (-), args->k);
}

INST_HANDLER (ADDLW) {
	op->type = R_ANAL_OP_TYPE_ADD;
	ef (PIC_MIDRANGE_ESIL_LW_OP (+), args->k);
}

INST_HANDLER (IORLW) {
	op->type = R_ANAL_OP_TYPE_OR;
	ef (PIC_MIDRANGE_ESIL_LW_OP (|), args->k);
}

INST_HANDLER (ANDLW) {
	op->type = R_ANAL_OP_TYPE_AND;
	ef (PIC_MIDRANGE_ESIL_LW_OP (&), args->k);
}

INST_HANDLER (XORLW) {
	op->type = R_ANAL_OP_TYPE_XOR;
	ef (PIC_MIDRANGE_ESIL_LW_OP (^), args->k);
}

INST_HANDLER (MOVLW) {
	op->type = R_ANAL_OP_TYPE_LOAD;
	ef ("0x%x,wreg,=,", args->k);
}

INST_HANDLER (RETLW) {
	op->type = R_ANAL_OP_TYPE_RET;
	ef ("0x%x,wreg,=,", args->k);
	e ("0x1f,stkptr,==,$z,?{,BREAK,},");
	e ("_stack,stkptr,2,*,+,[2],2,*,pc,=,");
	e ("0x01,stkptr,-=,");
	e ("0xff,stkptr,==,$z,?{,0x1f,stkptr,=,},");
}

INST_HANDLER (MOVLP) {
	op->type = R_ANAL_OP_TYPE_LOAD;
	ef ("0x%x,pclath,=,", args->f);
}

INST_HANDLER (MOVLB) {
	op->type = R_ANAL_OP_TYPE_LOAD;
	ef ("0x%x,bsr,=,", args->k);
}

INST_HANDLER (CALLW) {
	op->type = R_ANAL_OP_TYPE_UCALL;
	e ("8,pclath,<<,0x%x,+,wreg,2,*,pc,=,");
	e ("0x1f,stkptr,==,$z,?{,0xff,stkptr,=,},");
	e ("0x0f,stkptr,==,$z,?{,0xff,stkptr,=,},");
	e ("0x01,stkptr,+=,");
	ef ("0x%" PFMT64x ",_stack,stkptr,2,*,+,=[2],", (addr + 2) / 2);
}

INST_HANDLER (MOVWF) {
	op->type = R_ANAL_OP_TYPE_STORE;
	ef ("wreg," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],", args->f);
}

INST_HANDLER (MOVF) {
	op->type = R_ANAL_OP_TYPE_LOAD;
	if (args->d) {
		ef (PIC_MIDRANGE_ESIL_BSR_ADDR
		    ",[1]," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],",
		    args->f, args->f);
	} else {
		ef (PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],wreg,=,", args->f);
	}
	e ("$z,z,:=,");
}

INST_HANDLER (SWAPF) {
	ef ("4," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,0x0f,&,", args->f);
	ef ("4," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],<<,0xf0,&,", args->f);
	e ("|,");
	ef (PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],", args->f);
}

INST_HANDLER (LSLF) {
	op->type = R_ANAL_OP_TYPE_SHL;
	ef ("7," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,c,=,", args->f);
	if (args->d) {
		ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",<<=[1],", args->f);
	} else {
		ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],<<,wreg,=,",
		    args->f);
	}
	e ("$z,z,:=,");
}

INST_HANDLER (LSRF) {
	op->type = R_ANAL_OP_TYPE_SHR;
	ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],&,c,=,", args->f);
	if (args->d) {
		ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",>>=[1],", args->f);
	} else {
		ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,wreg,=,",
		    args->f);
	}
	e ("$z,z,:=,");
}

INST_HANDLER (ASRF) {
	op->type = R_ANAL_OP_TYPE_SHR;
	ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],&,c,=,", args->f);
	ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,", args->f);
	ef ("0x80," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],&,", args->f);
	if (args->d) {
		ef ("|," PIC_MIDRANGE_ESIL_BSR_ADDR ",=[1],", args->f);
	} else {
		e ("|,wreg,=,");
	}
	e ("$z,z,:=,");
}

INST_HANDLER (RRF) {
	op->type = R_ANAL_OP_TYPE_ROR;
	ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],&,", args->f);
	if (args->d) {
		ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",>>=[1],"
		    "c," PIC_MIDRANGE_ESIL_BSR_ADDR ",|=[1],",
		    args->f, args->f);
	} else {
		ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,wreg,=,"
		    "c,wreg,|=[1],",
		    args->f);
	}
	e ("c,=,");
}

INST_HANDLER (RLF) {
	op->type = R_ANAL_OP_TYPE_ROL;
	ef ("7," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],>>,", args->f);
	if (args->d) {
		ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",<<=[1],"
		    "c," PIC_MIDRANGE_ESIL_BSR_ADDR ",|=[1],",
		    args->f, args->f);
	} else {
		ef ("1," PIC_MIDRANGE_ESIL_BSR_ADDR ",[1],<<,wreg,=,"
		    "c,wreg,|=[1],",
		    args->f);
	}
	e ("c,=,");
}

INST_HANDLER (COMF) {
	if (args->d) {
		ef ("0xff," PIC_MIDRANGE_ESIL_BSR_ADDR ",^=[1],", args->f);
	} else {
		ef ("0xff," PIC_MIDRANGE_ESIL_BSR_ADDR ",^,wreg,=,", args->f);
	}
	e ("$z,z,:=,");
}

INST_HANDLER (RESET) {
	op->type = R_ANAL_OP_TYPE_JMP;
	op->jump = 0;
	e ("0x0,pc,=,");
	e ("0x1f,stkptr,=,");
}

INST_HANDLER (ADDFSR) {
	op->type = R_ANAL_OP_TYPE_ADD;
	if (args->n == 0) {
		ef ("0x%x,fsr0l,+=,", args->k);
		e ("7,$c,?{,0x01,fsr0h,+=,},");
	} else {
		ef ("0x%x,fsr1l,+=,", args->k);
		e ("7,$c,?{,0x01,fsr1h,+=,},");
	}
}

INST_HANDLER (CLRWDT) {
	e ("1,to,=,");
	e ("1,pd,=,");
}

INST_HANDLER (SLEEP) {
	e ("1,to,=,");
	e ("0,pd,=,");
}

INST_HANDLER (SUBWFB) {
	op->type = R_ANAL_OP_TYPE_SUB;
	e ("c,!=,");
	if (args->d) {
		ef (PIC_MIDRANGE_ESIL_FWF_OP_C (-), args->f);
	} else {
		ef (PIC_MIDRANGE_ESIL_WWF_OP_C (-), args->f);
		e ("wreg,0x00,-,wreg,=,c,!=,dc,!=,");
	}
}

INST_HANDLER (ADDWFC) {
	op->type = R_ANAL_OP_TYPE_ADD;
	if (args->d) {
		ef (PIC_MIDRANGE_ESIL_FWF_OP_C (+), args->f);
	} else {
		ef (PIC_MIDRANGE_ESIL_WWF_OP_C (+), args->f);
	}
}

INST_HANDLER (MOVIW_1) {
	if (args->n == 0) {
		if (!(args->m & 2)) {
			ef ("1,fsr0l,%s=,", (args->m & 1) ? "-" : "+");
			ef ("7,$c%s,fsr0h,%s,", (args->m & 1) ? ",!" : "",
			    (args->m & 1) ? "-" : "+");
		}
		e ("indf0,wreg,=,");
		e ("$z,z,:=,");
		if (args->m & 2) {
			ef ("1,fsr0l,%s=,", (args->m & 1) ? "-" : "+");
			ef ("7,$c%s,fsr0h,%s,", (args->m & 1) ? ",!" : "",
			    (args->m & 1) ? "-" : "+");
		}
	} else {
		if (!(args->m & 2)) {
			ef ("1,fsr1l,%s=,", (args->m & 1) ? "-" : "+");
			ef ("7,$c%s,fsr1h,%s,", (args->m & 1) ? ",!" : "",
			    (args->m & 1) ? "-" : "+");
		}
		e ("indf1,wreg,=,");
		e ("$z,z,:=,");
		if (args->m & 2) {
			ef ("1,fsr1l,%s=,", (args->m & 1) ? "-" : "+");
			ef ("7,$c%s,fsr1h,%s,", (args->m & 1) ? ",!" : "",
			    (args->m & 1) ? "-" : "+");
		}
	}
}

INST_HANDLER (MOVWI_1) {
	if (args->n == 0) {
		if (!(args->m & 2)) {
			ef ("1,fsr0l,%s=,", (args->m & 1) ? "-" : "+");
			ef ("$c7%s,fsr0h,%s,", (args->m & 1) ? ",!" : "",
			    (args->m & 1) ? "-" : "+");
		}
		e ("wreg,indf0=,");
		e ("$z,z,:=,");
		if (args->m & 2) {
			ef ("1,fsr0l,%s=,", (args->m & 1) ? "-" : "+");
			ef ("$c7%s,fsr0h,%s,", (args->m & 1) ? ",!" : "",
			    (args->m & 1) ? "-" : "+");
		}
	} else {
		if (!(args->m & 2)) {
			ef ("1,fsr1l,%s=,", (args->m & 1) ? "-" : "+");
			ef ("$c7,fsr1h,%s,", (args->m & 1) ? ",!" : "");
		}
		e ("wreg,indf1=,");
		e ("$z,z,:=,");
		if (args->m & 2) {
			ef ("1,fsr1l,%s=,", (args->m & 1) ? "-" : "+");
			ef ("$c7%s,fsr1h,%s,", (args->m & 1) ? ",!" : "",
			    (args->m & 1) ? "-" : "+");
		}
	}
}

INST_HANDLER (MOVIW_2) {
	if (args->n == 0) {
		e ("fsr0l,8,fsr0h,<<,+,");
	} else {
		e ("fsr1l,8,fsr1h,<<,+,");
	}
	ef ("0x%x,+,[1],wreg,=,", args->k);
}

INST_HANDLER (MOVWI_2) {
	e ("wreg,");
	if (args->n == 0) {
		e ("fsr0l,8,fsr0h,<<,+,");
	} else {
		e ("fsr1l,8,fsr1h,<<,+,");
	}
	e ("=[1],");
}

#define PIC_MIDRANGE_OPINFO_LEN 52
static const PicMidrangeOpAnalInfo pic_midrange_op_anal_info[PIC_MIDRANGE_OPINFO_LEN] = {
	INST_DECL (NOP, NONE),      INST_DECL (RETURN, NONE),
	INST_DECL (RETFIE, NONE),   INST_DECL (OPTION, NONE),
	INST_DECL (SLEEP, NONE),    INST_DECL (CLRWDT, NONE),
	INST_DECL (TRIS, 2F),       INST_DECL (MOVWF, 7F),
	INST_DECL (CLR, 1D_7F),     INST_DECL (SUBWF, 1D_7F),
	INST_DECL (DECF, 1D_7F),    INST_DECL (IORWF, 1D_7F),
	INST_DECL (ANDWF, 1D_7F),   INST_DECL (XORWF, 1D_7F),
	INST_DECL (ADDWF, 1D_7F),   INST_DECL (MOVF, 1D_7F),
	INST_DECL (COMF, 1D_7F),    INST_DECL (INCF, 1D_7F),
	INST_DECL (DECFSZ, 1D_7F),  INST_DECL (RRF, 1D_7F),
	INST_DECL (RLF, 1D_7F),     INST_DECL (SWAPF, 1D_7F),
	INST_DECL (INCFSZ, 1D_7F),  INST_DECL (BCF, 3B_7F),
	INST_DECL (BSF, 3B_7F),     INST_DECL (BTFSC, 3B_7F),
	INST_DECL (BTFSS, 3B_7F),   INST_DECL (CALL, 11K),
	INST_DECL (GOTO, 11K),      INST_DECL (MOVLW, 8K),
	INST_DECL (RETLW, 8K),      INST_DECL (IORLW, 8K),
	INST_DECL (ANDLW, 8K),      INST_DECL (XORLW, 8K),
	INST_DECL (SUBLW, 8K),      INST_DECL (ADDLW, 8K),
	INST_DECL (RESET, NONE),    INST_DECL (CALLW, NONE),
	INST_DECL (BRW, NONE),      INST_DECL (MOVIW_1, 1N_2M),
	INST_DECL (MOVWI_1, 1N_2M), INST_DECL (MOVLB, 4K),
	INST_DECL (LSLF, 1D_7F),    INST_DECL (LSRF, 1D_7F),
	INST_DECL (ASRF, 1D_7F),    INST_DECL (SUBWFB, 1D_7F),
	INST_DECL (ADDWFC, 1D_7F),  INST_DECL (ADDFSR, 1N_6K),
	INST_DECL (MOVLP, 7F),      INST_DECL (BRA, 9K),
	INST_DECL (MOVIW_2, 1N_6K), INST_DECL (MOVWI_2, 1N_6K)
};

static void anal_pic_midrange_extract_args (ut16 instr,
					    PicMidrangeOpArgs args,
					    PicMidrangeOpArgsVal *args_val) {

	memset (args_val, 0, sizeof (PicMidrangeOpArgsVal));

	switch (args) {
	case PIC_MIDRANGE_OP_ARGS_NONE: return;
	case PIC_MIDRANGE_OP_ARGS_2F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_2F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_7F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_7F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_1D_7F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_1D_7F_MASK_F;
		args_val->d =
			(instr & PIC_MIDRANGE_OP_ARGS_1D_7F_MASK_D) >> 7;
		return;
	case PIC_MIDRANGE_OP_ARGS_1N_6K:
		args_val->n =
			(instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_N) >> 6;
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_3B_7F:
		args_val->b =
			(instr & PIC_MIDRANGE_OP_ARGS_3B_7F_MASK_B) >> 7;
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_3B_7F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_4K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_4K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_8K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_8K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_9K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_9K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_11K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_11K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_1N_2M:
		args_val->n =
			(instr & PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_N) >> 2;
		args_val->m = instr & PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_M;
		return;
	}
}

static RIODesc *mem_sram = 0;
static RIODesc *mem_stack = 0;

static RIODesc *cpu_memory_map (RIOBind *iob, RIODesc *desc, ut32 addr,
				ut32 size) {
	char *mstr = r_str_newf ("malloc://%d", size);
	if (desc && iob->fd_get_name (iob->io, desc->fd)) {
		iob->fd_remap (iob->io, desc->fd, addr);
	} else {
		desc = iob->open_at (iob->io, mstr, R_PERM_RW, 0, addr);
	}
	free (mstr);
	return desc;
}

static bool pic_midrange_reg_write (RReg *reg, const char *regname, ut32 num) {
	if (reg) {
		RRegItem *item = r_reg_get (reg, regname, R_REG_TYPE_GPR);
		if (item) {
			r_reg_set_value (reg, item, num);
			return true;
		}
	}
	return false;
}

static void anal_pic_midrange_malloc (RAnal *anal, bool force) {
	static bool init_done = false;

	if (!init_done || force) {
		// Allocate memory as needed.
		// We assume that code is already allocated with firmware
		// image
		mem_sram =
			cpu_memory_map (&anal->iob, mem_sram,
					PIC_MIDRANGE_ESIL_SRAM_START, 0x1000);
		mem_stack =
			cpu_memory_map (&anal->iob, mem_stack,
					PIC_MIDRANGE_ESIL_CSTACK_TOP, 0x20);

		pic_midrange_reg_write (anal->reg, "_sram",
					PIC_MIDRANGE_ESIL_SRAM_START);
		pic_midrange_reg_write (anal->reg, "_stack",
					PIC_MIDRANGE_ESIL_CSTACK_TOP);
		pic_midrange_reg_write (anal->reg, "stkptr", 0x1f);

		init_done = true;
	}
}

static int anal_pic_midrange_op (RAnal *anal, RAnalOp *op, ut64 addr,
				 const ut8 *buf, int len) {

	ut16 instr;
	int i;

	anal_pic_midrange_malloc (anal, false);

	if (!buf || len < 2) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return op->size;
	}

	instr = r_read_le16 (buf);

	// Default op params
	op->size = 2;
	op->cycles = 1;
	op->type = R_ANAL_OP_TYPE_NOP;

	PicMidrangeOpcode opcode = pic_midrange_get_opcode (instr);
	PicMidrangeOpArgsVal args_val;

	for (i = 0; i < PIC_MIDRANGE_OPINFO_LEN; i++) {
		if (pic_midrange_op_anal_info[i].opcode == opcode) {
			anal_pic_midrange_extract_args (
				instr, pic_midrange_op_anal_info[i].args,
				&args_val);
			pic_midrange_op_anal_info[i].handler (anal, op, addr,
							      &args_val);
			break;
		}
	}

	return op->size;
}

static void pic18_cond_branch (RAnalOp *op, ut64 addr, const ut8 *buf, char *flag) {
	op->type = R_ANAL_OP_TYPE_CJMP;
	op->jump = addr + 2 + 2 * (*(ut16 *)buf & 0xff);
	op->fail = addr + op->size;
	op->cycles = 2;
	r_strbuf_setf (&op->esil, "%s,?,{,0x%" PFMT64x ",pc,=,}", flag, op->jump);
}

static int anal_pic_pic18_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	//TODO code should be refactored and broken into smaller chunks!!
	//TODO complete the esil emitter
	if (len < 2) {
		op->size = len;
		goto beach; //pancake style :P
	}
	op->size = 2;
	ut16 b = *(ut16 *)buf;
	ut32 dword_instr = 0;
	memcpy (&dword_instr, buf, R_MIN (sizeof (dword_instr), len));
	switch (b >> 9) {
	case 0x76: //call
		if (len < 4) {
			goto beach;
		}
		if (dword_instr >> 28 != 0xf) {
			goto beach;
		}
		op->size = 4;
		op->type = R_ANAL_OP_TYPE_CALL;
		return op->size;
	};
	switch (b >> 11) { //NEX_T
	case 0x1b:	//rcall
		op->type = R_ANAL_OP_TYPE_CALL;
		return op->size;
	case 0x1a: //bra
		op->type = R_ANAL_OP_TYPE_JMP;
		op->cycles = 2;
		op->jump = addr + 2 + 2 * (*(ut16 *)buf & 0x7ff);
		r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", op->jump);
		return op->size;
	}
	switch (b >> 12) { //NOP,movff,BAF_T
	case 0xf:	//nop
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, ",");
		return op->size;
	case 0xc: //movff
		if (len < 4) {
			goto beach;
		}
		if (dword_instr >> 28 != 0xf) {
			goto beach;
		}
		op->size = 4;
		op->type = R_ANAL_OP_TYPE_MOV;
		return op->size;
	case 0xb: //btfsc
	case 0xa: //btfss
		op->type = R_ANAL_OP_TYPE_CJMP;
		return op->size;
	case 0x9: //bcf
	case 0x8: //bsf
	case 0x7: //btg
		op->type = R_ANAL_OP_TYPE_UNK;
		return op->size;
	};

	switch (b >> 8) { //GOTO_T,N_T,K_T
	case 0xe0:	//bz
		pic18_cond_branch (op, addr, buf, "z");
		return op->size;
	case 0xe1: //bnz
		pic18_cond_branch (op, addr, buf, "z,!");
		return op->size;
	case 0xe3: //bnc
		pic18_cond_branch (op, addr, buf, "c,!");
		return op->size;
	case 0xe4: //bov
		pic18_cond_branch (op, addr, buf, "ov");
		return op->size;
	case 0xe5: //bnov
		pic18_cond_branch (op, addr, buf, "ov,!");
		return op->size;
	case 0xe6: //bn
		pic18_cond_branch (op, addr, buf, "n");
		return op->size;
	case 0xe7: //bnn
		pic18_cond_branch (op, addr, buf, "n,!");
		return op->size;
	case 0xe2: //bc
		pic18_cond_branch (op, addr, buf, "c");
		return op->size;
	case 0xef: //goto
		if (len < 4) {
			goto beach;
		}
		if (dword_instr >> 28 != 0xf) {
			goto beach;
		}
		op->size = 4;
		op->cycles = 2;
		op->jump = ((dword_instr & 0xff) | ((dword_instr & 0xfff0000) >> 8)) * 2;
		r_strbuf_setf (&op->esil, "0x%" PFMT64x ",pc,=", op->jump);
		op->type = R_ANAL_OP_TYPE_JMP;
		return op->size;
	case 0xf: //addlw
		op->type = R_ANAL_OP_TYPE_ADD;
		op->cycles = 1;
		//TODO add support for dc flag
		r_strbuf_setf (&op->esil, "0x%x,wreg,+=,$z,z,:=,7,$s,n,:=,7,$c,c,:=,7,$o,ov,:=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0xe: //movlw
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,wreg,=,", *(ut16* )buf & 0xff);
		return op->size;
	case 0xd: //mullw
		op->type = R_ANAL_OP_TYPE_MUL;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,wreg,*,prod,=", *(ut16 *)buf & 0xff);
		return op->size;
	case 0xc: //retlw
		op->type = R_ANAL_OP_TYPE_RET;
		op->cycles = 2;
		r_strbuf_setf (&op->esil, "0x%x,wreg,=,tos,pc,=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0xb: //andlw
		op->type = R_ANAL_OP_TYPE_AND;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,wreg,&=,$z,z,:=,7,$s,n,:=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0xa: //xorlw
		op->type = R_ANAL_OP_TYPE_XOR;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,wreg,^=,$z,z,:=,7,$s,n,:=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0x9: //iorlw
		op->type = R_ANAL_OP_TYPE_OR;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,wreg,^=,$z,z,:=,7,$s,n,:=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0x8: //sublw
		op->type = R_ANAL_OP_TYPE_SUB;
		op->cycles = 1;
		//TODO add support for dc flag
		r_strbuf_setf (&op->esil, "wreg,0x%x,-,wreg,=,$z,z,:=,7,$s,n,:=,7,$c,c,:=,7,$o,ov,:=,", *(ut16 *)buf & 0xff);
		return op->size;
	};

	switch (b >> 6) { //LFSR
	case 0x3b8:       //lfsr
		if (len < 4) {
			goto beach;
		}
		if (dword_instr >> 28 != 0xf) {
			goto beach;
		}
		op->size = 4;
		op->type = R_ANAL_OP_TYPE_LOAD;
		return op->size;
	};
	switch (b >> 10) { //DAF_T
	case 0x17:	//subwf
	case 0x16:	//subwfb
	case 0x15:	//subfwb
	case 0x13:	//dcfsnz
	case 0xb:	//decfsz
	case 0x1:	//decf
		op->type = R_ANAL_OP_TYPE_SUB;
		return op->size;
	case 0x14: //movf
		op->type = R_ANAL_OP_TYPE_MOV;
		return op->size;
	case 0x12: //infsnz
	case 0xf:  //incfsz
	case 0xa:  //incf
	case 0x8:  //addwfc
		op->type = R_ANAL_OP_TYPE_ADD;
		return op->size;
	case 0x9: //addwf
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ADD;
		return op->size;
	case 0x11: //rlncf
	case 0xd:  //rlcf
		op->type = R_ANAL_OP_TYPE_ROL;
		return op->size;
	case 0x10: //rrncf
	case 0xc:  //rrcf
		op->type = R_ANAL_OP_TYPE_ROR;
		return op->size;
	case 0xe: //swapf
		op->type = R_ANAL_OP_TYPE_UNK;
		return op->size;
	case 0x7: //comf
		op->type = R_ANAL_OP_TYPE_CPL;
		return op->size;
	case 0x6: //xorwf
		op->type = R_ANAL_OP_TYPE_XOR;
		return op->size;
	case 0x5: //andwf
		op->type = R_ANAL_OP_TYPE_AND;
		return op->size;
	case 0x4: //iorwf
		op->type = R_ANAL_OP_TYPE_OR;
		return op->size;
	};
	switch (b >> 9) { //AF_T
	case 0x37:	//movwf
		op->type = R_ANAL_OP_TYPE_STORE;
		return op->size;
	case 0x36: //negf
	case 0x35: //clrf
	case 0x34: //setf
		op->type = R_ANAL_OP_TYPE_UNK;
		return op->size;
	case 0x33: //tstfsz
		op->type = R_ANAL_OP_TYPE_CJMP;
		return op->size;
	case 0x32: //cpfsgt
	case 0x31: //cpfseq
	case 0x30: //cpfslt
		op->type = R_ANAL_OP_TYPE_CMP;
		return op->size;
	case 0x1: //mulwf
		op->type = R_ANAL_OP_TYPE_MUL;
		return op->size;
	};
	switch (b >> 4) {
	case 0x10: //movlb
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,bsr,=,", *(ut16 *)buf & 0xf);
		return op->size;
	};
	switch (b) {
	case 0xff: //reset
	case 0x7:  //daw
	case 0x4:  //clwdt
	case 0x3:  //sleep
		op->type = R_ANAL_OP_TYPE_UNK;
		return op->size;
	case 0x13: //return
		op->type = R_ANAL_OP_TYPE_RET;
		op->cycles = 2;
		r_strbuf_setf (&op->esil, "tos,pc,=,");
		return op->size;
	case 0x12: //return
		op->type = R_ANAL_OP_TYPE_RET;
		op->cycles = 2;
		r_strbuf_setf (&op->esil, "tos,pc,=");
		return op->size;
	case 0x11: //retfie
	case 0x10: //retfie
		op->type = R_ANAL_OP_TYPE_RET;
		return op->size;
	case 0xf: //tblwt
	case 0xe: //tblwt
	case 0xd: //tblwt
	case 0xc: //tblwt
		op->type = R_ANAL_OP_TYPE_LOAD;
		return op->size;
	case 0xb: //tblrd
	case 0xa: //tblrd
	case 0x9: //tblrd
	case 0x8: //tblrd
		op->type = R_ANAL_OP_TYPE_STORE;
		return op->size;
	case 0x6: //pop
		op->type = R_ANAL_OP_TYPE_POP;
		return op->size;
	case 0x5: //push
		op->type = R_ANAL_OP_TYPE_PUSH;
		return op->size;
	case 0x0: //nop
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, ",");
		return op->size;
	};
beach:
	op->type = R_ANAL_OP_TYPE_ILL;
	return op->size;
}

static bool anal_pic_midrange_set_reg_profile (RAnal *esil) {
	const char *p = \
		"=PC	pc\n"
		"=SP	stkptr\n"
		"=A0	porta\n"
		"=A1	portb\n"
		"gpr	indf0	.8	0	0\n"
		"gpr	indf1	.8	1	0\n"
		"gpr	pcl		.8	2	0\n"
		"gpr	status	.8	3	0\n"
		"flg	c		.1	3.0	0\n"
		"flg	dc		.1	3.1	0\n"
		"flg	z		.1	3.2	0\n"
		"flg	pd		.1	3.3	0\n"
		"flg	to		.1	3.4	0\n"
		"gpr	fsr0l	.8	4	0\n"
		"gpr	fsr0h	.8	5	0\n"
		"gpr	fsr1l	.8	6	0\n"
		"gpr	fsr1h	.8	7	0\n"
		"gpr	bsr		.8	8	0\n"
		"gpr	wreg	.8	9	0\n"
		"gpr	pclath	.8	10	0\n"
		"gpr	intcon	.8	11	0\n"
		"gpr	pc		.16	12	0\n"
		"gpr	stkptr	.8	14	0\n"
		"gpr	_sram	.32 15	0\n"
		"gpr	_stack	.32 19	0\n";
	return r_reg_set_profile_string (esil->reg, p);
}

static bool anal_pic_pic18_set_reg_profile(RAnal *esil) {
	const char *p =
		"#pc lives in nowhere actually"
		"=PC	pc\n"
		"=SP	tos\n"
		"=A0	porta\n"
		"=A1	portb\n"
		"gpr	pc	.32	0	0\n"
		"gpr	pcl	.8	0	0\n"
		"gpr	pclath	.8	1	0\n"
		"gpr	pclatu	.8	2	0\n"
		"#bsr max is 0b111\n"
		"gpr	bsr	.8	4	0\n"
		"#tos doesn't exist\n"
		"#general rule of thumb any register of size >8 bits has no existence\n"
		"gpr	tos	.32	5	0\n"
		"gpr	tosl	.8	5	0\n"
		"gpr	tosh	.8	6	0\n"
		"gpr	tosu	.8	7	0\n"

		"gpr	indf0	.16	9	0\n"
		"gpr	fsr0	.12	9	0\n"
		"gpr	fsr0l	.8	9	0\n"
		"gpr	fsr0h	.8	10	0\n"
		"gpr	indf1	.16	11	0\n"
		"gpr	fsr1	.12	11	0\n"
		"gpr	fsr1l	.8	11	0\n"
		"gpr	fsr1h	.8	12	0\n"
		"gpr	indf2	.16	13	0\n"
		"gpr	fsr2	.12	13	0\n"
		"gpr	frs2l	.8	13	0\n"
		"gpr	fsr2h	.8	14	0\n"
		"gpr	tblptr	.22	15	0\n"
		"gpr	tblptrl	.8	15	0\n"
		"gpr	tblptrh	.8	16	0\n"
		"gpr	tblptru	.8	17	0\n"
		"gpr	rcon	.8	18	0\n"
		"gpr	memcon	.8	19	0\n"
		"gpr	intcon	.8	20	0\n"
		"gpr	intcon2	.8	21	0\n"
		"gpr	intcon3	.8	22	0\n"
		"gpr	pie1	.8	23	0\n"
		"gpr	porta	.7	29	0\n"
		"gpr	trisa	.8	30	0\n"
		"gpr	portb	.8	33	0\n"
		"gpr	tisb	.8	34	0\n"
		"gpr	latb	.8	35	0\n"
		"gpr	portc	.8	36	0\n"
		"gpr	trisc	.8	37	0\n"
		"gpr	latc	.8	38	0\n"
		"gpr	portd	.8	39	0\n"
		"gpr	trisd	.8	40	0\n"
		"gpr	latd	.8	41	0\n"
		"gpr	pspcon	.8	42	0\n"
		"gpr	porte	.8	43	0\n"
		"gpr	trise	.8	44	0\n"
		"gpr	late	.8	45	0\n"
		"gpr	t0con	.8	46	0\n"
		"gpr	t1con	.8	47	0\n"
		"gpr	t2con	.8	48	0\n"
		"gpr	tmr1h	.8	50	0\n"
		"gpr	tmr0h	.8	51	0\n"
		"gpr	tmr1l	.8	52	0\n"
		"gpr	tmr2	.8	53	0\n"
		"gpr	pr2	.8	54	0\n"
		"gpr	ccpr1h	.8	55	0\n"
		"gpr	postinc2 .8	56	0\n"
		"gpr	ccpr1l	.8	57	0\n"
		"gpr	postdec2 .8	58	0\n"
		"gpr	ccp1con	.8	59	0\n"
		"gpr	preinc2	.8	60	0\n"
		"gpr	ccpr2h	.8	61	0\n"
		"gpr	plusw2	.8	62	0\n"
		"gpr	ccpr2l	.8	63	0\n"
		"gpr	ccp2con	.8	64	0\n"
		"gpr	status	.8	65	0\n"
		"flg	c	.1	.520	0\n"
		"flg	dc	.1	.521	0\n"
		"flg	z	.1	.522	0\n"
		"flg	ov	.1	.523	0\n"
		"flg	n	.1	.524	0\n"
		"gpr	prod	.16	66	0\n"
		"gpr	prodl	.8	66	0\n"
		"gpr	prodh	.8	67	0\n"
		"gpr	osccon	.8	68	0\n"
		"gpr	tmr3h	.8	69	0\n"
		"gpr	lvdcon	.8	70	0\n"
		"gpr	tmr3l	.8	71	0\n"
		"gpr	wdtcon	.8	72	0\n"
		"gpr	t3con	.8	73	0\n"
		"gpr	spbrg	.8	74	0\n"
		"gpr	postinc0 .8	75	0\n"
		"gpr	rcreg	.8	76	0\n"
		"gpr	postdec0 .8	77	0\n"
		"gpr	txreg	.8	78	0\n"
		"gpr	preinc0	.8	79	0\n"
		"gpr	txsta	.8	80	0\n"
		"gpr	plusw0	.8	81	0\n"
		"gpr	rcsta	.8	82	0\n"
		"gpr	sspbuf	.8	83	0\n"
		"gpr	wreg	.8	84	0\n"
		"gpr	sspadd	.8	85	0\n"
		"gpr	sspstat	.8	86	0\n"
		"gpr	postinc1 .8	87	0\n"
		"gpr	sspcon1	.8	88	0\n"
		"gpr	postdec1 .8	89	0\n"
		"gpr	sspcon2	.8	90	0\n"
		"gpr	preinc1	.8	91	0\n"
		"gpr	adresh	.8	92	0\n"
		"gpr	plusw1	.8	93	0\n"
		"gpr	adresl	.8	94	0\n"
		"gpr	adcon0	.8	95	0\n"
		"#stkprt max is 0b11111\n"
		"gpr	stkptr	.8	96	0\n"
		"gpr	tablat	.8	14	0\n";

	return r_reg_set_profile_string (esil->reg, p);
}


static int anal_pic_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	if (anal->cpu && strcasecmp (anal->cpu, "baseline") == 0) {
		// TODO: implement
		return -1;
	}
	if (anal->cpu && strcasecmp (anal->cpu, "midrange") == 0) {
		return anal_pic_midrange_op (anal, op, addr, buf, len);
	}
	if (anal->cpu && strcasecmp (anal->cpu, "pic18") == 0) {
		return anal_pic_pic18_op (anal, op, addr, buf, len);
	}
	return -1;
}

static bool anal_pic_set_reg_profile(RAnal *anal) {
	if (anal->cpu && strcasecmp (anal->cpu, "baseline") == 0) {
		// TODO: We are using the midrange profile as the baseline
		return anal_pic_midrange_set_reg_profile (anal);
	}
	if (anal->cpu && strcasecmp (anal->cpu, "midrange") == 0) {
		return anal_pic_midrange_set_reg_profile (anal);
	}
	if (anal->cpu && strcasecmp (anal->cpu, "pic18") == 0) {
		return anal_pic_pic18_set_reg_profile (anal);
	}
	return false;
}

RAnalPlugin r_anal_plugin_pic = {
	.name = "pic",
	.desc = "PIC analysis plugin",
	.license = "LGPL3",
	.arch = "pic",
	.bits = 8,
	.op = &anal_pic_op,
	.set_reg_profile = &anal_pic_set_reg_profile,
	.esil = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_pic,
	.version = R2_VERSION
};
#endif
