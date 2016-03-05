/* radare - LGPL - Copyright 2015 - oddcoder */
#include <r_types.h>
#include <r_anal.h>
#include <r_asm.h>
#include <r_lib.h>
static int pic18c_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len){
	if(len<2){
		op->size=len;
		goto beach; //pancake style :P
	}
	op->size=2;
	ut16 b = *(ut16*) buf;
	switch (b>>9){
	case 0x76://call
		if(len<4)
			goto beach;
		if(*(ut32*)buf>>28!=0xf)
			goto beach;
		op->size=4;
		op->type=R_ANAL_OP_TYPE_CALL;
		return op->size;

	};
	switch(b>>11){//NEX_T
	case 0x1b://rcall
		op->type=R_ANAL_OP_TYPE_CALL;
		return op->size;
	case 0x1a:
		op->type= R_ANAL_OP_TYPE_JMP;
		return op->size;
	}
	switch(b>>12){//NOP,movff,BAF_T
	case 0xf://nop
		op->type=R_ANAL_OP_TYPE_NOP;
		return op->size;
	case 0xc://movff
		if(len<4)
			goto beach;
		if(*(ut32*)buf>>28!=0xf)
			goto beach;
		op->size=4;
		op->type=R_ANAL_OP_TYPE_MOV;
		return op->size;
	case 0xb: //btfsc
	case 0xa: //btfss
		op->type=R_ANAL_OP_TYPE_CJMP;
		return op->size;
	case 0x9: //bcf
	case 0x8: //bsf
	case 0x7: //btg
		op->type=R_ANAL_OP_TYPE_UNK;
		return op->size;
	};

	switch(b>>8){//GOTO_T,N_T,K_T
	case 0xe0://bz
	case 0xe1://bnz
	case 0xe2://bc
	case 0xe3://bnc
	case 0xe4://bov
	case 0xe5://bnov
	case 0xe6://bn
	case 0xe7://bnn
		op->type=R_ANAL_OP_TYPE_CJMP;
		return op->size;
	case 0xef://goto
		if(len<4)
			goto beach;
		if(*(ut32*)buf>>28!=0xf)
			goto beach;
		op->size=4;
		op->type=R_ANAL_OP_TYPE_JMP;
		return op->size;
	case 0xf://addlw
		op->type=R_ANAL_OP_TYPE_ADD;
		return op->size;
	case 0xe://movlw
		op->type=R_ANAL_OP_TYPE_LOAD;
		return op->size;
	case 0xd://mullw
		op->type=R_ANAL_OP_TYPE_MUL;
		return op->size;
	case 0xc://retlw
		op->type=R_ANAL_OP_TYPE_RET;
		return op->size;
	case 0xb://andlw
		op->type=R_ANAL_OP_TYPE_AND;
		return op->size;
	case 0xa://xorlw
		op->type=R_ANAL_OP_TYPE_XOR;
		return op->size;
	case 0x9://iorlw
		op->type=R_ANAL_OP_TYPE_OR;
		return op->size;
	case 0x8://sublw
		op->type=R_ANAL_OP_TYPE_SUB;
		return op->size;
	};

	switch(b>>6){//LFSR
	case 0x3b8://lfsr
		if(len<4)
			goto beach;
		if(*(ut32*)buf>>28!=0xf)
			goto beach;
		op->size=4;
		op->type=R_ANAL_OP_TYPE_LOAD;
		return op->size;

	};
	switch(b>>10){//DAF_T
	case 0x17://subwf
	case 0x16://subwfb
	case 0x15://subfwb
	case 0x13://dcfsnz
	case 0xb://decfsz
	case 0x1://decf
		op->type=R_ANAL_OP_TYPE_SUB;
		return op->size;
	case 0x14://movf
		op->type=R_ANAL_OP_TYPE_MOV;
		return op->size;
	case 0x12://infsnz
	case 0xf://incfsz
	case 0xa://incf
	case 0x9://addwf
	case 0x8://addwfc
		op->type=R_ANAL_OP_TYPE_ADD;
		return op->size;
	case 0x11://rlncf
	case 0xd://rlcf
		op->type=R_ANAL_OP_TYPE_ROL;
		return op->size;
	case 0x10://rrncf
	case 0xc://rrcf
		op->type=R_ANAL_OP_TYPE_ROR;
		return op->size;
	case 0xe://swapf
		op->type=R_ANAL_OP_TYPE_UNK;
		return op->size;
	case 0x7://comf
		op->type=R_ANAL_OP_TYPE_CPL;
		return op->size;
	case 0x6://xorwf
		op->type=R_ANAL_OP_TYPE_XOR;
		return op->size;
	case 0x5://andwf
		op->type=R_ANAL_OP_TYPE_AND;
		return op->size;
	case 0x4://iorwf
		op->type=R_ANAL_OP_TYPE_OR;
		return op->size;
	};
	switch(b>>9){//AF_T
	case 0x37://movwf
		op->type=R_ANAL_OP_TYPE_STORE;
		return op->size;
	case 0x36://negf
	case 0x35://clrf
	case 0x34://setf
		op->type=R_ANAL_OP_TYPE_UNK;
		return op->size;
	case 0x33://tstfsz
		op->type=R_ANAL_OP_TYPE_CJMP;
		return op->size;
	case 0x32://cpfsgt
	case 0x31://cpfseq
	case 0x30://cpfslt
		op->type=R_ANAL_OP_TYPE_CMP;
		return op->size;
	case 0x1://mulwf
		op->type= R_ANAL_OP_TYPE_MUL;
		return op->size;
	};
	switch(b>>4){
	case 0x10://movlb
		op->type=R_ANAL_OP_TYPE_LOAD;
		return op->size;
	};
	switch(b){
	case 0xff://reset
	case 0x7://daw
	case 0x4://clwdt
	case 0x3://sleep
		op->type=R_ANAL_OP_TYPE_UNK;
		return op->size;
	case 0x13://return
	case 0x12://return
	case 0x11://retfie
	case 0x10://retfie
		op->type=R_ANAL_OP_TYPE_RET;
		return op->size;
	case 0xf://tblwt
	case 0xe://tblwt
	case 0xd://tblwt
	case 0xc://tblwt
		op->type=R_ANAL_OP_TYPE_LOAD;
		return op->size;
	case 0xb://tblrd
	case 0xa://tblrd
	case 0x9://tblrd
	case 0x8://tblrd
		op->type=R_ANAL_OP_TYPE_STORE;
		return op->size;
	case 0x6://pop
		op->type=R_ANAL_OP_TYPE_POP;
		return op->size;
	case 0x5://push
		op->type=R_ANAL_OP_TYPE_PUSH;
		return op->size;
	case 0x0://nop
		op->type=R_ANAL_OP_TYPE_NOP;
		return op->size;

	};
beach:	op->type = R_ANAL_OP_TYPE_ILL;
	return op->size;
}
struct r_anal_plugin_t r_anal_plugin_pic18c = {
    .name = "pic18c",
    .desc = "PIC 18c analysis plugin",
    .license = "LGPL3",
    .arch = "PIC 18c",
    .bits = 16,
    .init = NULL,
    .fini = NULL,
    .op = &pic18c_anal,
    .set_reg_profile = NULL,
    .fingerprint_bb = NULL,
    .fingerprint_fcn = NULL,
    .diff_bb = NULL,
    .diff_fcn = NULL,
    .diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_pic18c,
    .version = R2_VERSION
};
#endif
