/* radare - LGPL - Copyright 2015-2016 - oddcoder */

#include <r_types.h>
#include <r_anal.h>
#include <r_asm.h>
#include <r_lib.h>

void cond_branch (RAnalOp *op, ut64 addr, const ut8 *buf, char *flag) {
	op->type = R_ANAL_OP_TYPE_CJMP;
	op->jump = addr + 2 + 2 * (*(ut16 *)buf & 0xff);
	op->fail = addr + op->size;
	op->cycles = 2;
	r_strbuf_setf (&op->esil, "%s,?,{,0x%x,pc,=,}", flag, op->jump);
}
static int pic18c_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	//TODO code should be refactored and brocken into smaller chuncks!!
	//TODO complete the esil emitter
	if (len < 2) {
		op->size = len;
		goto beach; //pancake style :P
	}
	op->size = 2;
	ut16 b = *(ut16 *)buf;
	switch (b >> 9) {
	case 0x76: //call
		if (len < 4)
			goto beach;
		if (*(ut32 *)buf >> 28 != 0xf)
			goto beach;
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
		r_strbuf_setf (&op->esil, "0x%x,pc,=", op->jump);
		return op->size;
	}
	switch (b >> 12) { //NOP,movff,BAF_T
	case 0xf:	//nop
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, ",");
		return op->size;
	case 0xc: //movff
		if (len < 4)
			goto beach;
		if (*(ut32 *)buf >> 28 != 0xf)
			goto beach;
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
		cond_branch (op, addr, buf, "z");
		return op->size;
	case 0xe1: //bnz
		cond_branch (op, addr, buf, "z,!");
		return op->size;
	case 0xe3: //bnc
		cond_branch (op, addr, buf, "c,!");
		return op->size;
	case 0xe4: //bov
		cond_branch (op, addr, buf, "ov");
		return op->size;
	case 0xe5: //bnov
		cond_branch (op, addr, buf, "ov,!");
		return op->size;
	case 0xe6: //bn
		cond_branch (op, addr, buf, "n");
		return op->size;
	case 0xe7: //bnn
		cond_branch (op, addr, buf, "n,!");
		return op->size;
	case 0xe2: //bc
		cond_branch (op, addr, buf, "c");
		return op->size;
	case 0xef: //goto
		if (len < 4)
			goto beach;
		if (*(ut32 *)buf >> 28 != 0xf)
			goto beach;
		op->size = 4;
		op->cycles = 2;
		ut32 dword_instr = *(ut32 *)buf;
		op->jump = ((dword_instr & 0xff) | ((dword_instr & 0xfff0000) >> 8)) * 2;
		r_strbuf_setf (&op->esil, "0x%x,pc,=", op->jump);
		op->type = R_ANAL_OP_TYPE_JMP;
		return op->size;
	case 0xf: //addlw
		op->type = R_ANAL_OP_TYPE_ADD;
		op->cycles = 1;
		//TODO add support for dc flag
		r_strbuf_setf (&op->esil, "0x%x,wreg,+=,$z,z,=,$s,n,=,$c,c,=,$o,ov,=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0xe: //movlw
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,wreg,=,");
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
		r_strbuf_setf (&op->esil, "0x%x,wreg,&=,$z,z,=,$s,n,=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0xa: //xorlw
		op->type = R_ANAL_OP_TYPE_XOR;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,wreg,^=,$z,z,=,$s,n,=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0x9: //iorlw
		op->type = R_ANAL_OP_TYPE_OR;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,wreg,^=,$z,z,=,$s,n,=,", *(ut16 *)buf & 0xff);
		return op->size;
	case 0x8: //sublw
		op->type = R_ANAL_OP_TYPE_SUB;
		op->cycles = 1;
		//TODO add support for dc flag
		r_strbuf_setf (&op->esil, "wreg,0x%x,-,wreg,=,$z,z,=,$s,n,=,$c,c,=,$o,ov,=,", *(ut16 *)buf & 0xff);
		return op->size;
	};

	switch (b >> 6) { //LFSR
	case 0x3b8:       //lfsr
		if (len < 4)
			goto beach;
		if (*(ut32 *)buf >> 28 != 0xf)
			goto beach;
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
static int set_reg_profile(RAnal *esil) {
	const char *p;
	p =
		"#pc lives in nowhere actually"
		"=PC	pc\n"
		"=SP	tos\n"
		"gpr	pc	.32	0	0\n"
		"gpr	pcl	.8	0	0\n"
		"gpr	pclath	.8	1	0\n"
		"gpr	pclatu	.8	2	0\n"
		"#bsr max is 0b111\n"
		"gpr	bsr	.8	4	0\n"
		"#tos doesn't exist\n"
		"#general rule of thumb any register of size >8 bits has no existance\n"
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
struct r_anal_plugin_t r_anal_plugin_pic18c = {
	.name = "pic18c",
	.desc = "PIC 18c analysis plugin",
	.license = "LGPL3",
	.arch = "PIC 18c",
	.bits = 8,
	.op = &pic18c_anal,
	.set_reg_profile = &set_reg_profile,
	.esil = true };

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_pic18c,
	.version = R2_VERSION };
#endif
