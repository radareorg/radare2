/* radare - LGPL - Copyright 2011-2015 - pancake, Roc Valles */

#if 0
http://www.atmel.com/images/atmel-0856-avr-instruction-set-manual.pdf
https://en.wikipedia.org/wiki/Atmel_AVR_instruction_set
#endif

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define	AVR_SOFTCAST(x,y)	(x+(y*0x100))

static int avr_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	short ofst;
	ut8 kbuf[2];
	ut16 ins = AVR_SOFTCAST(buf[0],buf[1]);

	if (op == NULL)
		return 2;
	op->size = 2;
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_UNK;
	if (ins == 0) {
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
	}
	if ((buf[1] & 0xec) == 12) {		//ADD + ADC
		op->type = R_ANAL_OP_TYPE_ADD;
		op->cycles = 1;
	}
	if ((buf[1] & 0xec) == 8) {		//SUB + SBC
		op->type = R_ANAL_OP_TYPE_SUB;
		op->cycles = 1;
	}
	if (((buf[0] & 0xf) == 7) && ((buf[1] & 0xfe) == 0x94)) {
		op->type = R_ANAL_OP_TYPE_ROR;
		op->cycles = 1;
	}
	if (buf[1] == 1) {			//MOVW
		op->type = R_ANAL_OP_TYPE_MOV;
		op->cycles = 1;
	}
	if ((buf[1] & 0xf0) == 0xe0) {		//LDI
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->cycles = 1;
	}
	if ((buf[1] & 0xec) == 4) {		//CP + CPC
		op->type = R_ANAL_OP_TYPE_CMP;
		op->cycles = 1;
	}
	switch (buf[1] & 0xfc) {
		case 0x10:			//CPSE
			op->type = R_ANAL_OP_TYPE_CMP;
			op->type2 = R_ANAL_OP_TYPE_CJMP;
			op->failcycles = 1;	//TODO Cycles
			break;
		case 0x20:			//TST
			op->type = R_ANAL_OP_TYPE_ACMP;
			op->cycles = 1;
			break;
		case 0x24:			//EOR
			op->type = R_ANAL_OP_TYPE_XOR;
			op->cycles = 1;
			break;
		case 0x28:			//OR
			op->type = R_ANAL_OP_TYPE_OR;
			op->cycles = 1;
			break;
		case 0x2c:			//MOV
			op->type = R_ANAL_OP_TYPE_MOV;
			op->cycles = 1;
			break;
	}
	switch (buf[1]) {
		case 0x96:			//ADIW
			op->type = R_ANAL_OP_TYPE_ADD;
			op->cycles = 2;
			break;
		case 0x97:			//SBIW
			op->type = R_ANAL_OP_TYPE_SUB;
			op->cycles = 2;
			break;
		case 0x98:			//SBI
		case 0x9a:			//CBI
			op->type = R_ANAL_OP_TYPE_IO;
			op->cycles = 2;		//1 for atTiny
			break;
		case 0x99:			//SBIC
		case 0x9b:			//SBIS
			op->type = R_ANAL_OP_TYPE_CMP;
			op->type2 = R_ANAL_OP_TYPE_CJMP;
			op->failcycles = 1;
			break;
	}
	if (!memcmp (buf, "\x0e\x94", 2)) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_CALL; // call (absolute)
		op->fail = (op->addr)+4;
// override even if len<4 wtf
		len = 4;
		if (len>3) {
			memcpy (kbuf, buf+2, 2);
			op->size = 4;
			//anal->iob.read_at (anal->iob.io, addr+2, kbuf, 2);
			op->jump = AVR_SOFTCAST(kbuf[0],kbuf[1])*2;
		} else {
			op->size = 0;
			return -1;
			return op->size;		//WTF
		}
		//eprintf("addr: %x inst: %x dest: %x fail:%x\n", op->addr, *ins, op->jump, op->fail);
	}
	if ((buf[1] & 0xf0) == 0xd0) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_CALL; // rcall (relative)
		op->fail = (op->addr)+2;
		ofst = ins<<4;
		ofst>>=4;
		ofst*=2;
		op->jump = addr+ofst+2;
		//eprintf("addr: %x inst: %x ofst: %d dest: %x fail:%x\n", op->addr, *ins, ofst, op->jump, op->fail);
	}
	if (((buf[1] & 0xfe) == 0x94) && ((buf[0] & 0x0e)==0x0c)) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_CJMP; // breq, jmp (absolute)
		op->fail = (op->addr)+4;
		anal->iob.read_at (anal->iob.io, addr+2, kbuf, 2);
		// TODO: check return value
		op->jump = AVR_SOFTCAST(kbuf[0],kbuf[1])*2;
		//eprintf("addr: %x inst: %x dest: %x fail:%x\n", op->addr, *ins, op->jump, op->fail);
	}
	if ((buf[1] & 0xf0) == 0xc0) { // rjmp (relative)
		op->addr=addr;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->fail = (op->addr)+2;
		ofst = ins<<4;
		ofst>>=4;
		ofst*=2;
		op->jump = addr+ofst+2;
		//eprintf("addr: %x inst: %x ofst: %d dest: %x fail:%x\n", op->addr, *ins, ofst, op->jump, op->fail);
	}
	if (ins == 0x9508 || ins == 0x9518) { // ret || reti
		op->type = R_ANAL_OP_TYPE_RET;
		op->cycles = 4;			//5 for 22-bit bus
		op->eob = true;
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	char *p =
		"=pc	PC\n"
		"=sp	SP\n"
// explained in http://www.nongnu.org/avr-libc/user-manual/FAQ.html
// and http://www.avrfreaks.net/forum/function-calling-convention-gcc-generated-assembly-file
		"=a0	r25\n"
		"=a1	r24\n"
		"=a2	r23\n"
		"=a3	r22\n"
		"=r0	r24\n"
#if 0
PC: 16- or 22-bit program counter
SP: 8- or 16-bit stack pointer
SREG: 8-bit status register
RAMPX, RAMPY, RAMPZ, RAMPD and EIND:
#endif

// 8bit registers x 32
		"gpr	r0	.8	0	0\n"
		"gpr	r1	.8	1	0\n"
		"gpr	r2	.8	2	0\n"
		"gpr	r3	.8	3	0\n"
		"gpr	r4	.8	4	0\n"
		"gpr	r5	.8	5	0\n"
		"gpr	r6	.8	6	0\n"
		"gpr	r7	.8	7	0\n"
		"gpr	r8	.8	8	0\n"
		"gpr	r9	.8	9	0\n"
		"gpr	r10	.8	10	0\n"
		"gpr	r11	.8	11	0\n"
		"gpr	r12	.8	12	0\n"
		"gpr	r13	.8	13	0\n"
		"gpr	r14	.8	14	0\n"
		"gpr	r15	.8	15	0\n"
		"gpr	r16	.8	16	0\n"
		"gpr	r17	.8	17	0\n"
		"gpr	r18	.8	18	0\n"
		"gpr	r19	.8	19	0\n"
		"gpr	r20	.8	20	0\n"
		"gpr	r21	.8	21	0\n"
		"gpr	r22	.8	22	0\n"
		"gpr	r23	.8	23	0\n"
		"gpr	r24	.8	24	0\n"
		"gpr	r25	.8	25	0\n"
		"gpr	r26	.8	26	0\n"
		"gpr	r27	.8	27	0\n"
		"gpr	r28	.8	28	0\n"
		"gpr	r29	.8	29	0\n"
		"gpr	r30	.8	30	0\n"
		"gpr	r31	.8	31	0\n"

// 16 bit overlapped registers for memory addressing
		"gpr	X	.16	26	0\n"
		"gpr	Y	.16	28	0\n"
		"gpr	Z	.16	30	0\n"
// special purpose registers
		"gpr	PC	.16	32	0\n"
		"gpr	SP	.16	34	0\n"
		"gpr	SREG	.8	36	0\n"
// 8bit segment registers to be added to X, Y, Z to get 24bit offsets
		"gpr	RAMPX	.8	37	0\n"
		"gpr	RAMPY	.8	38	0\n"
		"gpr	RAMPZ	.8	39	0\n"
		"gpr	RAMPD	.8	40	0\n"
		"gpr	EIND	.8	41	0\n"
// status bit register stored in SREG
#if 0
C Carry flag. This is a borrow flag on subtracts.
Z Zero flag. Set to 1 when an arithmetic result is zero.
N Negative flag. Set to a copy of the most significant bit of an arithmetic result.
V Overflow flag. Set in case of two's complement overflow.
S Sign flag. Unique to AVR, this is always N⊕V, and shows the true sign of a comparison.
H Half carry. This is an internal carry from additions and is used to support BCD arithmetic.
T Bit copy. Special bit load and bit store instructions use this bit.
I Interrupt flag. Set when interrupts are enabled.
#endif
		"gpr	CF	.1	288	0\n" // 288 = (offsetof(SREG))*8= 36 * 8
		"gpr	ZF	.1	289	0\n"
		"gpr	NF	.1	290	0\n"
		"gpr	VF	.1	291	0\n"
		"gpr	SF	.1	292	0\n"
		"gpr	HF	.1	293	0\n"
		"gpr	TF	.1	294	0\n"
		"gpr	IF	.1	295	0\n"
		;

	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_avr = {
	.name = "avr",
	.desc = "AVR code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_AVR,
	.bits = 8|16, // 24 big regs conflicts
	.op = &avr_op,
	.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_avr,
	.version = R2_VERSION
};
#endif
