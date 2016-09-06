/* radare - LGPL - Copyright 2015-2016 - oddcoder */
#include <r_asm.h>
#include <r_lib.h>
//PIC18CXXX instruction set

//instruction classification according to the argument types
#define NO_ARG 0
#define DAF_T 1
#define F32_T 2
#define BAF_T 3
#define K_T 4
#define N_T 5
#define CALL_T 6
#define NEX_T 7
#define AF_T 8
#define GOTO_T 9
#define SHK_T 10
#define S_T 11
#define LFSR_T 12

static char *fsr[] = {"fsr0", "fsr1", "fsr2", "reserved"};

static struct {
	ut16 opmin;
	ut16 opmax;
	char *name;
	ut8 optype;
	//and some magical hocus pocus ;)
} ops[] = {
	{0xf000, 0xffff, "nop", NO_ARG},
	{0xef00, 0xefff, "goto", GOTO_T},
	{0xee00, 0xee3f, "lfsr", LFSR_T},
	{0xec00, 0xedff, "call", CALL_T},
	{0xe700, 0xe7ff, "bnn", N_T},
	{0xe600, 0xe6ff, "bn", N_T},
	{0xe500, 0xe5ff, "bnov", N_T},
	{0xe400, 0xe4ff, "bov", N_T},
	{0xe300, 0xe3ff, "bnc", N_T},
	{0xe200, 0xe2ff, "bc", N_T},
	{0xe100, 0xe1ff, "bnz", N_T},
	{0xe000, 0xe0ff, "bz", N_T},
	{0xd800, 0xdfff, "rcall", NEX_T},
	{0xd000, 0xd7ff, "bra", NEX_T},
	{0xc000, 0xcfff, "movff", F32_T},
	{0xb000, 0xbfff, "btfsc", BAF_T},
	{0xa000, 0xafff, "btfss", BAF_T},
	{0x9000, 0x9fff, "bcf", BAF_T},
	{0x8000, 0x8fff, "bsf", BAF_T},
	{0x7000, 0x7fff, "btg", BAF_T},
	{0x6e00, 0x6fff, "movwf", AF_T},
	{0x6c00, 0x6dff, "negf", AF_T},
	{0x6a00, 0x6bff, "clrf", AF_T},
	{0x6800, 0x69ff, "setf", AF_T},
	{0x6600, 0x67ff, "tstfsz", AF_T},
	{0x6400, 0x65ff, "cpfsgt", AF_T},
	{0x6200, 0x63ff, "cpfseq", AF_T},
	{0x6000, 0x61ff, "cpfslt", AF_T},
	{0x5c00, 0x5fff, "subwf", DAF_T},
	{0x5800, 0x5bff, "subwfb", DAF_T},
	{0x5400, 0x57ff, "subfwb", DAF_T},
	{0x5000, 0x53ff, "movf", DAF_T},
	{0x4c00, 0x4fff, "dcfsnz", DAF_T},
	{0x4800, 0x4bff, "infsnz", DAF_T},
	{0x4400, 0x47ff, "rlncf", DAF_T},
	{0x4000, 0x43ff, "rrncf", DAF_T},
	{0x3c00, 0x3fff, "incfsz", DAF_T},
	{0x3800, 0x3bff, "swapf", DAF_T},
	{0x3400, 0x37ff, "rlcf", DAF_T},
	{0x3000, 0x33ff, "rrcf", DAF_T},
	{0x2c00, 0x2fff, "decfsz", DAF_T},
	{0x2800, 0x2bff, "incf", DAF_T},
	{0x2400, 0x27ff, "addwf", DAF_T},
	{0x2000, 0x23ff, "addwfc", DAF_T},
	{0x1c00, 0x1fff, "comf", DAF_T},
	{0x1800, 0x1bff, "xorwf", DAF_T},
	{0x1400, 0x17ff, "andwf", DAF_T},
	{0x1000, 0x13ff, "iorwf", DAF_T},
	{0xf00, 0xfff, "addlw", K_T},
	{0xe00, 0xeff, "movlw", K_T},
	{0xd00, 0xdff, "mullw", K_T},
	{0xc00, 0xcff, "retlw", K_T},
	{0xb00, 0xbff, "andlw", K_T},
	{0xa00, 0xaff, "xorlw", K_T},
	{0x900, 0x9ff, "iorlw", K_T},
	{0x800, 0x8ff, "sublw", K_T},
	{0x400, 0x7ff, "decf", DAF_T},
	{0x200, 0x3ff, "mulwf", AF_T},
	{0x100, 0x10f, "movlb", SHK_T},
	{0xff, 0xff, "reset", NO_ARG},
	{0x12, 0x13, "return", S_T},
	{0x10, 0x11, "retfie", S_T},
	{0xf, 0xf, "tblwt+*", NO_ARG},
	{0xe, 0xe, "tblwt*-", NO_ARG},
	{0xd, 0xd, "tblwt*+", NO_ARG},
	{0xc, 0xc, "tblwt*", NO_ARG},
	{0xb, 0xb, "tblrd+*", NO_ARG},
	{0xa, 0xa, "tblrd*-", NO_ARG},
	{0x9, 0x9, "tblrd*+", NO_ARG},
	{0x8, 0x8, "tblrd*", NO_ARG},
	{0x7, 0x7, "daw", NO_ARG},
	{0x6, 0x6, "pop", NO_ARG},
	{0x5, 0x5, "push", NO_ARG},
	{0x4, 0x4, "clrwdt", NO_ARG},
	{0x3, 0x3, "sleep", NO_ARG},
	{0x0, 0x0, "nop", NO_ARG},
	{0x0, 0xffff, "invalid", NO_ARG},
};

static int pic_disassem(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	int i;
	if(l<2){//well noone loves reading bitstream of size zero or 1 !!
		strncpy (op->buf_asm,"invalid", R_ASM_BUFSIZE);
		op->size = l;
		return -1;

	}
	ut16 instr = *(ut16 *)b; //instruction
	// if still redundan code is reported think of this of instr=0x2
	for (i = 0;ops[i].opmin != (ops[i].opmin & instr) || ops[i].opmax != (ops[i].opmax | instr); i++);
	if (ops[i].opmin == 0 && ops[i].opmax==0xffff) {
		strncpy (op->buf_asm, ops[i].name, R_ASM_BUFSIZE);
		op->size = 2;
		return -1;
	}
	op->size = 2;
	switch (ops[i].optype) {
	case NO_ARG:
		strncpy (op->buf_asm, ops[i].name, R_ASM_BUFSIZE);
		return 2;
	case N_T:
	case K_T:
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x",
			ops[i].name, instr & 0xff);
		break;
	case DAF_T:
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x, %d, %d",
			ops[i].name, instr & 0xff, (instr >> 9) & 1, (instr >> 8) & 1);
		break;
	case AF_T:
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x, %d", ops[i].name,
			instr & 0xff, (instr >> 8) & 1);
		break;

	case BAF_T:
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x, %d, %d", ops[i].name,
			instr & 0xff, (instr >> 9) & 0x7, (instr >> 8) & 0x1);
		break;
	case NEX_T:
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x",
			ops[i].name, instr & 0x7ff);
		break;
	case CALL_T: {
		if (l < 4) {
			strcpy (op->buf_asm, "invalid");
			return -1;
		}
		op->size = 4;
		ut32 dword_instr = *(ut32 *)b;
		//I dont even know how the bits are arranged but it works !!!
		//`the wierdness of little endianess`
		if (dword_instr >> 28 != 0xf) {
			strcpy (op->buf_asm, "invalid");
			return -1;
		}
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x, %d", ops[i].name,
			(dword_instr & 0xff) |
				(dword_instr >> 8 & 0xfff00),
			(dword_instr >> 8) & 0x1);
		break;
	}
	case GOTO_T: {
		if (l < 4) {
			strcpy (op->buf_asm, "invalid");
			return -1;
		}
		op->size = 4;
		ut32 dword_instr = *(ut32 *)b;
		if (dword_instr >> 28 != 0xf) {
			strcpy (op->buf_asm, "invalid");
			return -1;
		}
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x", ops[i].name,
			((dword_instr & 0xff) | ((dword_instr &  0xfff0000) >>8) )*2);
		break;
	}
	case F32_T: {
		if (l < 4) {
			strcpy (op->buf_asm, "invalid");
			return -1;
		}
		op->size = 4;
		ut32 dword_instr = *(ut32 *)b;
		if (dword_instr >> 28 != 0xf) {
			strcpy (op->buf_asm, "invalid");
			return -1;
		}
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x, 0x%x", ops[i].name,
			dword_instr & 0xfff,
			(dword_instr >> 16) & 0xfff);
		break;
	}
	case SHK_T:
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s 0x%x",
			ops[i].name, instr & 0xf);
		break;
	case S_T:
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %d",
			ops[i].name, instr & 0x1);
		break;
	case LFSR_T: {
		op->size = 4;
		ut32 dword_instr = *(ut32 *)b;
		if (dword_instr >> 28 != 0xf) {
			strcpy (op->buf_asm, "invalid");
			return -1;
		}
		ut8 reg_n = (dword_instr >> 4) & 0x3;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %s, %d", ops[i].name,
			fsr[reg_n], (dword_instr & 0xf) << 8 |
					((dword_instr >> 16) & 0xff));
		break;
	}
	default:
		sprintf (op->buf_asm, "unknown args");
	};
	return op->size;
}

RAsmPlugin r_asm_plugin_pic18c = {
	.disassemble = pic_disassem,
	.name = "pic18c",
	.arch = "pic18c",
	.license = "LGPL3",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "pic18c disassembler"
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pic18c
};
#endif
