/* radare - LGPL - Copyright 2011-2016 - pancake, Roc Valles, condret, killabyte */

#if 0
http://www.atmel.com/images/atmel-0856-avr-instruction-set-manual.pdf
https://en.wikipedia.org/wiki/Atmel_AVR_instruction_set
#endif

#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

// hack to get avr disasm in anal, this must be fixed by merging both worlds
#include "../asm/arch/avr/disasm.c"

#define	AVR_SOFTCAST(x,y) (x+(y*0x100))

typedef struct _cpu_models_tag_ {
	const char *const model;
	int pc_bits;
	int pc_mask;
	int pc_size;
	int eeprom_size;
	int io_size;
} CPU_MODEL;

typedef void (*inst_handler_t) (RAnal *anal, RAnalOp *op, const ut8 *buf, int *fail, CPU_MODEL *cpu);

typedef struct _opcodes_tag_ {
	const char *const name;
	int mask;
	int selector;
	inst_handler_t handler;
	int cycles;
	int size;
	ut64 type;
} OPCODE_DESC;

static int avr_op_analyze(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, CPU_MODEL *cpu);

#define CPU_MODEL_DECL(model, pc_bits, eeprom_sz, io_sz)		\
	{								\
		model,							\
		(pc_bits),						\
		~(~((unsigned int) 0) << (pc_bits)),			\
		((pc_bits) >> 3) + (((pc_bits) & 0x07) ? 1 : 0),	\
		eeprom_sz,						\
		io_sz							\
	}

#define INST_HANDLER(OPCODE_NAME)	static void _inst__ ## OPCODE_NAME (RAnal *anal, RAnalOp *op, const ut8 *buf, int *fail, CPU_MODEL *cpu)
#define INST_DECL(OP, M, SL, C, SZ, T)	{ #OP, (M), (SL), _inst__ ## OP, (C), (SZ), R_ANAL_OP_TYPE_ ## T }
#define INST_LAST			{ "unknown", 0, 0, (void *) 0, 2, 1, R_ANAL_OP_TYPE_UNK      }

#define INST_CALL(OPCODE_NAME)		_inst__ ## OPCODE_NAME (anal, op, buf, fail, cpu)
#define INST_INVALID			{ *fail = 1; return; }
#define INST_ASSERT(x)			{ if (!(x)) { INST_INVALID; } }

#define ESIL_A(e, ...)			r_strbuf_appendf (&op->esil, e, ##__VA_ARGS__)

#define STR_BEGINS(in, s)		strncasecmp (in, s, strlen (s))

CPU_MODEL cpu_models[] = {
	CPU_MODEL_DECL ("ATmega48",    11, 512, 512),
	CPU_MODEL_DECL ("ATmega8",     12, 512, 512),
	CPU_MODEL_DECL ("ATmega88",    12, 512, 512),
	CPU_MODEL_DECL ("ATmega168",   13, 512, 512),
	CPU_MODEL_DECL ("ATmega640",   16, 512, 512),
	CPU_MODEL_DECL ("ATmega1280",  16, 512, 512),
	CPU_MODEL_DECL ("ATmega1281",  16, 512, 512),
	CPU_MODEL_DECL ("ATmega2560",  22, 512, 512),
	CPU_MODEL_DECL ("ATmega2561",  22, 512, 512),
	CPU_MODEL_DECL ("unknown_avr", 12, 512, 512)
};

RStrBuf *__generic_io_dest(ut8 port, int write) {
	RStrBuf *r = r_strbuf_new ("");

	switch (port) {
	case 0x3f: /* SREG */ r_strbuf_set (r, "sreg"); break;
	case 0x3e: /* SPH  */ r_strbuf_set (r, "sph");  break;
	case 0x3d: /* SPL  */ r_strbuf_set (r, "spl");  break;
	default:
		r_strbuf_setf (r, "_io,%d,+,%s[1]", port, write ? "=" : "");
	}

	return r;
}

void __generic_bitop_flags(RAnalOp *op) {
	ESIL_A ("0,vf,=,");					// V
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("vf,nf,^,sf,=,");				// S
}

void __generic_ld_st(RAnalOp *op, char *mem, char ireg, int use_ramp, int prepostdec, int offset, int st) {
	if (ireg) {
		// preincrement index register
		if (prepostdec < 0) {
			ESIL_A ("1,%c,-,%c,=,", ireg, ireg);
		}
		// set register index address
		ESIL_A ("%c,", ireg);
		// add offset
		if (offset != 0) {
			ESIL_A ("%d,+,", offset);
		}
	} else {
		ESIL_A ("%d,", offset);
	}
	if (use_ramp) {
		ESIL_A ("16,ramp%c,<<,+,", ireg ? ireg : 'd');
	}
	// set SRAM base address
	ESIL_A ("_%s,+,", mem);
	// read/write from SRAM
	ESIL_A ("%s[1],", st ? "=" : "");
	// postincrement index register
	if (ireg && prepostdec > 0) {
		ESIL_A ("1,%c,+,%c,=,", ireg, ireg);
	}
}

void __generic_pop(RAnalOp *op, int sz) {
	if (sz > 1) {
		ESIL_A ("1,sp,+,_sram,+,");	// calc SRAM(sp+1)
		ESIL_A ("[%d],", sz);		// read value
		ESIL_A ("%d,sp,+=,", sz);	// sp += item_size
	} else {
		ESIL_A ("1,sp,+=,"		// increment stack pointer
			"sp,_sram,+,[1],");	// load SRAM[sp]
	}
}

void __generic_push(RAnalOp *op, int sz) {
	ESIL_A ("sp,_sram,+,");			// calc pointer SRAM(sp)
	if (sz > 1) {
		ESIL_A ("-%d,+,", sz - 1);	// dec SP by 'sz'
	}
	ESIL_A ("=[%d],", sz);			// store value in stack
	ESIL_A ("-%d,sp,+=,", sz);		// decrement stack pointer
}

INST_HANDLER (adc) {	// ADC Rd, Rr
			// ROL Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A ("r%d,cf,+,r%d,+,", r, d);			// Rd + Rr + C
								// FLAGS:
	ESIL_A ("r%d,0x08,&,!,!," "r%d,0x08,&,!,!,"     "&,"	// H
		"r%d,0x08,&,!,!," "0,RPICK,0x08,&,!,"   "&,"
		"r%d,0x08,&,!,!," "0,RPICK,0x08,&,!,"   "&,"
		"|,|,hf,=,",
		d, r, r, d);
	ESIL_A ("r%d,0x80,&,!,!," "r%d,0x80,&,!,!,"     "&,"	// V
		""                "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,"   "r%d,0x80,&,!,"       "&,"
		""                "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, r, d, r);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("r%d,0x80,&,!,!," "r%d,0x80,&,!,!,"     "&," 	// C
		"r%d,0x80,&,!,!," "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,!," "0,RPICK,0x80,&,!,"   "&,"
		"|,|,cf,=,",
		d, r, r, d);
	ESIL_A ("vf,nf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = result
}

INST_HANDLER (add) {	// ADD Rd, Rr
			// LSL Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A ("r%d,r%d,+,", r, d);				// Rd + Rr
								// FLAGS:
	ESIL_A ("r%d,0x08,&,!,!," "r%d,0x08,&,!,!,"     "&,"	// H
		"r%d,0x08,&,!,!," "0,RPICK,0x08,&,!,"   "&,"
		"r%d,0x08,&,!,!," "0,RPICK,0x08,&,!,"   "&,"
		"|,|,hf,=,",
		d, r, r, d);
	ESIL_A ("r%d,0x80,&,!,!," "r%d,0x80,&,!,!,"     "&,"	// V
		""                "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,"   "r%d,0x80,&,!,"       "&,"
		""                "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, r, d, r);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("r%d,0x80,&,!,!," "r%d,0x80,&,!,!,"     "&," 	// C
		"r%d,0x80,&,!,!," "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,!," "0,RPICK,0x80,&,!,"   "&,"
		"|,|,cf,=,",
		d, r, r, d);
	ESIL_A ("vf,nf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = result
}

INST_HANDLER (adiw) {	// ADIW Rd+1:Rd, K
	int d = ((buf[0] & 0x30) >> 3) + 24;
	int k = (buf[0] & 0xf) | ((buf[0] >> 2) & 0x30);
	ESIL_A ("r%d:r%d,%d,+,", d + 1, d, k);			// Rd+1:Rd + Rr
								// FLAGS:
	ESIL_A ("r%d,0x80,&,!,"					// V
		"0,RPICK,0x8000,&,!,!,"
		"&,vf,=,", d + 1);
	ESIL_A ("0,RPICK,0x8000,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("r%d,0x80,&,!,!,"				// C
		"0,RPICK,0x8000,&,!,"
		"&,cf,=,", d + 1);
	ESIL_A ("vf,nf,^,sf,=,");				// S
	ESIL_A ("r%d:r%d,=,", d + 1, d);			// Rd = result
}

INST_HANDLER (and) {	// AND Rd, Rr
			// TST Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A ("r%d,r%d,&,", r, d);				// 0: Rd & Rr
	__generic_bitop_flags (op);				// up flags
	ESIL_A ("r%d,=,", d);					// Rd = Result
}

INST_HANDLER (andi) {	// ANDI Rd, K
			// CBR Rd, K (= ANDI Rd, 1-K)
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = (buf[1] & 0xf0) | (buf[0] & 0x0f);
	ESIL_A ("%d,r%d,&,", k, d);				// 0: Rd & Rr
	__generic_bitop_flags (op);				// up flags
	ESIL_A ("r%d,=,", d);					// Rd = Result
}

INST_HANDLER (asr) {	// ASR Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	ESIL_A ("1,r%d,>>,r%d,0x80,&,|,", d, d);		// 0: R=(Rd >> 1) | Rd7
	ESIL_A ("r%d,0x1,&,!,!,cf,=,", d);			// C = Rd0
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("nf,cf,^,vf,=,");				// V
	ESIL_A ("nf,vf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = R
}

INST_HANDLER (bclr) {	// BCLR s
			// CLC
			// CLH
			// CLI
			// CLN
			// CLR
			// CLS
			// CLT
			// CLV
			// CLZ
	int s = (buf[0] >> 4) & 0x7;
	ESIL_A ("0xff,%d,1,<<,^,sreg,&=,", s);
}

INST_HANDLER (bld) {	// BLD Rd, b
	int d = ((buf[1] & 0x01) << 4) | ((buf[0] >> 4) & 0xf);
	int b = buf[0] & 0x7;
	ESIL_A ("r%d,%d,1,<<,0xff,^,&,", d, b);			// Rd/b = 0
	ESIL_A ("%d,tf,<<,|,r%d,=,", b, d);			// Rd/b |= T<<b
}

INST_HANDLER (brbx) {	// BRBC s, k
			// BRBS s, k
			// BRBC/S 0:		BRCC		BRCS
			//			BRSH		BRLO
			// BRBC/S 1:		BREQ		BRNE
			// BRBC/S 2:		BRPL		BRMI
			// BRBC/S 3:		BRVC		BRVS
			// BRBC/S 4:		BRGE		BRLT
			// BRBC/S 5:		BRHC		BRHS
			// BRBC/S 6:		BRTC		BRTS
			// BRBC/S 7:		BRID		BRIE
	int s = buf[0] & 0x7;
	op->jump = op->addr
		+ ((((buf[1] & 0x03) << 6) | ((buf[0] & 0xf8) >> 2))
			| (buf[1] & 0x2 ? ~((int) 0x7f) : 0))
		+ 2;
	op->cycles = 1;	// XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to true, this instruction
			// needs 2 cycles, elsewhere it needs only 1 cycle.
	ESIL_A ("%d,1,<<,sreg,&,", s);				// SREG(s)
	ESIL_A (buf[1] & 0x4
			? "!,"		// BRBC => branch if cleared
			: "!,!,");	// BRBS => branch if set
	ESIL_A ("?{,%"PFMT64d",pc,=,},", op->jump);	// ?true => jmp
}

INST_HANDLER (break) {	// BREAK
	ESIL_A ("BREAK");
}

INST_HANDLER (bset) {	// BSET s
			// SEC
			// SEH
			// SEI
			// SEN
			// SER
			// SES
			// SET
			// SEV
			// SEZ
	int s = (buf[0] >> 4) & 0x7;
	ESIL_A ("%d,1,<<,sreg,|=,", s);
}

INST_HANDLER (bst) {	// BST Rd, b
	ESIL_A ("r%d,%d,1,<<,&,!,!,tf,=,",			// tf = Rd/b
		((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf),	// r
		buf[0] & 0x7);					// b
}

INST_HANDLER (call) {	// CALL k
	op->jump = (buf[2] << 1)
		 | (buf[3] << 9)
		 | (buf[1] & 0x01) << 23
		 | (buf[0] & 0x01) << 17
		 | (buf[0] & 0xf0) << 14;
	op->cycles = cpu->pc_bits <= 16 ? 3 : 4;
	if (!STR_BEGINS (cpu->model, "ATxmega")) {
		op->cycles--;	// AT*mega optimizes one cycle
	}
	ESIL_A ("pc,");				// esil is already pointing to
						// next instruction (@ret)
	__generic_push (op, cpu->pc_size);	// push @ret in stack
	ESIL_A ("%"PFMT64d",pc,=,", op->jump);	// jump!
}

INST_HANDLER (cbi) {	// CBI A, b
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RStrBuf *io_port;

	op->family = R_ANAL_OP_FAMILY_IO;
	op->type2 = 1;
	op->val = a;

	// read port a and clear bit b
	io_port = __generic_io_dest (a, 0);
	ESIL_A ("0xff,%d,1,<<,^,%s,&,", b, io_port);
	r_strbuf_free (io_port);

	// write result to port a
	io_port = __generic_io_dest (a, 1);
	ESIL_A ("%s,=,", r_strbuf_get (io_port));
	r_strbuf_free (io_port);
}

INST_HANDLER (com) {	// COM Rd
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[0] & 1) << 4);

	ESIL_A ("r%d,0xff,^,1,+,0xff,&,r%d,=,", r, r);		// Rd = 0-Rd
								// FLAGS:
	ESIL_A ("0,cf,=,");					// C
	__generic_bitop_flags (op);				// ...rest...
}

INST_HANDLER (cp) {	// CP Rd, Rr
	int r = (buf[0]        & 0x0f) | ((buf[1] << 3) & 0x10);
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	ESIL_A ("r%d,r%d,-,", r, d);				// do Rd - Rr
								// FLAGS:
	ESIL_A ("r%d,0x08,&,!,"   "r%d,0x08,&,!,!,"     "&,"	// H
		"r%d,0x08,&,!,!," "0,RPICK,0x08,&,!,!," "&,"
		"r%d,0x08,&,!,"   "0,RPICK,0x08,&,!,!," "&,"
		"|,|,hf,=,",
		d, r, d, r);
	ESIL_A ("r%d,0x80,&,!,!," "r%d,0x80,&,!,"       "&,"	// V
		""                "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,"   "r%d,0x80,&,!,!,"     "&,"
		""                "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, r, d, r);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("r%d,0x80,&,!,"   "r%d,0x80,&,!,!,"     "&," 	// C
		"r%d,0x80,&,!,!," "0,RPICK,0x80,&,!,!," "&,"
		"r%d,0x80,&,!,"   "0,RPICK,0x80,&,!,!," "&,"
		"|,|,cf,=,",
		d, r, d, r);
	ESIL_A ("vf,nf,^,sf,=,");				// S
}

INST_HANDLER (cpc) {	// CPC Rd, Rr
	int r = (buf[0]        & 0x0f) | ((buf[1] << 3) & 0x10);
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	ESIL_A ("cf,r%d,-,r%d,-,", r, d);			// Rd - Rr - C
								// FLAGS:
	ESIL_A ("r%d,0x08,&,!,"   "r%d,0x08,&,!,!,"     "&,"	// H
		"r%d,0x08,&,!,!," "0,RPICK,0x08,&,!,!," "&,"
		"r%d,0x08,&,!,"   "0,RPICK,0x08,&,!,!," "&,"
		"|,|,hf,=,",
		d, r, d, r);
	ESIL_A ("r%d,0x80,&,!,!," "r%d,0x80,&,!,"       "&,"	// V
		""                "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,"   "r%d,0x80,&,!,!,"     "&,"
		""                "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, r, d, r);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,&,zf,=,");			// Z
	ESIL_A ("r%d,0x80,&,!,"   "r%d,0x80,&,!,!,"     "&," 	// C
		"r%d,0x80,&,!,!," "0,RPICK,0x80,&,!,!," "&,"
		"r%d,0x80,&,!,"   "0,RPICK,0x80,&,!,!," "&,"
		"|,|,cf,=,",
		d, r, r, d);
	ESIL_A ("vf,nf,^,sf,=,");				// S
}

INST_HANDLER (cpi) { // CPI Rd, K
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = (buf[0] & 0xf) | ((buf[1] & 0xf) << 4);
	ESIL_A ("%d,r%d,-,", k, d);				// Rd - k
								// FLAGS:
	ESIL_A ("r%d,0x08,&,!,"   "%d,0x08,&,!,!,"     "&,"	// H
		"r%d,0x08,&,!,!," "0,RPICK,0x08,&,!,!," "&,"
		"%d,0x08,&,!,"   "0,RPICK,0x08,&,!,!," "&,"
		"|,|,hf,=,",
		d, k, d, k);
	ESIL_A ("r%d,0x80,&,!,!," "%d,0x80,&,!,"        "&,"	// V
		""                "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,"   "%d,0x80,&,!,!,"      "&,"
		""                "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, k, d, k);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("r%d,0x80,&,!,"  "%d,0x80,&,!,!,"      "&," 	// C
		"%d,0x80,&,!,!," "0,RPICK,0x80,&,!,!," "&,"
		"r%d,0x80,&,!,"  "0,RPICK,0x80,&,!,!," "&,"
		"|,|,cf,=,",
		d, k, k, d);
	ESIL_A ("vf,nf,^,sf,=,");				// S
}

INST_HANDLER (cpse) {	// CPSE Rd, Rr
	int r = (buf[0] & 0xf) | ((buf[1] & 0x2) << 3);
	int d = ((buf[0] & 0xf) >> 4) | ((buf[1] & 0x1) << 4);
	RAnalOp next_op;

	// calculate next instruction size (call recursively avr_op_analyze)
	// and free next_op's esil string (we dont need it now)
	avr_op_analyze (anal,
			&next_op,
			op->addr + op->size, buf + op->size,
			cpu);
	r_strbuf_fini (&next_op.esil);
	op->jump = op->addr + next_op.size + 2;

	// cycles
	op->cycles = 1;	// XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to true, this instruction
			// needs 2/3 cycles, elsewhere it needs only 1 cycle.
	ESIL_A ("r%d,r%d,^,!,", r, d);			// Rr == Rd
	ESIL_A ("?{,%"PFMT64d",pc,=,},", op->jump);	// ?true => jmp
}

INST_HANDLER (dec) {	// DEC Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	ESIL_A ("-1,r%d,+,", d);				// --Rd
								// FLAGS:
	ESIL_A ("0,RPICK,0x7f,==,vf,=,");			// V
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("vf,nf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = Result
}

INST_HANDLER (des) {	// DES k
//if (d < 16) {	//DES
//	op->type = R_ANAL_OP_TYPE_CRYPTO;
//	op->cycles = 1;		//redo this
//	r_strbuf_setf (&op->esil, "%d,des", d);
//}
}

INST_HANDLER (eijmp) {	// EIJMP
	ut64 z, eind;
	// read z and eind for calculating jump address on runtime
	r_anal_esil_reg_read (anal->esil, "z",    &z,    NULL);
	r_anal_esil_reg_read (anal->esil, "eind", &eind, NULL);
	// real target address may change during execution, so this value will
	// be changing all the time
	op->jump = (eind << 16) + z;
	// jump
	ESIL_A ("z,16,eind,<<,+,pc,=,");
	// cycles
	op->cycles = 2;
}

INST_HANDLER (eicall) {	// EICALL
	// push pc in stack
	ESIL_A ("pc,");				// esil is already pointing to
						// next instruction (@ret)
	__generic_push (op, cpu->pc_size);	// push @ret in stack
	// do a standard EIJMP
	INST_CALL (eijmp);
	// fix cycles
	op->cycles = !STR_BEGINS (cpu->model, "ATxmega") ? 3 : 4;
}

INST_HANDLER (elpm) {	// ELPM
			// ELPM Rd
			// ELPM Rd, Z+
	int d = ((buf[1] & 0xfe) == 0x90)
			? ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf)	// Rd
			: 0;						// R0
	ESIL_A ("16,rampz,<<,z,+,_prog,+,[1],");	// read RAMPZ:Z
	ESIL_A ("r%d,=,", d);				// Rd = [1]
	if ((buf[1] & 0xfe) == 0x90 && (buf[0] & 0xf) == 0x7) {
		ESIL_A ("16,1,z,+,DUP,z,=,>>,1,&,rampz,+=,");	// ++(rampz:z)
	}
}

INST_HANDLER (eor) {	// EOR Rd, Rr
			// CLR Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A ("r%d,r%d,^,", r, d);			// 0: Rd ^ Rr
	__generic_bitop_flags (op);			// up flags
	ESIL_A ("r%d,=,", d);				// Rd = Result
}

INST_HANDLER (fmul) {	// FMUL Rd, Rr
	int d = ((buf[0] >> 4) & 0x7) + 16;
	int r = (buf[0] & 0x7) + 16;

	ESIL_A ("1,r%d,r%d,*,<<,", r, d);		// 0: (Rd*Rr)<<1
	ESIL_A ("0xffff,&,");				// prevent overflow
	ESIL_A ("DUP,0xff,&,r0,=,");			// r0 = LO(0)
	ESIL_A ("8,0,RPICK,>>,0xff,&,r1,=,");		// r1 = HI(0)
	ESIL_A ("DUP,0x8000,&,!,!,cf,=,");		// C = R/16
	ESIL_A ("DUP,!,zf,=,");				// Z = !R
}

INST_HANDLER (fmuls) {	// FMULS Rd, Rr
	int d = ((buf[0] >> 4) & 0x7) + 16;
	int r = (buf[0] & 0x7) + 16;

	ESIL_A ("1,");
	ESIL_A ("r%d,DUP,0x80,&,?{,0xffff00,|,},", d);	// sign extension Rd
	ESIL_A ("r%d,DUP,0x80,&,?{,0xffff00,|,},", r);	// sign extension Rr
	ESIL_A ("*,<<,", r, d);				// 0: (Rd*Rr)<<1

	ESIL_A ("0xffff,&,");				// prevent overflow
	ESIL_A ("DUP,0xff,&,r0,=,");			// r0 = LO(0)
	ESIL_A ("8,0,RPICK,>>,0xff,&,r1,=,");		// r1 = HI(0)
	ESIL_A ("DUP,0x8000,&,!,!,cf,=,");		// C = R/16
	ESIL_A ("DUP,!,zf,=,");				// Z = !R
}

INST_HANDLER (fmulsu) {	// FMULSU Rd, Rr
	int d = ((buf[0] >> 4) & 0x7) + 16;
	int r = (buf[0] & 0x7) + 16;

	ESIL_A ("1,");
	ESIL_A ("r%d,DUP,0x80,&,?{,0xffff00,|,},", d);	// sign extension Rd
	ESIL_A ("r%d", r);				// unsigned Rr
	ESIL_A ("*,<<,");				// 0: (Rd*Rr)<<1

	ESIL_A ("0xffff,&,");				// prevent overflow
	ESIL_A ("DUP,0xff,&,r0,=,");			// r0 = LO(0)
	ESIL_A ("8,0,RPICK,>>,0xff,&,r1,=,");		// r1 = HI(0)
	ESIL_A ("DUP,0x8000,&,!,!,cf,=,");		// C = R/16
	ESIL_A ("DUP,!,zf,=,");				// Z = !R
}

INST_HANDLER (icall) {	// ICALL k
	ut64 z;
	// read z for calculating jump address on runtime
	r_anal_esil_reg_read (anal->esil, "z", &z, NULL);
	// real target address may change during execution, so this value will
	// be changing all the time
	op->jump = z;
	op->cycles = cpu->pc_bits <= 16 ? 3 : 4;
	if (!STR_BEGINS (cpu->model, "ATxmega")) {
		// AT*mega optimizes 1 cycle!
		op->cycles--;
	}
	ESIL_A ("pc,");				// esil already points to next
						// instruction (@ret)
	__generic_push (op, cpu->pc_size);	// push @ret addr
	ESIL_A ("z,pc,=,");			// jump!
}

INST_HANDLER (ijmp) {	// IJMP k
	ut64 z;
	// read z for calculating jump address on runtime
	r_anal_esil_reg_read (anal->esil, "z", &z, NULL);
	// real target address may change during execution, so this value will
	// be changing all the time
	op->jump = z;
	op->cycles = 2;
	ESIL_A ("z,pc,=,");			// jump!
}

INST_HANDLER (in) {	// IN Rd, A
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 0x01) << 4);
	int a = (buf[0] & 0x0f) | ((buf[1] & 0x6) << 3);
	RStrBuf *io_src = __generic_io_dest (a, 0);
	op->type2 = 0;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;
	ESIL_A ("%s,r%d,=,", r_strbuf_get (io_src), r);
	r_strbuf_free (io_src);
}

INST_HANDLER (inc) {	// INC Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	ESIL_A ("1,r%d,+,", d);					// ++Rd
								// FLAGS:
	ESIL_A ("0,RPICK,0x80,==,vf,=,");			// V
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("vf,nf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = Result
}

INST_HANDLER (jmp) {	// JMP k
	op->jump = (buf[2] << 1)
		 | (buf[3] << 9)
		 | (buf[1] & 0x01) << 23
		 | (buf[0] & 0x01) << 17
		 | (buf[0] & 0xf0) << 14;
	op->cycles = 3;
	ESIL_A ("%"PFMT64d",pc,=,", op->jump);	// jump!
}

INST_HANDLER (lac) {	// LAC Z, Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st (op, "sram", 'z', 1, 0, 0, 0);	// 0: Read (RAMPZ:Z)
	ESIL_A ("r%d,0xff,^,&,", d);			// 0: (Z) & ~Rd
	ESIL_A ("DUP,r%d,=,", d);			// Rd = [0]
	__generic_ld_st (op, "sram", 'z', 1, 0, 0, 1);	// Store in RAM
}

INST_HANDLER (las) {	// LAS Z, Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st (op, "sram", 'z', 1, 0, 0, 0);	// 0: Read (RAMPZ:Z)
	ESIL_A ("r%d,|,", d);				// 0: (Z) | Rd
	ESIL_A ("DUP,r%d,=,", d);			// Rd = [0]
	__generic_ld_st (op, "sram", 'z', 1, 0, 0, 1);	// Store in RAM
}

INST_HANDLER (lat) {	// LAT Z, Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st (op, "sram", 'z', 1, 0, 0, 0);	// 0: Read (RAMPZ:Z)
	ESIL_A ("r%d,^,", d);				// 0: (Z) ^ Rd
	ESIL_A ("DUP,r%d,=,", d);			// Rd = [0]
	__generic_ld_st (op, "sram", 'z', 1, 0, 0, 1);	// Store in RAM
}

INST_HANDLER (ld) {	// LD Rd, X
			// LD Rd, X+
			// LD Rd, -X
	// read memory
	__generic_ld_st (
		op, "sram",
		'x',				// use index register X
		0,				// no use RAMP* registers
		(buf[0] & 0xf) == 0xe
			? -1			// pre decremented
			: (buf[0] & 0xf) == 0xd
				? 1		// post incremented
				: 0,		// no increment
		0,				// offset always 0
		0);				// load operation (!st)
	// load register
	ESIL_A ("r%d,=,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// cycles
	op->cycles = (buf[0] & 0x3) == 0
			? 2			// LD Rd, X
			: (buf[0] & 0x3) == 1
				? 2		// LD Rd, X+
				: 3;		// LD Rd, -X
	if (!STR_BEGINS (cpu->model, "ATxmega") && op->cycles > 1) {
		// AT*mega optimizes 1 cycle!
		op->cycles--;
	}
}

INST_HANDLER (ldd) {	// LD Rd, Y	LD Rd, Z
			// LD Rd, Y+	LD Rd, Z+
			// LD Rd, -Y	LD Rd, -Z
			// LD Rd, Y+q	LD Rd, Z+q
	// calculate offset (this value only has sense in some opcodes,
	// but we are optimistic and we calculate it always)
	int offset = (buf[1] & 0x20)
			| ((buf[1] & 0xc) << 1)
			| (buf[0] & 0x7);
	// read memory
	__generic_ld_st (
		op, "sram",
		buf[0] & 0x8 ? 'y' : 'z',	// index register Y/Z
		0,				// no use RAMP* registers
		!(buf[1] & 0x1)
			? 0			// no increment
			: buf[0] & 0x1
				? 1		// post incremented
				: -1,		// pre decremented
		!(buf[1] & 0x1) ? offset : 0,	// offset or not offset
		0);				// load operation (!st)
	// load register
	ESIL_A ("r%d,=,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// cycles
	op->cycles = 
		(buf[1] & 0x1) == 0
			? (!offset ? 1 : 3)		// LDD
			: (buf[0] & 0x3) == 0
				? 1			// LD Rd, X
				: (buf[0] & 0x3) == 1
					? 2		// LD Rd, X+
					: 3;		// LD Rd, -X
	if (!STR_BEGINS (cpu->model, "ATxmega") && op->cycles > 1) {
		// AT*mega optimizes 1 cycle!
		op->cycles--;
	}
}

INST_HANDLER (ldi) {	// LDI Rd, K
	int k = (buf[0] & 0xf) + ((buf[1] & 0xf) << 4);
	int d = ((buf[0] >> 4) & 0xf) + 16;
	ESIL_A ("0x%x,r%d,=,", k, d);
}

INST_HANDLER (lds) {	// LDS Rd, k
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	int k = (buf[3] << 8) | buf[2];

	// load value from RAMPD:k
	__generic_ld_st (op, "sram", 0, 1, 0, k, 0);
	ESIL_A ("r%d,=,", d);
}

INST_HANDLER (lds16) {	// LDS Rd, k
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = (buf[0] & 0x0f)
		| ((buf[1] << 3) & 0x30)
		| ((buf[1] << 4) & 0x40)
		| (~(buf[1] << 4) & 0x80);

	// load value from @k
	__generic_ld_st (op, "sram", 0, 0, 0, k, 0);
	ESIL_A ("r%d,=,", d);
}

INST_HANDLER (lpm) {	// LPM
			// LPM Rd, Z
			// LPM Rd, Z+
	ut16 ins = (((ut16) buf[1]) << 8) | ((ut16) buf[0]);
	// read program memory
	__generic_ld_st (
		op, "prog",
		'z',				// index register Y/Z
		1,				// use RAMP* registers
		(ins & 0xfe0f) == 0x9005
			? 1			// post incremented
			: 0,			// no increment
		0,				// not offset
		0);				// load operation (!st)
	// load register
	ESIL_A ("r%d,=,",
		(ins == 0x95c8)
			? 0			// LPM (r0)
			: ((buf[0] >> 4) & 0xf)	// LPM Rd
				| ((buf[1] & 0x1) << 4));
}

INST_HANDLER (lsr) {	// LSR Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	ESIL_A ("1,r%d,>>,", d);				// 0: R=(Rd >> 1)
	ESIL_A ("r%d,0x1,&,!,!,cf,=,", d);			// C = Rd0
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("0,nf,=,");					// N
	ESIL_A ("nf,cf,^,vf,=,");				// V
	ESIL_A ("nf,vf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = R
}

INST_HANDLER (mov) {	// MOV Rd, Rr
	int d = ((buf[1] << 4) & 0x10) | ((buf[0] >> 4) & 0x0f);
	int r = ((buf[1] << 3) & 0x10) | (buf[0] & 0x0f);
	ESIL_A ("r%d,r%d,=,", r, d);
}

INST_HANDLER (movw) {	// MOVW Rd+1:Rd, Rr+1:Rr
	int d = (buf[0] & 0xf0) >> 3;
	int r = (buf[0] & 0x0f) << 1;
	ESIL_A ("r%d,r%d,=,r%d,r%d,=,", r, d, r + 1, d + 1);
}

INST_HANDLER (mul) {	// MUL Rd, Rr
	int d = ((buf[1] << 4) & 0x10) | ((buf[0] >> 4) & 0x0f);
	int r = ((buf[1] << 3) & 0x10) | (buf[0] & 0x0f);

	ESIL_A ("r%d,r%d,*,", r, d);			// 0: (Rd*Rr)<<1
	ESIL_A ("DUP,0xff,&,r0,=,");			// r0 = LO(0)
	ESIL_A ("8,0,RPICK,>>,0xff,&,r1,=,");		// r1 = HI(0)
	ESIL_A ("DUP,0x8000,&,!,!,cf,=,");		// C = R/15
	ESIL_A ("DUP,!,zf,=,");				// Z = !R
}

INST_HANDLER (muls) {	// MULS Rd, Rr
	int d = (buf[0] >> 4 & 0x0f) + 16;
	int r = (buf[0] & 0x0f) + 16;

	ESIL_A ("r%d,DUP,0x80,&,?{,0xffff00,|,},", r);	// sign extension Rr
	ESIL_A ("r%d,DUP,0x80,&,?{,0xffff00,|,},", d);	// sign extension Rd
	ESIL_A ("*,");					// 0: (Rd*Rr)
	ESIL_A ("DUP,0xff,&,r0,=,");			// r0 = LO(0)
	ESIL_A ("8,0,RPICK,>>,0xff,&,r1,=,");		// r1 = HI(0)
	ESIL_A ("DUP,0x8000,&,!,!,cf,=,");		// C = R/15
	ESIL_A ("DUP,!,zf,=,");				// Z = !R
}

INST_HANDLER (mulsu) {	// MULSU Rd, Rr
	int d = (buf[0] >> 4 & 0x07) + 16;
	int r = (buf[0] & 0x07) + 16;

	ESIL_A ("r%d,", r);				// unsigned Rr
	ESIL_A ("r%d,DUP,0x80,&,?{,0xffff00,|,},", d);	// sign extension Rd
	ESIL_A ("*,");					// 0: (Rd*Rr)
	ESIL_A ("DUP,0xff,&,r0,=,");			// r0 = LO(0)
	ESIL_A ("8,0,RPICK,>>,0xff,&,r1,=,");		// r1 = HI(0)
	ESIL_A ("DUP,0x8000,&,!,!,cf,=,");		// C = R/15
	ESIL_A ("DUP,!,zf,=,");				// Z = !R
}

INST_HANDLER (neg) {	// NEG Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	ESIL_A ("r%d,0x00,-,0xff,&,", d);			// 0: (0-Rd)
	ESIL_A ("DUP,r%d,0xff,^,|,0x08,&,!,!,hf,=,", d);	// H
	ESIL_A ("DUP,0x80,-,!,vf,=,", d);			// V
	ESIL_A ("DUP,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("DUP,!,zf,=,");					// Z
	ESIL_A ("DUP,!,!,cf,=,");				// C
	ESIL_A ("vf,nf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = result
}

INST_HANDLER (nop) {	// NOP
	ESIL_A (",,");
}

INST_HANDLER (or) {	// OR Rd, Rr
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A ("r%d,r%d,|,", r, d);				// 0: (Rd | Rr)
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,vf,=,");					// V
	ESIL_A ("nf,sf,=,");					// S
	ESIL_A ("r%d,=,", d);					// Rd = result
}

INST_HANDLER (ori) {	// ORI Rd, K
			// SBR Rd, K
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = (buf[0] & 0xf) | ((buf[1] & 0xf) << 4);
	ESIL_A ("r%d,%d,|,", d, k);				// 0: (Rd | k)
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,vf,=,");					// V
	ESIL_A ("nf,sf,=,");					// S
	ESIL_A ("r%d,=,", d);					// Rd = result
}

INST_HANDLER (out) {	// OUT A, Rr
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 0x01) << 4);
	int a = (buf[0] & 0x0f) | ((buf[1] & 0x6) << 3);
	RStrBuf *io_dst = __generic_io_dest (a, 1);
	op->type2 = 1;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;
	ESIL_A ("r%d,%s,=,", r, r_strbuf_get (io_dst));
	r_strbuf_free (io_dst);
}

INST_HANDLER (pop) {	// POP Rd
	int d = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	__generic_pop (op, 1);
	ESIL_A ("r%d,=,", d);	// store in Rd
		
}

INST_HANDLER (push) {	// PUSH Rr
	int r = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	ESIL_A ("r%d,", r);	// load Rr
	__generic_push (op, 1);	// push it into stack
	// cycles
	op->cycles = !STR_BEGINS (cpu->model, "ATxmega")
			? 1	// AT*mega optimizes one cycle
			: 2;
}

INST_HANDLER (rcall) {	// RCALL k
	// target address
	op->jump = (op->addr
		+ (((((buf[1] & 0xf) << 8) | buf[0]) << 1)
			| (((buf[1] & 0x8) ? ~((int) 0x1fff) : 0)))
		+ 2) & cpu->pc_mask;
	// esil
	ESIL_A ("pc,");				// esil already points to next
						// instruction (@ret)
	__generic_push (op, cpu->pc_size);	// push @ret addr
	ESIL_A ("%"PFMT64d",pc,=,", op->jump);	// jump!
	// cycles
	if (!strncasecmp (cpu->model, "ATtiny", 6)) {
		op->cycles = 4;	// ATtiny is always slow
	} else {
		// PC size decides required runtime!
		op->cycles = cpu->pc_bits <= 16 ? 3 : 4;
		if (!STR_BEGINS (cpu->model, "ATxmega")) {
			op->cycles--;	// ATxmega optimizes one cycle
		}
	}
}

INST_HANDLER (ret) {	// RET
	op->eob = true;
	// esil
	__generic_pop (op, cpu->pc_size);
	ESIL_A ("pc,=,");	// jump!
	// cycles
	if (cpu->pc_size > 2) {	// if we have a bus bigger than 16 bit
		op->cycles++;	// (i.e. a 22-bit bus), add one extra cycle
	}
}

INST_HANDLER (reti) {	// RETI
	//XXX: There are not privileged instructions in ATMEL/AVR
	op->family = R_ANAL_OP_FAMILY_PRIV;

	// first perform a standard 'ret'
	INST_CALL (ret);

	// RETI: The I-bit is cleared by hardware after an interrupt
	// has occurred, and is set by the RETI instruction to enable
	// subsequent interrupts
	ESIL_A ("1,if,=,");
}

INST_HANDLER (rjmp) {	// RJMP k
	op->jump = (op->addr
		+ (((typeof (op->jump)) (((buf[1] & 0xf) << 9) | (buf[0] << 1)))
			| (buf[1] & 0x8 ? ~((typeof (op->jump)) 0x1fff) : 0))
		+ 2) & cpu->pc_mask;
	ESIL_A ("%"PFMT64d",pc,=,", op->jump);
}

INST_HANDLER (ror) {	// ROR Rd
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	ESIL_A ("1,r%d,>>,8,cf,<<,|,", d);		// 0: (Rd>>1) | (cf<<8)
	ESIL_A ("r%d,1,&,cf,=,");			// C
	ESIL_A ("0,RPICK,!,zf,=,");			// Z
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");		// N
	ESIL_A ("nf,cf,^,vf,=,");			// V
	ESIL_A ("vf,nf,^,sf,=,");			// S
	ESIL_A ("r%d,=,", d);				// Rd = result
}

INST_HANDLER (sbc) {	// SBC Rd, Rr
	int r = (buf[1] & 0x0f) | ((buf[0] & 0x2) >> 1);
	int d = ((buf[1] >> 4) & 0xf) | (buf[0] & 0x1);
	ESIL_A ("cf,r%d,-,r%d,-,", r, d);			// 0: (Rd-Rr-C)
	ESIL_A ("r%d,0x08,&,!,"   "r%d,0x08,&,!,!,"     "&,"	// H
		"r%d,0x08,&,!,!," "0,RPICK,0x08,&,!,!," "&,"
		"r%d,0x08,&,!,"   "0,RPICK,0x08,&,!,!," "&,"
		"|,|,hf,=,",
		d, r, r, d);
	ESIL_A ("r%d,0x80,&,!,!," "r%d,0x80,&,!,"       "&,"	// V
		""                "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,"   "r%d,0x80,&,!,!,"     "&,"
		""                "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, r, d, r);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,&,zf,=,");			// Z (C)
	ESIL_A ("r%d,0x80,&,!,"   "r%d,0x80,&,!,!,"     "&," 	// C
		"r%d,0x80,&,!,!," "0,RPICK,0x80,&,!,!," "&,"
		"r%d,0x80,&,!,"   "0,RPICK,0x80,&,!,!," "&,"
		"|,|,cf,=,",
		d, r, r, d);
	ESIL_A ("vf,nf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = Result
}

INST_HANDLER (sbci) {	// SBCI Rd, k
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = ((buf[1] & 0xf) << 4) | (buf[0] & 0xf);
	ESIL_A ("cf,%d,-,r%d,-,", k, d);			// 0: (Rd-k-C)
	ESIL_A ("r%d,0x08,&,!,"  "%d,0x08,&,!,!,"      "&,"	// H
		"%d,0x08,&,!,!," "0,RPICK,0x08,&,!,!," "&,"
		"%d,0x08,&,!,"   "0,RPICK,0x08,&,!,!," "&,"
		"|,|,hf,=,",
		d, k, k, d);
	ESIL_A ("r%d,0x80,&,!,!," "%d,0x80,&,!,"        "&,"	// V
		""                "0,RPICK,0x80,&,!,"   "&,"
		"r%d,0x80,&,!,"   "%d,0x80,&,!,!,"      "&,"
		""                "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, k, d, k);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,&,zf,=,");			// Z (C)
	ESIL_A ("r%d,0x80,&,!,"  "%d,0x80,&,!,!,"      "&," 	// C
		"%d,0x80,&,!,!," "0,RPICK,0x80,&,!,!," "&,"
		"r%d,0x80,&,!,"  "0,RPICK,0x80,&,!,!," "&,"
		"|,|,cf,=,",
		d, k, k, d);
	ESIL_A ("vf,nf,^,sf,=,");				// S
	ESIL_A ("r%d,=,", d);					// Rd = Result
}

INST_HANDLER (sbi) {	// SBI A, b
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RStrBuf *io_port;

	op->type2 = 1;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;

	// read port a and clear bit b
	io_port = __generic_io_dest (a, 0);
	ESIL_A ("0xff,%d,1,<<,|,%s,&,", b, io_port);
	r_strbuf_free (io_port);

	// write result to port a
	io_port = __generic_io_dest (a, 1);
	ESIL_A ("%s,=,", r_strbuf_get (io_port));
	r_strbuf_free (io_port);
}

INST_HANDLER (sbix) {	// SBIC A, b
			// SBIS A, b
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RAnalOp next_op;
	RStrBuf *io_port;

	op->type2 = 0;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;

	// calculate next instruction size (call recursively avr_op_analyze)
	// and free next_op's esil string (we dont need it now)
	avr_op_analyze (anal,
			&next_op,
			op->addr + op->size, buf + op->size,
			cpu);
	r_strbuf_fini (&next_op.esil);
	op->jump = op->addr + next_op.size + 2;

	// cycles
	op->cycles = 1;	// XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to false, this instruction
			// needs 2/3 cycles, elsewhere it needs only 1 cycle.

	// read port a and clear bit b
	io_port = __generic_io_dest (a, 0);
	ESIL_A ("%d,1,<<,%s,&,", b, io_port);		// IO(A,b)
	ESIL_A ((buf[1] & 0xe) == 0xc
			? "!,"				// SBIC => branch if 0
			: "!,!,");			// SBIS => branch if 1
	ESIL_A ("?{,%"PFMT64d",pc,=,},", op->jump);	// ?true => jmp
	r_strbuf_free (io_port);
}

INST_HANDLER (sbiw) {	// SBIW Rd+1:Rd, K
	int d = ((buf[0] & 0x30) >> 3) + 24;
	int k = (buf[0] & 0xf) | ((buf[0] >> 2) & 0x30);
	ESIL_A ("%d,r%d:r%d,-,", k, d + 1, d);		// 0(Rd+1:Rd - Rr)
	ESIL_A ("r%d,0x80,&,!,!,"			// V
		"0,RPICK,0x8000,&,!,"
		"&,vf,=,", d + 1);
	ESIL_A ("0,RPICK,0x8000,&,!,!,nf,=,");		// N
	ESIL_A ("0,RPICK,!,zf,=,");			// Z
	ESIL_A ("r%d,0x80,&,!,"				// C
		"0,RPICK,0x8000,&,!,!,"
		"&,cf,=,", d + 1);
	ESIL_A ("vf,nf,^,sf,=,");			// S
	ESIL_A ("r%d:r%d,=,", d + 1, d);		// Rd = result
}

INST_HANDLER (sbrx) {	// SBRC Rr, b
			// SBRS Rr, b
	int b = buf[0] & 0x7;
	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x01) << 4);
	RAnalOp next_op;

	// calculate next instruction size (call recursively avr_op_analyze)
	// and free next_op's esil string (we dont need it now)
	avr_op_analyze (anal,
			&next_op,
			op->addr + op->size, buf + op->size,
			cpu);
	r_strbuf_fini (&next_op.esil);
	op->jump = op->addr + next_op.size + 2;

	// cycles
	op->cycles = 1;	// XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to false, this instruction
			// needs 2/3 cycles, elsewhere it needs only 1 cycle.
	ESIL_A ("%d,1,<<,r%d,&,", b, r);			// Rr(b)
	ESIL_A ((buf[1] & 0xe) == 0xc
			? "!,"		// SBRC => branch if cleared
			: "!,!,");	// SBRS => branch if set
	ESIL_A ("?{,%"PFMT64d",pc,=,},", op->jump);	// ?true => jmp
}

INST_HANDLER (sleep) {	// SLEEP
	ESIL_A ("BREAK");
}

INST_HANDLER (st) {	// ST X, Rr
			// ST X+, Rr
			// ST -X, Rr
	// load register
	ESIL_A ("r%d,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// write in memory
	__generic_ld_st (
		op, "sram",
		'x',				// use index register X
		0,				// no use RAMP* registers
		(buf[0] & 0xf) == 0xe
			? -1			// pre decremented
			: (buf[0] & 0xf) == 0xd
				? 1		// post increment
				: 0,		// no increment
		0,				// offset always 0
		1);				// store operation (st)
//	// cycles
//	op->cycles = buf[0] & 0x3 == 0
//			? 2			// LD Rd, X
//			: buf[0] & 0x3 == 1
//				? 2		// LD Rd, X+
//				: 3;		// LD Rd, -X
//	if (!STR_BEGINS (cpu->model, "ATxmega") && op->cycles > 1) {
//		// AT*mega optimizes 1 cycle!
//		op->cycles--;
//	}
}

INST_HANDLER (std) {	// ST Y, Rr	ST Z, Rr
			// ST Y+, Rr	ST Z+, Rr
			// ST -Y, Rr	ST -Z, Rr
			// ST Y+q, Rr	ST Z+q, Rr
	// load register
	ESIL_A ("r%d,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// write in memory
	__generic_ld_st (
		op, "sram",
		buf[0] & 0x8 ? 'y' : 'z',	// index register Y/Z
		0,				// no use RAMP* registers
		!(buf[1] & 0x1)
			? 0			// no increment
			: buf[0] & 0x1
				? 1		// post incremented
				: -1,		// pre decremented
		!(buf[1] & 0x1)
			? (buf[1] & 0x20)	// offset
			| ((buf[1] & 0xc) << 1)
			| (buf[0] & 0x7)
			: 0,			// no offset
		1);				// load operation (!st)
//	// cycles
//	op->cycles = 
//		buf[1] & 0x1 == 0
//			? !(offset ? 1 : 3)		// LDD
//			: buf[0] & 0x3 == 0
//				? 1			// LD Rd, X
//				: buf[0] & 0x3 == 1
//					? 2		// LD Rd, X+
//					: 3;		// LD Rd, -X
//	if (!STR_BEGINS (cpu->model, "ATxmega") && op->cycles > 1) {
//		// AT*mega optimizes 1 cycle!
//		op->cycles--;
//	}
}

OPCODE_DESC opcodes[] = {
	//         op     mask    select  cycles  size type
	INST_DECL (break,  0xffff, 0x9698, 1,      2,   TRAP   ), // BREAK
	INST_DECL (eicall, 0xffff, 0x9519, 0,      2,   UCALL  ), // EICALL
	INST_DECL (eijmp,  0xffff, 0x9419, 0,      2,   UJMP   ), // EIJMP
	INST_DECL (icall,  0xffff, 0x9509, 0,      2,   UCALL  ), // ICALL
	INST_DECL (ijmp,   0xffff, 0x9409, 0,      2,   UJMP   ), // IJMP
	INST_DECL (lpm,    0xffff, 0x95c8, 3,      2,   LOAD   ), // LPM
	INST_DECL (nop,    0xffff, 0x0000, 1,      2,   NOP    ), // NOP
	INST_DECL (ret,    0xffff, 0x9508, 4,      2,   RET    ), // RET
	INST_DECL (reti,   0xffff, 0x9518, 4,      2,   RET    ), // RETI
	INST_DECL (sleep,  0xffff, 0x9588, 1,      2,   NOP    ), // SLEEP
	INST_DECL (bclr,   0xff8f, 0x9488, 1,      2,   SWI    ), // BCLR s
	INST_DECL (bset,   0xff8f, 0x9408, 1,      2,   SWI    ), // BSET s
	INST_DECL (fmul,   0xff88, 0x0308, 2,      2,   MUL    ), // FMUL Rd, Rr
	INST_DECL (fmuls,  0xff88, 0x0380, 2,      2,   MUL    ), // FMULS Rd, Rr
	INST_DECL (fmulsu, 0xff88, 0x0388, 2,      2,   MUL    ), // FMULSU Rd, Rr
	INST_DECL (mulsu,  0xff88, 0x0300, 2,      2,   AND    ), // MUL Rd, Rr
	INST_DECL (des,    0xff0f, 0x940b, 0,      2,   CRYPTO ), // DES k
	INST_DECL (adiw,   0xff00, 0x9600, 2,      2,   ADD    ), // ADIW Rd+1:Rd, K
	INST_DECL (sbiw,   0xff00, 0x9700, 2,      2,   SUB    ), // SBIW Rd+1:Rd, K
	INST_DECL (cbi,    0xff00, 0x9800, 1,      2,   IO     ), // CBI A, K
	INST_DECL (sbi,    0xff00, 0x9a00, 1,      2,   IO     ), // SBI A, K
	INST_DECL (movw,   0xff00, 0x0100, 1,      2,   MOV    ), // MOVW Rd+1:Rd, Rr+1:Rr
	INST_DECL (muls,   0xff00, 0x0200, 2,      2,   AND    ), // MUL Rd, Rr
	INST_DECL (asr,    0xfe0f, 0x9405, 1,      2,   SAR    ), // ASR Rd
	INST_DECL (com,    0xfe0f, 0x9400, 1,      2,   SWI    ), // BLD Rd, b
	INST_DECL (dec,    0xfe0f, 0x940a, 1,      2,   SUB    ), // DEC Rd
	INST_DECL (elpm,   0xfe0f, 0x9006, 0,      2,   LOAD   ), // ELPM Rd, Z
	INST_DECL (elpm,   0xfe0f, 0x9007, 0,      2,   LOAD   ), // ELPM Rd, Z+
	INST_DECL (inc,    0xfe0f, 0x9403, 1,      2,   ADD    ), // INC Rd
	INST_DECL (lac,    0xfe0f, 0x9206, 2,      2,   LOAD   ), // LAC Z, Rd
	INST_DECL (las,    0xfe0f, 0x9205, 2,      2,   LOAD   ), // LAS Z, Rd
	INST_DECL (lat,    0xfe0f, 0x9207, 2,      2,   LOAD   ), // LAT Z, Rd
	INST_DECL (ld,     0xfe0f, 0x900c, 0,      2,   LOAD   ), // LD Rd, X
	INST_DECL (ld,     0xfe0f, 0x900d, 0,      2,   LOAD   ), // LD Rd, X+
	INST_DECL (ld,     0xfe0f, 0x900e, 0,      2,   LOAD   ), // LD Rd, -X
	INST_DECL (lds,    0xfe0f, 0x9000, 0,      4,   LOAD   ), // LDS Rd, k
	INST_DECL (lpm,    0xfe0f, 0x9004, 3,      2,   LOAD   ), // LPM Rd, Z
	INST_DECL (lpm,    0xfe0f, 0x9005, 3,      2,   LOAD   ), // LPM Rd, Z+
	INST_DECL (lsr,    0xfe0f, 0x9406, 1,      2,   SHR    ), // LSR Rd
	INST_DECL (neg,    0xfe0f, 0x9401, 2,      2,   SUB    ), // NEG Rd
	INST_DECL (pop,    0xfe0f, 0x900f, 2,      2,   POP    ), // PUSH Rr
	INST_DECL (push,   0xfe0f, 0x920f, 0,      2,   PUSH   ), // PUSH Rr
	INST_DECL (ror,    0xfe0f, 0x9407, 1,      2,   SAR    ), // PUSH Rr
	INST_DECL (st,     0xfe0f, 0x920c, 2,      2,   STORE  ), // ST X, Rr
	INST_DECL (st,     0xfe0f, 0x920d, 0,      2,   STORE  ), // ST X+, Rr
	INST_DECL (st,     0xfe0f, 0x920e, 0,      2,   STORE  ), // ST -X, Rr
	INST_DECL (call,   0xfe0e, 0x940e, 0,      4,   CALL   ), // CALL k
	INST_DECL (jmp,    0xfe0e, 0x940c, 2,      4,   JMP    ), // JMP k
	INST_DECL (bld,    0xfe08, 0xf800, 1,      2,   SWI    ), // BLD Rd, b
	INST_DECL (bst,    0xfe08, 0xfa00, 1,      2,   SWI    ), // BST Rd, b
	INST_DECL (sbix,   0xfe08, 0x9900, 2,      2,   CJMP   ), // SBIC A, b
	INST_DECL (sbix,   0xfe08, 0x9900, 2,      2,   CJMP   ), // SBIS A, b
	INST_DECL (sbrx,   0xfe08, 0xfc00, 2,      2,   CJMP   ), // SBRC Rr, b
	INST_DECL (sbrx,   0xfe08, 0xfe00, 2,      2,   CJMP   ), // SBRS Rr, b
	INST_DECL (ldd,    0xfe07, 0x9001, 0,      2,   LOAD   ), // LD Rd, Y/Z+
	INST_DECL (ldd,    0xfe07, 0x9002, 0,      2,   LOAD   ), // LD Rd, -Y/Z
	INST_DECL (std,    0xfe07, 0x9201, 0,      2,   STORE  ), // LD Y/Z+, Rr
	INST_DECL (std,    0xfe07, 0x9202, 0,      2,   STORE  ), // LD -Y/Z, Rr
	INST_DECL (adc,    0xfc00, 0x1c00, 1,      2,   ADD    ), // ADC Rd, Rr
	INST_DECL (add,    0xfc00, 0x0c00, 1,      2,   ADD    ), // ADD Rd, Rr
	INST_DECL (and,    0xfc00, 0x2000, 1,      2,   AND    ), // AND Rd, Rr
	INST_DECL (brbx,   0xfc00, 0xf000, 0,      2,   CJMP   ), // BRBS s, k
	INST_DECL (brbx,   0xfc00, 0xf400, 0,      2,   CJMP   ), // BRBC s, k
	INST_DECL (cp,     0xfc00, 0x1400, 1,      2,   CMP    ), // CP Rd, Rr
	INST_DECL (cpc,    0xfc00, 0x0400, 1,      2,   CMP    ), // CPC Rd, Rr
	INST_DECL (cpse,   0xfc00, 0x1000, 0,      2,   CJMP   ), // CPSE Rd, Rr
	INST_DECL (eor,    0xfc00, 0x2400, 1,      2,   XOR    ), // EOR Rd, Rr
	INST_DECL (mov,    0xfc00, 0x2c00, 1,      2,   MOV    ), // MOV Rd, Rr
	INST_DECL (mul,    0xfc00, 0x9c00, 2,      2,   AND    ), // MUL Rd, Rr
	INST_DECL (or,     0xfc00, 0x2800, 1,      2,   OR     ), // OR Rd, Rr
	INST_DECL (sbc,    0xfc00, 0x0800, 1,      2,   SUB    ), // SBC Rd, Rr
	INST_DECL (in,     0xf800, 0xb000, 1,      2,   IO     ), // IN Rd, A
	INST_DECL (lds16,  0xf800, 0xa000, 1,      2,   LOAD   ), // LDS Rd, k
	INST_DECL (out,    0xf800, 0xb800, 1,      2,   IO     ), // OUT A, Rr
	INST_DECL (andi,   0xf000, 0x7000, 1,      2,   AND    ), // ANDI Rd, K
	INST_DECL (cpi,    0xf000, 0x3000, 1,      2,   CMP    ), // CPI Rd, K
	INST_DECL (ldi,    0xf000, 0xe000, 1,      2,   LOAD   ), // LDI Rd, K
	INST_DECL (ori,    0xf000, 0x6000, 1,      2,   OR     ), // ORI Rd, K
	INST_DECL (rcall,  0xf000, 0xd000, 0,      2,   CALL   ), // RCALL k
	INST_DECL (rjmp,   0xf000, 0xc000, 2,      2,   JMP    ), // RJMP k
	INST_DECL (sbci,   0xf000, 0x0400, 1,      2,   SUB    ), // SBC Rd, Rr
	INST_DECL (ldd,    0xd200, 0x8000, 0,      2,   LOAD   ), // LD Rd, Y/Z+q
	INST_DECL (std,    0xd200, 0x8200, 0,      2,   STORE  ), // LD Y/Z+q, Rr

	INST_LAST
};

static int avr_op_analyze(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, CPU_MODEL *cpu) {
	OPCODE_DESC *opcode_desc;
	ut16 ins = (buf[1] << 8) | buf[0];
	int fail;
	char *t;

	// initialize op struct
	memset (op, 0, sizeof (RAnalOp));
	r_strbuf_init (&op->esil);

	// process opcode
	for (opcode_desc = opcodes; opcode_desc->handler; opcode_desc++) {
		if ((ins & opcode_desc->mask) == opcode_desc->selector) {
			fail = 0;

			// copy default cycles/size values
			op->cycles = opcode_desc->cycles;
			op->size = opcode_desc->size;
			op->type = opcode_desc->type;
			op->fail = addr + op->size;
			op->addr = addr;

			// start void esil expression
			r_strbuf_setf (&op->esil, "");

			// handle opcode
			opcode_desc->handler (anal, op, buf, &fail, cpu);
			if (fail) {
				goto INVALID_OP;
			}
			if (op->cycles <= 0) {
				eprintf ("opcode %s @%"PFMT64x" returned 0 cycles.\n", opcode_desc->name, op->addr);
				opcode_desc->cycles = 2;
			}
			op->nopcode = (op->type == R_ANAL_OP_TYPE_UNK);

			// remove trailing coma (COMETE LA COMA)
			t = r_strbuf_get (&op->esil);
			if (t && strlen (t) > 1) {
				t += strlen (t) - 1;
				if (*t == ',') {
					*t = '\0';
				}
			}

			return op->size;
		}
	}

	// ignore reserved opcodes (if they have not been caught by the previous loop)
	if ((ins & 0xff00) == 0xff00 && (ins & 0xf) > 7) {
		goto INVALID_OP;
	}

INVALID_OP:
	// An unknown or invalid option has appeared.
	//  -- Throw pokeball!
	op->family = R_ANAL_OP_FAMILY_UNKNOWN;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->addr = addr;
	op->fail = UT64_MAX;
	op->jump = UT64_MAX;
	op->ptr = UT64_MAX;
	op->val = UT64_MAX;
	op->nopcode = 1;
	op->cycles = 1;
	op->size = 2;
	// launch esil trap (for communicating upper layers about this weird
	// and stinky situation
	r_strbuf_set (&op->esil, "1,$");

	return op->size;
}

static int avr_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	CPU_MODEL *cpu;
	// init op
	if (!op) {
		return 2;
	}
	// select cpu info
	for (cpu = cpu_models; cpu < cpu_models + ((sizeof (cpu_models) / sizeof (CPU_MODEL))) - 1; cpu++) {
		if (!strcasecmp (anal->cpu, cpu->model)) {
			break;
		}
	}
	// set memory layout registers
	if (anal->esil) {
		r_anal_esil_reg_write (anal->esil, "_prog",   0);
		r_anal_esil_reg_write (anal->esil, "_eeprom", (1 << cpu->pc_bits));
		r_anal_esil_reg_write (anal->esil, "_io",     (1 << cpu->pc_bits) + cpu->eeprom_size);
		r_anal_esil_reg_write (anal->esil, "_sram",   (1 << cpu->pc_bits) + cpu->eeprom_size + cpu->io_size);
	}
	// process opcode
	avr_op_analyze (anal, op, addr, buf, cpu);

	return op->size;
}

static int avr_custom_des (RAnalEsil *esil) {
	char *round;
	ut64 key, text;
	int r, enc;
	if (!esil || !esil->anal || !esil->anal->reg) {
		return false;
	}
	round = r_anal_esil_pop (esil);
	if (!round) {
		return false;
	}
	if (!r_anal_esil_get_parm (esil, round, &key)) {
		free (round);
		return false;
	}
	free (round);
	r = (int)key;
	r_anal_esil_reg_read (esil, "hf", &key, NULL);
	enc = (int)key;
	r_anal_esil_reg_read (esil, "deskey", &key, NULL);
	r_anal_esil_reg_read (esil, "text", &text, NULL);
//	eprintf ("des - key: 0x%"PFMT64x" - text: 0x%"PFMT64x" - round: %d - %s\n", key, text, r, enc ? "decrypt" : "encrypt");
	key = r_des_get_roundkey (key, r, enc);
	text = r_des_round (text, key);
	r_anal_esil_reg_write (esil, "text", text);
	return true;
}

static int esil_avr_init (RAnalEsil *esil) {
	if (!esil)
		return false;
	r_anal_esil_set_op (esil, "des", avr_custom_des);

	return true;
}

static int esil_avr_fini (RAnalEsil *esil) {
	return true;
}

static int set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	pcl\n"
		"=SP	sp\n"
// explained in http://www.nongnu.org/avr-libc/user-manual/FAQ.html
// and http://www.avrfreaks.net/forum/function-calling-convention-gcc-generated-assembly-file
		"=A0	r25\n"
		"=A1	r24\n"
		"=A2	r23\n"
		"=A3	r22\n"
		"=R0	r24\n"
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
		"gpr	text	.64	0	0\n"
		"gpr	r8	.8	8	0\n"
		"gpr	r9	.8	9	0\n"
		"gpr	r10	.8	10	0\n"
		"gpr	r11	.8	11	0\n"
		"gpr	r12	.8	12	0\n"
		"gpr	r13	.8	13	0\n"
		"gpr	r14	.8	14	0\n"
		"gpr	r15	.8	15	0\n"
		"gpr	deskey	.64	8	0\n"
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

// 16 bit overlapped registers for 16 bit math
		"gpr	r25:r24	.16	24	0\n"
		"gpr	r27:r26	.16	26	0\n"
		"gpr	r29:r28	.16	28	0\n"
		"gpr	r31:r30	.16	30	0\n"

// 16 bit overlapped registers for memory addressing
		"gpr	x	.16	26	0\n"
		"gpr	y	.16	28	0\n"
		"gpr	z	.16	30	0\n"
// program counter
// NOTE: program counter size in AVR depends on the CPU model. It seems that
// the PC may range from 16 bits to 22 bits.
		"gpr	pc	.32	32	0\n"
		"gpr	pcl	.16	32	0\n"
		"gpr	pch	.16	34	0\n"
// special purpose registers
		"gpr	sp	.16	36	0\n"
		"gpr	spl	.8	36	0\n"
		"gpr	sph	.8	37	0\n"
// status bit register (SREG)
		"gpr	sreg	.8	38	0\n"
		"gpr	cf	.1	38.0	0\n" // Carry. This is a borrow flag on subtracts.
		"gpr	zf	.1	38.1	0\n" // Zero. Set to 1 when an arithmetic result is zero.
		"gpr	nf	.1	38.2	0\n" // Negative. Set to a copy of the most significant bit of an arithmetic result.
		"gpr	vf	.1	38.3	0\n" // Overflow flag. Set in case of two's complement overflow.
		"gpr	sf	.1	38.4	0\n" // Sign flag. Unique to AVR, this is always (N ^ V) (xor), and shows the true sign of a comparison.
		"gpr	hf	.1	38.5	0\n" // Half carry. This is an internal carry from additions and is used to support BCD arithmetic.
		"gpr	tf	.1	38.6	0\n" // Bit copy. Special bit load and bit store instructions use this bit.
		"gpr	if	.1	38.7	0\n" // Interrupt flag. Set when interrupts are enabled.
// 8bit segment registers to be added to X, Y, Z to get 24bit offsets
		"gpr	rampx	.8	39	0\n"
		"gpr	rampy	.8	40	0\n"
		"gpr	rampz	.8	41	0\n"
		"gpr	rampd	.8	42	0\n"
		"gpr	eind	.8	43	0\n"
// memory mapping emulator registers
		"gpr	_prog	.32	44	0\n"
		"gpr	_eeprom	.32	48	0\n"
		"gpr	_io	.32	52	0\n"
		"gpr	_sram	.32	56	0\n"
		;

	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
	if (q == R_ANAL_ARCHINFO_ALIGN)
		return 2;
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE)
		return 4;
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE)
		return 2;
	return 2; // XXX
}

RAnalPlugin r_anal_plugin_avr = {
	.name = "avr",
	.desc = "AVR code analysis plugin",
	.license = "LGPL3",
	.arch = "avr",
	.esil = true,
	.archinfo = archinfo,
	.bits = 8 | 16, // 24 big regs conflicts
	.op = &avr_op,
	.set_reg_profile = &set_reg_profile,
	.esil_init = esil_avr_init,
	.esil_fini = esil_avr_fini,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_avr,
	.version = R2_VERSION
};
#endif
