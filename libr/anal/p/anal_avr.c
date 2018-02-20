/* radare - LGPL - Copyright 2011-2018 - pancake, Roc Valles, condret, killabyte */

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

static RDESContext desctx;

typedef struct _cpu_const_tag {
	const char *const key;
	ut8 type;
	ut32 value;
	ut8 size;
} CPU_CONST;

#define CPU_CONST_NONE	0
#define CPU_CONST_PARAM	1
#define CPU_CONST_REG	2

typedef struct _cpu_model_tag {
	const char *const model;
	int pc;
	char *inherit;
	struct _cpu_model_tag *inherit_cpu_p;
	CPU_CONST *consts[10];
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

#define CPU_MODEL_DECL(model, pc, consts)				\
	{								\
		model,							\
		pc,							\
		consts							\
	}
#define MASK(bits)			((bits) == 32 ? 0xffffffff : (~((~((ut32) 0)) << (bits))))
#define CPU_PC_MASK(cpu)		MASK((cpu)->pc)
#define CPU_PC_SIZE(cpu)		((((cpu)->pc) >> 3) + ((((cpu)->pc) & 0x07) ? 1 : 0))

#define INST_HANDLER(OPCODE_NAME)	static void _inst__ ## OPCODE_NAME (RAnal *anal, RAnalOp *op, const ut8 *buf, int *fail, CPU_MODEL *cpu)
#define INST_DECL(OP, M, SL, C, SZ, T)	{ #OP, (M), (SL), _inst__ ## OP, (C), (SZ), R_ANAL_OP_TYPE_ ## T }
#define INST_LAST			{ "unknown", 0, 0, (void *) 0, 2, 1, R_ANAL_OP_TYPE_UNK }

#define INST_CALL(OPCODE_NAME)		_inst__ ## OPCODE_NAME (anal, op, buf, fail, cpu)
#define INST_INVALID			{ *fail = 1; return; }
#define INST_ASSERT(x)			{ if (!(x)) { INST_INVALID; } }

#define ESIL_A(e, ...)			r_strbuf_appendf (&op->esil, e, ##__VA_ARGS__)

#define STR_BEGINS(in, s)		strncasecmp (in, s, strlen (s))

// Following IO definitions are valid for:
//	ATmega8
//	ATmega88
CPU_CONST cpu_reg_common[] = {
	{ "spl",    CPU_CONST_REG, 0x3d, sizeof (ut8) },
	{ "sph",    CPU_CONST_REG, 0x3e, sizeof (ut8) },
	{ "sreg",   CPU_CONST_REG, 0x3f, sizeof (ut8) },
	{ "spmcsr", CPU_CONST_REG, 0x37, sizeof (ut8) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_common[] = {
	{ "eeprom_size", CPU_CONST_PARAM,  512, sizeof (ut32) },
	{ "io_size",     CPU_CONST_PARAM, 0x40, sizeof (ut32) },
	{ "sram_start",  CPU_CONST_PARAM, 0x60, sizeof (ut32) },
	{ "sram_size",   CPU_CONST_PARAM, 1024, sizeof (ut32) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_m640_m1280m_m1281_m2560_m2561[] = {
	{ "eeprom_size", CPU_CONST_PARAM,    512, sizeof (ut32) },
	{ "io_size",     CPU_CONST_PARAM,  0x1ff, sizeof (ut32) },
	{ "sram_start",  CPU_CONST_PARAM,  0x200, sizeof (ut32) },
	{ "sram_size",   CPU_CONST_PARAM, 0x2000, sizeof (ut32) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_xmega128a4u[] = {
	{ "eeprom_size", CPU_CONST_PARAM,  0x800, sizeof (ut32) },
	{ "io_size",     CPU_CONST_PARAM, 0x1000, sizeof (ut32) },
	{ "sram_start",  CPU_CONST_PARAM,  0x800, sizeof (ut32) },
	{ "sram_size",   CPU_CONST_PARAM, 0x2000, sizeof (ut32) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_pagesize_5_bits[] = {
	{ "page_size", CPU_CONST_PARAM, 5, sizeof (ut8) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_pagesize_7_bits[] = {
	{ "page_size", CPU_CONST_PARAM, 7, sizeof (ut8) },
	{ NULL, 0, 0, 0 },
};

CPU_MODEL cpu_models[] = {
	{ .model = "ATmega640",   .pc = 15,
		.consts = {
			cpu_reg_common,
			cpu_memsize_m640_m1280m_m1281_m2560_m2561,
			cpu_pagesize_7_bits,
			NULL
		},
	},
	{
		.model = "ATxmega128a4u", .pc = 17,
		.consts = {
			cpu_reg_common,
			cpu_memsize_xmega128a4u,
			cpu_pagesize_7_bits,
			NULL
		}
	},
	{ .model = "ATmega1280",  .pc = 16, .inherit = "ATmega640" },
	{ .model = "ATmega1281",  .pc = 16, .inherit = "ATmega640" },
	{ .model = "ATmega2560",  .pc = 17, .inherit = "ATmega640" },
	{ .model = "ATmega2561",  .pc = 17, .inherit = "ATmega640" },
	{ .model = "ATmega88",    .pc = 8,  .inherit = "ATmega8" },
//	CPU_MODEL_DECL ("ATmega168",   13, 512, 512),
	// last model is the default AVR - ATmega8 forever!
	{
		.model = "ATmega8", .pc = 13,
		.consts = {
			cpu_reg_common,
			cpu_memsize_common,
			cpu_pagesize_5_bits,
			NULL
		}
	},
};

static CPU_MODEL *get_cpu_model(char *model);

static CPU_MODEL *__get_cpu_model_recursive(char *model) {
	CPU_MODEL *cpu = NULL;

	for (cpu = cpu_models; cpu < cpu_models + ((sizeof (cpu_models) / sizeof (CPU_MODEL))) - 1; cpu++) {
		if (!strcasecmp (model, cpu->model)) {
			break;
		}
	}

	// fix inheritance tree
	if (cpu->inherit && !cpu->inherit_cpu_p) {
		cpu->inherit_cpu_p = get_cpu_model (cpu->inherit);
		if (!cpu->inherit_cpu_p) {
			eprintf ("ERROR: Cannot inherit from unknown CPU model '%s'.\n", cpu->inherit);
		}
	}

	return cpu;
}

static CPU_MODEL *get_cpu_model(char *model) {
	static CPU_MODEL *cpu = NULL;

	// cached value?
	if (cpu && !strcasecmp (model, cpu->model))
		return cpu;

	// do the real search
	cpu = __get_cpu_model_recursive (model);

	return cpu;
}

static ut32 const_get_value(CPU_CONST *c) {
	return c ? MASK (c->size * 8) & c->value : 0;
}


static CPU_CONST *const_by_name(CPU_MODEL *cpu, int type, char *c) {
	CPU_CONST **clist, *citem;

	for (clist = cpu->consts; *clist; clist++) {
		for (citem = *clist; citem->key; citem++) {
			if (!strcmp (c, citem->key)
			&& (type == CPU_CONST_NONE || type == citem->type)) {
				return citem;
			}
		}
	}
	if (cpu->inherit_cpu_p)
		return const_by_name (cpu->inherit_cpu_p, type, c);
	eprintf ("ERROR: CONSTANT key[%s] NOT FOUND.\n", c);
	return NULL;
}

static int __esil_pop_argument(RAnalEsil *esil, ut64 *v) {
	char *t = r_anal_esil_pop (esil);
	if (!t || !r_anal_esil_get_parm (esil, t, v)) {
		free (t);
		return false;
	}
	free (t);
	return true;
}

static CPU_CONST *const_by_value(CPU_MODEL *cpu, int type, ut32 v) {
	CPU_CONST **clist, *citem;

	for (clist = cpu->consts; *clist; clist++) {
		for (citem = *clist; citem && citem->key; citem++) {
			if (citem->value == (MASK (citem->size * 8) & v)
			&& (type == CPU_CONST_NONE || type == citem->type)) {
				return citem;
			}
		}
	}
	if (cpu->inherit_cpu_p)
		return const_by_value (cpu->inherit_cpu_p, type, v);
	return NULL;
}

static RStrBuf *__generic_io_dest(ut8 port, int write, CPU_MODEL *cpu) {
	RStrBuf *r = r_strbuf_new ("");
	CPU_CONST *c = const_by_value (cpu, CPU_CONST_REG, port);
	if (c != NULL) {
		r_strbuf_set (r, c->key);
		if (write) {
			r_strbuf_append (r, ",=");
		}
	} else {
		r_strbuf_setf (r, "_io,%d,+,%s[1]", port, write ? "=" : "");
	}

	return r;
}

static void __generic_bitop_flags(RAnalOp *op) {
	ESIL_A ("0,vf,=,");					// V
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("vf,nf,^,sf,=,");				// S
}

static void __generic_ld_st(RAnalOp *op, char *mem, char ireg, int use_ramp, int prepostdec, int offset, int st) {
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

static void __generic_pop(RAnalOp *op, int sz) {
	if (sz > 1) {
		ESIL_A ("1,sp,+,_ram,+,");	// calc SRAM(sp+1)
		ESIL_A ("[%d],", sz);		// read value
		ESIL_A ("%d,sp,+=,", sz);	// sp += item_size
	} else {
		ESIL_A ("1,sp,+=,"		// increment stack pointer
			"sp,_ram,+,[1],");	// load SRAM[sp]
	}
}

static void __generic_push(RAnalOp *op, int sz) {
	ESIL_A ("sp,_ram,+,");			// calc pointer SRAM(sp)
	if (sz > 1) {
		ESIL_A ("-%d,+,", sz - 1);	// dec SP by 'sz'
	}
	ESIL_A ("=[%d],", sz);			// store value in stack
	ESIL_A ("-%d,sp,+=,", sz);		// decrement stack pointer
}

static void __generic_add_update_flags(RAnalOp *op, char t_d, ut64 v_d, char t_rk, ut64 v_rk) {
	RStrBuf *d_strbuf, *rk_strbuf;
	char *d, *rk;

	d_strbuf = r_strbuf_new (NULL);
	rk_strbuf = r_strbuf_new (NULL);
	r_strbuf_setf (d_strbuf,  t_d  == 'r' ? "r%d" : "%" PFMT64d, v_d);
	r_strbuf_setf (rk_strbuf, t_rk == 'r' ? "r%d" : "%" PFMT64d, v_rk);

	d = r_strbuf_get(d_strbuf);
	rk = r_strbuf_get(rk_strbuf);

	ESIL_A ("%s,0x08,&,!,!," "%s,0x08,&,!,!,"    "&,"	// H
		"%s,0x08,&,!,!," "0,RPICK,0x08,&,!," "&,"
		"%s,0x08,&,!,!," "0,RPICK,0x08,&,!," "&,"
		"|,|,hf,=,",
		d, rk, rk, d);
	ESIL_A ("%s,0x80,&,!,!," "%s,0x80,&,!,!,"      "&,"	// V
		""               "0,RPICK,0x80,&,!,"   "&,"
		"%s,0x80,&,!,"   "%s,0x80,&,!,"        "&,"
		""               "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, rk, d, rk);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	ESIL_A ("0,RPICK,!,zf,=,");				// Z
	ESIL_A ("%s,0x80,&,!,!," "%s,0x80,&,!,!,"    "&,"	// C
		"%s,0x80,&,!,!," "0,RPICK,0x80,&,!," "&,"
		"%s,0x80,&,!,!," "0,RPICK,0x80,&,!," "&,"
		"|,|,cf,=,",
		d, rk, rk, d);
	ESIL_A ("vf,nf,^,sf,=,");				// S

	r_strbuf_free (d_strbuf);
	r_strbuf_free (rk_strbuf);
}

static void __generic_add_update_flags_rr(RAnalOp *op, int d, int r) {
	__generic_add_update_flags(op, 'r', d, 'r', r);
}

static void __generic_sub_update_flags(RAnalOp *op, char t_d, ut64 v_d, char t_rk, ut64 v_rk, int carry) {
	RStrBuf *d_strbuf, *rk_strbuf;
	char *d, *rk;

	d_strbuf = r_strbuf_new (NULL);
	rk_strbuf = r_strbuf_new (NULL);
	r_strbuf_setf (d_strbuf,  t_d  == 'r' ? "r%d" : "%" PFMT64d, v_d);
	r_strbuf_setf (rk_strbuf, t_rk == 'r' ? "r%d" : "%" PFMT64d, v_rk);

	d = r_strbuf_get(d_strbuf);
	rk = r_strbuf_get(rk_strbuf);

	ESIL_A ("%s,0x08,&,!,"   "%s,0x08,&,!,!,"      "&,"	// H
		"%s,0x08,&,!,!," "0,RPICK,0x08,&,!,!," "&,"
		"%s,0x08,&,!,"   "0,RPICK,0x08,&,!,!," "&,"
		"|,|,hf,=,",
		d, rk, rk, d);
	ESIL_A ("%s,0x80,&,!,!," "%s,0x80,&,!,"        "&,"	// V
		""               "0,RPICK,0x80,&,!,"   "&,"
		"%s,0x80,&,!,"   "%s,0x80,&,!,!,"      "&,"
		""               "0,RPICK,0x80,&,!,!," "&,"
		"|,vf,=,",
		d, rk, d, rk);
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");			// N
	if (carry)
		ESIL_A ("0,RPICK,!,zf,&,zf,=,");		// Z
	else
		ESIL_A ("0,RPICK,!,zf,=,");			// Z
	ESIL_A ("%s,0x80,&,!,"   "%s,0x80,&,!,!,"      "&,"	// C
		"%s,0x80,&,!,!," "0,RPICK,0x80,&,!,!," "&,"
		"%s,0x80,&,!,"   "0,RPICK,0x80,&,!,!," "&,"
		"|,|,cf,=,",
		d, rk, rk, d);
	ESIL_A ("vf,nf,^,sf,=,");				// S

	r_strbuf_free (d_strbuf);
	r_strbuf_free (rk_strbuf);
}

static void __generic_sub_update_flags_rr(RAnalOp *op, int d, int r, int carry) {
	__generic_sub_update_flags(op, 'r', d, 'r', r, carry);
}

static void __generic_sub_update_flags_rk(RAnalOp *op, int d, int k, int carry) {
	__generic_sub_update_flags(op, 'r', d, 'k', k, carry);
}

INST_HANDLER (adc) {	// ADC Rd, Rr
			// ROL Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A ("r%d,cf,+,r%d,+,", r, d);		// Rd + Rr + C
	__generic_add_update_flags_rr(op, d, r);	// FLAGS
	ESIL_A ("r%d,=,", d);				// Rd = result
}

INST_HANDLER (add) {	// ADD Rd, Rr
			// LSL Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	ESIL_A ("r%d,r%d,+,", r, d);			// Rd + Rr
	__generic_add_update_flags_rr(op, d, r);	// FLAGS
	ESIL_A ("r%d,=,", d);				// Rd = result
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
	int k = ((buf[1] & 0x0f) << 4) | (buf[0] & 0x0f);
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
	op->fail = op->addr + op->size;
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
	op->fail = op->addr + op->size;
	op->cycles = cpu->pc <= 16 ? 3 : 4;
	if (!STR_BEGINS (cpu->model, "ATxmega")) {
		op->cycles--;	// AT*mega optimizes one cycle
	}
	ESIL_A ("pc,");				// esil is already pointing to
						// next instruction (@ret)
	__generic_push (op, CPU_PC_SIZE (cpu));	// push @ret in stack
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
	io_port = __generic_io_dest (a, 0, cpu);
	ESIL_A ("0xff,%d,1,<<,^,%s,&,", b, io_port);
	r_strbuf_free (io_port);

	// write result to port a
	io_port = __generic_io_dest (a, 1, cpu);
	ESIL_A ("%s,", r_strbuf_get (io_port));
	r_strbuf_free (io_port);
}

INST_HANDLER (com) {	// COM Rd
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 1) << 4);

	ESIL_A ("r%d,0xff,-,0xff,&,r%d,=,", r, r);		// Rd = 0xFF-Rd
								// FLAGS:
	ESIL_A ("0,cf,=,");					// C
	__generic_bitop_flags (op);				// ...rest...
}

INST_HANDLER (cp) {	// CP Rd, Rr
	int r = (buf[0]        & 0x0f) | ((buf[1] << 3) & 0x10);
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	ESIL_A ("r%d,r%d,-,", r, d);			// do Rd - Rr
	__generic_sub_update_flags_rr (op, d, r, 0);	// FLAGS (no carry)
}

INST_HANDLER (cpc) {	// CPC Rd, Rr
	int r = (buf[0]        & 0x0f) | ((buf[1] << 3) & 0x10);
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);

	ESIL_A ("cf,r%d,+,r%d,-,", r, d);		// Rd - Rr - C
	__generic_sub_update_flags_rr (op, d, r, 1);	// FLAGS (carry)
}

INST_HANDLER (cpi) { // CPI Rd, K
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = (buf[0] & 0xf) | ((buf[1] & 0xf) << 4);
	ESIL_A ("%d,r%d,-,", k, d);			// Rd - k
	__generic_sub_update_flags_rk (op, d, k, 0);	// FLAGS (carry)
}

INST_HANDLER (cpse) {	// CPSE Rd, Rr
	int r = (buf[0] & 0xf) | ((buf[1] & 0x2) << 3);
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
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
	if (desctx.round < 16) {	//DES
		op->type = R_ANAL_OP_TYPE_CRYPTO;
		op->cycles = 1;		//redo this
		r_strbuf_setf (&op->esil, "%d,des", desctx.round);
	}
}

INST_HANDLER (eijmp) {	// EIJMP
	ut64 z, eind;
	// read z and eind for calculating jump address on runtime
	r_anal_esil_reg_read (anal->esil, "z",    &z,    NULL);
	r_anal_esil_reg_read (anal->esil, "eind", &eind, NULL);
	// real target address may change during execution, so this value will
	// be changing all the time
	op->jump = ((eind << 16) + z) << 1;
	// jump
	ESIL_A ("1,z,16,eind,<<,+,<<,pc,=,");
	// cycles
	op->cycles = 2;
}

INST_HANDLER (eicall) {	// EICALL
	// push pc in stack
	ESIL_A ("pc,");				// esil is already pointing to
						// next instruction (@ret)
	__generic_push (op, CPU_PC_SIZE (cpu));	// push @ret in stack
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

INST_HANDLER (ijmp) {	// IJMP k
	ut64 z;
	// read z for calculating jump address on runtime
	r_anal_esil_reg_read (anal->esil, "z", &z, NULL);
	// real target address may change during execution, so this value will
	// be changing all the time
	op->jump = z << 1;
	op->cycles = 2;
	ESIL_A ("1,z,<<,pc,=,");		// jump!
}

INST_HANDLER (icall) {	// ICALL k
	// push pc in stack
	ESIL_A ("pc,");				// esil is already pointing to
						// next instruction (@ret)
	__generic_push (op, CPU_PC_SIZE (cpu));	// push @ret in stack
	// do a standard IJMP
	INST_CALL (ijmp);
	// fix cycles
	if (!STR_BEGINS (cpu->model, "ATxmega")) {
		// AT*mega optimizes 1 cycle!
		op->cycles--;
	}
}

INST_HANDLER (in) {	// IN Rd, A
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 0x01) << 4);
	int a = (buf[0] & 0x0f) | ((buf[1] & 0x6) << 3);
	RStrBuf *io_src = __generic_io_dest (a, 0, cpu);
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
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 0);	// 0: Read (RAMPZ:Z)
	ESIL_A ("r%d,0xff,^,&,", d);			// 0: (Z) & ~Rd
	ESIL_A ("DUP,r%d,=,", d);			// Rd = [0]
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 1);	// Store in RAM
}

INST_HANDLER (las) {	// LAS Z, Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 0);	// 0: Read (RAMPZ:Z)
	ESIL_A ("r%d,|,", d);				// 0: (Z) | Rd
	ESIL_A ("DUP,r%d,=,", d);			// Rd = [0]
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 1);	// Store in RAM
}

INST_HANDLER (lat) {	// LAT Z, Rd
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 0);	// 0: Read (RAMPZ:Z)
	ESIL_A ("r%d,^,", d);				// 0: (Z) ^ Rd
	ESIL_A ("DUP,r%d,=,", d);			// Rd = [0]
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 1);	// Store in RAM
}

INST_HANDLER (ld) {	// LD Rd, X
			// LD Rd, X+
			// LD Rd, -X
	// read memory
	__generic_ld_st (
		op, "ram",
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
		op, "ram",
		buf[0] & 0x8 ? 'y' : 'z',	// index register Y/Z
		0,				// no use RAMP* registers
		!(buf[1] & 0x10)
			? 0			// no increment
			: buf[0] & 0x1
				? 1		// post incremented
				: -1,		// pre decremented
		!(buf[1] & 0x10) ? offset : 0,	// offset or not offset
		0);				// load operation (!st)
	// load register
	ESIL_A ("r%d,=,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// cycles
	op->cycles =
		(buf[1] & 0x10) == 0
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
	__generic_ld_st (op, "ram", 0, 1, 0, k, 0);
	ESIL_A ("r%d,=,", d);
}

INST_HANDLER (sts) {	// STS k, Rr
	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	int k = (buf[3] << 8) | buf[2];

	ESIL_A ("r%d,", r);
	__generic_ld_st (op, "ram", 0, 1, 0, k, 1);

	op->cycles = 2;
}

#if 0
INST_HANDLER (lds16) {	// LDS Rd, k
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = (buf[0] & 0x0f)
		| ((buf[1] << 3) & 0x30)
		| ((buf[1] << 4) & 0x40)
		| (~(buf[1] << 4) & 0x80);

	// load value from @k
	__generic_ld_st (op, "ram", 0, 0, 0, k, 0);
	ESIL_A ("r%d,=,", d);
}
#endif

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
	RStrBuf *io_dst = __generic_io_dest (a, 1, cpu);
	op->type2 = 1;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;
	ESIL_A ("r%d,%s,", r, r_strbuf_get (io_dst));
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
		+ 2) & CPU_PC_MASK (cpu);
	op->fail = op->addr + op->size;
	// esil
	ESIL_A ("pc,");				// esil already points to next
						// instruction (@ret)
	__generic_push (op, CPU_PC_SIZE (cpu));	// push @ret addr
	ESIL_A ("%"PFMT64d",pc,=,", op->jump);	// jump!
	// cycles
	if (!strncasecmp (cpu->model, "ATtiny", 6)) {
		op->cycles = 4;	// ATtiny is always slow
	} else {
		// PC size decides required runtime!
		op->cycles = cpu->pc <= 16 ? 3 : 4;
		if (!STR_BEGINS (cpu->model, "ATxmega")) {
			op->cycles--;	// ATxmega optimizes one cycle
		}
	}
}

INST_HANDLER (ret) {	// RET
	op->eob = true;
	// esil
	__generic_pop (op, CPU_PC_SIZE (cpu));
	ESIL_A ("pc,=,");	// jump!
	// cycles
	if (CPU_PC_SIZE (cpu) > 2) {	// if we have a bus bigger than 16 bit
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
#ifdef _MSC_VER
#pragma message ("anal_avr.c: WARNING: Probably broken on windows")
		+ ((((( buf[1] & 0xf) << 9) | (buf[0] << 1)))
			| (buf[1] & 0x8 ? ~(0x1fff) : 0))
#else
		+ ((((( (typeof (op->jump)) buf[1] & 0xf) << 9) | ((typeof (op->jump)) buf[0] << 1)))
			| (buf[1] & 0x8 ? ~((typeof (op->jump)) 0x1fff) : 0))
#endif
		+ 2) & CPU_PC_MASK (cpu);
	ESIL_A ("%"PFMT64d",pc,=,", op->jump);
}

INST_HANDLER (ror) {	// ROR Rd
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	ESIL_A ("1,r%d,>>,7,cf,<<,|,", d);		// 0: (Rd>>1) | (cf<<7)
	ESIL_A ("r%d,1,&,cf,=,", d);			// C
	ESIL_A ("0,RPICK,!,zf,=,");			// Z
	ESIL_A ("0,RPICK,0x80,&,!,!,nf,=,");		// N
	ESIL_A ("nf,cf,^,vf,=,");			// V
	ESIL_A ("vf,nf,^,sf,=,");			// S
	ESIL_A ("r%d,=,", d);				// Rd = result
}

INST_HANDLER (sbc) {	// SBC Rd, Rr
	int r = (buf[0] & 0x0f) | ((buf[1] & 0x2) << 3);
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	ESIL_A ("cf,r%d,+,r%d,-,", r, d);		// 0: (Rd-Rr-C)
	__generic_sub_update_flags_rr (op, d, r, 1);	// FLAGS (carry)
	ESIL_A ("r%d,=,", d);				// Rd = Result
}

INST_HANDLER (sbci) {	// SBCI Rd, k
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = ((buf[1] & 0xf) << 4) | (buf[0] & 0xf);

	ESIL_A ("cf,%d,+,r%d,-,", k, d);		// 0: (Rd-k-C)
	__generic_sub_update_flags_rk (op, d, k, 1);	// FLAGS (carry)
	ESIL_A ("r%d,=,", d);				// Rd = Result
}

INST_HANDLER (sub) {	// SUB Rd, Rr
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);

	ESIL_A ("r%d,r%d,-,", r, d);			// 0: (Rd-k)
	__generic_sub_update_flags_rr (op, d, r, 0);	// FLAGS (no carry)
	ESIL_A ("r%d,=,", d);				// Rd = Result
}

INST_HANDLER (subi) {	// SUBI Rd, k
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = ((buf[1] & 0xf) << 4) | (buf[0] & 0xf);

	ESIL_A ("%d,r%d,-,", k, d);			// 0: (Rd-k)
	__generic_sub_update_flags_rk (op, d, k, 1);	// FLAGS (no carry)
	ESIL_A ("r%d,=,", d);				// Rd = Result
}

INST_HANDLER (sbi) {	// SBI A, b
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RStrBuf *io_port;

	op->type2 = 1;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;

	// read port a and clear bit b
	io_port = __generic_io_dest (a, 0, cpu);
	ESIL_A ("0xff,%d,1,<<,|,%s,&,", b, io_port);
	r_strbuf_free (io_port);

	// write result to port a
	io_port = __generic_io_dest (a, 1, cpu);
	ESIL_A ("%s,", r_strbuf_get (io_port));
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
	io_port = __generic_io_dest (a, 0, cpu);
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

INST_HANDLER (spm) {	// SPM Z+
	ut64 spmcsr;

	// read SPM Control Register (SPMCR)
	r_anal_esil_reg_read (anal->esil, "spmcsr", &spmcsr, NULL);

	// clear SPMCSR
	ESIL_A ("0x7c,spmcsr,&=,");

	// decide action depending on the old value of SPMCSR
	switch (spmcsr & 0x7f) {
		case 0x03: // PAGE ERASE
			// invoke SPM_CLEAR_PAGE (erases target page writing
			// the 0xff value
			ESIL_A ("16,rampz,<<,z,+,"); // push target address
			ESIL_A ("SPM_PAGE_ERASE,");  // do magic
			break;

		case 0x01: // FILL TEMPORARY BUFFER
			ESIL_A ("r1,r0,");           // push data
			ESIL_A ("z,");               // push target address
			ESIL_A ("SPM_PAGE_FILL,");   // do magic
			break;

		case 0x05: // WRITE PAGE
			ESIL_A ("16,rampz,<<,z,+,"); // push target address
			ESIL_A ("SPM_PAGE_WRITE,");  // do magic
			break;

		default:
			eprintf ("SPM: I dont know what to do with SPMCSR %02x.\n",
					(unsigned int) spmcsr);
	}

	op->cycles = 1;	// This is truly false. Datasheets do not publish how
			// many cycles this instruction uses in all its
			// operation modes and I am pretty sure that this value
			// can vary substantially from one MCU type to another.
			// So... one cycle is fine.
}

INST_HANDLER (st) {	// ST X, Rr
			// ST X+, Rr
			// ST -X, Rr
	// load register
	ESIL_A ("r%d,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// write in memory
	__generic_ld_st (
		op, "ram",
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
		op, "ram",
		buf[0] & 0x8 ? 'y' : 'z',	// index register Y/Z
		0,				// no use RAMP* registers
		!(buf[1] & 0x10)
			? 0			// no increment
			: buf[0] & 0x1
				? 1		// post incremented
				: -1,		// pre decremented
		!(buf[1] & 0x10)
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

INST_HANDLER (swap) {	// SWAP Rd
	int d = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	ESIL_A ("4,r%d,>>,0x0f,&,", d);		// (Rd >> 4) & 0xf
	ESIL_A ("4,r%d,<<,0xf0,&,", d);		// (Rd >> 4) & 0xf
	ESIL_A ("|,", d);			// S[0] | S[1]
	ESIL_A ("r%d,=,", d);			// Rd = result
}

OPCODE_DESC opcodes[] = {
	//         op      mask    select  cycles  size type
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
	INST_DECL (spm,    0xffff, 0x95e8, 1,      2,   TRAP   ), // SPM ...
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
	INST_DECL (sts,    0xfe0f, 0x9200, 2,      4,   STORE  ), // STS k, Rr
	INST_DECL (lpm,    0xfe0f, 0x9004, 3,      2,   LOAD   ), // LPM Rd, Z
	INST_DECL (lpm,    0xfe0f, 0x9005, 3,      2,   LOAD   ), // LPM Rd, Z+
	INST_DECL (lsr,    0xfe0f, 0x9406, 1,      2,   SHR    ), // LSR Rd
	INST_DECL (neg,    0xfe0f, 0x9401, 2,      2,   SUB    ), // NEG Rd
	INST_DECL (pop,    0xfe0f, 0x900f, 2,      2,   POP    ), // POP Rd
	INST_DECL (push,   0xfe0f, 0x920f, 0,      2,   PUSH   ), // PUSH Rr
	INST_DECL (ror,    0xfe0f, 0x9407, 1,      2,   SAR    ), // ROR Rd
	INST_DECL (st,     0xfe0f, 0x920c, 2,      2,   STORE  ), // ST X, Rr
	INST_DECL (st,     0xfe0f, 0x920d, 0,      2,   STORE  ), // ST X+, Rr
	INST_DECL (st,     0xfe0f, 0x920e, 0,      2,   STORE  ), // ST -X, Rr
	INST_DECL (swap,   0xfe0f, 0x9402, 1,      2,   SAR    ), // SWAP Rd
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
	INST_DECL (std,    0xfe07, 0x9201, 0,      2,   STORE  ), // ST Y/Z+, Rr
	INST_DECL (std,    0xfe07, 0x9202, 0,      2,   STORE  ), // ST -Y/Z, Rr
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
	INST_DECL (sub,    0xfc00, 0x1800, 1,      2,   SUB    ), // SUB Rd, Rr
	INST_DECL (in,     0xf800, 0xb000, 1,      2,   IO     ), // IN Rd, A
	//INST_DECL (lds16,  0xf800, 0xa000, 1,      2,   LOAD   ), // LDS Rd, k
	INST_DECL (out,    0xf800, 0xb800, 1,      2,   IO     ), // OUT A, Rr
	INST_DECL (andi,   0xf000, 0x7000, 1,      2,   AND    ), // ANDI Rd, K
	INST_DECL (cpi,    0xf000, 0x3000, 1,      2,   CMP    ), // CPI Rd, K
	INST_DECL (ldi,    0xf000, 0xe000, 1,      2,   LOAD   ), // LDI Rd, K
	INST_DECL (ori,    0xf000, 0x6000, 1,      2,   OR     ), // ORI Rd, K
	INST_DECL (rcall,  0xf000, 0xd000, 0,      2,   CALL   ), // RCALL k
	INST_DECL (rjmp,   0xf000, 0xc000, 2,      2,   JMP    ), // RJMP k
	INST_DECL (sbci,   0xf000, 0x4000, 1,      2,   SUB    ), // SBC Rd, Rr
	INST_DECL (subi,   0xf000, 0x5000, 1,      2,   SUB    ), // SUBI Rd, Rr
	INST_DECL (ldd,    0xd200, 0x8000, 0,      2,   LOAD   ), // LD Rd, Y/Z+q
	INST_DECL (std,    0xd200, 0x8200, 0,      2,   STORE  ), // ST Y/Z+q, Rr

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
			op->jump = UT64_MAX;
			op->fail = UT64_MAX;
			// op->fail = addr + op->size;
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
	ut64 offset;

	// init op
	if (!op) {
		return 2;
	}

	// select cpu info
	cpu = get_cpu_model (anal->cpu);

	// set memory layout registers
	if (anal->esil) {
		offset = 0;
		r_anal_esil_reg_write (anal->esil, "_prog", offset);

		offset += (1 << cpu->pc);
		r_anal_esil_reg_write (anal->esil, "_io", offset);

		offset += const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "sram_start"));
		r_anal_esil_reg_write (anal->esil, "_sram", offset);

		offset += const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "sram_size"));
		r_anal_esil_reg_write (anal->esil, "_eeprom", offset);

		offset += const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "eeprom_size"));
		r_anal_esil_reg_write (anal->esil, "_page", offset);
	}
	// process opcode
	avr_op_analyze (anal, op, addr, buf, cpu);

	return op->size;
}

static int avr_custom_des (RAnalEsil *esil) {
	ut64 key, encrypt, text,des_round;
	ut32 key_lo, key_hi, buf_lo, buf_hi;
	if (!esil || !esil->anal || !esil->anal->reg) {
		return false;
	}
	if (!__esil_pop_argument (esil, &des_round)) {
		return false;
	}
	r_anal_esil_reg_read (esil, "hf", &encrypt, NULL);
	r_anal_esil_reg_read (esil, "deskey", &key, NULL);
	r_anal_esil_reg_read (esil, "text", &text, NULL);

	key_lo = key & UT32_MAX;
	key_hi = key >> 32;
	buf_lo = text & UT32_MAX;
	buf_hi = text >> 32;

	if (des_round != desctx.round) {
		desctx.round = des_round;
	}

	if (!desctx.round) {
		int i;
		//generating all round keys
		r_des_permute_key (&key_lo, &key_hi);
		for (i = 0; i < 16; i++) {
			r_des_round_key (i, &desctx.round_key_lo[i], &desctx.round_key_hi[i], &key_lo, &key_hi);
		}
		r_des_permute_block0 (&buf_lo, &buf_hi);
	}

	if (encrypt) {
		r_des_round (&buf_lo, &buf_hi, &desctx.round_key_lo[desctx.round], &desctx.round_key_hi[desctx.round]);
	} else {
		r_des_round (&buf_lo, &buf_hi, &desctx.round_key_lo[15 - desctx.round], &desctx.round_key_hi[15 - desctx.round]);
	}

	if (desctx.round == 15) {
		r_des_permute_block1 (&buf_hi, &buf_lo);
		desctx.round = 0;
	} else {
		desctx.round++;
	}

	r_anal_esil_reg_write (esil, "text", text);
	return true;
}

// ESIL operation SPM_PAGE_ERASE
static int avr_custom_spm_page_erase(RAnalEsil *esil) {
	CPU_MODEL *cpu;
	ut8 c;
	ut64 addr, page_size_bits, i;

	// sanity check
	if (!esil || !esil->anal || !esil->anal->reg) {
		return false;
	}

	// get target address
	if (!__esil_pop_argument(esil, &addr)) {
		return false;
	}

	// get details about current MCU and fix input address
	cpu = get_cpu_model (esil->anal->cpu);
	page_size_bits = const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "page_size"));

	// align base address to page_size_bits
	addr &= ~(MASK (page_size_bits));

	// perform erase
	//eprintf ("SPM_PAGE_ERASE %ld bytes @ 0x%08" PFMT64x ".\n", page_size, addr);
	c = 0xff;
	for (i = 0; i < (1ULL << page_size_bits); i++) {
		r_anal_esil_mem_write (
			esil, (addr + i) & CPU_PC_MASK (cpu), &c, 1);
	}

	return true;
}

// ESIL operation SPM_PAGE_FILL
static int avr_custom_spm_page_fill(RAnalEsil *esil) {
	CPU_MODEL *cpu;
	ut64 addr, page_size_bits, i;
	ut8 r0, r1;

	// sanity check
	if (!esil || !esil->anal || !esil->anal->reg) {
		return false;
	}

	// get target address, r0, r1
	if (!__esil_pop_argument(esil, &addr)) {
		return false;
	}

	if (!__esil_pop_argument (esil, &i)) {
		return false;
	}
	r0 = i;

	if (!__esil_pop_argument (esil, &i)) {
		return false;
	}
	r1 = i;

	// get details about current MCU and fix input address
	cpu = get_cpu_model (esil->anal->cpu);
	page_size_bits = const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "page_size"));

	// align and crop base address
	addr &= (MASK (page_size_bits) ^ 1);

	// perform write to temporary page
	//eprintf ("SPM_PAGE_FILL bytes (%02x, %02x) @ 0x%08" PFMT64x ".\n", r1, r0, addr);
	r_anal_esil_mem_write (esil, addr++, &r0, 1);
	r_anal_esil_mem_write (esil, addr++, &r1, 1);

	return true;
}

// ESIL operation SPM_PAGE_WRITE
static int avr_custom_spm_page_write(RAnalEsil *esil) {
	CPU_MODEL *cpu;
	char *t = NULL;
	ut64 addr, page_size_bits, tmp_page;

	// sanity check
	if (!esil || !esil->anal || !esil->anal->reg) {
		return false;
	}

	// get target address
	if (!__esil_pop_argument (esil, &addr)) {
		return false;
	}

	// get details about current MCU and fix input address and base address
	// of the internal temporary page
	cpu = get_cpu_model (esil->anal->cpu);
	page_size_bits = const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "page_size"));
	r_anal_esil_reg_read (esil, "_page", &tmp_page, NULL);

	// align base address to page_size_bits
	addr &= (~(MASK (page_size_bits)) & CPU_PC_MASK (cpu));

	// perform writing
	//eprintf ("SPM_PAGE_WRITE %ld bytes @ 0x%08" PFMT64x ".\n", page_size, addr);
	if (!(t = malloc (1 << page_size_bits))) {
		eprintf ("Cannot alloc a buffer for copying the temporary page.\n");
		return false;
	}
	r_anal_esil_mem_read (esil, tmp_page, (ut8 *) t, 1 << page_size_bits);
	r_anal_esil_mem_write (esil, addr, (ut8 *) t, 1 << page_size_bits);

	return true;
}

static int esil_avr_hook_reg_write(RAnalEsil *esil, const char *name, ut64 *val) {
	CPU_MODEL *cpu;

	if (!esil || !esil->anal) {
		return 0;
	}

	// select cpu info
	cpu = get_cpu_model (esil->anal->cpu);

	// crop registers and force certain values
	if (!strcmp (name, "pc")) {
		*val &= CPU_PC_MASK (cpu);
	} else if (!strcmp (name, "pcl")) {
		if (cpu->pc < 8) {
			*val &= MASK (8);
		}
	} else if (!strcmp (name, "pch")) {
		*val = cpu->pc > 8
			? *val & MASK (cpu->pc - 8)
			: 0;
	}

	return 0;
}

static int esil_avr_init(RAnalEsil *esil) {
	if (!esil) {
		return false;
	}
	desctx.round = 0;
	r_anal_esil_set_op (esil, "des", avr_custom_des);
	r_anal_esil_set_op (esil, "SPM_PAGE_ERASE", avr_custom_spm_page_erase);
	r_anal_esil_set_op (esil, "SPM_PAGE_FILL", avr_custom_spm_page_fill);
	r_anal_esil_set_op (esil, "SPM_PAGE_WRITE", avr_custom_spm_page_write);
	esil->cb.hook_reg_write = esil_avr_hook_reg_write;

	return true;
}

static int esil_avr_fini(RAnalEsil *esil) {
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
		"gpr	r17:r16	.16	16	0\n"
		"gpr	r19:r18	.16	18	0\n"
		"gpr	r21:r20	.16	20	0\n"
		"gpr	r23:r22	.16	22	0\n"
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
//      _prog
//		the program flash. It has its own address space.
//	_ram
//	_io
//		start of the data addres space. It is the same address of IO,
//		because IO is the first memory space addressable in the AVR.
//	_sram
//		start of the SRAM (this offset depends on IO size, and it is
//		inside the _ram address space)
//      _eeprom
//              this is another address space, outside ram and flash
//      _page
//              this is the temporary page used by the SPM instruction. This
//              memory is not directly addressable and it is used internally by
//              the CPU when autoflashing.
		"gpr	_prog	.32	44	0\n"
		"gpr    _page   .32     48	0\n"
		"gpr	_eeprom	.32	52	0\n"
		"gpr	_ram	.32	56	0\n"
		"gpr	_io	.32	56	0\n"
		"gpr	_sram	.32	60	0\n"
// other important MCU registers
//	spmcsr/spmcr
//		Store Program Memory Control and Status Register (SPMCSR)
		"gpr    spmcsr  .8      64      0\n"
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
