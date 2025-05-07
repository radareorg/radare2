/* radare - LGPL - Copyright 2011-2024 - pancake, Roc Valles, condret, killabyte */

#if 0
http://www.atmel.com/images/atmel-0856-avr-instruction-set-manual.pdf
https://en.wikipedia.org/wiki/Atmel_AVR_instruction_set
#endif

#include <r_arch.h>
#include <r_anal.h>

#include "./disasm.h"
#include "./assemble.h"
#include "../crypto/p/des.inc.c"

typedef struct _cpu_const_tag {
	const char *const key;
	ut8 type;
	ut32 value;
	ut8 size;
} CPU_CONST;

#define CPU_CONST_NONE  0
#define CPU_CONST_PARAM 1
#define CPU_CONST_REG   2

typedef struct _cpu_model_tag {
	const char *const model;
	int pc;
	char *inherit;
	struct _cpu_model_tag *inherit_cpu_p;
	CPU_CONST *consts[10];
} CPU_MODEL;

typedef struct plugin_data_t {
	CPU_MODEL *cpu;
} PluginData;

typedef void (*inst_handler_t) (RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu);

typedef struct _opcodes_tag_ {
	const char *const name;
	int mask;
	int selector;
	inst_handler_t handler;
	int cycles;
	int size;
	ut64 type;
} OPCODE_DESC;

static OPCODE_DESC *avr_op_analyze(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, CPU_MODEL *cpu);

#define CPU_MODEL_DECL(model, pc, consts)\
	{\
		model,\
		pc,\
		consts\
	}
#define MASK(bits)       ((bits) == 32 ? 0xffffffff : (~((~((ut32)0)) << (bits))))
#define CPU_PC_MASK(cpu) MASK ((cpu)->pc)
#define CPU_PC_SIZE(cpu) cpu ? ((((cpu)->pc) >> 3) + ((((cpu)->pc) & 0x07) ? 1 : 0)) : 0

#define INST_CALL(OPCODE_NAME) _inst__##OPCODE_NAME (as, op, buf, len, fail, cpu)
#define INST_INVALID\
	{\
		*fail = 1;\
		return;\
	}
#define INST_ASSERT(x)\
	{\
		if (!(x)) {\
			INST_INVALID;\
		}\
	}

#define STR_BEGINS(in, s) r_str_ncasecmp (in, s, strlen (s))

// Following IO definitions are valid for:
//	ATmega8
//	ATmega88
CPU_CONST cpu_reg_common[] = {
	{ "spl", CPU_CONST_REG, 0x3d, sizeof (ut8) },
	{ "sph", CPU_CONST_REG, 0x3e, sizeof (ut8) },
	{ "sreg", CPU_CONST_REG, 0x3f, sizeof (ut8) },
	{ "spmcsr", CPU_CONST_REG, 0x37, sizeof (ut8) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_common[] = {
	{ "eeprom_size", CPU_CONST_PARAM, 512, sizeof (ut32) },
	{ "io_size", CPU_CONST_PARAM, 0x40, sizeof (ut32) },
	{ "sram_start", CPU_CONST_PARAM, 0x60, sizeof (ut32) },
	{ "sram_size", CPU_CONST_PARAM, 1024, sizeof (ut32) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_m640_m1280m_m1281_m2560_m2561[] = {
	{ "eeprom_size", CPU_CONST_PARAM, 512, sizeof (ut32) },
	{ "io_size", CPU_CONST_PARAM, 0x1ff, sizeof (ut32) },
	{ "sram_start", CPU_CONST_PARAM, 0x200, sizeof (ut32) },
	{ "sram_size", CPU_CONST_PARAM, 0x2000, sizeof (ut32) },
	{ NULL, 0, 0, 0 },
};

CPU_CONST cpu_memsize_xmega128a4u[] = {
	{ "eeprom_size", CPU_CONST_PARAM, 0x800, sizeof (ut32) },
	{ "io_size", CPU_CONST_PARAM, 0x1000, sizeof (ut32) },
	{ "sram_start", CPU_CONST_PARAM, 0x800, sizeof (ut32) },
	{ "sram_size", CPU_CONST_PARAM, 0x2000, sizeof (ut32) },
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
	{
		.model = "ATmega640",
		.pc = 15,
		.consts = {
			cpu_reg_common,
			cpu_memsize_m640_m1280m_m1281_m2560_m2561,
			cpu_pagesize_7_bits,
			NULL
		}
	},
	{
		.model = "ATmega1280",
		.pc = 16,
		.inherit = "ATmega640"
	},
	{
		.model = "ATmega1281",
		.pc = 16,
		.inherit = "ATmega640"
	},
	{
		.model = "ATmega2560",
		.pc = 17,
		.inherit = "ATmega640"
	},
	{
		.model = "ATmega2561",
		.pc = 17,
		.inherit = "ATmega640"
	},
	{
		.model = "ATmega88",
		.pc = 8,
		.inherit = "ATmega8"
	},
	{
		.model = "ATmega8",
		.pc = 13,
		.consts = {
			cpu_reg_common,
			cpu_memsize_common,
			cpu_pagesize_5_bits,
			NULL
		}
	},
	// last model is the default AVR
	{
		.model = "ATxmega128a4u",
		.pc = 17,
		.consts = {
			cpu_reg_common,
			cpu_memsize_xmega128a4u,
			cpu_pagesize_7_bits,
			NULL
		}
	}
	//{ .model = NULL },
};

/// XXX this code is awful
static CPU_MODEL *get_cpu_model(PluginData *pd, const char *model);

static CPU_MODEL *__get_cpu_model_recursive(PluginData *pd, const char *model) {
	CPU_MODEL *cpu = NULL;
	for (cpu = cpu_models; cpu < cpu_models + ((sizeof (cpu_models) / sizeof (CPU_MODEL))) - 1; cpu++) {
		if (!r_str_casecmp (model, cpu->model)) {
			break;
		}
	}
	// fix inheritance tree
	if (cpu && cpu->inherit && !cpu->inherit_cpu_p) {
		cpu->inherit_cpu_p = get_cpu_model (pd, cpu->inherit);
		if (!cpu->inherit_cpu_p) {
			R_LOG_ERROR ("Cannot inherit from unknown CPU model '%s'", cpu->inherit);
		}
	}
	return cpu;
}

static CPU_MODEL *get_cpu_model(PluginData *pd, const char *model) {
	if (!model) {
		model = "ATmega8";
	}
	// cache
	if (pd->cpu && pd->cpu->model && !r_str_casecmp (model, pd->cpu->model)) {
		return pd->cpu;
	}

	pd->cpu = __get_cpu_model_recursive (pd, model);
	return pd->cpu;
}

static ut32 const_get_value(CPU_CONST *c) {
	return c ? MASK (c->size * 8) & c->value : 0;
}

static CPU_CONST *const_by_name(CPU_MODEL *cpu, int type, char *c) {
	CPU_CONST **clist, *citem;
	if (!cpu) {
		return NULL;
	}

	for (clist = cpu->consts; *clist; clist++) {
		for (citem = *clist; citem->key; citem++) {
			if (!strcmp (c, citem->key) && (type == CPU_CONST_NONE || type == citem->type)) {
				return citem;
			}
		}
	}
	if (cpu->inherit_cpu_p) {
		return const_by_name (cpu->inherit_cpu_p, type, c);
	}
	R_LOG_ERROR ("CONSTANT key[%s] NOT FOUND", c);
	return NULL;
}

static int __esil_pop_argument(REsil *esil, ut64 *v) {
	char *t = r_esil_pop (esil);
	if (!t || !r_esil_get_parm (esil, t, v)) {
		free (t);
		return false;
	}
	free (t);
	return true;
}

static CPU_CONST *const_by_value(CPU_MODEL *cpu, int type, ut32 v) {
	CPU_CONST **clist, *citem;
	if (!cpu) {
		return NULL;
	}
	for (clist = cpu->consts; *clist; clist++) {
		for (citem = *clist; citem && citem->key; citem++) {
			if (citem->value == (MASK (citem->size * 8) & v) && (type == CPU_CONST_NONE || type == citem->type)) {
				return citem;
			}
		}
	}
	if (cpu->inherit_cpu_p) {
		return const_by_value (cpu->inherit_cpu_p, type, v);
	}
	return NULL;
}

static RStrBuf *__generic_io_dest(ut8 port, int write, CPU_MODEL *cpu) {
	RStrBuf *r = r_strbuf_new ("");
	CPU_CONST *c = const_by_value (cpu, CPU_CONST_REG, port);
	if (c) {
		r_strbuf_set (r, c->key);
		if (write) {
			r_strbuf_append (r, ",=");
		}
	} else {
		r_strbuf_setf (r, "_io,%d,+,%s[1]", port, write ? "=" : "");
	}

	return r;
}

static void __generic_ld_st(RAnalOp *op, char *mem, char ireg, int use_ramp, int prepostdec, int offset, int st) {
	if (ireg) {
		// preincrement index register
		if (prepostdec < 0) {
			r_strbuf_appendf (&op->esil, "1,%c,-,%c,=,", ireg, ireg);
		}
		// set register index address
		r_strbuf_appendf (&op->esil, "%c,", ireg);
		// add offset
		if (offset != 0) {
			r_strbuf_appendf (&op->esil, "%d,+,", offset);
		}
	} else {
		r_strbuf_appendf (&op->esil, "%d,", offset);
	}
	if (use_ramp) {
		r_strbuf_appendf (&op->esil, "16,ramp%c,<<,+,", ireg? ireg: 'd');
	}
	// set SRAM base address
	r_strbuf_appendf (&op->esil, "_%s,+,", mem);
	// read/write from SRAM
	r_strbuf_appendf (&op->esil, "%s[1],", st ? "=" : "");
	// postincrement index register
	if (ireg && prepostdec > 0) {
		r_strbuf_appendf (&op->esil, "1,%c,+,%c,=,", ireg, ireg);
	}
}

static void __generic_pop(RAnalOp *op, int sz) {
	if (sz > 1) {
		r_strbuf_append (&op->esil, "1,sp,+,_ram,+,"); //calc SRAM(sp+1)
		r_strbuf_appendf (&op->esil, "[%d],", sz);	//read value
		r_strbuf_appendf (&op->esil, "%d,sp,+=,", sz);	//sp += item_size
	} else {
		r_strbuf_append (&op->esil, "1,sp,+=,"		//increment stack pointer
					     "sp,_ram,+,[1],"); //load SRAM[sp]
	}
}

static void __generic_push(RAnalOp *op, int sz) {
	r_strbuf_append (&op->esil, "sp,_ram,+,"); // calc pointer SRAM(sp)
	if (sz > 1) {
		r_strbuf_appendf (&op->esil, "-%d,+,", sz - 1); // dec SP by 'sz'
	}
	r_strbuf_appendf (&op->esil, "=[%d],", sz); // store value in stack
	r_strbuf_appendf (&op->esil, "-%d,sp,+=,", sz); // decrement stack pointer
}

static void _inst__adc(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ADC Rd, Rr
	// ROL Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	r_strbuf_appendf (&op->esil, "r%d,cf,+,r%d,+=,", r, d); // Rd + Rr + C
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$c,hf,:=,");
	r_strbuf_append (&op->esil, "7,$c,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_appendf (&op->esil, "0x80,r%d,&,!,!,nf,:=", d);
}

static void _inst__add(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ADD Rd, Rr
	// LSL Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	r_strbuf_appendf (&op->esil, "r%d,r%d,+=,", r, d); // Rd + Rr
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$c,hf,:=,");
	r_strbuf_append (&op->esil, "7,$c,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_appendf (&op->esil, "0x80,r%d,&,!,!,nf,:=,", d);
}

static void _inst__adiw(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ADIW Rd+1:Rd, K
	if (len < 1) {
		return;
	}
	const ut32 d = ((buf[0] & 0x30) >> 3) + 24;
	const ut32 k = (buf[0] & 0x0f) | ((buf[0] >> 2) & 0x30);
	op->val = k;
	r_strbuf_appendf (&op->esil, "%d,r%d_r%d,+=,", k, d + 1, d); // Rd+1_Rd + k
								     // FLAGS:
	r_strbuf_append (&op->esil, "7,$o,vf,:=,"); // V
	r_strbuf_appendf (&op->esil, "r%d_r%d,0x8000,&,!,!,nf,:=,", d + 1, d); // N
	r_strbuf_append (&op->esil, "$z,zf,:=,"); // Z
	r_strbuf_append (&op->esil, "15,$c,cf,:=,"); // C
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:="); // S
}

static void _inst__and(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// AND Rd, Rr
	// TST Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	r_strbuf_appendf (&op->esil, "r%d,r%d,&=,$z,zf,:=,r%d,0x80,&,!,!,nf,:=,0,vf,:=,nf,sf,:=,", r, d, d);
}

static void _inst__andi(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ANDI Rd, K
	// CBR Rd, K (= ANDI Rd, 1-K)
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = ((buf[1] & 0x0f) << 4) | (buf[0] & 0x0f);
	op->val = k;
	r_strbuf_appendf (&op->esil, "%d,r%d,&=,$z,zf,:=,r%d,0x80,&,!,!,nf,:=,0,vf,:=,nf,sf,:=,", k, d, d);
}

static void _inst__asr(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ASR Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	r_strbuf_appendf (&op->esil, "r%d,0x1,&,cf,:=,0x1,r%d,>>,r%d,0x80,&,|,", d, d, d);
	// 0: R=(Rd >> 1) | Rd7
	r_strbuf_append (&op->esil, "$z,zf,:=,"); // Z
	r_strbuf_appendf (&op->esil, "r%d,0x80,&,!,!,nf,:=,", d); // N
	r_strbuf_append (&op->esil, "nf,cf,^,vf,:=,"); // V
	r_strbuf_append (&op->esil, "nf,vf,^,sf,:=,"); // S
}

static void _inst__bclr(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// BCLR s
	// CLC
	// CLH
	// CLI
	// CLN
	// CLR
	// CLS
	// CLT
	// CLV
	// CLZ
	if (len < 1) {
		return;
	}
	int s = (buf[0] >> 4) & 0x7;
	r_strbuf_appendf (&op->esil, "0xff,%d,1,<<,^,sreg,&=,", s);
}

static void _inst__bld(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// BLD Rd, b
	if (len < 2) {
		return;
	}
	int d = ((buf[1] & 0x01) << 4) | ((buf[0] >> 4) & 0xf);
	int b = buf[0] & 0x7;
	r_strbuf_appendf (&op->esil, "r%d,%d,1,<<,0xff,^,&,", d, b); // Rd/b = 0
	r_strbuf_appendf (&op->esil, "%d,tf,<<,|,r%d,=,", b, d); // Rd/b |= T<<b
}

static void _inst__brbx(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// BRBC s, k
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
	if (len < 2) {
		return;
	}
	int s = buf[0] & 0x7;
	op->jump = (op->addr + ((((buf[1] & 0x03) << 6) |
		((buf[0] & 0xf8) >> 2)) | (buf[1] & 0x2? ~((int)0x7f): 0)) + 2) & CPU_PC_MASK (cpu);
	op->fail = op->addr + op->size;
	op->cycles = 1; // XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to true, this instruction
			// needs 2 cycles, elsewhere it needs only 1 cycle.
	r_strbuf_appendf (&op->esil, "%d,1,<<,sreg,&,", s); // SREG(s)
	r_strbuf_append (&op->esil, buf[1] & 0x4 ? "!," // BRBC => branch if cleared
						  : "!,!,"); // BRBS => branch if set
	r_strbuf_appendf (&op->esil, "?{,0x%"PFMT64x",pc,:=,},", op->jump); // ?true => jmp
}

static void _inst__break(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// BREAK
	r_strbuf_append (&op->esil, "BREAK");
}

static void _inst__bset(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// BSET s
	// SEC
	// SEH
	// SEI
	// SEN
	// SER
	// SES
	// SET
	// SEV
	// SEZ
	if (len < 1) {
		return;
	}
	int s = (buf[0] >> 4) & 0x7;
	r_strbuf_appendf (&op->esil, "%d,1,<<,sreg,|=,", s);
}

static void _inst__bst(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// BST Rd, b
	if (len < 2) {
		return;
	}
	r_strbuf_appendf (&op->esil, "r%d,%d,1,<<,&,!,!,tf,=,", // tf = Rd/b
		((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf), // r
		buf[0] & 0x7); // b
}

static void _inst__call(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// CALL k
	if (len < 4) {
		return;
	}
	op->jump = ((buf[2] << 1) | (buf[3] << 9) | (buf[1] & 0x01) << 23 |
		(buf[0] & 0x01) << 17 | (buf[0] & 0xf0) << 14) & (cpu? CPU_PC_MASK (cpu): 0x1ffff);
	op->fail = op->addr + op->size;
	if (cpu) {
		op->cycles = cpu->pc <= 16 ? 3 : 4;
		if (!STR_BEGINS (cpu->model, "ATxmega")) {
			op->cycles--; // AT*mega optimizes one cycle
		}
		r_strbuf_append (&op->esil, "pc,");	// esil is already pointing to
							// next instruction (@ret)
		__generic_push (op, CPU_PC_SIZE (cpu)); // push @ret in stack
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x",pc,:=,", op->jump); // jump!
	} else {
		op->cycles = 1;
	}
}

static void _inst__cbi(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// CBI A, b
	if (len < 1) {
		return;
	}
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RStrBuf *io_port;

	op->family = R_ANAL_OP_FAMILY_IO;
	op->type2 = 1;
	op->val = a;

	// read port a and clear bit b
	io_port = __generic_io_dest (a, 0, cpu);
	r_strbuf_appendf (&op->esil, "0xff,%d,1,<<,^,%s,&,", b, r_strbuf_tostring (io_port));
	r_strbuf_free (io_port);

	// write result to port a
	io_port = __generic_io_dest (a, 1, cpu);
	r_strbuf_appendf (&op->esil, "%s,", r_strbuf_tostring (io_port));
	r_strbuf_free (io_port);
}

static void _inst__com(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// COM Rd
	if (len < 2) {
		return;
	}
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 1) << 4);

	r_strbuf_appendf (&op->esil, "r%d,0xff,-,r%d,=,$z,zf,:=,0,cf,:=,0,vf,:=,r%d,0x80,&,!,!,nf,:=,vf,nf,^,sf,:=", r, r, r);
	// Rd = 0xFF-Rd
}

static void _inst__cp(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// CP Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 r = (buf[0] & 0x0f) | ((buf[1] << 3) & 0x10);
	const ut32 d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	r_strbuf_appendf (&op->esil, "r%d,r%d,-,0x80,&,!,!,nf,:=,", r, d);
	r_strbuf_appendf (&op->esil, "r%d,r%d,==,", r, d);
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$b,hf,:=,");
	r_strbuf_append (&op->esil, "8,$b,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=");
}

static void _inst__cpc(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// CPC Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 r = (buf[0] & 0x0f) | ((buf[1] << 3) & 0x10);
	const ut32 d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);

	r_strbuf_appendf (&op->esil, "cf,r%d,+,DUP,r%d,-,0x80,&,!,!,nf,:=,", r, d); // Rd - Rr - C
	r_strbuf_appendf (&op->esil, "r%d,==,", d);
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$b,hf,:=,");
	r_strbuf_append (&op->esil, "8,$b,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=");
}

static void _inst__cpi(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// CPI Rd, K
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = (buf[0] & 0xf) | ((buf[1] & 0xf) << 4);
	r_strbuf_appendf (&op->esil, "%d,r%d,-,0x80,&,!,!,nf,:=,", k, d); // Rd - k
	r_strbuf_appendf (&op->esil, "%d,r%d,==,", k, d);
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$b,hf,:=,");
	r_strbuf_append (&op->esil, "8,$b,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=");
}

static void _inst__cpse(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// CPSE Rd, Rr
	if (len < 2) {
		return;
	}
	int r = (buf[0] & 0xf) | ((buf[1] & 0x2) << 3);
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	RAnalOp next_op = { 0 };

	// calculate next instruction size (call recursively avr_op_analyze)
	// and free next_op's esil string (we dont need it now)
	avr_op_analyze (as,
		&next_op,
		op->addr + op->size, buf + op->size, len - op->size,
		cpu);
	r_strbuf_fini (&next_op.esil);
	op->jump = (op->addr + next_op.size + 2) & CPU_PC_MASK (cpu);
	op->fail = op->addr + 2;

	// cycles
	op->cycles = 1; // XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to true, this instruction
			// needs 2/3 cycles, elsewhere it needs only 1 cycle.
	r_strbuf_appendf (&op->esil, "r%d,r%d,^,!,", r, d); // Rr == Rd
	r_strbuf_appendf (&op->esil, "?{,0x%"PFMT64x",pc,:=,},", op->jump); // ?true => jmp
}

static void _inst__dec(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// DEC Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	r_strbuf_appendf (&op->esil, "0x1,r%d,-=,", d); // Rd--
							// FLAGS:
	r_strbuf_append (&op->esil, "7,$o,vf,:=,"); // V
	r_strbuf_appendf (&op->esil, "r%d,0x80,&,!,!,nf,:=,", d); // N
	r_strbuf_append (&op->esil, "$z,zf,:=,"); // Z
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=,"); // S
}

static void _inst__des(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// DES k
	op->type = R_ANAL_OP_TYPE_CRYPTO;
	op->cycles = 1; // redo this
	// <text>,<deskey><encrypt>,<round>,des,<text>,:=
	r_strbuf_setf (&op->esil, "text,deskey,hf,%d,des,text,:=", buf[0] >> 4);
}

static void _inst__eijmp(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	r_strbuf_appendf (&op->esil, "1,z,16,eind,<<,+,<<,0x%x,&,pc,:=,", CPU_PC_MASK (cpu));
	// cycles
	op->cycles = 2;
}

static void _inst__eicall(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// EICALL
	// push pc in stack
	r_strbuf_set (&op->esil, "pc,");
	__generic_push (op, CPU_PC_SIZE (cpu));	// push @ret in stack
	// do a standard EIJMP
	INST_CALL (eijmp);
	// fix cycles
	op->cycles = !STR_BEGINS (cpu->model, "ATxmega")? 3: 4;
}

static void _inst__elpm(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ELPM
	// ELPM Rd
	// ELPM Rd, Z+
	if (len < 2) {
		return;
	}
	int d = ((buf[1] & 0xfe) == 0x90)
		? ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf) // Rd
		: 0; // R0
	r_strbuf_append (&op->esil, "16,rampz,<<,z,+,_prog,+,[1],"); // read RAMPZ:Z
	r_strbuf_appendf (&op->esil, "r%d,=,", d); // Rd = [1]
	if ((buf[1] & 0xfe) == 0x90 && (buf[0] & 0xf) == 0x7) {
		r_strbuf_append (&op->esil, "16,1,z,+,DUP,z,=,>>,1,&,rampz,+=,"); // ++(rampz:z)
	}
}

static void _inst__eor(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// EOR Rd, Rr
	// CLR Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	r_strbuf_appendf (&op->esil, "r%d,r%d,^=,$z,zf,:=,0,vf,:=,r%d,0x80,&,!,!,nf,:=,nf,sf,:=", r, d, d);
	// 0: Rd ^= Rr
}

static void _inst__fmul(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// FMUL Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0x7) + 16;
	const ut32 r = (buf[0] & 0x7) + 16;

	r_strbuf_appendf (&op->esil, "0xffff,1,r%d,r%d,*,<<,&,r1_r0,=,", r, d); // 0: r1_r0 = (rd * rr) << 1
	r_strbuf_append (&op->esil, "r1_r0,0x8000,&,!,!,cf,:=,"); // C = R/15
	r_strbuf_append (&op->esil, "$z,zf,:="); // Z = !R
}

static void _inst__fmuls(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// FMULS Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0x7) + 16;
	const ut32 r = (buf[0] & 0x7) + 16;

	r_strbuf_append (&op->esil, "1,");
	r_strbuf_appendf (&op->esil, "r%d,DUP,0x80,&,?{,0xff00,|,},", d); // sign extension Rd
	r_strbuf_appendf (&op->esil, "r%d,DUP,0x80,&,?{,0xff00,|,},", r); // sign extension Rr
	r_strbuf_append (&op->esil, "*,<<,r1_r0,=,"); // 0: (Rd*Rr)<<1

	r_strbuf_append (&op->esil, "r1_r0,0x8000,&,!,!,cf,:=,"); // C = R/16
	r_strbuf_append (&op->esil, "$z,zf,:="); // Z = !R
}

static void _inst__fmulsu(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// FMULSU Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0x7) + 16;
	const ut32 r = (buf[0] & 0x7) + 16;

	r_strbuf_append (&op->esil, "1,");
	r_strbuf_appendf (&op->esil, "r%d,DUP,0x80,&,?{,0xff00,|,},", d); // sign extension Rd
	r_strbuf_appendf (&op->esil, "r%d,*,<<,r1_r0,=,", r); // 0: (Rd*Rr)<<1

	r_strbuf_append (&op->esil, "r1_r0,0x8000,&,!,!,cf,:=,"); // C = R/16
	r_strbuf_append (&op->esil, "$z,zf,:="); // Z = !R
}

static void _inst__ijmp(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// IJMP k
	op->cycles = 2;
	r_strbuf_appendf (&op->esil, "1,z,<<,0x%x,&,pc,:=,", CPU_PC_MASK (cpu)); // jump!
}

static void _inst__icall(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ICALL k
	// push pc in stack
	r_strbuf_set (&op->esil, "pc,");
	__generic_push (op, CPU_PC_SIZE (cpu)); // push @ret in stack
	// do a standard IJMP
	INST_CALL (ijmp);
	// fix cycles
	if (!STR_BEGINS (cpu->model, "ATxmega")) {
		// AT*mega optimizes 1 cycle!
		op->cycles--;
	}
}

static void _inst__in(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// IN Rd, A
	if (len < 2) {
		return;
	}
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 0x01) << 4);
	int a = (buf[0] & 0x0f) | ((buf[1] & 0x6) << 3);
	RStrBuf *io_src = __generic_io_dest (a, 0, cpu);
	op->type2 = 0;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;
	r_strbuf_appendf (&op->esil, "%s,r%d,=,", r_strbuf_tostring (io_src), r);
	r_strbuf_free (io_src);
}

static void _inst__inc(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// INC Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	r_strbuf_appendf (&op->esil, "1,r%d,+=,", d); // Rd++
						      // FLAGS:
	r_strbuf_append (&op->esil, "7,$o,vf,:=,"); // V
	r_strbuf_appendf (&op->esil, "r%d,0x80,&,!,!,nf,:=,", d); // N
	r_strbuf_append (&op->esil, "$z,zf,:=,"); // Z
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=,"); // S
}

static void _inst__jmp(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// JMP k
	if (len < 4) {
		return;
	}
	op->jump = ((buf[2] << 1) | (buf[3] << 9) | (buf[1] & 0x01) << 23 |
		(buf[0] & 0x01) << 17 | (buf[0] & 0xf0) << 14) & CPU_PC_MASK (cpu);
	op->cycles = 3;
	r_strbuf_appendf (&op->esil, "0x%"PFMT64x",pc,:=,", op->jump); // jump!
}

static void _inst__lac(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LAC Z, Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 0); // 0: Read (RAMPZ:Z)
	r_strbuf_appendf (&op->esil, "r%d,0xff,^,&,", d); // 0: (Z) & ~Rd
	r_strbuf_appendf (&op->esil, "DUP,r%d,=,", d); // Rd = [0]
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 1); // Store in RAM
}

static void _inst__las(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LAS Z, Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 0); // 0: Read (RAMPZ:Z)
	r_strbuf_appendf (&op->esil, "r%d,|,", d); // 0: (Z) | Rd
	r_strbuf_appendf (&op->esil, "DUP,r%d,=,", d); // Rd = [0]
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 1); // Store in RAM
}

static void _inst__lat(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LAT Z, Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	// read memory from RAMPZ:Z
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 0); // 0: Read (RAMPZ:Z)
	r_strbuf_appendf (&op->esil, "r%d,^,", d); // 0: (Z) ^ Rd
	r_strbuf_appendf (&op->esil, "DUP,r%d,=,", d); // Rd = [0]
	__generic_ld_st (op, "ram", 'z', 1, 0, 0, 1); // Store in RAM
}

static void _inst__ld(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LD Rd, X
	// LD Rd, X+
	// LD Rd, -X
	if (len < 2) {
		return;
	}
	// read memory
	__generic_ld_st (
		op, "ram",
		'x', // use index register X
		0, // no use RAMP* registers
		(buf[0] & 0xf) == 0xe
			? -1 // pre decremented
			: (buf[0] & 0xf) == 0xd
			? 1 // post incremented
			: 0, // no increment
		0, // offset always 0
		0); // load operation (!st)
	// load register
	r_strbuf_appendf (&op->esil, "r%d,=,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// cycles
	op->cycles = (buf[0] & 0x3) == 0
		? 2 // LD Rd, X
		: (buf[0] & 0x3) == 1
		? 2 // LD Rd, X+
		: 3; // LD Rd, -X
	if (!STR_BEGINS (cpu->model, "ATxmega") && op->cycles > 1) {
		// AT*mega optimizes 1 cycle!
		op->cycles--;
	}
}

static void _inst__ldd(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LD Rd, Y	LD Rd, Z
	// LD Rd, Y+	LD Rd, Z+
	// LD Rd, -Y	LD Rd, -Z
	// LD Rd, Y+q	LD Rd, Z+q
	if (len < 2) {
		return;
	}
	// calculate offset (this value only has sense in some opcodes,
	// but we are optimistic and we calculate it always)
	int offset = (buf[1] & 0x20) | ((buf[1] & 0xc) << 1) | (buf[0] & 0x7);
	// read memory
	__generic_ld_st (
		op, "ram",
		buf[0] & 0x8 ? 'y' : 'z', // index register Y/Z
		0, // no use RAMP* registers
		!(buf[1] & 0x10)
			? 0 // no increment
			: buf[0] & 0x1
			? 1 // post incremented
			: -1, // pre decremented
		!(buf[1] & 0x10) ? offset : 0, // offset or not offset
		0); // load operation (!st)
	// load register
	r_strbuf_appendf (&op->esil, "r%d,=,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// cycles
	op->cycles =
		(buf[1] & 0x10) == 0
		? (!offset ? 1 : 3) // LDD
		: (buf[0] & 0x3) == 0
		? 1 // LD Rd, X
		: (buf[0] & 0x3) == 1
		? 2 // LD Rd, X+
		: 3; // LD Rd, -X
	if (!STR_BEGINS (cpu->model, "ATxmega") && op->cycles > 1) {
		// AT*mega optimizes 1 cycle!
		op->cycles--;
	}
}

static void _inst__ldi(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LDI Rd, K
	if (len < 2) {
		return;
	}
	int k = (buf[0] & 0xf) + ((buf[1] & 0xf) << 4);
	int d = ((buf[0] >> 4) & 0xf) + 16;
	op->val = k;
	r_strbuf_appendf (&op->esil, "0x%x,r%d,=,", k, d);
}

static void _inst__lds(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LDS Rd, k
	if (len < 4) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	int k = (buf[3] << 8) | buf[2];
	op->ptr = k;

	// load value from RAMPD:k
	__generic_ld_st (op, "ram", 0, 1, 0, k, 0);
	r_strbuf_appendf (&op->esil, "r%d,=,", d);
}

static void _inst__sts(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// STS k, Rr
	if (len < 4) {
		return;
	}
	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	int k = (buf[3] << 8) | buf[2];
	op->ptr = k;

	r_strbuf_appendf (&op->esil, "r%d,", r);
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
	op->ptr = k;

	// load value from @k
	__generic_ld_st (op, "ram", 0, 0, 0, k, 0);
	r_strbuf_appendf (&op->esil, "r%d,=,", d);
}
#endif

static void _inst__lpm(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LPM
	// LPM Rd, Z
	// LPM Rd, Z+
	if (len < 2) {
		return;
	}
	ut16 ins = (((ut16)buf[1]) << 8) | ((ut16)buf[0]);
	// read program memory
	__generic_ld_st (
		op, "prog",
		'z', // index register Y/Z
		1, // use RAMP* registers
		(ins & 0xfe0f) == 0x9005
			? 1 // post incremented
			: 0, // no increment
		0, // not offset
		0); // load operation (!st)
	// load register
	r_strbuf_appendf (&op->esil, "r%d,=,",
		(ins == 0x95c8)
			? 0 // LPM (r0)
			: ((buf[0] >> 4) & 0xf) // LPM Rd
				| ((buf[1] & 0x1) << 4));
}

static void _inst__lsr(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// LSR Rd
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	r_strbuf_appendf (&op->esil, "r%d,0x1,&,cf,:=,", d); // C = Rd0
	r_strbuf_appendf (&op->esil, "1,r%d,>>=,", d); // 0: R=(Rd >> 1)
	r_strbuf_append (&op->esil, "$z,zf,:=,"); // Z
	r_strbuf_append (&op->esil, "0,nf,:=,"); // N
	r_strbuf_append (&op->esil, "cf,vf,:=,"); // V
	r_strbuf_append (&op->esil, "cf,sf,:=,"); // S
}

static void _inst__mov(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// MOV Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[1] << 4) & 0x10) | ((buf[0] >> 4) & 0x0f);
	const ut32 r = ((buf[1] << 3) & 0x10) | (buf[0] & 0x0f);
	r_strbuf_appendf (&op->esil, "r%d,r%d,=,", r, d);
}

static void _inst__movw(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// MOVW Rd+1:Rd, Rr+1:Rr
	if (len < 1) {
		return;
	}
	const ut32 d = (buf[0] & 0xf0) >> 3;
	const ut32 r = (buf[0] & 0x0f) << 1;
	r_strbuf_appendf (&op->esil, "r%d,r%d,=,r%d,r%d,=,", r, d, r + 1, d + 1);
}

static void _inst__mul(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// MUL Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[1] << 4) & 0x10) | ((buf[0] >> 4) & 0x0f);
	const ut32 r = ((buf[1] << 3) & 0x10) | (buf[0] & 0x0f);

	r_strbuf_appendf (&op->esil, "r%d,r%d,*,r1_r0,=,", r, d); // 0: r1_r0 = rd * rr
	r_strbuf_append (&op->esil, "r1_r0,0x8000,&,!,!,cf,:=,"); // C = R/15
	r_strbuf_append (&op->esil, "$z,zf,:="); // Z = !R
}

static void _inst__muls(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// MULS Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = (buf[0] >> 4 & 0x0f) + 16;
	const ut32 r = (buf[0] & 0x0f) + 16;

	r_strbuf_appendf (&op->esil, "r%d,DUP,0x80,&,?{,0xff00,|,},", d); // sign extension Rd
	r_strbuf_appendf (&op->esil, "r%d,DUP,0x80,&,?{,0xff00,|,},", r); // sign extension Rr
	r_strbuf_append (&op->esil, "*,r1_r0,=,"); // 0: (Rd*Rr)

	r_strbuf_append (&op->esil, "r1_r0,0x8000,&,!,!,cf,:=,"); // C = R/16
	r_strbuf_append (&op->esil, "$z,zf,:="); // Z = !R
}

static void _inst__mulsu(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// MULSU Rd, Rr
	if (len < 1) {
		return;
	}
	const ut32 d = (buf[0] >> 4 & 0x07) + 16;
	const ut32 r = (buf[0] & 0x07) + 16;

	r_strbuf_appendf (&op->esil, "r%d,DUP,0x80,&,?{,0xff00,|,},", d); // sign extension Rd
	r_strbuf_appendf (&op->esil, "r%d,*,r1_r0,=,", r); // 0: (Rd*Rr)

	r_strbuf_append (&op->esil, "r1_r0,0x8000,&,!,!,cf,:=,"); // C = R/16
	r_strbuf_append (&op->esil, "$z,zf,:="); // Z = !R
}

static void _inst__neg(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// NEG Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	r_strbuf_appendf (&op->esil, "r%d,0x00,-,0xff,&,", d); // 0: (0-Rd)
	r_strbuf_appendf (&op->esil, "DUP,r%d,0xff,^,|,0x08,&,!,!,hf,=,", d); // H
	r_strbuf_append (&op->esil, "DUP,0x80,-,!,vf,=,"); // V
	r_strbuf_append (&op->esil, "DUP,0x80,&,!,!,nf,=,"); // N
	r_strbuf_append (&op->esil, "DUP,!,zf,=,"); // Z
	r_strbuf_append (&op->esil, "DUP,!,!,cf,=,"); // C
	r_strbuf_append (&op->esil, "vf,nf,^,sf,=,"); // S
	r_strbuf_appendf (&op->esil, "r%d,=,", d); // Rd = result
}

static void _inst__nop(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// NOP
	r_strbuf_append (&op->esil, ",,");
}

static void _inst__or(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// OR Rd, Rr
	if (len < 2) {
		return;
	}
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	r_strbuf_appendf (&op->esil, "r%d,r%d,|=,", r, d); // 0: (Rd | Rr)
	r_strbuf_append (&op->esil, "$z,zf,:=,"); // Z
	r_strbuf_appendf (&op->esil, "r%d,&,!,!,nf,:=,", d); // N
	r_strbuf_append (&op->esil, "0,vf,:=,"); // V
	r_strbuf_append (&op->esil, "nf,sf,:="); // S
}

static void _inst__ori(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ORI Rd, K
	// SBR Rd, K
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = (buf[0] & 0xf) | ((buf[1] & 0xf) << 4);
	op->val = k;
	r_strbuf_appendf (&op->esil, "%d,r%d,|=,", k, d); // 0: (Rd | k)
	r_strbuf_append (&op->esil, "$z,zf,:=,"); // Z
	r_strbuf_appendf (&op->esil, "r%d,0x80,&,!,!,nf,:=,", d); // N
	r_strbuf_append (&op->esil, "0,vf,:=,"); // V
	r_strbuf_append (&op->esil, "nf,sf,:="); // S
}

static void _inst__out(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// OUT A, Rr
	if (len < 2) {
		return;
	}
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 0x01) << 4);
	int a = (buf[0] & 0x0f) | ((buf[1] & 0x6) << 3);
	RStrBuf *io_dst = __generic_io_dest (a, 1, cpu);
	op->type2 = 1;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;
	r_strbuf_appendf (&op->esil, "r%d,%s,", r, r_strbuf_tostring (io_dst));
	r_strbuf_free (io_dst);
}

static void _inst__pop(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// POP Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	__generic_pop (op, 1);
	r_strbuf_appendf (&op->esil, "r%d,=,", d); // store in Rd
}

static void _inst__push(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// PUSH Rr
	if (len < 2) {
		return;
	}
	int r = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	r_strbuf_appendf (&op->esil, "r%d,", r); // load Rr
	__generic_push (op, 1); // push it into stack
	// AT*mega optimizes one cycle
	op->cycles = !STR_BEGINS (cpu->model, "ATxmega") ? 1 : 2;
}

static void _inst__rcall(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// RCALL k
	if (len < 2) {
		return;
	}
	// target address
	op->jump = (op->addr + ((((((buf[1] & 0xf) << 8) | buf[0]) << 1) |
		(((buf[1] & 0x8)? ~((int)0x1fff): 0))) + 2)) & CPU_PC_MASK (cpu);
	op->fail = op->addr + op->size;
	// esil
	r_strbuf_append (&op->esil, "pc,"); // esil already points to next
					     // instruction (@ret)
	__generic_push (op, CPU_PC_SIZE (cpu)); // push @ret addr
	r_strbuf_appendf (&op->esil, "0x%"PFMT64x",pc,:=,", op->jump); // jump!
	// cycles
	if (!r_str_ncasecmp (cpu->model, "ATtiny", 6)) {
		op->cycles = 4; // ATtiny is always slow
	} else {
		// PC size decides required runtime!
		op->cycles = cpu->pc <= 16? 3: 4;
		if (!STR_BEGINS (cpu->model, "ATxmega")) {
			op->cycles--; // ATxmega optimizes one cycle
		}
	}
}

static void _inst__ret(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// RET
	op->eob = true;
	// esil
	__generic_pop (op, CPU_PC_SIZE (cpu));
	r_strbuf_append (&op->esil, "pc,=,"); // jump!
	// cycles
	if (CPU_PC_SIZE (cpu) > 2) { // if we have a bus bigger than 16 bit
		op->cycles++; // (i.e. a 22-bit bus), add one extra cycle
	}
}

static void _inst__reti(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// RETI
	// XXX: There are not privileged instructions in ATMEL/AVR
	op->family = R_ANAL_OP_FAMILY_PRIV;

	// first perform a standard 'ret'
	INST_CALL (ret);

	// RETI: The I-bit is cleared by hardware after an interrupt
	// has occurred, and is set by the RETI instruction to enable
	// subsequent interrupts
	r_strbuf_append (&op->esil, "1,if,=,");
}

static void _inst__rjmp(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// RJMP k
	st32 jump = (((((buf[1] & 0xf) << 9) | (buf[0] << 1))) | (buf[1] & 0x8 ? ~(0x1fff) : 0)) + 2;
	op->jump = (op->addr + jump) & CPU_PC_MASK (cpu);
	r_strbuf_appendf (&op->esil, "0x%"PFMT64x",pc,:=,", op->jump);
}

static void _inst__ror(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ROR Rd
	const ut32 d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	r_strbuf_append (&op->esil, "cf,nf,:=,"); // N
	r_strbuf_appendf (&op->esil, "r%d,0x1,&,", d); // C
	r_strbuf_appendf (&op->esil, "1,r%d,>>,7,cf,<<,|,r%d,=,cf,:=,", d, d); // 0: (Rd>>1) | (cf<<7)
	r_strbuf_append (&op->esil, "$z,zf,:=,"); // Z
	r_strbuf_append (&op->esil, "nf,cf,^,vf,:=,"); // V
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:="); // S
}

static void _inst__sbc(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SBC Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 r = (buf[0] & 0x0f) | ((buf[1] & 0x2) << 3);
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);

	r_strbuf_appendf (&op->esil, "cf,r%d,+,r%d,-=,", r, d); // 0: (Rd-Rr-C)
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$b,hf,:=,");
	r_strbuf_append (&op->esil, "8,$b,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_appendf (&op->esil, "0x80,r%d,&,!,!,nf,:=,", d);
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=");
}

static void _inst__sbci(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SBCI Rd, k
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = ((buf[1] & 0xf) << 4) | (buf[0] & 0xf);
	op->val = k;

	r_strbuf_appendf (&op->esil, "cf,%d,+,r%d,-=,", k, d); // 0: (Rd-k-C)
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$b,hf,:=,");
	r_strbuf_append (&op->esil, "8,$b,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_appendf (&op->esil, "0x80,r%d,&,!,!,nf,:=,", d);
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=");
}

static void _inst__sub(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SUB Rd, Rr
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 1) << 4);
	const ut32 r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);

	r_strbuf_appendf (&op->esil, "r%d,r%d,-=,", r, d); // 0: (Rd-k)
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$b,hf,:=,");
	r_strbuf_append (&op->esil, "8,$b,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_appendf (&op->esil, "0x80,r%d,&,!,!,nf,:=,", d);
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=");
}

static void _inst__subi(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SUBI Rd, k
	if (len < 2) {
		return;
	}
	const ut32 d = ((buf[0] >> 4) & 0xf) + 16;
	const ut32 k = ((buf[1] & 0xf) << 4) | (buf[0] & 0xf);
	op->val = k;

	r_strbuf_appendf (&op->esil, "%d,r%d,-=,", k, d); // 0: (Rd-k)
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "3,$b,hf,:=,");
	r_strbuf_append (&op->esil, "8,$b,cf,:=,");
	r_strbuf_append (&op->esil, "7,$o,vf,:=,");
	r_strbuf_appendf (&op->esil, "0x80,r%d,&,!,!,nf,:=,", d);
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:=");
}

static void _inst__sbi(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SBI A, b
	if (len < 1) {
		return;
	}
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RStrBuf *io_port;

	op->type2 = 1;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;

	// read port a and clear bit b
	io_port = __generic_io_dest (a, 0, cpu);
	r_strbuf_appendf (&op->esil, "0xff,%d,1,<<,|,%s,&,", b, r_strbuf_tostring (io_port));
	r_strbuf_free (io_port);

	// write result to port a
	io_port = __generic_io_dest (a, 1, cpu);
	r_strbuf_appendf (&op->esil, "%s,", r_strbuf_tostring (io_port));
	r_strbuf_free (io_port);
}

static void _inst__sbix(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SBIC A, b
	// SBIS A, b
	if (len < 2) {
		return;
	}
	int a = (buf[0] >> 3) & 0x1f;
	int b = buf[0] & 0x07;
	RAnalOp next_op = { 0 };
	RStrBuf *io_port;

	op->type2 = 0;
	op->val = a;
	op->family = R_ANAL_OP_FAMILY_IO;

	// calculate next instruction size (call recursively avr_op_analyze)
	// and free next_op's esil string (we dont need it now)
	avr_op_analyze (as,
		&next_op,
		op->addr + op->size, buf + op->size,
		len - op->size,
		cpu);
	r_strbuf_fini (&next_op.esil);
	op->jump = (op->addr + next_op.size + 2) & CPU_PC_MASK (cpu);
	op->fail = op->addr + op->size;

	// cycles
	op->cycles = 1; // XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to false, this instruction
			// needs 2/3 cycles, elsewhere it needs only 1 cycle.

	// read port a and clear bit b
	io_port = __generic_io_dest (a, 0, cpu);
	r_strbuf_appendf (&op->esil, "%d,1,<<,%s,&,", b, r_strbuf_tostring (io_port)); // IO(A,b)
	r_strbuf_append (&op->esil, (buf[1] & 0xe) == 0xc ? "!," // SBIC => branch if 0
							   : "!,!,"); // SBIS => branch if 1
	r_strbuf_appendf (&op->esil, "?{,0x%"PFMT64x",pc,:=,},", op->jump); // ?true => jmp
	r_strbuf_free (io_port);
}

static void _inst__sbiw(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SBIW Rd+1:Rd, K
	if (len < 1) {
		return;
	}
	int d = ((buf[0] & 0x30) >> 3) + 24;
	int k = (buf[0] & 0xf) | ((buf[0] >> 2) & 0x30);
	op->val = k;
	r_strbuf_appendf (&op->esil, "%d,r%d_r%d,-=,", k, d + 1, d); // 0(Rd+1:Rd - Rr)
	r_strbuf_append (&op->esil, "$z,zf,:=,");
	r_strbuf_append (&op->esil, "15,$c,cf,:=,"); // C
	r_strbuf_appendf (&op->esil, "r%d_r%d,0x8000,&,!,!,nf,:=,", d + 1, d); // N
	r_strbuf_appendf (&op->esil, "r%d_r%d,0x8080,&,0x8080,!,vf,:=,", d + 1, d); // V
	r_strbuf_append (&op->esil, "vf,nf,^,sf,:="); // S
}

static void _inst__sbrx(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SBRC Rr, b
	// SBRS Rr, b
	if (len < 2) {
		return;
	}
	int b = buf[0] & 0x7;
	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x01) << 4);
	RAnalOp next_op = { 0 };

	// calculate next instruction size (call recursively avr_op_analyze)
	// and free next_op's esil string (we dont need it now)
	avr_op_analyze (as,
		&next_op,
		op->addr + op->size, buf + op->size, len - op->size,
		cpu);
	r_strbuf_fini (&next_op.esil);
	op->jump = (op->addr + next_op.size + 2) & CPU_PC_MASK (cpu);
	op->fail = op->addr + 2;

	// cycles
	op->cycles = 1; // XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to false, this instruction
			// needs 2/3 cycles, elsewhere it needs only 1 cycle.
	r_strbuf_appendf (&op->esil, "%d,1,<<,r%d,&,", b, r); // Rr(b)
	r_strbuf_append (&op->esil, (buf[1] & 0xe) == 0xc ? "!," // SBRC => branch if cleared
							   : "!,!,"); // SBRS => branch if set
	r_strbuf_appendf (&op->esil, "?{,0x%"PFMT64x",pc,:=,},", op->jump); // ?true => jmp
}

static void _inst__sleep(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SLEEP
	r_strbuf_append (&op->esil, "BREAK");
}

static void _inst__spm(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SPM Z+
	r_strbuf_set (&op->esil, "spmcsr,0x7f,&,"
		"spmcsr,0x7f,&,"
		"spmcsr,0x7f,&,"
		"0x7c,spmcsr,&=,"
		"0x1,^,!,?{,r1,r0,z,SPM_PAGE_FILL,CLEAR,BREAK,},"
		"0x3,^,!,?{,16,rampz,<<,z,+,SPM_PAGE_ERASE,CLEAR,BREAK,},"
		"0x5,^,!,?{,16,rampz,<<,z,+,SPM_PAGE_WRITE,}"
	);
	op->cycles = 1; // This is truly false. Datasheets do not publish how
			// many cycles this instruction uses in all its
			// operation modes and I am pretty sure that this value
			// can vary substantially from one MCU type to another.
			// So... one cycle is fine.
}

static void _inst__st(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ST X, Rr
	// ST X+, Rr
	// ST -X, Rr
	if (len < 2) {
		return;
	}
	// load register
	r_strbuf_appendf (&op->esil, "r%d,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// write in memory
	__generic_ld_st (
		op, "ram",
		'x', // use index register X
		0, // no use RAMP* registers
		(buf[0] & 0xf) == 0xe
			? -1 // pre decremented
			: (buf[0] & 0xf) == 0xd
			? 1 // post increment
			: 0, // no increment
		0, // offset always 0
		1); // store operation (st)
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

static void _inst__std(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// ST Y, Rr	ST Z, Rr
	// ST Y+, Rr	ST Z+, Rr
	// ST -Y, Rr	ST -Z, Rr
	// ST Y+q, Rr	ST Z+q, Rr
	if (len < 2) {
		return;
	}
	// load register
	r_strbuf_appendf (&op->esil, "r%d,", ((buf[1] & 1) << 4) | ((buf[0] >> 4) & 0xf));
	// write in memory
	__generic_ld_st (
		op, "ram",
		buf[0] & 0x8 ? 'y' : 'z', // index register Y/Z
		0, // no use RAMP* registers
		!(buf[1] & 0x10)
			? 0 // no increment
			: buf[0] & 0x1
			? 1 // post incremented
			: -1, // pre decremented
		!(buf[1] & 0x10)
			? (buf[1] & 0x20) // offset
				| ((buf[1] & 0xc) << 1) | (buf[0] & 0x7)
			: 0, // no offset
		1); // load operation (!st)
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

static void _inst__swap(RArchSession *as, RAnalOp *op, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu) {
	// SWAP Rd
	if (len < 2) {
		return;
	}
	int d = ((buf[1] & 0x1) << 4) | ((buf[0] >> 4) & 0xf);
	r_strbuf_appendf (&op->esil, "4,r%d,>>,0x0f,&,", d); // (Rd >> 4) & 0xf
	r_strbuf_appendf (&op->esil, "4,r%d,<<,0xf0,&,", d); // (Rd >> 4) & 0xf
	r_strbuf_append (&op->esil, "|,"); // S[0] | S[1]
	r_strbuf_appendf (&op->esil, "r%d,=,", d); // Rd = result
}

OPCODE_DESC opcodes[] = {
	{ "break", (0xffff), (0x9698), _inst__break, (1), (2), R_ANAL_OP_TYPE_TRAP },
	{ "eicall", (0xffff), (0x9519), _inst__eicall, (0), (2), R_ANAL_OP_TYPE_UCALL },
	{ "eijmp", (0xffff), (0x9419), _inst__eijmp, (0), (2), R_ANAL_OP_TYPE_UJMP },
	{ "icall", (0xffff), (0x9509), _inst__icall, (0), (2), R_ANAL_OP_TYPE_UCALL },
	{ "ijmp", (0xffff), (0x9409), _inst__ijmp, (0), (2), R_ANAL_OP_TYPE_UJMP },
	{ "lpm", (0xffff), (0x95c8), _inst__lpm, (3), (2), R_ANAL_OP_TYPE_LOAD },
	{ "nop", (0xffff), (0x0000), _inst__nop, (1), (2), R_ANAL_OP_TYPE_NOP },
	{ "ret", (0xffff), (0x9508), _inst__ret, (4), (2), R_ANAL_OP_TYPE_RET },
	{ "reti", (0xffff), (0x9518), _inst__reti, (4), (2), R_ANAL_OP_TYPE_RET },
	{ "sleep", (0xffff), (0x9588), _inst__sleep, (1), (2), R_ANAL_OP_TYPE_NOP },
	{ "spm", (0xffff), (0x95e8), _inst__spm, (1), (2), R_ANAL_OP_TYPE_TRAP },
	{ "bclr", (0xff8f), (0x9488), _inst__bclr, (1), (2), R_ANAL_OP_TYPE_MOV },
	{ "bset", (0xff8f), (0x9408), _inst__bset, (1), (2), R_ANAL_OP_TYPE_MOV },
	{ "fmul", (0xff88), (0x0308), _inst__fmul, (2), (2), R_ANAL_OP_TYPE_MUL },
	{ "fmuls", (0xff88), (0x0380), _inst__fmuls, (2), (2), R_ANAL_OP_TYPE_MUL },
	{ "fmulsu", (0xff88), (0x0388), _inst__fmulsu, (2), (2), R_ANAL_OP_TYPE_MUL },
	{ "mulsu", (0xff88), (0x0300), _inst__mulsu, (2), (2), R_ANAL_OP_TYPE_AND },
	{ "des", (0xff0f), (0x940b), _inst__des, (0), (2), R_ANAL_OP_TYPE_CRYPTO },
	{ "adiw", (0xff00), (0x9600), _inst__adiw, (2), (2), R_ANAL_OP_TYPE_ADD },
	{ "sbiw", (0xff00), (0x9700), _inst__sbiw, (2), (2), R_ANAL_OP_TYPE_SUB },
	{ "cbi", (0xff00), (0x9800), _inst__cbi, (1), (2), R_ANAL_OP_TYPE_IO },
	{ "sbi", (0xff00), (0x9a00), _inst__sbi, (1), (2), R_ANAL_OP_TYPE_IO },
	{ "movw", (0xff00), (0x0100), _inst__movw, (1), (2), R_ANAL_OP_TYPE_MOV },
	{ "muls", (0xff00), (0x0200), _inst__muls, (2), (2), R_ANAL_OP_TYPE_AND },
	{ "asr", (0xfe0f), (0x9405), _inst__asr, (1), (2), R_ANAL_OP_TYPE_SAR },
	{ "com", (0xfe0f), (0x9400), _inst__com, (1), (2), R_ANAL_OP_TYPE_NOT },
	{ "dec", (0xfe0f), (0x940a), _inst__dec, (1), (2), R_ANAL_OP_TYPE_SUB },
	{ "elpm", (0xfe0f), (0x9006), _inst__elpm, (0), (2), R_ANAL_OP_TYPE_LOAD },
	{ "elpm", (0xfe0f), (0x9007), _inst__elpm, (0), (2), R_ANAL_OP_TYPE_LOAD },
	{ "inc", (0xfe0f), (0x9403), _inst__inc, (1), (2), R_ANAL_OP_TYPE_ADD },
	{ "lac", (0xfe0f), (0x9206), _inst__lac, (2), (2), R_ANAL_OP_TYPE_LOAD },
	{ "las", (0xfe0f), (0x9205), _inst__las, (2), (2), R_ANAL_OP_TYPE_LOAD },
	{ "lat", (0xfe0f), (0x9207), _inst__lat, (2), (2), R_ANAL_OP_TYPE_LOAD },
	{ "ld", (0xfe0f), (0x900c), _inst__ld, (0), (2), R_ANAL_OP_TYPE_LOAD },
	{ "ld", (0xfe0f), (0x900d), _inst__ld, (0), (2), R_ANAL_OP_TYPE_LOAD },
	{ "ld", (0xfe0f), (0x900e), _inst__ld, (0), (2), R_ANAL_OP_TYPE_LOAD },
	{ "lds", (0xfe0f), (0x9000), _inst__lds, (0), (4), R_ANAL_OP_TYPE_LOAD },
	{ "sts", (0xfe0f), (0x9200), _inst__sts, (2), (4), R_ANAL_OP_TYPE_STORE },
	{ "lpm", (0xfe0f), (0x9004), _inst__lpm, (3), (2), R_ANAL_OP_TYPE_LOAD },
	{ "lpm", (0xfe0f), (0x9005), _inst__lpm, (3), (2), R_ANAL_OP_TYPE_LOAD },
	{ "lsr", (0xfe0f), (0x9406), _inst__lsr, (1), (2), R_ANAL_OP_TYPE_SHR },
	{ "neg", (0xfe0f), (0x9401), _inst__neg, (2), (2), R_ANAL_OP_TYPE_SUB },
	{ "pop", (0xfe0f), (0x900f), _inst__pop, (2), (2), R_ANAL_OP_TYPE_POP },
	{ "push", (0xfe0f), (0x920f), _inst__push, (0), (2), R_ANAL_OP_TYPE_PUSH },
	{ "ror", (0xfe0f), (0x9407), _inst__ror, (1), (2), R_ANAL_OP_TYPE_SAR },
	{ "st", (0xfe0f), (0x920c), _inst__st, (2), (2), R_ANAL_OP_TYPE_STORE },
	{ "st", (0xfe0f), (0x920d), _inst__st, (0), (2), R_ANAL_OP_TYPE_STORE },
	{ "st", (0xfe0f), (0x920e), _inst__st, (0), (2), R_ANAL_OP_TYPE_STORE },
	{ "swap", (0xfe0f), (0x9402), _inst__swap, (1), (2), R_ANAL_OP_TYPE_SAR },
	{ "call", (0xfe0e), (0x940e), _inst__call, (0), (4), R_ANAL_OP_TYPE_CALL },
	{ "jmp", (0xfe0e), (0x940c), _inst__jmp, (2), (4), R_ANAL_OP_TYPE_JMP },
	{ "bld", (0xfe08), (0xf800), _inst__bld, (1), (2), R_ANAL_OP_TYPE_MOV },
	{ "bst", (0xfe08), (0xfa00), _inst__bst, (1), (2), R_ANAL_OP_TYPE_MOV },
	{ "sbix", (0xff00), (0x9900), _inst__sbix, (2), (2), R_ANAL_OP_TYPE_CJMP },
	{ "sbix", (0xff00), (0x9b00), _inst__sbix, (2), (2), R_ANAL_OP_TYPE_CJMP },
	{ "sbrx", (0xfe08), (0xfc00), _inst__sbrx, (2), (2), R_ANAL_OP_TYPE_CJMP },
	{ "sbrx", (0xfe08), (0xfe00), _inst__sbrx, (2), (2), R_ANAL_OP_TYPE_CJMP },
	{ "ldd", (0xfe07), (0x9001), _inst__ldd, (0), (2), R_ANAL_OP_TYPE_LOAD },
	{ "ldd", (0xfe07), (0x9002), _inst__ldd, (0), (2), R_ANAL_OP_TYPE_LOAD },
	{ "std", (0xfe07), (0x9201), _inst__std, (0), (2), R_ANAL_OP_TYPE_STORE },
	{ "std", (0xfe07), (0x9202), _inst__std, (0), (2), R_ANAL_OP_TYPE_STORE },
	{ "adc", (0xfc00), (0x1c00), _inst__adc, (1), (2), R_ANAL_OP_TYPE_ADD },
	{ "add", (0xfc00), (0x0c00), _inst__add, (1), (2), R_ANAL_OP_TYPE_ADD },
	{ "and", (0xfc00), (0x2000), _inst__and, (1), (2), R_ANAL_OP_TYPE_AND },
	{ "brbx", (0xfc00), (0xf000), _inst__brbx, (0), (2), R_ANAL_OP_TYPE_CJMP },
	{ "brbx", (0xfc00), (0xf400), _inst__brbx, (0), (2), R_ANAL_OP_TYPE_CJMP },
	{ "cp", (0xfc00), (0x1400), _inst__cp, (1), (2), R_ANAL_OP_TYPE_CMP },
	{ "cpc", (0xfc00), (0x0400), _inst__cpc, (1), (2), R_ANAL_OP_TYPE_CMP },
	{ "cpse", (0xfc00), (0x1000), _inst__cpse, (0), (2), R_ANAL_OP_TYPE_CJMP },
	{ "eor", (0xfc00), (0x2400), _inst__eor, (1), (2), R_ANAL_OP_TYPE_XOR },
	{ "mov", (0xfc00), (0x2c00), _inst__mov, (1), (2), R_ANAL_OP_TYPE_MOV },
	{ "mul", (0xfc00), (0x9c00), _inst__mul, (2), (2), R_ANAL_OP_TYPE_AND },
	{ "or", (0xfc00), (0x2800), _inst__or, (1), (2), R_ANAL_OP_TYPE_OR },
	{ "sbc", (0xfc00), (0x0800), _inst__sbc, (1), (2), R_ANAL_OP_TYPE_SUB },
	{ "sub", (0xfc00), (0x1800), _inst__sub, (1), (2), R_ANAL_OP_TYPE_SUB },
	{ "in", (0xf800), (0xb000), _inst__in, (1), (2), R_ANAL_OP_TYPE_IO },
	{ "out", (0xf800), (0xb800), _inst__out, (1), (2), R_ANAL_OP_TYPE_IO },
	{ "andi", (0xf000), (0x7000), _inst__andi, (1), (2), R_ANAL_OP_TYPE_AND },
	{ "cpi", (0xf000), (0x3000), _inst__cpi, (1), (2), R_ANAL_OP_TYPE_CMP },
	{ "ldi", (0xf000), (0xe000), _inst__ldi, (1), (2), R_ANAL_OP_TYPE_LOAD },
	{ "ori", (0xf000), (0x6000), _inst__ori, (1), (2), R_ANAL_OP_TYPE_OR },
	{ "rcall", (0xf000), (0xd000), _inst__rcall, (0), (2), R_ANAL_OP_TYPE_CALL },
	{ "rjmp", (0xf000), (0xc000), _inst__rjmp, (2), (2), R_ANAL_OP_TYPE_JMP },
	{ "sbci", (0xf000), (0x4000), _inst__sbci, (1), (2), R_ANAL_OP_TYPE_SUB },
	{ "subi", (0xf000), (0x5000), _inst__subi, (1), (2), R_ANAL_OP_TYPE_SUB },
	{ "ldd", (0xd200), (0x8000), _inst__ldd, (0), (2), R_ANAL_OP_TYPE_LOAD },
	{ "std", (0xd200), (0x8200), _inst__std, (0), (2), R_ANAL_OP_TYPE_STORE },
	{ "unknown", 0, 0, (void *)0, 2, 1, R_ANAL_OP_TYPE_UNK }
};

static void set_invalid_op(RAnalOp *op, ut64 addr) {
	// Unknown or invalid instruction.
	op->family = R_ANAL_OP_FAMILY_UNKNOWN;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->addr = addr;
	op->nopcode = 1;
	op->cycles = 1;
	op->size = 2;
	// set an esil trap to prevent the execution of it
	r_strbuf_set (&op->esil, "1,$");
}

static OPCODE_DESC *avr_op_analyze(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, CPU_MODEL *cpu) {
	OPCODE_DESC *opcode_desc;
	if (len < 2) {
		return NULL;
	}
	ut16 ins = (buf[1] << 8) | buf[0];
	int fail;
	char *t;

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
			r_strbuf_setf (&op->esil, "%s", "");

			// handle opcode
			opcode_desc->handler (as, op, buf, len, &fail, cpu);
			if (fail) {
				goto INVALID_OP;
			}
			if (op->cycles <= 0) {
				// eprintf ("opcode %s @%"PFMT64x" returned 0 cycles.\n", opcode_desc->name, op->addr);
				opcode_desc->cycles = 2;
			}
			op->nopcode = (op->type == R_ANAL_OP_TYPE_UNK);

			// remove trailing coma (COMETE LA COMA)
			t = r_strbuf_tostring (&op->esil);
			if (t && strlen (t) > 1) {
				t += strlen (t) - 1;
				if (*t == ',') {
					*t = '\0';
				}
			}

			return opcode_desc;
		}
	}
#if 0
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
	op->nopcode = 1;
	op->cycles = 1;
	op->size = 2;
	// launch esil trap (for communicating upper layers about this weird
	// and stinky situation
	r_strbuf_set (&op->esil, "1,$");
#else
INVALID_OP:
	set_invalid_op (op, addr);
#endif

	return NULL;
}

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	ut8 outbuf[4];

	int size = avr_encode (as, op->addr, op->mnemonic, outbuf);
	const bool is_valid = size > 0;
	if (is_valid) {
		free (op->bytes);
		op->bytes = r_mem_dup (outbuf, size);
		op->size = size;
	}

	return is_valid;
}

// TODO: remove register analysis comment when each avr cpu will be implemented in asm plugin
static bool decode(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	const int mnemonic_len = 32;
	op->mnemonic = calloc (mnemonic_len, 1);

	set_invalid_op (op, addr);

	int size = avr_anal (as, op->mnemonic, mnemonic_len, addr, buf, len);

	if (!strcmp (op->mnemonic, "invalid") || !strcmp (op->mnemonic, "truncated")) {
		op->eob = true;
		op->size = 2;
		return 2; // R_MIN (len, 2);
	}

	// select cpu info
	CPU_MODEL *cpu = get_cpu_model (as->data, as->config->cpu);

#if 0
	// set memory layout registers
	if (as->arch->esil) {
		ut64 offset = 0;
		r_esil_reg_write (as->arch->esil, "_prog", offset);

		offset += (1ULL << (cpu ? cpu->pc : 8));
		r_esil_reg_write (as->arch->esil, "_io", offset);

		offset += const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "sram_start"));
		r_esil_reg_write (as->arch->esil, "_sram", offset);

		offset += const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "sram_size"));
		r_esil_reg_write (as->arch->esil, "_eeprom", offset);

		offset += const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "eeprom_size"));
		r_esil_reg_write (as->arch->esil, "_page", offset);
	}
#endif
	// process opcode
	avr_op_analyze (as, op, addr, buf, len, cpu);

	op->size = size;
	if (op->size <= 0) {
		op->mnemonic = strdup ("invalid");
	}

	return size;
}

static bool avr_custom_des(REsil *esil) {
	if (!esil) {
		return false;
	}
	ut64 text, key, encrypt, des_round;
	if (!__esil_pop_argument (esil, &text)) {
		return false;
	}
	if (!__esil_pop_argument (esil, &key)) {
		return false;
	}
	if (!__esil_pop_argument (esil, &encrypt)) {
		return false;
	}
	if (!__esil_pop_argument (esil, &des_round)) {
		return false;
	}

	ut32 key_lo = key & UT32_MAX;
	ut32 key_hi = key >> 32;
	ut32 buf_lo = text & UT32_MAX;
	ut32 buf_hi = text >> 32;

	des_round &= 0xf;
	if (!encrypt) {
		des_round ^= 0xf;
	}

	ut32 round_key_lo, round_key_hi;
	r_des_round_key (des_round, &round_key_lo, &round_key_hi, &key_lo, &key_hi);

	if (!des_round) {
		r_des_permute_block0 (&buf_lo, &buf_hi);
	}
	r_des_round (&buf_lo, &buf_hi, &round_key_lo, &round_key_hi);
	if (des_round == 0xf) {
		r_des_permute_block1 (&buf_hi, &buf_lo);
	}

	return r_esil_pushnum (esil, (((ut64)buf_hi) << 32) | buf_lo);
}

// ESIL operation SPM_PAGE_ERASE
static bool avr_custom_spm_page_erase(REsil *esil) {
	// sanity check
	PluginData *pd = R_UNWRAP5 (esil, anal, arch, session, data);
	if (!esil || !esil->anal || !pd) {
		return false;
	}

	// get target address
	ut64 addr;
	if (!__esil_pop_argument (esil, &addr)) {
		return false;
	}

	// get details about current MCU and fix input address
	CPU_MODEL *cpu = get_cpu_model (pd, esil->anal->config->cpu);
	ut64 page_size_bits = const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "page_size"));

	// align base address to page_size_bits
	addr &= ~(MASK (page_size_bits));

	// perform erase
	// eprintf ("SPM_PAGE_ERASE %ld bytes @ 0x%08" PFMT64x ".\n", page_size, addr);
	ut8 c = 0xff;
	ut64 i;
	for (i = 0; i < (1ULL << page_size_bits); i++) {
		r_esil_mem_write (esil, (addr + i) & CPU_PC_MASK (cpu), &c, 1);
	}

	return true;
}

// ESIL operation SPM_PAGE_FILL
static bool avr_custom_spm_page_fill(REsil *esil) {
	ut64 addr, i;
	ut8 r0, r1;

	// sanity check
	PluginData *pd = R_UNWRAP5 (esil, anal, arch, session, data);
	if (!esil || !esil->anal || !pd) {
		return false;
	}

	// get target address, r0, r1
	if (!__esil_pop_argument (esil, &addr)) {
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
	CPU_MODEL *cpu = get_cpu_model (pd, esil->anal->config->cpu);
	ut64 page_size_bits = const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "page_size"));

	// align and crop base address
	addr &= (MASK (page_size_bits) ^ 1);

	// perform write to temporary page
	// eprintf ("SPM_PAGE_FILL bytes (%02x, %02x) @ 0x%08" PFMT64x ".\n", r1, r0, addr);
	r_esil_mem_write (esil, addr++, &r0, 1);
	r_esil_mem_write (esil, addr++, &r1, 1);

	return true;
}

// ESIL operation SPM_PAGE_WRITE
static bool avr_custom_spm_page_write(REsil *esil) {
	CPU_MODEL *cpu;
	char *t = NULL;
	ut64 addr, page_size_bits, tmp_page;

	// sanity check
	PluginData *pd = R_UNWRAP5 (esil, anal, arch, session, data);
	if (!esil || !esil->anal || !pd) {
		return false;
	}

	// get target address
	if (!__esil_pop_argument (esil, &addr)) {
		return false;
	}

	// get details about current MCU and fix input address and base address
	// of the internal temporary page
	cpu = get_cpu_model (pd, esil->anal->config->cpu);
	page_size_bits = const_get_value (const_by_name (cpu, CPU_CONST_PARAM, "page_size"));
	r_esil_reg_read (esil, "_page", &tmp_page, NULL);

	// align base address to page_size_bits
	addr &= (~(MASK (page_size_bits)) & CPU_PC_MASK (cpu));

	// perform writing
	// eprintf ("SPM_PAGE_WRITE %ld bytes @ 0x%08" PFMT64x ".\n", page_size, addr);
	if (!(t = malloc (1 << page_size_bits))) {
		return false;
	}
	r_esil_mem_read (esil, tmp_page, (ut8 *)t, 1 << page_size_bits);
	r_esil_mem_write (esil, addr, (ut8 *)t, 1 << page_size_bits);

	return true;
}

static bool esil_avr_init(RArchSession *as, REsil *esil) {
	R_RETURN_VAL_IF_FAIL (as && as->data && esil, false);
	r_esil_set_op (esil, "des", avr_custom_des, 1, 4, R_ESIL_OP_TYPE_CUSTOM | R_ESIL_OP_TYPE_CRYPTO, NULL);
	r_esil_set_op (esil, "SPM_PAGE_ERASE", avr_custom_spm_page_erase, 0, 1, R_ESIL_OP_TYPE_CUSTOM, NULL);
	r_esil_set_op (esil, "SPM_PAGE_FILL", avr_custom_spm_page_fill, 0, 3, R_ESIL_OP_TYPE_CUSTOM, NULL);
	r_esil_set_op (esil, "SPM_PAGE_WRITE", avr_custom_spm_page_write, 0, 1, R_ESIL_OP_TYPE_CUSTOM, NULL);
	return true;
}

static bool esil_avr_fini(RArchSession *as, REsil *esil) {
	return true;
}

static char *regs(RArchSession *as) {
	const char *registers_profile =
		"=PC	pcl\n"
		"=SN	r24\n"
		"=SP	sp\n"
		"=BP    y\n"
		"=RS	8\n"

		// explained in https://www.nongnu.org/avr-libc/user-manual/FAQ.html
		// and https://www.avrfreaks.net/forum/function-calling-convention-gcc-generated-assembly-file
		"=A0	r25\n"
		"=A1	r24\n"
		"=A2	r23\n"
		"=A3	r22\n"
		"=R0	r24\n"

		/*
		PC: 16- or 22-bit program counter
		SP: 8- or 16-bit stack pointer
		SREG: 8-bit status register
		RAMPX, RAMPY, RAMPZ, RAMPD and EIND:
		*/

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
		"gpr	r1_r0	.16	0	0\n" // this is a hack for mul

		"gpr	r17_r16	.16	16	0\n"
		"gpr	r19_r18	.16	18	0\n"
		"gpr	r21_r20	.16	20	0\n"
		"gpr	r23_r22	.16	22	0\n"
		"gpr	r25_r24	.16	24	0\n"
		"gpr	r27_r26	.16	26	0\n"
		"gpr	r29_r28	.16	28	0\n"
		"gpr	r31_r30	.16	30	0\n"

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
		"gpr    spmcsr  .8      64      0\n";

	if (!strcmp (r_str_get (as->config->cpu), "ATmega328p")) {
		const char *section_two =
			"gpr		pinb	.8		65		0\n"
			"gpr		pinb0	.8		66		0\n"
			"gpr		pinb1	.8		67		0\n"
			"gpr		pinb2	.8		68		0\n"
			"gpr		pinb3	.8		69		0\n"
			"gpr		pinb4	.8		70		0\n"
			"gpr		pinb5	.8		71		0\n"
			"gpr		pinb6	.8		72		0\n"
			"gpr		pinb7	.8		73		0\n"

			"gpr		pinc	.8		74		0\n"
			"gpr		pinc0	.1		74		0\n"
			"gpr		pinc1	.1		74		0\n"
			"gpr		pinc2	.1		74		0\n"
			"gpr		pinc3	.1		74		0\n"
			"gpr		pinc4	.1		74		0\n"
			"gpr		pinc5	.1		74		0\n"
			"gpr		pinc6	.1		74		0\n"

			"gpr		pind	.8		75		0\n"
			"gpr		ddrb	.8		76		0\n"
			"gpr		ddb0	.1		76		0\n"
			"gpr		ddb1	.1		76		0\n"
			"gpr		ddb2	.1		76		0\n"
			"gpr		ddb3	.1		76		0\n"
			"gpr		ddb4	.1		76		0\n"
			"gpr		ddb5	.1		76		0\n"
			"gpr		ddb6	.1		76		0\n"
			"gpr		ddb7	.1		76		0\n"

			"gpr		ddrc	.8		77		0\n"
			"gpr		ddc0	.1		77		0\n"
			"gpr		ddc1	.1		77		0\n"
			"gpr		ddc2	.1		77		0\n"
			"gpr		ddc3	.1		77		0\n"
			"gpr		ddc4	.1		77		0\n"
			"gpr		ddc5	.1		77		0\n"
			"gpr		ddc6	.1		77		0\n"

			"gpr		dddd	.8		78		0\n"
			"gpr		ddd0	.1		78		0\n"
			"gpr		ddd1	.1		78		0\n"
			"gpr		ddd2	.1		78		0\n"
			"gpr		ddd3	.1		78		0\n"
			"gpr		ddd4	.1		78		0\n"
			"gpr		ddd5	.1		78		0\n"
			"gpr		ddd6	.1		78		0\n"

			"gpr		portb	.8		80		0\n"
			"gpr		portb0	.1		80		0\n"
			"gpr		portb1	.1		80		0\n"
			"gpr		portb2	.1		80		0\n"
			"gpr		portb3	.1		80		0\n"
			"gpr		portb4	.1		80		0\n"
			"gpr		portb5	.1		80		0\n"
			"gpr		portb6	.1		80		0\n"
			"gpr		portb7	.1		80		0\n"

			"gpr		portc	.8		80		0\n"
			"gpr		portc0	.1		80		0\n"
			"gpr		portc1	.1		80		0\n"
			"gpr		portc2	.1		80		0\n"
			"gpr		portc3	.1		80		0\n"
			"gpr		portc4	.1		80		0\n"
			"gpr		portc5	.1		80		0\n"
			"gpr		portc6	.1		80		0\n"
			"gpr		portc7	.1		80		0\n"

			"gpr		portd	.8		80		0\n"
			"gpr		portd0	.1		80		0\n"
			"gpr		portd1	.1		80		0\n"
			"gpr		portd2	.1		80		0\n"
			"gpr		portd3	.1		80		0\n"
			"gpr		portd4	.1		80		0\n"
			"gpr		portd5	.1		80		0\n"
			"gpr		portd6	.1		80		0\n"
			"gpr		portd7	.1		80		0\n"

			"gpr		tifr0	.8		82		0\n"
			"gpr		ocf0a	.1		82		0\n"
			"gpr		ocf0b	.1		82		0\n"

			"gpr		tifr1	.8		83		0\n"
			/*"gpr		tov1	.8		83		0\n"
			"gpr		ocf1a	.8		83		0\n"
			"gpr		ocf1a	.8		83		0\n"
			"gpr		icf1	.8		83		0\n"*/
			"gpr		tifr2	.8		84		0\n"

			"gpr		pcifr	.8		85		0\n"
			"gpr		eifr	.8		86		0\n"
			"gpr		eimsk	.8		87		0\n"
			"gpr		gpior0	.8		88		0\n"

			"gpr		eear	.16		89		0\n"
			"gpr		eearl	.8		89		0\n"
			"gpr		eear0	.1		89		0\n"
			"gpr		eear1	.1		89		0\n"
			"gpr		eear2	.1		89		0\n"
			"gpr		eear3	.1		89		0\n"
			"gpr		eear4	.1		89		0\n"
			"gpr		eear5	.1		89		0\n"
			"gpr		eear6	.1		89		0\n"
			"gpr		eear7	.1		89		0\n"

			"gpr		eearh	.8		89		0\n"
			"gpr		eear8	.1		89		0\n"
			"gpr		eear9	.1		89		0\n"

			"gpr		eecr	.8		90		0\n"
			"gpr		eedr	.8		91		0\n"
			"gpr		eedr0	.1		91		0\n"
			"gpr		eedr1	.1		91		0\n"
			"gpr		eedr2	.1		91		0\n"
			"gpr		eedr3	.1		91		0\n"
			"gpr		eedr4	.1		91		0\n"
			"gpr		eedr5	.1		91		0\n"
			"gpr		eedr6	.1		91		0\n"
			"gpr		eedr7	.1		91		0\n"

			// TODO: continue from here: https://github.com/vancegroup-mirrors/avr-libc/blob/06cc6ff5e6120b36f1b246871728addee58d3f87/avr-libc/include/avr/iom328p.h#L216
			// add subregisters?

			"gpr		gtcrr	.8		90		0\n"
			"gpr		tcnt0	.8		90		0\n"
			"gpr		ocr0a	.8		90		0\n"
			"gpr		ocr0b	.8		90		0\n"
			"gpr		gpior1	.8		90		0\n"
			"gpr		gpior2	.8		90		0\n"
			"gpr		spcr	.8		90		0\n"
			"gpr		spsr	.8		90		0\n"
			"gpr		spdr	.8		90		0\n"
			"gpr		smcr	.8		90		0\n"
			"gpr		mcusr	.8		90		0\n"
			"gpr		mcucr	.8		90		0\n"
			"gpr		wdtcsr	.8		90		0\n"
			"gpr		clkpr	.8		90		0\n"
			"gpr		prr		.8		90		0\n"
			"gpr		osccal	.8		90		0\n"
			"gpr		acsr	.8		90		0\n"
			"gpr		eicra	.8		90		0\n"
			"gpr		pcmsk0	.8		90		0\n"
			"gpr		pcmsk1	.8		90		0\n"
			"gpr		pcmsk2	.8		90		0\n"
			"gpr		timsk0	.8		90		0\n"
			"gpr		timsk1	.8		90		0\n"
			"gpr		timsk2	.8		90		0\n"
			"gpr		pcicr	.8		90		0\n"
			"gpr		adc		.8		90		0\n"
			"gpr		adcw	.8		90		0\n"
			"gpr		adcl	.8		90		0\n"
			"gpr		adch	.8		90		0\n"
			"gpr		adcsra	.8		90		0\n"
			"gpr		adcsrb	.8		90		0\n"

			"gpr		admux	.8		90		0\n"
			"gpr		didr0	.8		90		0\n"
			"gpr		didr1	.8		90		0\n"
			"gpr		tccr1a	.8		90		0\n"
			"gpr		tccr1b	.8		90		0\n"
			"gpr		tccr1c	.8		90		0\n"
			"gpr		tcnt1	.8		90		0\n"
			"gpr		tcnt1l	.8		90		0\n"
			"gpr		icr1	.8		90		0\n"
			"gpr		icr1l	.8		90		0\n"
			"gpr		icr1h	.8		90		0\n"
			"gpr		ocr1h	.16		90		0\n"
			"gpr		ocr1ah	.8		90		0\n"
			"gpr		ocr1al	.8		90		0\n"
			"gpr		ocr1b	.16		90		0\n"
			"gpr		ocr1bl	.8		90		0\n"
			"gpr		ocr1bh	.8		90		0\n"
			"gpr		tccr2a	.8		90		0\n"
			"gpr		tccr2b	.8		90		0\n"
			"gpr		tcnt2	.8		90		0\n"
			"gpr		ocr2a	.8		90		0\n"
			"gpr		ocr2b	.8		90		0\n"
			"gpr		twsr	.8		90		0\n"
			"gpr		twar	.8		90		0\n"
			"gpr		twdr	.8		90		0\n"
			"gpr		twcr	.8		90		0\n"
			"gpr		twbr	.8		90		0\n"
			"gpr		twamr	.8		90		0\n"
			"gpr		ucsr0a	.8		90		0\n"
			"gpr		ucsr0b	.8		90		0\n"
			"gpr		ucsr0c	.8		90		0\n"
			"gpr		ubrr0l	.8		90		0\n"
			"gpr		ubrr0h	.8		90		0\n"
			"gpr		udr0	.8		90		0\n";
		RStrBuf *sb = r_strbuf_new (registers_profile);
		r_strbuf_append (sb, section_two);
		return r_strbuf_drain (sb);
	}

	return strdup (registers_profile);
}

static int info(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_CODE_ALIGN) {
		return 2;
	}
	if (q == R_ARCH_INFO_MAXOP_SIZE) {
		return 4;
	}
	if (q == R_ARCH_INFO_MINOP_SIZE) {
		return 2;
	}
	return 2; // XXX
}

#if 0
// made obsolete by "e anal.mask = true"
static ut8 *anal_mask_avr(RArchSession *as, int size, const ut8 *data, ut64 at) {
	RAnalOp *op = NULL;
	ut8 *ret = NULL;
	int idx;

	if (!(op = r_anal_op_new ())) {
		return NULL;
	}

	if (!(ret = malloc (size))) {
		r_anal_op_free (op);
		return NULL;
	}

	memset (ret, 0xff, size);

	CPU_MODEL *cpu = get_cpu_model (as->data, as->config->cpu);

	for (idx = 0; idx + 1 < size; idx += op->size) {
		OPCODE_DESC* opcode_desc = avr_op_analyze (as, op, at + idx, data + idx, size - idx, cpu);

		if (op->size < 1) {
			break;
		}

		if (!opcode_desc) { // invalid instruction
			continue;
		}

		// the additional data for "long" opcodes (4 bytes) is usually something we want to ignore for matching
		// (things like memory offsets or jump addresses)
		if (op->size == 4) {
			ret[idx + 2] = 0;
			ret[idx + 3] = 0;
		}

		if (op->ptr != UT64_MAX || op->jump != UT64_MAX) {
			ret[idx] = opcode_desc->mask;
			ret[idx + 1] = opcode_desc->mask >> 8;
		}
	}

	r_anal_op_free (op);

	return ret;
}
#endif

static bool esil_cb(RArchSession *as, RArchEsilAction action) {
	REsil *esil = as->arch->esil;
	if (!esil) {
		return false;
	}

	switch (action) {
	case R_ARCH_ESIL_ACTION_INIT:
		return esil_avr_init (as, esil);
	case R_ARCH_ESIL_ACTION_FINI:
		return esil_avr_fini (as, esil);
	default:
		return false;
	}
	return true;
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	as->data = R_NEW0 (PluginData);
	return !!as->data;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	R_FREE (as->data);
	return true;
}

const RArchPlugin r_arch_plugin_avr = {
	.meta = {
		.name = "avr",
		.author = "pancake,rvalles,condret,killabyte",
		.desc = "AVR microcontroller CPU by Atmel",
		.license = "LGPL-3.0-only",
	},
	.arch = "avr",
	.info = info,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.bits = R_SYS_BITS_PACK2 (8, 16), // 24 big regs conflicts
	.decode = decode,
	.encode = encode,
	.regs = regs,
	.esilcb = esil_cb,
	.init = init,
	.fini = fini,
	.cpus = "ATxmega128a4u,"	// First one is default
		"ATmega8,"
		"ATmega1280,"
		"ATmega1281,"
		"ATmega168,"
		"ATmega2560,"
		"ATmega2561,"
		"ATmega328p,"
		"ATmega32u4,"
		"ATmega48,"
		"ATmega640,"
		"ATmega88"
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_avr,
	.version = R2_VERSION
};
#endif
