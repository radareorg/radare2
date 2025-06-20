/* radare - LGPL - Copyright 2013-2024 - pancake, dkreuter, astuder  */

#include <r_asm.h>
#include <r_anal.h>

#include "8051_ops.h"
#include "8051_ass.c"
#include "8051_disas.c"

typedef struct {
	const char *name;
	ut32 map_code;
	ut32 map_idata;
	ut32 map_sfr;
	ut32 map_xdata;
	ut32 map_pdata;
} i8051_cpu_model;

static const i8051_cpu_model cpu_models[] = {
	{
		.name = "8051-generic",
		.map_code	= 0,
		.map_idata	= 0x10000000,
		.map_sfr	= 0x10000180,
		.map_xdata	= 0x20000000,
		.map_pdata	= 0x00000000
	},
	{
		.name = "8051-shared-code-xdata",
		.map_code	= 0,
		.map_idata	= 0x10000000,
		.map_sfr	= 0x10000180,
		.map_xdata	= 0x00000000,
		.map_pdata	= 0x00000000
	},
	{
		.name = NULL	// last entry
	}
};

typedef struct plugin_data_t {
	const i8051_cpu_model *cpu_curr_model;
	REsilCallbacks ocbs;
	bool i8051_is_init;
} PluginData;

static bool i8051_reg_write(RArchSession *as, const char *regname, ut32 num) {
	RReg *reg = NULL; // TODO
	if (reg) {
		RRegItem *item = r_reg_get (reg, regname, R_REG_TYPE_GPR);
		if (item) {
			r_reg_set_value (reg, item, num);
			return true;
		}
	}
	return false;
}

static ut32 i8051_reg_read(RArchSession *as, const char *regname) {
	RReg *reg = NULL; // TODO
	if (reg) {
		RRegItem *item = r_reg_get (reg, regname, R_REG_TYPE_GPR);
		if (item) {
			return r_reg_get_value (reg, item);
		}
	}
	return 0;
}

typedef struct {
	RIODesc *desc;
	int desc_fd;
	ut32 addr;
	const char *name;
} i8051_map_entry;

enum {
	I8051_IDATA = 0,
	I8051_SFR = 1,
	I8051_XDATA = 2
};

#if 0 // TODO
static i8051_map_entry mem_map[3] = {
	{ NULL, -1, UT32_MAX, "idata" },
	{ NULL, -1, UT32_MAX, "sfr" },
	{ NULL, -1, UT32_MAX, "xdata" }
};

static void map_cpu_memory(RArchSession *as, int entry, ut32 addr, ut32 size, bool force) {
	RIODesc *desc = mem_map[entry].desc; // XXX this is UAFable
	int fd = desc? mem_map[entry].desc_fd: -1;
	if (fd != -1 && anal->iob.fd_get_name (anal->iob.io, fd)) {
		if (force || addr != mem_map[entry].addr) {
			// reallocate mapped memory if address changed
			anal->iob.fd_remap (anal->iob.io, fd, addr);
		}
	} else {
		// allocate memory for address space
		char *mstr = r_str_newf ("malloc://%d", size);
		desc = anal->iob.open_at (anal->iob.io, mstr, R_PERM_RW, 0, addr);
		free (mstr);
		fd = desc? desc->fd: -1;
		// set 8051 address space as name of mapped memory
		if (desc && anal->iob.fd_get_name (anal->iob.io, fd)) {
			RList *maps = anal->iob.fd_get_map (anal->iob.io, fd);
			RIOMap *current_map;
			RListIter *iter;
			r_list_foreach (maps, iter, current_map) {
				char *cmdstr = r_str_newf ("omni %d %s", current_map->id, mem_map[entry].name);
				anal->coreb.cmd (anal->coreb.core, cmdstr);
				free (cmdstr);
			}
			r_list_free (maps);
		}
	}
	mem_map[entry].desc = desc;
	mem_map[entry].desc_fd = fd;
	mem_map[entry].addr = addr;
}
#endif

static void set_cpu_model(RArchSession *as, bool force) {
	ut32 addr_idata, addr_sfr, addr_xdata;

	if (!as || !as->config || !as->data) {
		return;
	}

	const char *cpu = as->config->cpu;
	if (!cpu || !cpu[0]) {
		cpu = cpu_models[0].name;
	}

	// if cpu model changed, reinitialize emulation
	PluginData *pd = as->data;
	if (force || !pd->cpu_curr_model || r_str_casecmp (cpu, pd->cpu_curr_model->name)) {
		// find model by name
		int i = 0;
		while (cpu_models[i].name && r_str_casecmp (cpu, cpu_models[i].name)) {
			i++;
		}
		if (!cpu_models[i].name) {
			i = 0;	// if not found, default to generic 8051
		}
		pd->cpu_curr_model = &cpu_models[i];

		// TODO: Add flags as needed - seek using pseudo registers works w/o flags

		// set memory map registers
		addr_idata = cpu_models[i].map_idata;
		addr_sfr = cpu_models[i].map_sfr;
		addr_xdata = cpu_models[i].map_xdata;
		i8051_reg_write (as, "_code", cpu_models[i].map_code);
		i8051_reg_write (as, "_idata", addr_idata);
		i8051_reg_write (as, "_sfr", addr_sfr - 0x80);
		i8051_reg_write (as, "_xdata", addr_xdata);
		i8051_reg_write (as, "_pdata", cpu_models[i].map_pdata);
	} else {
		addr_idata = i8051_reg_read (as, "_idata");
		addr_sfr = i8051_reg_read (as, "_sfr") + 0x80;
		addr_xdata = i8051_reg_read (as, "_xdata");
	}

	// (Re)allocate memory as needed.
	// We assume that code is allocated with firmware image
#if 0 // TODO
	if (anal->iob.fd_get_name && anal->coreb.cmd) {
		map_cpu_memory (as, I8051_IDATA, addr_idata, 0x100, force);
		map_cpu_memory (as, I8051_SFR, addr_sfr, 0x80, force);
		map_cpu_memory (as, I8051_XDATA, addr_xdata, 0x10000, force);
	}
#endif
}

static ut8 bitindex[] = {
	// bit 'i' can be found in (ram[bitindex[i>>3]] >> (i&7)) & 1
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, // 0x00
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, // 0x40
	0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, // 0x80
	0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8  // 0xC0
};

#if 0
typedef struct {
	const char *name;
	ut8 offset; // offset into memory, where the value is held
	ut8 resetvalue; // value the register takes in case of a reset
	ut8 num_bytes; // no more than sizeof (ut64)
	ut8 banked : 1;
	ut8 isdptr : 1;
} RI8051Reg;

// custom reg read/write temporarily disabled - see r2 issue #9242
static RI8051Reg registers[] = {
	// keep these sorted
	{ "a",     0xE0, 0x00, 1, 0},
	{ "b",     0xF0, 0x00, 1, 0},
	{ "dph",   0x83, 0x00, 1, 0},
	{ "dpl",   0x82, 0x00, 1, 0},
	{ "dptr",  0x82, 0x00, 2, 0, 1},
	{ "ie",    0xA8, 0x00, 1, 0},
	{ "ip",    0xB8, 0x00, 1, 0},
	{ "p0",    0x80, 0xFF, 1, 0},
	{ "p1",    0x90, 0xFF, 1, 0},
	{ "p2",    0xA0, 0xFF, 1, 0},
	{ "p3",    0xB0, 0xFF, 1, 0},
	{ "pcon",  0x87, 0x00, 1, 0},
	{ "psw",   0xD0, 0x00, 1, 0},
	{ "r0",    0x00, 0x00, 1, 1},
	{ "r1",    0x01, 0x00, 1, 1},
	{ "r2",    0x02, 0x00, 1, 1},
	{ "r3",    0x03, 0x00, 1, 1},
	{ "r4",    0x04, 0x00, 1, 1},
	{ "r5",    0x05, 0x00, 1, 1},
	{ "r6",    0x06, 0x00, 1, 1},
	{ "r7",    0x07, 0x00, 1, 1},
	{ "sbuf",  0x99, 0x00, 1, 0},
	{ "scon",  0x98, 0x00, 1, 0},
	{ "sp",    0x81, 0x07, 1, 0},
	{ "tcon",  0x88, 0x00, 1, 0},
	{ "th0",   0x8C, 0x00, 1, 0},
	{ "th1",   0x8D, 0x00, 1, 0},
	{ "tl0",   0x8A, 0x00, 1, 0},
	{ "tl1",   0x8B, 0x00, 1, 0},
	{ "tmod",  0x89, 0x00, 1, 0}
};
#endif

#define flag_c "7,$c,c,:=,"
#define flag_b "8,$b,c,:=,"
#define flag_ac "3,$c,ac,:=,"
#define flag_ab "3,$b,ac,:=,"
#define flag_ov "6,$c,ov,:=,"
#define flag_ob "7,$b,6,$b,^,ov,:=,"
#define flag_p "0xff,a,&=,$p,!,p,:=,"

#define ev_a 0
#define ev_bit bitindex[buf[1]>>3]
#define ev_c 0
#define ev_dir1 buf[1]
#define ev_dir2 buf[2]
#define ev_dp 0
#define ev_dpx 0
#define ev_imm1 buf[1]
#define ev_imm2 buf[2]
#define ev_imm16 op->val
#define ev_ri (1 & buf[0])
#define ev_rix (1 & buf[0])
#define ev_rn (7 & buf[0])
#define ev_sp2 0
#define ev_sp1 0

static void exr_a(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "a,");
}

static void exr_dir1(RAnalOp *op, ut8 addr) {
	if (addr < 0x80) {
		r_strbuf_appendf (&op->esil, "_idata,%d,+,[1],", addr);
	} else {
		r_strbuf_appendf (&op->esil, "_sfr,%d,+,[1],", addr);
	}
}

static void exr_bit(RAnalOp *op, ut8 addr) {
	exr_dir1 (op, addr);
}

static void exr_dpx(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "_xdata,dptr,+,[1],");
}

static void exr_imm1(RAnalOp *op, ut8 val) {
	r_strbuf_appendf (&op->esil, "%d,", val);
}

static void exr_imm2(RAnalOp *op, ut8 val) {
	r_strbuf_appendf (&op->esil, "%d,", val);
}

static void exr_imm16(RAnalOp *op, ut16 val) {
	r_strbuf_appendf (&op->esil, "%d,", val);
}

static void exr_ri(RAnalOp *op, ut8 reg) {
	r_strbuf_appendf (&op->esil, "_idata,r%d,+,[1],", reg);
}

static void exr_rix(RAnalOp *op, ut8 reg) {
	r_strbuf_appendf (&op->esil, "8,0xff,_pdata,&,<<,_xdata,+,r%d,+,[1],", reg);
}

static void exr_rn(RAnalOp *op, ut8 reg) {
	r_strbuf_appendf (&op->esil, "r%d,", reg);
}

static void exr_sp1(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "_idata,sp,+,[1],");
	r_strbuf_append (&op->esil, "1,sp,-=,");
}

static void exr_sp2(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "1,sp,-=,");
	r_strbuf_append (&op->esil, "_idata,sp,+,[2],");
	r_strbuf_append (&op->esil, "1,sp,-=,");
}

static void exw_a(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "a,=,");
}

static void exw_c(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "c,=,");
}

static void exw_dir1(RAnalOp *op, ut8 addr) {
	if (addr < 0x80) {
		r_strbuf_appendf (&op->esil, "_idata,%d,+,=[1],", addr);
	} else {
		r_strbuf_appendf (&op->esil, "_sfr,%d,+,=[1],", addr);
	}
}

static void exw_dir2(RAnalOp *op, ut8 addr) {
	exw_dir1 (op, addr);
}

static void exw_bit(RAnalOp *op, ut8 addr) {
	exw_dir1 (op, addr);
}

static void exw_dp(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "dptr,=,");
}

static void exw_dpx(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "_xdata,dptr,+,=[1],");
}

static void exw_ri(RAnalOp *op, ut8 reg) {
	r_strbuf_appendf (&op->esil, "_idata,r%d,+,=[1],", reg);
}

static void exw_rix(RAnalOp *op, ut8 reg) {
	r_strbuf_appendf (&op->esil, "8,0xff,_pdata,&,<<,_xdata,+,r%d,+,=[1],", reg);
}

static void exw_rn(RAnalOp *op, ut8 reg) {
	r_strbuf_appendf (&op->esil, "r%d,=,", reg);
}

static void exw_sp1(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "1,sp,+=,");
	r_strbuf_append (&op->esil, "_idata,sp,+,=[1],");
}

static void exw_sp2(RAnalOp *op, ut8 dummy) {
	r_strbuf_append (&op->esil, "1,sp,+=,");
	r_strbuf_append (&op->esil, "_idata,sp,+,=[2],");
	r_strbuf_append (&op->esil, "1,sp,+=,");
}

static void exi_a(RAnalOp *op, ut8 dummy, const char* operation) {
	r_strbuf_appendf (&op->esil, "a,%s=,", operation);
}

static void exi_c(RAnalOp *op, ut8 dummy, const char* operation) {
	r_strbuf_appendf (&op->esil, "c,%s=,", operation);
}

static void exi_dp(RAnalOp *op, ut8 dummy, const char *operation) {
	r_strbuf_appendf (&op->esil, "dptr,%s=,", operation);
}

static void exi_dir1(RAnalOp *op, ut8 addr, const char *operation) {
	if (addr < 0x80) {
		r_strbuf_appendf (&op->esil, "_idata,%d,+,%s=[1],", addr, operation);
	} else {
		r_strbuf_appendf (&op->esil, "_sfr,%d,+,%s=[1],", addr, operation);
	}
}

static void exi_bit(RAnalOp *op, ut8 addr, const char *operation) {
	exi_dir1 (op, addr, operation);
}

static void exi_ri(RAnalOp *op, ut8 reg, const char *operation) {
	r_strbuf_appendf (&op->esil, "_idata,r%d,+,%s=[1],", reg, operation);
}

static void exi_rn(RAnalOp *op, ut8 reg, const char *operation) {
	r_strbuf_appendf (&op->esil, "r%d,%s=,", reg, operation);
}

#define xr(subject) exr_##subject (op, ev_##subject)
#define xw(subject) exw_##subject (op, ev_##subject)
#define xi(subject, operation) exi_##subject (op, ev_##subject, operation)

#define bit_set r_strbuf_appendf (&op->esil ,"%d,1,<<,", buf[1] & 7)
#define bit_mask bit_set; r_strbuf_append (&op->esil, "255,^,")
#define bit_r r_strbuf_appendf (&op->esil, "%d,", buf[1] & 7); \
	xr (bit); \
	r_strbuf_append (&op->esil, ">>,1,&,")
#define bit_c r_strbuf_appendf (&op->esil, "%d,c,<<,", buf[1] & 7);

#define jmp r_strbuf_appendf (&op->esil, "%" PFMT64d ",pc,=", op->jump)
#define cjmp r_strbuf_append (&op->esil, "?{,"); jmp; r_strbuf_append (&op->esil, ",}")
#define call r_strbuf_appendf (&op->esil, "%" PFMT64d ",", op->fail); xw (sp2); jmp

#define alu_op(val, aluop, flags) xr (val); r_strbuf_append (&op->esil, "a," aluop "=," flags)
#define alu_op_c(val, aluop, flags) r_strbuf_append (&op->esil, "c,"); xr (val); r_strbuf_append (&op->esil, "+,a," aluop "=," flags)
#define alu_op_d(val, aluop) xr (val); xi (dir1, aluop)

#define template_alu4_c(base, aluop, flags) \
	case base + 0x4: \
		alu_op_c (imm1, aluop, flags); break; \
	case base + 0x5: \
		alu_op_c (dir1, aluop, flags); break; \
	case base + 0x6: \
	case base + 0x7: \
		alu_op_c (ri, aluop, flags); break; \
	case base + 0x8: case base + 0x9: \
	case base + 0xA: case base + 0xB: \
	case base + 0xC: case base + 0xD: \
	case base + 0xE: case base + 0xF: \
		alu_op_c (rn, aluop, flags); break;

#define template_alu2(base, aluop) \
	case base + 0x2: \
		alu_op_d (a, aluop); break; \
	case base + 0x3: \
		alu_op_d (imm2, aluop); break; \

#define template_alu4(base, aluop, flags) \
	case base + 0x4: \
		alu_op (imm1, aluop, flags); break; \
	case base + 0x5: \
		alu_op (dir1, aluop, flags); break; \
	case base + 0x6: \
	case base + 0x7: \
		alu_op (ri, aluop, flags); break; \
	case base + 0x8: case base + 0x9: \
	case base + 0xA: case base + 0xB: \
	case base + 0xC: case base + 0xD: \
	case base + 0xE: case base + 0xF: \
		alu_op (rn, aluop, flags); break;

static void analop_esil(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf) {
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	switch (buf[0]) {
	// Irregulars sorted by lower nibble
	case 0x00: /* nop */
		r_strbuf_append (&op->esil, ",");
		break;

	case 0x10: /* jbc bit, offset */
		r_strbuf_appendf (&op->esil, "%d,", buf[1] & 7);
		exr_bit (op, bitindex[buf[1]>>3]);
		r_strbuf_appendf (&op->esil ,">>,1,&,?{,%d,1,<<,0xff,^,", buf[1] & 7);
		exi_bit (op, bitindex[buf[1]>>3], "&");
		r_strbuf_appendf (&op->esil, "%"PFMT64d",pc,:=,}", op->jump);
		break;
	case 0x20: /* jb bit, offset */
  		r_strbuf_appendf (&op->esil, "%d,", buf[1] & 7);
		exr_bit (op, bitindex[buf[1]>>3]);
		r_strbuf_appendf (&op->esil, ">>,1,&,?{,%"PFMT64d",pc,:=,}", op->jump);
		break;
	case 0x30: /* jnb bit, offset */
		r_strbuf_appendf (&op->esil, "%d,", buf[1] & 7);
		exr_bit (op, bitindex[buf[1]>>3]);
		r_strbuf_appendf (&op->esil, ">>,1,&,!,?{,%"PFMT64d",pc,:=,}", op->jump);
		break;
	case 0x40: /* jc offset */
		r_strbuf_appendf (&op->esil, "c,1,&,?{,%"PFMT64d",pc,:=,}", op->jump);
		break;
	case 0x50: /* jnc offset */
		r_strbuf_appendf (&op->esil, "c,1,&,!,?{,%"PFMT64d",pc,:=,}", op->jump);
		break;
	case 0x60: /* jz offset */
		r_strbuf_appendf (&op->esil, "a,!,?{,%"PFMT64d",pc,:=,}", op->jump);
		break;
	case 0x70: /* jnz offset */
		r_strbuf_appendf (&op->esil, "a,!,!,?{,%"PFMT64d",pc,:=,}", op->jump);
		break;

	case 0x11: case 0x31: case 0x51: case 0x71:
	case 0x91: case 0xB1: case 0xD1: case 0xF1: /* acall addr11 */
	case 0x12: /* lcall addr16 */
		call;
		break;
	case 0x01: case 0x21: case 0x41: case 0x61:
	case 0x81: case 0xA1: case 0xC1: case 0xE1: /* ajmp addr11 */
	case 0x02: /* ljmp addr16 */
	case 0x80: /* sjmp offset */
		jmp;
		break;

	case 0x22: /* ret */
	case 0x32: /* reti */
		xr (sp2);
		r_strbuf_append (&op->esil, "pc,=");
		break;

	case 0x03: /* rr a */
		r_strbuf_append (&op->esil, "1,a,0x101,*,>>,a,=," flag_p);
		break;
	case 0x04: /* inc a */
		xi (a, "++");
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0x05: /* inc direct */
		xi (dir1, "++");
		break;
	case 0x06: case 0x07: /* inc @Ri */
		xi (ri, "++");
		break;
	case 0x08: case 0x09: case 0x0A: case 0x0B:
	case 0x0C: case 0x0D: case 0x0E: case 0x0F: /* inc @Rn */
		xi (rn, "++");
		break;
	case 0x13: /* rrc a */
		r_strbuf_append (&op->esil,
			"7,c,<<,1,a,&,c,=,0x7f,1,a,>>,&,+,a,=,0xff,a,&=,$p,!,p,:=,");
		break;
	case 0x14: /* dec a */
		xi (a, "--");
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0x15: /* dec direct */
		xi (dir1, "--");
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0x16: case 0x17: /* dec @Ri */
		xi (ri, "--");
		break;
	case 0x18: case 0x19: case 0x1A: case 0x1B:
	case 0x1C: case 0x1D: case 0x1E: case 0x1F: /* dec @Rn */
		xi (rn, "--");
		break;
	case 0x23: /* rl a */
		r_strbuf_append (&op->esil, "7,a,0x101,*,>>,a,=,0xff,a,&=,$p,!,p,:=,");
		break;
	template_alu4 (0x20, "+", flag_c flag_ac flag_ov flag_p) /* 0x24..0x2f add a,.. */
	case 0x33: /* rlc a */
		r_strbuf_append (&op->esil, "c,1,&,a,a,+=,7,$c,c,:=,a,+=,0xff,a,&=,$p,!,p,:=,");
		break;
	template_alu4_c (0x30, "+", flag_c flag_ac flag_ov flag_p) /* 0x34..0x3f addc a,.. */
	template_alu2 (0x40, "|") /* 0x42..0x43 orl direct,.. */
	template_alu4 (0x40, "|", flag_p) /* 0x44..0x4f orl a,.. */
	template_alu2 (0x50, "&") /* 0x52..0x53 anl direct,.. */
	template_alu4 (0x50, "&", flag_p) /* 0x54..0x5f anl a,.. */
	template_alu2 (0x60, "^") /* 0x62..0x63 xrl direct,.. */
	template_alu4 (0x60, "^", flag_p) /* 0x64..0x6f xrl a,.. */
	case 0x72: /* orl C, bit */
		bit_r; xi (c, "|");
		break;
	case 0x73: /* jmp @a+dptr */
		r_strbuf_append (&op->esil, "dptr,a,+,pc,=");
		break;
	case 0x74: /* mov a, imm */
		exr_imm1 (op, buf[1]);
		exw_a (op, 0);
  		r_strbuf_append (&op->esil, "0xff,a,&=,$p,!,p,:=,");
		break;
	case 0x75: /* mov direct, imm */
		exr_imm2 (op, buf[2]);
		exw_dir1 (op, buf[1]);
		break;
	case 0x76: case 0x77: /* mov @Ri, imm */
		exr_imm1 (op, buf[1]);
		exw_ri (op, (1 & buf[0]));
		break;
	case 0x78: case 0x79: case 0x7A: case 0x7B:
	case 0x7C: case 0x7D: case 0x7E: case 0x7F: /* mov Rn, imm */
		exr_imm1 (op, buf[1]);
		exw_rn (op, (7 & buf[0]));
		break;
	case 0x82: /* anl C, bit */
		bit_r; xi (c, "&");
		break;
	case 0x83: /* movc a, @a+pc */
		r_strbuf_append (&op->esil, "a,pc,--,+,[1],a,=,0xff,a,&=,$p,!,p,:=,");
		break;
	case 0x84: /* div ab */
		// note: escape % if this becomes a format string
		r_strbuf_append (&op->esil,
			"b,!,ov,:=,b,a,%,b,a,/=,b,=,0,c,=,0xff,a,&=,$p,!,p,:=,");
		break;
	case 0x85: /* mov direct, direct */
		exr_dir1 (op, buf[1]);
		exw_dir2 (op, buf[2]);
		break;
	case 0x86: case 0x87: /* mov direct, @Ri */
  		exr_ri (op, (1 & buf[0]));
		exw_dir1 (op, buf[1]);
		break;
	case 0x88: case 0x89: case 0x8A: case 0x8B:
	case 0x8C: case 0x8D: case 0x8E: case 0x8F: /* mov direct, Rn */
  		exr_rn (op, (7 & buf[0]));
		exw_dir1 (op, buf[1]);
		break;
	case 0x90: /* mov dptr, imm */
		exr_imm16 (op, op->val);
		exw_dp (op, 0);
		break;
	case 0x92: /* mov bit, C */
		bit_c; bit_mask; xr (bit);
		r_strbuf_append (&op->esil, "&,|,"); xw(bit);
		break;
	case 0x93: /* movc a, @a+dptr */
  		r_strbuf_append (&op->esil, "a,dptr,+,[1],a,=,0xff,a,&=,$p,!,p,:=,");
		break;
	template_alu4_c (0x90, "-", flag_b flag_ab flag_ob flag_p) /* 0x94..0x9f subb a,.. */
	case 0xA0: /* orl C, /bit */
		bit_r;
		r_strbuf_append (&op->esil, "!,"); xi (c, "|");
		break;
	case 0xA2: /* mov C, bit */
		bit_r; xw (c);
		break;
	case 0xA3: /* inc dptr */
  		exi_dp (op, 0, "++");
		break;
	case 0xA4: /* mul ab */
		r_strbuf_append (&op->esil,
			"8,a,b,*,DUP,a,=,>>,DUP,b,=,!,!,ov,:=,0,c,=,0xff,a,&=,$p,!,p,:=,");
		break;
	case 0xA5: /* "reserved" */
		r_strbuf_append (&op->esil, "0,trap");
		break;
	case 0xA6: case 0xA7: /* mov @Ri, direct */
		exr_dir1 (op, buf[1]);
		exw_ri (op, (1 & buf[0]));
		break;
	case 0xA8: case 0xA9: case 0xAA: case 0xAB:
	case 0xAC: case 0xAD: case 0xAE: case 0xAF: /* mov Rn, direct */
		exr_dir1 (op, buf[1]);
		exw_rn (op, (7 & buf[0]));
		break;
	case 0xB0: /* anl C, /bit */
		bit_r;
		r_strbuf_append (&op->esil, "!,"); xi (c, "&");
		break;
	case 0xB2: /* cpl bit */
		bit_set; xi (bit, "^");
		break;
	case 0xB3: /* cpl C */
		r_strbuf_append (&op->esil, "1,"); xi (c, "^");
		break;
	case 0xB4: /* cjne a, imm, offset */
		xr (imm1); xr (a);
		r_strbuf_append (&op->esil, "==,$z,!," flag_b); cjmp;
		break;
	case 0xB5: /* cjne a, direct, offset */
		xr (dir1); xr (a);
		r_strbuf_append (&op->esil, "==,$z,!," flag_b); cjmp;
		break;
	case 0xB6: case 0xB7: /* cjne @ri, imm, offset */
		xr (imm1); xr (ri);
		r_strbuf_append (&op->esil, "==,$z,!," flag_b); cjmp;
		break;
	case 0xB8: case 0xB9: case 0xBA: case 0xBB:
	case 0xBC: case 0xBD: case 0xBE: case 0xBF: /* cjne Rn, imm, offset */
		xr (imm1); xr (rn);
		r_strbuf_append (&op->esil, "==,$z,!," flag_b); cjmp;
		break;
	case 0xC0: /* push direct */
  		exr_dir1 (op, buf[1]);
		exw_sp1 (op, 0);
		break;
	case 0xC2: /* clr bit */
		bit_mask; xi (bit, "&");
		break;
	case 0xC3: /* clr C */
		r_strbuf_append (&op->esil, "0,"); xw (c);
		break;
	case 0xC4: /* swap a */
		r_strbuf_append (&op->esil, "0xff,4,a,0x101,*,>>,&,a,=," flag_p);
		break;
	case 0xC5: /* xch a, direct */
		xr (a);
		r_strbuf_append (&op->esil, "0,+,"); xr (dir1); xw (a); xw (dir1);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xC6: case 0xC7: /* xch a, @Ri */
		xr (a);
		r_strbuf_append (&op->esil, "0,+,"); xr (ri); xw (a); xw (ri);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xC8: case 0xC9: case 0xCA: case 0xCB:
	case 0xCC: case 0xCD: case 0xCE: case 0xCF: /* xch a, Rn */
		xr (a);
		r_strbuf_append (&op->esil, "0,+,"); xr (rn); xw (a); xw (rn);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xD0: /* pop direct */
		exr_sp1 (op, 0);
		exw_dir1 (op, buf[1]);
		break;
	case 0xD2: /* setb bit */
		bit_set; xi (bit, "|");
		break;
	case 0xD3: /* setb C */
		r_strbuf_append (&op->esil, "1,"); xw (c);
		break;
	case 0xD4: /* da a */
		// BCD adjust after add:
		// if (lower nibble > 9) or (AC == 1) add 6
		// if (higher nibble > 9) or (C == 1) add 0x60
		// carry |= carry caused by this operation
		r_strbuf_append (&op->esil, "a,0x0f,&,9,==,4,$b,ac,|,?{,6,a,+=,7,$c,c,|,c,:=,},a,0xf0,&,0x90,==,8,$b,c,|,?{,0x60,a,+=,7,$c,c,|,c,:=,}," flag_p);
		break;
	case 0xD5: /* djnz direct, offset */
		xi (dir1, "--"); xr (dir1);
		r_strbuf_append (&op->esil, "0,==,$z,!,"); cjmp;
		break;
	case 0xD6:
	case 0xD7: /* xchd a, @Ri*/
		xr (a);
		r_strbuf_append (&op->esil, "0xf0,&,"); xr (ri);
		r_strbuf_append (&op->esil, "0x0f,&,|,");
		xr (ri);
		r_strbuf_append (&op->esil, "0xf0,&,"); xr (a);
		r_strbuf_append (&op->esil, "0x0f,&,|,");
		xw (ri); xw (a);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xD8: case 0xD9: case 0xDA: case 0xDB:
	case 0xDC: case 0xDD: case 0xDE: case 0xDF: /* djnz Rn, offset */
		xi (rn, "--"); xr (rn);
		r_strbuf_append (&op->esil, "0,==,$z,!,"); cjmp;
		break;
	case 0xE0: /* movx a, @dptr */
		xr (dpx); xw (a);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xE2: case 0xE3: /* movx a, @Ri */
		xr (rix); xw (a);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xE4: /* clr a */
		r_strbuf_append (&op->esil, "0,"); xw (a);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xE5: /* mov a, direct */
		xr (dir1); xw (a);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xE6: case 0xE7: /* mov a, @Ri */
		xr (ri); xw (a);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xE8: case 0xE9: case 0xEA: case 0xEB:
	case 0xEC: case 0xED: case 0xEE: case 0xEF: /* mov a, Rn */
		xr (rn); xw (a);
		r_strbuf_append (&op->esil, flag_p);
		break;
	case 0xF0: /* movx @dptr, a */
  		exr_a (op, 0);
		exw_dpx (op, 0);
		break;
	case 0xF2: case 0xF3: /* movx @Ri, a */
		exr_a (op, 0);
		exw_rix (op, (1 & buf[0]));
		break;
	case 0xF4: /* cpl a */
		r_strbuf_append (&op->esil, "255,");
		exi_a (op, 0, "^");
		r_strbuf_append (&op->esil, "0xff,a,&=,$p,!,p,:=,");
		break;
	case 0xF5: /* mov direct, a */
  		exr_a (op, 0);
		exw_dir1 (op, buf[1]);
		break;
	case 0xF6: case 0xF7: /* mov  @Ri, a */
  		exr_a (op, 0);
		exw_ri (op, (1 & buf[0]));
		break;
	case 0xF8: case 0xF9: case 0xFA: case 0xFB:
	case 0xFC: case 0xFD: case 0xFE: case 0xFF: /* mov Rn, a */
		exr_a (op, 0);
		exw_rn (op, (7 & buf[0]));
		break;
	default:
		break;
	}
}

#if 0
// custom reg read/write temporarily disabled - see r2 issue #9242
static int i8051_hook_reg_read(REsil *, const char *, ut64 *, int *);

static int i8051_reg_compare(const void *name, const void *reg) {
	return strcmp ((const char*)name, ((RI8051Reg*)reg)->name);
}

static RI8051Reg *i8051_reg_find(const char *name) {
	return (RI8051Reg *) bsearch (
		name, registers,
		sizeof (registers) / sizeof (registers[0]),
		sizeof (registers[0]),
		i8051_reg_compare);
}

static int i8051_reg_get_offset(REsil *esil, RI8051Reg *ri) {
	ut8 offset = ri->offset;
	if (ri->banked) {
		ut64 psw = 0LL;
		i8051_hook_reg_read (esil, "psw", &psw, NULL);
		offset += psw & 0x18;
	}
	return offset;
}

// dkreuter: It would be nice if we could attach hooks to RRegItems directly.
//           That way we could avoid doing a string lookup on register names
//           as r_reg_get already does this. Also, the anal esil callbacks
//           approach interferes with r_reg_arena_swap.

static int i8051_hook_reg_read(REsil *esil, const char *name, ut64 *res, int *size) {
	int ret = 0;
	ut64 val = 0LL;
	RI8051Reg *ri;
	REsilCallbacks cbs = esil->cb;

	if ((ri = i8051_reg_find (name))) {
		ut8 offset = i8051_reg_get_offset(esil, ri);
		ret = r_esil_mem_read (esil, IRAM_BASE + offset, (ut8*)res, ri->num_bytes);
	}
	esil->cb = ocbs;
	if (!ret && ocbs.hook_reg_read) {
		ret = ocbs.hook_reg_read (esil, name, res, NULL);
	}
	if (!ret && ocbs.reg_read) {
		ret = ocbs.reg_read (esil, name, &val, NULL);
	}
	esil->cb = cbs;

	return ret;
}

static int i8051_hook_reg_write(REsil *esil, const char *name, ut64 *val) {
	int ret = 0;
	RI8051Reg *ri;
	REsilCallbacks cbs = esil->cb;
	if ((ri = i8051_reg_find (name))) {
		ut8 offset = i8051_reg_get_offset(esil, ri);
		ret = r_esil_mem_write (esil, IRAM_BASE + offset, (ut8*)val, ri->num_bytes);
	}
	esil->cb = ocbs;
	if (!ret && ocbs.hook_reg_write) {
		ret = ocbs.hook_reg_write (esil, name, val);
	}
	esil->cb = cbs;
	return ret;
}
#endif

#if 0
static int esil_i8051_init(RArchSession *as, REsil *esil) {
	PluginData *pd = as->data;
	if (esil->cb.user) {
		return true;
	}
	pd->ocbs = esil->cb;
	/* these hooks break esil emulation */
	/* pc is not read properly, mem mapped registers are not shown in ar, ... */
	/* all 8051 regs are mem mapped, and reg access via mem is very common */
//  disabled to make esil work, before digging deeper
//	esil->cb.hook_reg_read = i8051_hook_reg_read;
//	esil->cb.hook_reg_write = i8051_hook_reg_write;
	pd->i8051_is_init = true;
	return true;
}

static int esil_i8051_fini(RArchSession *as, REsil *esil) {
	PluginData *pd = as->data;

	if (!pd || !pd->i8051_is_init) {
		return false;
	}

	R_FREE (pd->ocbs.user);
	pd->i8051_is_init = false;
	return true;
}
#endif

static char *regs(RArchSession *as) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	bp\n"
		"=SN	r0\n"
		"=R0	r0\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"gpr	r0	.8	0	0\n"
		"gpr	r1	.8	1	0\n"
		"gpr	r2	.8	2	0\n"
		"gpr	r3	.8	3	0\n"
		"gpr	r4	.8	4	0\n"
		"gpr	r5	.8	5	0\n"
		"gpr	r6	.8	6	0\n"
		"gpr	r7	.8	7	0\n"
		"gpr	a	.8	8	0\n"
		"gpr	b	.8	9	0\n"
		"gpr	dptr	.16	10	0\n"
		"gpr	dpl	.8	10	0\n"
		"gpr	dph	.8	11	0\n"
		"gpr	psw	.8	12	0\n"
		"gpr	p	.1	.96	0\n"
		"gpr	ov	.1	.98	0\n"
		"gpr	ac	.1	.102	0\n"
		"gpr	c	.1	.103	0\n"
		"gpr	sp	.8	13	0\n"
		"gpr	pc	.16	15	0\n"
// ---------------------------------------------------
// 8051 memory emulation control registers
// These registers map 8051 memory classes to r2's
// linear address space. Registers contain base addr
// in r2 memory space representing the memory class.
// Offsets are initialized based on asm.cpu, but can
// be updated with ar command.
//
// _code
//		program memory (CODE)
// _idata
//		internal data memory (IDATA, IRAM)
// _sfr
//		special function registers (SFR)
// _xdata
//		external data memory (XDATA, XRAM)
// _pdata
//		page accessed by movx @ri op (PDATA, XREG)
//		r2 addr = (_pdata & 0xff) << 8 + x_data
//		if 0xffffffnn, addr = ([SFRnn] << 8) + _xdata (TODO)
		"gpr	_code	.32	20 0\n"
		"gpr	_idata	.32 24 0\n"
		"gpr	_sfr	.32	28 0\n"
		"gpr	_xdata	.32 32 0\n"
		"gpr	_pdata	.32	36 0\n";

#if 0
	int retval = r_reg_set_profile_string (anal->reg, p);
	if (retval) {
		// reset emulation control registers based on cpu
		set_cpu_model (anal, true);
	}
#endif

	return strdup (p);
}

static ut32 map_direct_addr(RArchSession *as, ut8 addr) {
	if (addr < 0x80) {
		return addr + i8051_reg_read (as, "_idata");
	} else {
		return addr + i8051_reg_read (as, "_sfr");
	}
}

static bool decode(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	set_cpu_model (as, false);

	int i = 0;
	if (buf[0]) {
		while (_8051_ops[i].string &&
			_8051_ops[i].op != (buf[0] & ~_8051_ops[i].mask)) {
			i++;
		}
	}

	ut8 arg1 = _8051_ops[i].arg1;
	ut8 arg2 = _8051_ops[i].arg2;

	op->cycles = _8051_ops[i].cycles;
	op->failcycles = _8051_ops[i].cycles;
	op->nopcode = 1;
	op->size = _8051_ops[i].len;
	op->type = _8051_ops[i].type;
	op->family = R_ANAL_OP_FAMILY_CPU; // maybe also FAMILY_IO...
	op->id = i;

	switch (_8051_ops[i].instr) {
	case OP_CJNE:
	case OP_DJNZ:
	case OP_JB:
	case OP_JBC:
	case OP_JNZ:
		op->cond = R_ANAL_CONDTYPE_NE;
		break;
	case OP_JNB:
	case OP_JZ:
		op->cond = R_ANAL_CONDTYPE_EQ;
		break;
	case OP_JC:
		op->cond = R_ANAL_CONDTYPE_HS;
		break;
	case OP_JNC:
		op->cond = R_ANAL_CONDTYPE_LO;
		break;
	default:
		op->cond = R_ANAL_CONDTYPE_AL;
		break;
	}

	switch (_8051_ops[i].instr) {
	case OP_CJNE:
	case OP_DJNZ:
	case OP_JB:
	case OP_JBC:
	case OP_JC:
	case OP_JMP:
	case OP_JNB:
	case OP_JNC:
	case OP_JNZ:
	case OP_JZ:
		op->eob = true;
		break;
	default:
		op->eob = false;
		break;
	}

	// TODO: op->datatype

	switch (arg1) {
	case A_DIRECT:
		if (len > 1) {
			op->ptr = map_direct_addr (as, buf[1]);
		}
		break;
	case A_BIT:
		if (len > 1) {
			op->ptr = map_direct_addr (as, arg_bit (buf[1]));
		}
		break;
	case A_IMMEDIATE:
		if (len > 1) {
			op->val = buf[1];
		}
		break;
	case A_IMM16:
		if (len > 2) {
			op->val = buf[1] * 256 + buf[2];
		} else {
			op->val = 0;
		}
		op->ptr = op->val + i8051_reg_read (as, "_xdata"); // best guess, it's a XRAM pointer
		break;
	}

	switch (arg2) {
	case A_DIRECT:
		if (arg1 == A_RI || arg1 == A_RN) {
			op->ptr = (len > 1)? map_direct_addr (as, buf[1]): 0;
		} else if (arg1 != A_DIRECT) {
			op->ptr = (len > 2)? map_direct_addr (as, buf[2]): 0;
		}
		break;
	case A_BIT:
		op->ptr = arg_bit ((arg1 == A_RI || arg1 == A_RN) ? buf[1] : buf[2]);
		op->ptr = map_direct_addr (as, op->ptr);
		break;
	case A_IMMEDIATE:
		if (len > 2) {
			op->val = (arg1 == A_RI || arg1 == A_RN) ? buf[1] : buf[2];
		}
		break;
	}

	switch (_8051_ops[i].instr) {
	case OP_PUSH:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;
		break;
	case OP_POP:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;
		break;
	case OP_RET:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;
		break;
	case OP_CALL:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		if (arg1 == A_ADDR11) {
			op->jump = arg_addr11 (addr + op->size, buf);
			op->fail = addr + op->size;
		} else if (arg1 == A_ADDR16) {
			op->jump = 0x100 * buf[1] + buf[2];
			op->fail = addr + op->size;
		}
		break;
	case OP_JMP:
		if (arg1 == A_ADDR11) {
			op->jump = arg_addr11 (addr + op->size, buf);
			op->fail = addr + op->size;
		} else if (arg1 == A_ADDR16) {
			op->jump = 0x100 * buf[1] + buf[2];
			op->fail = addr + op->size;
		} else if (arg1 == A_OFFSET) {
			op->jump = arg_offset (addr + op->size, buf[1]);
			op->fail = addr + op->size;
		}
		break;
	case OP_CJNE:
	case OP_DJNZ:
	case OP_JC:
	case OP_JNC:
	case OP_JZ:
	case OP_JNZ:
	case OP_JB:
	case OP_JBC:
	case OP_JNB:
		op->jump = arg_offset (addr + op->size, buf[op->size - 1]);
		op->fail = addr + op->size;
		break;
	default:
		// TODO
		break;
	}

	if (op->ptr != -1 && op->refptr == 0) {
		op->refptr = 1;
	}

	if (mask & R_ARCH_OP_MASK_ESIL) {
		ut8 copy[3] = {0, 0, 0};
		memcpy (copy, buf, len >= 3 ? 3 : len);
		analop_esil (as, op, addr, copy);
	}

	int olen = 0;
	op->mnemonic = r_8051_disas (addr, buf, len, &olen);
	op->size = olen;
	return op->size > 0;
}

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	ut8 outbuf[4];
	int size = assemble_8051 (op->addr, op->mnemonic, outbuf);
	if (size > 0) {
		free (op->bytes);
		op->bytes = r_mem_dup (outbuf, size);
		op->size = size;
		return true;
	}

	return false;
}

#if 0
static bool esil_cb(RArchSession *as, RArchEsilAction action) {
	REsil *esil = as->arch->esil;
	if (!esil) {
		return false;
	}

	switch (action) {
	case R_ARCH_ESIL_ACTION_INIT:
		esil_i8051_init (as, esil);
		break;
	case R_ARCH_ESIL_ACTION_FINI:
		esil_i8051_fini (as, esil);
		break;
	default:
		return false;
	}
	return true;
}
#endif

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 3;
	case R_ARCH_INFO_INVOP_SIZE:
		return 1;
	case R_ARCH_INFO_CODE_ALIGN:
		return 1;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	}
	return 0;
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

const RArchPlugin r_arch_plugin_8051 = {
	.meta = {
		.name = "8051",
		.author = "pancake,dkreuter,astuder",
		.desc = "8051 microcontroller (also known as MCS-51)",
		.license = "LGPL-3.0-only",
	},
	.arch = "8051",
	.bits = R_SYS_BITS_PACK2 (8, 16),
	.decode = decode,
	.encode = encode,
	.regs = regs,
//	.esilcb = esil_cb,
	.info = archinfo,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_8051,
	.version = R2_VERSION
};
#endif
