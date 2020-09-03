/* radare - LGPL - Copyright 2013-2019 - pancake, dkreuter, astuder  */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include <8051_ops.h>
#include "../asm/arch/8051/8051_disas.c"

typedef struct {
	const char *name;
	ut32 map_code;
	ut32 map_idata;
	ut32 map_sfr;
	ut32 map_xdata;
	ut32 map_pdata;
} i8051_cpu_model;

static i8051_cpu_model cpu_models[] = {
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

static bool i8051_is_init = false;
static const i8051_cpu_model *cpu_curr_model = NULL;

static bool i8051_reg_write (RReg *reg, const char *regname, ut32 num) {
	if (reg) {
		RRegItem *item = r_reg_get (reg, regname, R_REG_TYPE_GPR);
		if (item) {
			r_reg_set_value (reg, item, num);
			return true;
		}
	}
	return false;
}

static ut32 i8051_reg_read (RReg *reg, const char *regname) {
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
	ut32 addr;
	const char *name;
} i8051_map_entry;

static const int I8051_IDATA = 0;
static const int I8051_SFR = 1;
static const int I8051_XDATA = 2;

static i8051_map_entry mem_map[3] = {
	{ NULL, UT32_MAX, "idata" },
	{ NULL, UT32_MAX, "sfr" },
	{ NULL, UT32_MAX, "xdata" }
};

static void map_cpu_memory (RAnal *anal, int entry, ut32 addr, ut32 size, bool force) {
	RIODesc *desc = mem_map[entry].desc;
	if (desc && anal->iob.fd_get_name (anal->iob.io, desc->fd)) {
		if (force || addr != mem_map[entry].addr) {
			// reallocate mapped memory if address changed
			anal->iob.fd_remap (anal->iob.io, desc->fd, addr);
		}
	} else {
		// allocate memory for address space
		char *mstr = r_str_newf ("malloc://%d", size);
		desc = anal->iob.open_at (anal->iob.io, mstr, R_PERM_RW, 0, addr);
		free (mstr);
		// set 8051 address space as name of mapped memory
		if (desc && anal->iob.fd_get_name (anal->iob.io, desc->fd)) {
			RList *maps = anal->iob.fd_get_map (anal->iob.io, desc->fd);
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
	mem_map[entry].addr = addr;
}

static void set_cpu_model(RAnal *anal, bool force) {
	ut32 addr_idata, addr_sfr, addr_xdata;

	if (!anal->reg) {
		return;
	}

	const char *cpu = anal->cpu;
	if (!cpu || !cpu[0]) {
		cpu = cpu_models[0].name;
	}

	// if cpu model changed, reinitialize emulation
	if (force || !cpu_curr_model || r_str_casecmp (cpu, cpu_curr_model->name)) {
		// find model by name
		int i = 0;
		while (cpu_models[i].name && r_str_casecmp (cpu, cpu_models[i].name)) {
			i++;
		}
		if (!cpu_models[i].name) {
			i = 0;	// if not found, default to generic 8051
		}
		cpu_curr_model = &cpu_models[i];

		// TODO: Add flags as needed - seek using pseudo registers works w/o flags

		// set memory map registers
		addr_idata = cpu_models[i].map_idata;
		addr_sfr = cpu_models[i].map_sfr;
		addr_xdata = cpu_models[i].map_xdata;
		i8051_reg_write (anal->reg, "_code", cpu_models[i].map_code);
		i8051_reg_write (anal->reg, "_idata", addr_idata);
		i8051_reg_write (anal->reg, "_sfr", addr_sfr - 0x80);
		i8051_reg_write (anal->reg, "_xdata", addr_xdata);
		i8051_reg_write (anal->reg, "_pdata", cpu_models[i].map_pdata);
	} else {
		addr_idata = i8051_reg_read (anal->reg, "_idata");
		addr_sfr = i8051_reg_read (anal->reg, "_sfr") + 0x80;
		addr_xdata = i8051_reg_read (anal->reg, "_xdata");
	}

	// (Re)allocate memory as needed.
	// We assume that code is allocated with firmware image
	if (anal->iob.fd_get_name && anal->coreb.cmd) {
		map_cpu_memory (anal, I8051_IDATA, addr_idata, 0x100, force);
		map_cpu_memory (anal, I8051_SFR, addr_sfr, 0x80, force);
		map_cpu_memory (anal, I8051_XDATA, addr_xdata, 0x10000, force);
	}
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
	ut8 num_bytes; // no more than sizeof(ut64)
	ut8 banked : 1;
	ut8 isdptr : 1;
} RI8051Reg;

// custom reg read/write temporarily disabled - see r2 issue #9242
static RI8051Reg registers[] = {
	// keep these sorted
	{"a",     0xE0, 0x00, 1, 0},
	{"b",     0xF0, 0x00, 1, 0},
	{"dph",   0x83, 0x00, 1, 0},
	{"dpl",   0x82, 0x00, 1, 0},
	{"dptr",  0x82, 0x00, 2, 0, 1},
	{"ie",    0xA8, 0x00, 1, 0},
	{"ip",    0xB8, 0x00, 1, 0},
	{"p0",    0x80, 0xFF, 1, 0},
	{"p1",    0x90, 0xFF, 1, 0},
	{"p2",    0xA0, 0xFF, 1, 0},
	{"p3",    0xB0, 0xFF, 1, 0},
	{"pcon",  0x87, 0x00, 1, 0},
	{"psw",   0xD0, 0x00, 1, 0},
	{"r0",    0x00, 0x00, 1, 1},
	{"r1",    0x01, 0x00, 1, 1},
	{"r2",    0x02, 0x00, 1, 1},
	{"r3",    0x03, 0x00, 1, 1},
	{"r4",    0x04, 0x00, 1, 1},
	{"r5",    0x05, 0x00, 1, 1},
	{"r6",    0x06, 0x00, 1, 1},
	{"r7",    0x07, 0x00, 1, 1},
	{"sbuf",  0x99, 0x00, 1, 0},
	{"scon",  0x98, 0x00, 1, 0},
	{"sp",    0x81, 0x07, 1, 0},
	{"tcon",  0x88, 0x00, 1, 0},
	{"th0",   0x8C, 0x00, 1, 0},
	{"th1",   0x8D, 0x00, 1, 0},
	{"tl0",   0x8A, 0x00, 1, 0},
	{"tl1",   0x8B, 0x00, 1, 0},
	{"tmod",  0x89, 0x00, 1, 0}
};
#endif

#define e(frag) r_strbuf_append(&op->esil, frag)
#define ef(frag, ...) r_strbuf_appendf(&op->esil, frag, __VA_ARGS__)

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
	e ("a,");
}

static void exr_dir1(RAnalOp *op, ut8 addr) {
	if (addr < 0x80) {
		ef ("_idata,%d,+,[1],", addr);
	} else {
		ef ("_sfr,%d,+,[1],", addr);
	}
}

static void exr_bit(RAnalOp *op, ut8 addr) {
	exr_dir1 (op, addr);
}

static void exr_dpx (RAnalOp *op, ut8 dummy) {
	e ("_xdata,dptr,+,[1],");
}

static void exr_imm1(RAnalOp *op, ut8 val) {
	ef ("%d,", val);
}

static void exr_imm2(RAnalOp *op, ut8 val) {
	ef ("%d,", val);
}

static void exr_imm16(RAnalOp *op, ut16 val) {
	ef ("%d,", val);
}

static void exr_ri(RAnalOp *op, ut8 reg) {
	ef ("_idata,r%d,+,[1],", reg);
}

static void exr_rix(RAnalOp *op, ut8 reg) {
	ef ("8,0xff,_pdata,&,<<,_xdata,+,r%d,+,[1],", reg);
}

static void exr_rn(RAnalOp *op, ut8 reg) {
	ef ("r%d,", reg);
}

static void exr_sp1(RAnalOp *op, ut8 dummy) {
	e ("_idata,sp,+,[1],");
	e ("1,sp,-=,");
}

static void exr_sp2(RAnalOp *op, ut8 dummy) {
	e ("1,sp,-=,");
	e ("_idata,sp,+,[2],");
	e ("1,sp,-=,");
}

static void exw_a(RAnalOp *op, ut8 dummy) {
	e ("a,=,");
}

static void exw_c(RAnalOp *op, ut8 dummy) {
	e ("c,=,");
}

static void exw_dir1(RAnalOp *op, ut8 addr) {
	if (addr < 0x80) {
		ef ("_idata,%d,+,=[1],", addr);
	} else {
		ef ("_sfr,%d,+,=[1],", addr);
	}
}

static void exw_dir2(RAnalOp *op, ut8 addr) {
	exw_dir1 (op, addr);
}

static void exw_bit(RAnalOp *op, ut8 addr) {
	exw_dir1 (op, addr);
}

static void exw_dp (RAnalOp *op, ut8 dummy) {
	e ("dptr,=,");
}

static void exw_dpx (RAnalOp *op, ut8 dummy) {
	e ("_xdata,dptr,+,=[1],");
}

static void exw_ri(RAnalOp *op, ut8 reg) {
	ef ("_idata,r%d,+,=[1],", reg);
}

static void exw_rix(RAnalOp *op, ut8 reg) {
	ef ("8,0xff,_pdata,&,<<,_xdata,+,r%d,+,=[1],", reg);
}

static void exw_rn(RAnalOp *op, ut8 reg) {
	ef ("r%d,=,", reg);
}

static void exw_sp1(RAnalOp *op, ut8 dummy) {
	e ("1,sp,+=,");
	e ("_idata,sp,+,=[1],");
}

static void exw_sp2(RAnalOp *op, ut8 dummy) {
	e ("1,sp,+=,");
	e ("_idata,sp,+,=[2],");
	e ("1,sp,+=,");
}

static void exi_a(RAnalOp *op, ut8 dummy, const char* operation) {
	ef ("a,%s=,", operation);
}

static void exi_c(RAnalOp *op, ut8 dummy, const char* operation) {
	ef ("c,%s=,", operation);
}

static void exi_dp (RAnalOp *op, ut8 dummy, const char *operation) {
	ef ("dptr,%s=,", operation);
}

static void exi_dir1 (RAnalOp *op, ut8 addr, const char *operation) {
	if (addr < 0x80) {
		ef ("_idata,%d,+,%s=[1],", addr, operation);
	} else {
		ef ("_sfr,%d,+,%s=[1],", addr, operation);
	}
}

static void exi_bit (RAnalOp *op, ut8 addr, const char *operation) {
	exi_dir1 (op, addr, operation);
}

static void exi_ri(RAnalOp *op, ut8 reg, const char *operation) {
	ef ("_idata,r%d,+,%s=[1],", reg, operation);
}

static void exi_rn(RAnalOp *op, ut8 reg, const char *operation) {
	ef ("r%d,%s=,", reg, operation);
}

#define xr(subject) exr_##subject (op, ev_##subject)
#define xw(subject) exw_##subject (op, ev_##subject)
#define xi(subject, operation) exi_##subject (op, ev_##subject, operation)

#define bit_set ef ("%d,1,<<,", buf[1] & 7)
#define bit_mask bit_set; e ("255,^,")
#define bit_r ef ("%d,", buf[1] & 7); xr (bit); e (">>,1,&,")
#define bit_c ef ("%d,c,<<,", buf[1] & 7);

#define jmp ef ("%" PFMT64d ",pc,=", op->jump)
#define cjmp e ("?{,"); jmp; e (",}")
#define call ef ("%" PFMT64d ",", op->fail); xw (sp2); jmp

#define alu_op(val, aluop, flags) xr (val); e ("a," aluop "=," flags)
#define alu_op_c(val, aluop, flags) e ("c,"); xr (val); e ("+,a," aluop "=," flags)
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

static void analop_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf) {
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	switch (buf[0]) {
	// Irregulars sorted by lower nibble
	case 0x00: /* nop */
		e (",");
		break;

	case 0x10: /* jbc bit, offset */
		bit_r; e ("?{,"); bit_mask; xi (bit, "&"); jmp; e (",}");
		break;
	case 0x20: /* jb bit, offset */
		bit_r; cjmp;
		break;
	case 0x30: /* jnb bit, offset */
		bit_r; e ("!,"); cjmp;
		break;
	case 0x40: /* jc offset */
		e ("c,1,&,"); cjmp;
		break;
	case 0x50: /* jnc offset */
		e ("c,1,&,!,"); cjmp;
		break;
	case 0x60: /* jz offset */
		e ("a,0,==,$z,"); cjmp;
		break;
	case 0x70: /* jnz offset */
		e ("a,0,==,$z,!,"); cjmp;
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
		xr (sp2); e ("pc,=");
		break;

	case 0x03: /* rr a */
		e ("1,a,0x101,*,>>,a,=," flag_p);
		break;
	case 0x04: /* inc a */
		xi (a, "++"); e (flag_p);
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
		e ("7,c,<<,1,a,&,c,=,0x7f,1,a,>>,&,+,a,=," flag_p);
		break;
	case 0x14: /* dec a */
		xi (a, "--"); e (flag_p);
		break;
	case 0x15: /* dec direct */
		xi (dir1, "--"); e (flag_p);
		break;
	case 0x16: case 0x17: /* dec @Ri */
		xi (ri, "--");
		break;
	case 0x18: case 0x19: case 0x1A: case 0x1B:
	case 0x1C: case 0x1D: case 0x1E: case 0x1F: /* dec @Rn */
		xi (rn, "--");
		break;
	case 0x23: /* rl a */
		e ("7,a,0x101,*,>>,a,=," flag_p);
		break;
	template_alu4 (0x20, "+", flag_c flag_ac flag_ov flag_p) /* 0x24..0x2f add a,.. */
	case 0x33: /* rlc a */
		e ("c,1,&,a,a,+=,7,$c,c,:=,a,+=," flag_p);
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
		e ("dptr,a,+,pc,=");
		break;
	case 0x74: /* mov a, imm */
		xr (imm1); xw (a); e (flag_p);
		break;
	case 0x75: /* mov direct, imm */
		xr (imm2); xw (dir1);
		break;
	case 0x76: case 0x77: /* mov @Ri, imm */
		xr (imm1); xw (ri);
		break;
	case 0x78: case 0x79: case 0x7A: case 0x7B:
	case 0x7C: case 0x7D: case 0x7E: case 0x7F: /* mov Rn, imm */
		xr (imm1); xw (rn);
		break;
	case 0x82: /* anl C, bit */
		bit_r; xi (c, "&");
		break;
	case 0x83: /* movc a, @a+pc */
		e ("a,pc,--,+,[1],a,=," flag_p);
		break;
	case 0x84: /* div ab */
		// note: escape % if this becomes a format string
		e ("b,0,==,$z,ov,:=,b,a,%,b,a,/=,b,=,0,c,=," flag_p);
		break;
	case 0x85: /* mov direct, direct */
		xr (dir1); xw (dir2);
		break;
	case 0x86: case 0x87: /* mov direct, @Ri */
		xr (ri); xw (dir1);
		break;
	case 0x88: case 0x89: case 0x8A: case 0x8B:
	case 0x8C: case 0x8D: case 0x8E: case 0x8F: /* mov direct, Rn */
		xr (rn); xw (dir1);
		break;
	case 0x90: /* mov dptr, imm */
		xr (imm16); xw (dp);
		break;
	case 0x92: /* mov bit, C */
		bit_c; bit_mask; xr (bit); e ("&,|,"); xw(bit);
		break;
	case 0x93: /* movc a, @a+dptr */
		e ("a,dptr,+,[1],a,=," flag_p);
		break;
	template_alu4_c (0x90, "-", flag_b flag_ab flag_ob flag_p) /* 0x94..0x9f subb a,.. */
	case 0xA0: /* orl C, /bit */
		bit_r; e ("!,"); xi (c, "|");
		break;
	case 0xA2: /* mov C, bit */
		bit_r; xw (c);
		break;
	case 0xA3: /* inc dptr */
		xi (dp, "++");
		break;
	case 0xA4: /* mul ab */
		e ("8,a,b,*,DUP,a,=,>>,DUP,b,=,0,==,$z,!,ov,:=,0,c,=," flag_p);
		break;
	case 0xA5: /* "reserved" */
		e ("0,trap");
		break;
	case 0xA6: case 0xA7: /* mov @Ri, direct */
		xr (dir1); xw (ri);
		break;
	case 0xA8: case 0xA9: case 0xAA: case 0xAB:
	case 0xAC: case 0xAD: case 0xAE: case 0xAF: /* mov Rn, direct */
		xr (dir1); xw (rn);
		break;
	case 0xB0: /* anl C, /bit */
		bit_r; e ("!,"); xi (c, "&");
		break;
	case 0xB2: /* cpl bit */
		bit_set; xi (bit, "^");
		break;
	case 0xB3: /* cpl C */
		e ("1,"); xi (c, "^");
		break;
	case 0xB4: /* cjne a, imm, offset */
		xr (imm1); xr (a); e ("==,$z,!," flag_b); cjmp;
		break;
	case 0xB5: /* cjne a, direct, offset */
		xr (dir1); xr (a); e ("==,$z,!," flag_b); cjmp;
		break;
	case 0xB6: case 0xB7: /* cjne @ri, imm, offset */
		xr (imm1); xr (ri); e ("==,$z,!," flag_b); cjmp;
		break;
	case 0xB8: case 0xB9: case 0xBA: case 0xBB:
	case 0xBC: case 0xBD: case 0xBE: case 0xBF: /* cjne Rn, imm, offset */
		xr (imm1); xr (rn); e ("==,$z,!," flag_b); cjmp;
		break;
	case 0xC0: /* push direct */
		xr (dir1); xw (sp1);
		break;
	case 0xC2: /* clr bit */
		bit_mask; xi (bit, "&");
		break;
	case 0xC3: /* clr C */
		e ("0,"); xw (c);
		break;
	case 0xC4: /* swap a */
		e ("0xff,4,a,0x101,*,>>,&,a,=," flag_p);
		break;
	case 0xC5: /* xch a, direct */
		xr (a); e ("0,+,"); xr (dir1); xw (a); xw (dir1); e (flag_p);
		break;
	case 0xC6: case 0xC7: /* xch a, @Ri */
		xr (a); e ("0,+,"); xr (ri); xw (a); xw (ri); e (flag_p);
		break;
	case 0xC8: case 0xC9: case 0xCA: case 0xCB:
	case 0xCC: case 0xCD: case 0xCE: case 0xCF: /* xch a, Rn */
		xr (a); e ("0,+,"); xr (rn); xw (a); xw (rn); e (flag_p);
		break;
	case 0xD0: /* pop direct */
		xr (sp1); xw (dir1);
		break;
	case 0xD2: /* setb bit */
		bit_set; xi (bit, "|");
		break;
	case 0xD3: /* setb C */
		e ("1,"); xw (c);
		break;
	case 0xD4: /* da a */
		// BCD adjust after add:
		// if (lower nibble > 9) or (AC == 1) add 6
		// if (higher nibble > 9) or (C == 1) add 0x60
		// carry |= carry caused by this operation
		e ("a,0x0f,&,9,==,4,$b,ac,|,?{,6,a,+=,7,$c,c,|,c,:=,},a,0xf0,&,0x90,==,8,$b,c,|,?{,0x60,a,+=,7,$c,c,|,c,:=,}," flag_p);
		break;
	case 0xD5: /* djnz direct, offset */
		xi (dir1, "--"); xr (dir1); e ("0,==,$z,!,"); cjmp;
		break;
	case 0xD6:
	case 0xD7: /* xchd a, @Ri*/
		xr (a); e ("0xf0,&,"); xr (ri); e ("0x0f,&,|,");
		xr (ri); e ("0xf0,&,"); xr (a); e ("0x0f,&,|,");
		xw (ri); xw (a); e (flag_p);
		break;
	case 0xD8: case 0xD9: case 0xDA: case 0xDB:
	case 0xDC: case 0xDD: case 0xDE: case 0xDF: /* djnz Rn, offset */
		xi (rn, "--"); xr (rn); e ("0,==,$z,!,"); cjmp;
		break;
	case 0xE0: /* movx a, @dptr */
		xr (dpx); xw (a); e (flag_p);
		break;
	case 0xE2: case 0xE3: /* movx a, @Ri */
		xr (rix); xw (a); e (flag_p);
		break;
	case 0xE4: /* clr a */
		e ("0,"); xw (a); e (flag_p);
		break;
	case 0xE5: /* mov a, direct */
		xr (dir1); xw (a); e (flag_p);
		break;
	case 0xE6: case 0xE7: /* mov a, @Ri */
		xr (ri); xw (a); e (flag_p);
		break;
	case 0xE8: case 0xE9: case 0xEA: case 0xEB:
	case 0xEC: case 0xED: case 0xEE: case 0xEF: /* mov a, Rn */
		xr (rn); xw (a); e (flag_p);
		break;
	case 0xF0: /* movx @dptr, a */
		xr (a); xw (dpx);
		break;
	case 0xF2: case 0xF3: /* movx @Ri, a */
		xr (a); xw (rix);
		break;
	case 0xF4: /* cpl a */
		e ("255,"); xi (a, "^"); e (flag_p);
		break;
	case 0xF5: /* mov direct, a */
		xr (a); xw (dir1);
		break;
	case 0xF6: case 0xF7: /* mov  @Ri, a */
		xr (a); xw (ri);
		break;
	case 0xF8: case 0xF9: case 0xFA: case 0xFB:
	case 0xFC: case 0xFD: case 0xFE: case 0xFF: /* mov Rn, a */
		xr (a); xw (rn);
		break;
	default:
		break;
	}
}

static RAnalEsilCallbacks ocbs = {0};

#if 0
// custom reg read/write temporarily disabled - see r2 issue #9242
static int i8051_hook_reg_read(RAnalEsil *, const char *, ut64 *, int *);

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

static int i8051_reg_get_offset(RAnalEsil *esil, RI8051Reg *ri) {
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

static int i8051_hook_reg_read(RAnalEsil *esil, const char *name, ut64 *res, int *size) {
	int ret = 0;
	ut64 val = 0LL;
	RI8051Reg *ri;
	RAnalEsilCallbacks cbs = esil->cb;

	if ((ri = i8051_reg_find (name))) {
		ut8 offset = i8051_reg_get_offset(esil, ri);
		ret = r_anal_esil_mem_read (esil, IRAM_BASE + offset, (ut8*)res, ri->num_bytes);
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

static int i8051_hook_reg_write(RAnalEsil *esil, const char *name, ut64 *val) {
	int ret = 0;
	RI8051Reg *ri;
	RAnalEsilCallbacks cbs = esil->cb;
	if ((ri = i8051_reg_find (name))) {
		ut8 offset = i8051_reg_get_offset(esil, ri);
		ret = r_anal_esil_mem_write (esil, IRAM_BASE + offset, (ut8*)val, ri->num_bytes);
	}
	esil->cb = ocbs;
	if (!ret && ocbs.hook_reg_write) {
		ret = ocbs.hook_reg_write (esil, name, val);
	}
	esil->cb = cbs;
	return ret;
}
#endif

static int esil_i8051_init (RAnalEsil *esil) {
	if (esil->cb.user) {
		return true;
	}
	ocbs = esil->cb;
	/* these hooks break esil emulation */
	/* pc is not read properly, mem mapped registers are not shown in ar, ... */
	/* all 8051 regs are mem mapped, and reg access via mem is very common */
//  disabled to make esil work, before digging deeper
//	esil->cb.hook_reg_read = i8051_hook_reg_read;
//	esil->cb.hook_reg_write = i8051_hook_reg_write;
	i8051_is_init = true;
	return true;
}

static int esil_i8051_fini (RAnalEsil *esil) {
	if (!i8051_is_init) {
		return false;
	}
	R_FREE (ocbs.user);
	i8051_is_init = false;
	return true;
}

static bool set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
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

	int retval = r_reg_set_profile_string (anal->reg, p);
	if (retval) {
		// reset emulation control registers based on cpu
		set_cpu_model (anal, true);
	}

	return retval;
}

static ut32 map_direct_addr(RAnal *anal, ut8 addr) {
	if (addr < 0x80) {
		return addr + i8051_reg_read (anal->reg, "_idata");
	} else {
		return addr + i8051_reg_read (anal->reg, "_sfr");
	}
}

static int i8051_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	set_cpu_model (anal, false);

	int i = 0;
	while (_8051_ops[i].string && _8051_ops[i].op != (buf[0] & ~_8051_ops[i].mask))	{
		i++;
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
	default:
		op->cond = R_ANAL_COND_AL;
	break;
	case OP_CJNE:
	case OP_DJNZ:
	case OP_JB:
	case OP_JBC:
	case OP_JNZ:
		op->cond = R_ANAL_COND_NE;
	break;
	case OP_JNB:
	case OP_JZ:
		op->cond = R_ANAL_COND_EQ;
	break; case OP_JC:
		op->cond = R_ANAL_COND_HS;
	break; case OP_JNC:
		op->cond = R_ANAL_COND_LO;
	}

	switch (_8051_ops[i].instr) {
	default:
		op->eob = false;
	break;
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
	}

	// TODO: op->datatype

	switch (arg1) {
	default:
	break; case A_DIRECT:
		op->ptr = map_direct_addr (anal, buf[1]);
	break; case A_BIT:
		op->ptr = map_direct_addr (anal, arg_bit (buf[1]));
	break; case A_IMMEDIATE:
		op->val = buf[1];
	break; case A_IMM16:
		op->val = buf[1] * 256 + buf[2];
		op->ptr = op->val + i8051_reg_read (anal->reg, "_xdata"); // best guess, it's a XRAM pointer
	}

	switch (arg2) {
	default:
	break; case A_DIRECT:
		if (arg1 == A_RI || arg1 == A_RN) {
			op->ptr = map_direct_addr (anal, buf[1]);
		} else if (arg1 != A_DIRECT) {
			op->ptr = map_direct_addr (anal, buf[2]);
		}
	break; case A_BIT:
		op->ptr = arg_bit ((arg1 == A_RI || arg1 == A_RN) ? buf[1] : buf[2]);
		op->ptr = map_direct_addr (anal, op->ptr);
	break; case A_IMMEDIATE:
		op->val = (arg1 == A_RI || arg1 == A_RN) ? buf[1] : buf[2];
	}

	switch(_8051_ops[i].instr) {
	default:
	break; case OP_PUSH:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;
	break; case OP_POP:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;
	break; case OP_RET:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;
	break; case OP_CALL:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		if (arg1 == A_ADDR11) {
			op->jump = arg_addr11 (addr + op->size, buf);
			op->fail = addr + op->size;
		} else if (arg1 == A_ADDR16) {
			op->jump = 0x100 * buf[1] + buf[2];
			op->fail = addr + op->size;
		}
	break; case OP_JMP:
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
	}

	if (op->ptr != -1 && op->refptr == 0) {
		op->refptr = 1;
	}

	if (mask & R_ANAL_OP_MASK_ESIL) {
		ut8 copy[3] = {0, 0, 0};
		memcpy (copy, buf, len >= 3 ? 3 : len);
		analop_esil (anal, op, addr, copy);
	}

	int olen = 0;
	op->mnemonic = r_8051_disas (addr, buf, len, &olen);
	op->size = olen;

	if (mask & R_ANAL_OP_MASK_HINT) {
		// TODO: op->hint
	}

	return op->size;
}

RAnalPlugin r_anal_plugin_8051 = {
	.name = "8051",
	.arch = "8051",
	.esil = true,
	.bits = 8|16,
	.desc = "8051 CPU code analysis plugin",
	.license = "LGPL3",
	.op = &i8051_op,
	.set_reg_profile = &set_reg_profile,
	.esil_init = esil_i8051_init,
	.esil_fini = esil_i8051_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_8051,
	.version = R2_VERSION
};
#endif
