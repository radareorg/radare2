#include <r_types.h>
#include <r_util.h>

#include "cr16_disas.h"

#define GET_BIT(x, n) 	((x >> n) & 1)

static const char *cr16_regs_names[] = {
	[CR16_R0]	= "r0",
	[CR16_R1]	= "r1",
	[CR16_R2]	= "r2",
	[CR16_R3]	= "r3",
	[CR16_R4]	= "r4",
	[CR16_R5]	= "r5",
	[CR16_R6]	= "r6",
	[CR16_R7]	= "r7",
	[CR16_R8]	= "r8",
	[CR16_R9]	= "r9",
	[CR16_R10]	= "r10",
	[CR16_R11]	= "r11",
	[CR16_R12]	= "r12",
	[CR16_R13]	= "r13",
	[CR16_RA]	= "ra",
	[CR16_SP]	= "sp",
};

static const char *instrs_4bit[] = {
	[CR16_ADD]	= "add",
	[CR16_ADDU]	= "addu",
	[CR16_MUL]	= "mul",
	[CR16_ASHU]	= "ashu",
	[CR16_LSH]	= "lsh",
	[CR16_XOR]	= "xor",
	[CR16_CMP]	= "cmp",
	[CR16_AND]	= "and",
	[CR16_ADDC]	= "addc",
	[CR16_TBIT]	= "tbit",
	[CR16_TBIT_R_R]	= "tbit",
	[CR16_TBIT_I_R] = "tbit",
	[CR16_MOV]	= "mov",
	[CR16_SUB]	= "sub",
	[CR16_SUBC]	= "subc",
	[CR16_OR]	= "or",
	[CR16_LPR]	= "lpr",
	[CR16_SPR]	= "spr",
	[CR16_LOADM]	= "loadm",
	[CR16_STORM]	= "storm",
};

static const char *cr16_conds[] = {
	[CR16_COND_EQ] = "eq",
	[CR16_COND_NE] = "ne",
	[CR16_COND_GE] = "ge",
	[CR16_COND_CS] = "cs",
	[CR16_COND_CC] = "cc",
	[CR16_COND_HI] = "hi",
	[CR16_COND_LS] = "ls",
	[CR16_COND_LO] = "lo",
	[CR16_COND_HS] = "hs",
	[CR16_COND_GT] = "gt",
	[CR16_COND_LE] = "le",
	[CR16_COND_FS] = "fs",
	[CR16_COND_FC] = "fc",
	[CR16_COND_LT] = "lt",
};

static const char *ld_sw[] = {
	[0x0]		= "stor",
	[0x1]		= "stor",
	[0x2]		= "load",
	[0x3]		= "stor",
};

static const char *dedicated_regs[] = {
	[0x1]		= "psr",
	[0x3]		= "intbaseh",
	[0x4]		= "intbasel",
	[0x5]		= "cfg",
	[0x7]		= "dsr",
	[0x9]		= "dcr",
	[0xB]		= "isp",
	[0xD]		= "carl",
	[0xE]		= "carh",
};

static const char *ops_biti[] = {
	[0x0]		= "cbit",
	[0x1]		= "sbit",
	[0x2]		= "tbit",
};

static inline ut8 cr16_get_opcode_biti(const ut8 instr)
{
	return (instr >> 6) & 0x3;
}

static inline ut8 cr16_get_opcode_low(const ut16 instr)
{
	return (instr >> 9) & 0xF;
}

static inline ut8 cr16_get_opcode_hi(const ut16 instr)
{
	return instr >> 14;
}

static inline ut8 cr16_get_opcode_i(const ut16 instr)
{
	return (instr >> 13) & 1;
}

static inline ut8 cr16_get_short_imm(const ut16 instr)
{
	return instr & 0x1F;
}

static inline ut8 cr16_get_dstreg(const ut16 instr)
{
	return (instr >> 5) & 0xF;
}

static inline ut8 cr16_get_srcreg(const ut16 instr)
{
	return (instr >> 1) & 0xF;
}

static inline int cr16_check_instrs_4bit_bndrs(const ut8 opcode)
{
	if (opcode >=sizeof(instrs_4bit)/sizeof(void*)
			|| !instrs_4bit[opcode]) {
				return -1;
	}
	return 0;
}

static inline ut16 cr16_get_opcode_159_0(const ut16 opc)
{
	return (opc & 1) | ((opc >> 8) & 0xFE);
}

static inline int cr16_check_biti_boundaries(const ut8 opcode)
{
	if (opcode >= sizeof(ops_biti)/sizeof(void*) || !ops_biti[opcode]) {
		return -1;
	}
	return 0;
}

static inline int cr16_check_reg_boundaries(const ut8 reg)
{
	if (reg >= sizeof(cr16_regs_names)/sizeof(void*)
			|| !cr16_regs_names[reg]) {
		return -1;
	}
	return 0;
}

static inline int cr16_print_ld_sw_opcode(struct cr16_cmd *cmd, ut16 instr)
{
	ut8 opcode = instr >> 14;

	if (opcode >= sizeof(ld_sw)/sizeof(void*) || !ld_sw[opcode]) {
		return -1;
	}

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s%c", ld_sw[opcode],
			cr16_get_opcode_i(instr) ? 'w' : 'b');

	cmd->type = CR16_TYPE_MOV;

	cmd->instr[CR16_INSTR_MAXLEN - 1] = '\0';

	return 0;
}

static inline int cr16_print_short_reg(struct cr16_cmd *cmd, ut8 sh, ut8 reg)
{
	if (cr16_check_reg_boundaries(reg)) {
		return -1;
	}

	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
			"$0x%02x,%s", sh, cr16_regs_names[reg]);

	return 0;
}

static inline int cr16_print_reg_short(struct cr16_cmd * cmd, ut8 sh, ut8 reg)
{
	if (cr16_check_reg_boundaries(reg)) {
		return -1;
	}

	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
			"%s,$0x%02x", cr16_regs_names[reg], sh);

	return 0;
}

static inline int cr16_print_med_reg(struct cr16_cmd *cmd, ut16 med, ut8 reg)
{
	if (cr16_check_reg_boundaries(reg)) {
		return -1;
	}

	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
			"$0x%04x,%s", med, cr16_regs_names[reg]);

	return 0;
}

static inline int cr16_print_reg_med(struct cr16_cmd *cmd, ut16 med, ut8 reg)
{
	if (cr16_check_reg_boundaries(reg)) {
		return -1;
	}

	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
			"%s,$0x%04x", cr16_regs_names[reg], med);

	return 0;
}

static inline int cr16_print_biti_opcode(struct cr16_cmd *cmd, ut16 instr)
{
	ut8 opcode = cr16_get_opcode_biti(instr);

	if (cr16_check_biti_boundaries(opcode)) {
		return -1;
	}

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s%c",
			ops_biti[opcode],
			cr16_get_opcode_i(instr) ? 'w' : 'b');

	return 0;
}

static inline int cr16_print_short_abs18(struct cr16_cmd *cmd,
		ut8 sh, ut32 abs) {
	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
			"$0x%02x,0x%08x", sh, abs);
	return 0;
}

static inline int cr16_print_reg_reg_rel(struct cr16_cmd *cmd,
		ut8 src, ut16 rel, ut8 dst, ut8 swap)
{
	if (cr16_check_reg_boundaries(dst) || cr16_check_reg_boundaries(src)) {
		return -1;
	}

	if (swap) {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,0x%04x(%s)",
				cr16_regs_names[dst], rel, cr16_regs_names[src]);
	} else {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "0x%04x(%s),%s",
				rel, cr16_regs_names[src], cr16_regs_names[dst]);
	}

	return 0;
}

static inline int cr16_print_short_reg_rel(struct cr16_cmd *cmd,
				ut8 sh, ut16 rel, ut8 reg)
{
	if (cr16_check_reg_boundaries(reg)) {
		return -1;
	}

	if (rel) {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
			"$0x%02x,0x%04x(%s)", sh, rel, cr16_regs_names[reg]);
	} else {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
			"$0x%02x,0(%s)", sh, cr16_regs_names[reg]);
	}

	return 0;
}

static inline int cr16_print_reg_rel_reg(struct cr16_cmd *cmd,
				ut32 rel, ut8 srcreg, ut8 dstreg, ut8 swap)
{
	if (cr16_check_reg_boundaries(srcreg)) {
		return -1;
	}

	if (cr16_check_reg_boundaries(dstreg)) {
		return -1;
	}

	if (swap) {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,0x%08x(%s)",
			cr16_regs_names[dstreg], rel, cr16_regs_names[srcreg]);
	} else {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "0x%08x(%s),%s",
			rel, cr16_regs_names[srcreg], cr16_regs_names[dstreg]);
	}

	return 0;
}

static inline int cr16_print_long_reg(struct cr16_cmd *cmd, ut32 l, ut8 reg, ut8 swap)
{
	if (cr16_check_reg_boundaries(reg)) {
		return -1;
	}

	if (swap) {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
				"%s,0x%08x", cr16_regs_names[reg], l);
	} else {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
				"0x%08x,%s", l, cr16_regs_names[reg]);
	}

	return 0;
}

static inline int cr16_print_longregreg_reg(struct cr16_cmd *cmd,
		ut32 rel, ut8 src, ut8 dst, ut8 swap)
{
	if (cr16_check_reg_boundaries(src) || cr16_check_reg_boundaries(src + 1)
			|| cr16_check_reg_boundaries(dst)) {
		return -1;
	}

	if (swap) {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
				"%s,0x%08x(%s,%s)", cr16_regs_names[src], rel,
				cr16_regs_names[dst + 1],
				cr16_regs_names[dst]);
	} else {
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
			"0x%08x(%s,%s),%s", rel, cr16_regs_names[src + 1],
			cr16_regs_names[src], cr16_regs_names[dst]);

	}
	return 0;
}

static inline int cr16_print_reg_reg(struct cr16_cmd *cmd, ut8 src, ut8 dst)
{
	if (cr16_check_reg_boundaries(src) || cr16_check_reg_boundaries(dst)) {
		return -1;
	}

	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,%s",
			cr16_regs_names[src], cr16_regs_names[dst]);

	return 0;
}

#if 0
// This function is unused, shall we remove it?
static int cr16_decode_stcbiti(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut8 dstreg;
	ut16 in;

	r_mem_copyendian((ut8*)&in, instr, 2, LIL_ENDIAN);

	if (cr16_print_biti_opcode(cmd, in)) {
		return -1;
	}

	dstreg = cr16_get_dstreg(in);

	if (cr16_check_reg_boundaries(dstreg)) {
		return -1;
	}

	if (cr16_print_short_reg(cmd, (in >> 1) & 0xF, cr16_get_dstreg(in))) {
		return -1;
	}

	cmd->type = CR16_TYPE_BIT;

	return ret;
}
#endif

static inline int cr16_print_4biti_opcode(struct cr16_cmd *cmd, ut16 instr)
{
	if (cr16_check_instrs_4bit_bndrs(cr16_get_opcode_low(instr))) {
		return -1;
	}

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s%c",
			instrs_4bit[cr16_get_opcode_low(instr)],
			cr16_get_opcode_i(instr) ? 'w' : 'b');
	return 0;
}

static inline int cr16_print_4bit_opcode(struct cr16_cmd *cmd, ut16 instr)
{
	if (cr16_check_instrs_4bit_bndrs(cr16_get_opcode_low(instr))) {
		return -1;
	}

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s",
			instrs_4bit[cr16_get_opcode_low(instr)]);

	return 0;
}

static inline void cr16_anal_4bit_opcode(const ut16 in, struct cr16_cmd *cmd)
{
	switch (cr16_get_opcode_low(in)) {
	case CR16_ADDU:
	case CR16_ADD:
		cmd->type = CR16_TYPE_ADD;
		break;
	case CR16_BITI:
		cmd->type = CR16_TYPE_BIT;
		break;
	case CR16_MUL:
		cmd->type = CR16_TYPE_MUL;
		break;
	case CR16_SUBC:
	case CR16_SUB:
		cmd->type = CR16_TYPE_SUB;
		break;
	case CR16_CMP:
		cmd->type = CR16_TYPE_CMP;
		break;
	case CR16_XOR:
		cmd->type = CR16_TYPE_XOR;
		break;
	case CR16_OR:
		cmd->type = CR16_TYPE_OR;
		break;
	case CR16_ASHU:
	case CR16_LSH:
		cmd->type = CR16_TYPE_SHIFT;
		break;
	case CR16_MOV:
		cmd->type = CR16_TYPE_MOV;
		break;
	case CR16_AND:
		cmd->type = CR16_TYPE_AND;
		break;
	}
}

static inline int cr16_decode_i_r(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut16 in, immed, dstreg;

	r_mem_copyendian((ut8*)&in, instr, 2, LIL_ENDIAN);

	if (in == 0x0200)
		return -1;

	if (((in >> 9) != CR16_TBIT_I_R) && ((in >> 9) != CR16_TBIT_R_R)) {
		if (cr16_print_4biti_opcode(cmd, in)) {
			return -1;
		}
		cr16_anal_4bit_opcode(in, cmd);
	} else {
		if (cr16_print_4bit_opcode(cmd, in)) {
			return -1;
		}
	}

	switch((in & 0x1F) ^ 0x11) {
	case 0:
		if ((in & 0x1) == 0x1) {
			r_mem_copyendian((ut8*)&immed, instr + 2,
					2, LIL_ENDIAN);
			ret = 4;
		} else {
			immed = cr16_get_short_imm(in);
		}
		if (((in >> 9) != CR16_TBIT_I_R) && ((in >> 9) != CR16_TBIT_R_R)) {
			if (cr16_print_med_reg(cmd, immed, cr16_get_dstreg(in))) {
				return -1;
			}
		} else {
			if (cr16_print_reg_med(cmd, immed, cr16_get_dstreg(in))) {
				return -1;
			}
		}
		break;
	default:
		dstreg = cr16_get_dstreg(in);

		if (cr16_check_reg_boundaries(dstreg)) {
			ret = -1;
			break;
		}

		if (((in >> 9) != CR16_TBIT_I_R) && ((in >> 9) != CR16_TBIT_R_R)) {
			if (cr16_print_short_reg(cmd, cr16_get_short_imm(in),
						cr16_get_dstreg(in))) {
				return -1;
			}
		} else {
			if (cr16_print_reg_short(cmd, cr16_get_short_imm(in),
						cr16_get_dstreg(in))) {
				return -1;
			}
		}
		break;
	}

	return ret;
}

static inline int cr16_decode_ld_st(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut32 disp32;
	ut16 c, disp16;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if (cr16_print_ld_sw_opcode(cmd, c)) {
		return -1;
	}

	switch (cr16_get_opcode_159_0(c) & (~0x20)) {
	case 0x04:
		ret = 4;
		if ((c & 0xC0) != 0xC0) {
			ret = -1;
			break;
		}
		r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);

		disp32 = disp16 | ((c & 0x0100) << 9) | ((c & 0x0020) << 11);

		cr16_print_short_abs18(cmd, cr16_get_srcreg(c), disp32);
		break;
	case 0x05:
		ret = 4;
		r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);

		if (cr16_print_short_reg_rel(cmd, cr16_get_srcreg(c),
				disp16, cr16_get_dstreg(c) & 0x9)) {
			return -1;
		}
		break;
	case 0x45:
		if (!(c & 0x1) || ((c >> 6) & 0x3) != 0x3) {
			ret = -1;
			break;
		}
		if (cr16_print_short_reg_rel(cmd, cr16_get_srcreg(c), 0,
					cr16_get_dstreg(c) & 0x9)) {
				return -1;
		}
		break;
	default:
		ret = -1;
	}

	if (ret != -1)
		return ret;

	ret = 2;

	switch ((c >> 11) & (~0x4)) {
	case 0x12:
		ret = 4;
		if (!(c & 1)) {
			ret = -1;
			break;
		}
		r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);
		disp32 = disp16 | (((c >> 9) & 0x3) << 16);

		cr16_print_reg_rel_reg(cmd, disp32, cr16_get_srcreg(c),
				cr16_get_dstreg(c), 0);
		break;

	case 0x13:
		ret = 4;
		r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);
		disp32 = disp16 | (((c >> 9) & 0x3) << 16);

		if (cr16_get_srcreg(c) == 0xF) {
			cr16_print_long_reg(cmd, disp32, cr16_get_dstreg(c), 0);
		} else {
			cr16_print_longregreg_reg(cmd, disp32, cr16_get_srcreg(c),
					cr16_get_dstreg(c), 0);
		}
		break;
	case 0x1B:
		ret = 4;
		r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);
		disp32 = disp16 | (((c >> 9) & 0x3) << 16);

		if (cr16_get_srcreg(c) == 0xF) {
			cr16_print_long_reg(cmd, disp32, cr16_get_dstreg(c), 1);
		} else {
			cr16_print_longregreg_reg(cmd, disp32, cr16_get_dstreg(c),
					cr16_get_srcreg(c), 1);
		}
		break;
	case 0x1A:
		ret = 4;
		r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);
		disp32 = disp16 | (((c >> 9) & 0x3) << 16);

		cr16_print_reg_rel_reg(cmd, disp32, cr16_get_srcreg(c),
				cr16_get_dstreg(c), 1);

		break;
	default:
		ret = -1;
	}

	if (ret != -1)
		return ret;

	ret = 2;
	switch (c >> 14) {
	case 0x3:
		ret = 2;
		disp16 = (c & 0x1) | ((c >> 8) & 0x1E);
		cr16_print_reg_reg_rel(cmd, cr16_get_srcreg(c),
				disp16, cr16_get_dstreg(c), 1);
		break;
	case 0x2:
		ret = 2;
		disp16 = (c & 0x1) | ((c >> 8) & 0x1E);
		cr16_print_reg_reg_rel(cmd, cr16_get_srcreg(c),
				disp16, cr16_get_dstreg(c), 0);
		break;
	default:
		ret = -1;
	}
	return ret;
}

static int cr16_decode_slpr(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut16 c;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s",
			instrs_4bit[c >> 9]);

	switch (c >> 9) {
	case CR16_LPR:
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
				"%s,%s",cr16_regs_names[cr16_get_srcreg(c)],
				dedicated_regs[cr16_get_dstreg(c)]);
		break;
	case CR16_SPR:
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
				"%s,%s", dedicated_regs[cr16_get_dstreg(c)],
				cr16_regs_names[cr16_get_srcreg(c)]);
		break;
	}

	cmd->type = CR16_TYPE_SLPR;

	return ret;
}

static int cr16_decode_r_r(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut16 c;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if (!(c & 0x1)) {
		return -1;
	}

	if (((c >> 9) != CR16_TBIT_I_R) && ((c >> 9) != CR16_TBIT_R_R)) {
		if (cr16_print_4biti_opcode(cmd, c)) {
			return -1;
		}
		cr16_anal_4bit_opcode(c, cmd);
	} else {
		if (cr16_print_4bit_opcode(cmd, c)) {
			return -1;
		}
	}

	if (cr16_print_reg_reg(cmd, cr16_get_srcreg(c), cr16_get_dstreg(c))) {
		return -1;
	}

	return ret;
}

static inline ut8 cr16_get_cond(const ut16 c)
{
	return ((c >> 5) & 0xF);
}

static int cr16_decode_push_pop(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut16 c;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if ((c & 1)) {
		return -1;
	}

	switch (c >> 7) {
	case CR16_PUSH:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "push");
		break;
	case CR16_POP:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "pop");
		break;
	case CR16_POPRET_1:
	case CR16_POPRET_2:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "popret");
		break;
	}

	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "$0x%x,%s",
			((c >> 5) & 0x3) + 1,
			cr16_regs_names[(c >> 1) & 0xF]);

	return ret;
}

static int cr16_decode_jmp(const ut8 *instr, struct cr16_cmd *cmd)
{
	ut16 c;
	int ret = 2;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	switch (c >> 9) {
	case CR16_JUMP:
		if (((c >> 5) & 0xf) == 0xE) {
			snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "jump");
		} else {
			snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "j%s",
				cr16_conds[cr16_get_dstreg(c)]);
		}
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s",
			cr16_regs_names[cr16_get_srcreg(c)]);
		break;
	case CR16_JAL:
		if (!(c & 1)) {
			ret = -1;
			break;
		}
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "jal");
		cr16_print_reg_reg(cmd, cr16_get_dstreg(c), cr16_get_srcreg(c));
		cmd->type = CR16_TYPE_JUMP_UNK;
		break;
	case 0x0B:
		if (!(c & 1)) {
			strncpy(cmd->instr, "jal", CR16_INSTR_MAXLEN - 1);
			snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "(%s,%s),(%s,%s)",
					cr16_regs_names[cr16_get_dstreg(c) + 1],
					cr16_regs_names[cr16_get_dstreg(c)],
					cr16_regs_names[cr16_get_srcreg(c) + 1],
					cr16_regs_names[cr16_get_srcreg(c)]);
		} else if (cr16_get_dstreg(c) != 0xE) {
			snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "j%s",
					cr16_conds[cr16_get_dstreg(c)]);
			snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "(%s,%s)",
					cr16_regs_names[cr16_get_srcreg(c) + 1],
					cr16_regs_names[cr16_get_srcreg(c)]);
		} else {
			strncpy(cmd->instr, "jump", CR16_INSTR_MAXLEN - 1);
			snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "(%s,%s)",
					cr16_regs_names[cr16_get_srcreg(c) + 1],
					cr16_regs_names[cr16_get_srcreg(c)]);
		}
		break;
	default:
		return -1;
	}

	cmd->type = CR16_TYPE_JUMP_UNK;
	return ret;
}

static int cr16_decode_bcond_br(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;

	ut16 c, disp;
	ut32 disp32;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if (c & 0x1)
		return -1;

	if (!(c >> 14) && cr16_get_opcode_low(c) != 0xA)
		return -1;

	if (((c >> 5) & 0xF) == 0xE) {
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "br");
		if (((c >> 1) & 0x7) == 0x7) {
			r_mem_copyendian((ut8*)&disp, instr + 2, 2, LIL_ENDIAN);

			disp32 = disp | (((c >> 4) & 0x1) << 16);
			ret = 4;
			snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
					"0x%08x", disp32);

			if (disp32 & 0x10000) {
				disp32 |= 0xFFFE0000;
				cmd->reladdr = (st32)disp32;
			} else {
				cmd->reladdr = disp32;
			}
		} else {
			if (cr16_get_opcode_i(c)) {
				ret = 4;
				r_mem_copyendian((ut8*)&disp, instr + 2, 2, LIL_ENDIAN);
				disp32 = disp | (((c >> 1) & 0x7) << 17) | (((c >> 4) & 1) << 16);
				if (disp32 & 0x80000) {
					disp32 |= 0xFFF00000;
					cmd->reladdr = (st32)disp32;
				} else {
					cmd->reladdr = disp32;
				}
				snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "0x%08x", disp32);
			} else {
				disp = (c & 0x1F) | ((c >> 4) & 0x1E0);

				if (disp & 0x0100) {
					disp |= 0xFE00;
					cmd->reladdr = (st16)disp;
				} else {
					cmd->reladdr = disp;
				}

				snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "0x%04x", disp);
			}
		}
		cmd->type = CR16_TYPE_JUMP;
	} else {
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "b%s",
				cr16_conds[cr16_get_cond(c)]);
		if (c & 0x1)
			return -1;

		if ((c >> 8) == CR16_BCOND_2) {
			r_mem_copyendian((ut8*)&disp, instr + 2, 2, LIL_ENDIAN);
			disp32 = disp | (GET_BIT(c, 4) << 16);
			if (disp32 & 0x80000) {
				disp32 |= 0xFFF00000;
				cmd->reladdr = (st32)disp32;
			} else {
				cmd->reladdr = disp32;
			}
			ret = 4;
		} else {
			disp = (c & 0x1F) | ((c >> 4) & 0x1E0);

			if (disp & 0x0100) {
				disp |= 0xFE00;
				cmd->reladdr = (st16)disp;
			} else {
				cmd->reladdr = disp;
			}

			disp32 = disp;
		}

		cmd->type = CR16_TYPE_BCOND;
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "0x%04x", disp32);
	}

	return ret;
}

static int cr16_decode_bcond01i(const ut8 *instr, struct cr16_cmd *cmd)
{
	ut16 c;
	int ret = 2;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if (!(c & 1))
		return -1;

	if (c >> 14)
		return -1;


	switch ((c >> 6) & 0x3) {
	case 0x0:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s%c",
				"beq0", cr16_get_opcode_i(c) ? 'w' : 'b');
		break;
	case 0x1:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s%c",
				"beq1", cr16_get_opcode_i(c) ? 'w' : 'b');
		break;
	case 0x2:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s%c",
				"bne0", cr16_get_opcode_i(c) ? 'w' : 'b');
		break;
	case 0x3:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s%c",
				"bne1", cr16_get_opcode_i(c) ? 'w' : 'b');
		break;
	}

	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,0x%x",
			cr16_regs_names[cr16_get_dstreg(c)],
			(c >> 1) & 0xF);

	cmd->type = CR16_TYPE_BCOND;

	return ret;
}

static int cr16_decode_misc(const ut8 *instr, struct cr16_cmd *cmd)
{
	ut16 c;
	int ret = 2;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	cmd->operands[0] = '\0';
	switch (c) {
	case CR16_RETX:
		strncpy(cmd->instr, "retx", CR16_INSTR_MAXLEN - 1);
		cmd->type = CR16_TYPE_RETX;
		break;
	case CR16_DI:
		strncpy(cmd->instr, "di", CR16_INSTR_MAXLEN - 1);
		cmd->type = CR16_TYPE_DI;
		break;
	case CR16_EI:
		strncpy(cmd->instr, "ei", CR16_INSTR_MAXLEN - 1);
		cmd->type = CR16_TYPE_EI;
		break;
	case CR16_NOP:
		strncpy(cmd->instr, "nop", CR16_INSTR_MAXLEN - 1);
		cmd->type = CR16_TYPE_NOP;
		break;
	case CR16_WAIT:
		strncpy(cmd->instr, "wait", CR16_INSTR_MAXLEN - 1);
		cmd->type = CR16_TYPE_WAIT;
		break;
	case CR16_EWAIT:
		strncpy(cmd->instr, "eiwait", CR16_INSTR_MAXLEN - 1);
		cmd->type = CR16_TYPE_EWAIT;
		break;
	default:
		switch (c >> 5) {
		case 0x3DF:
			strncpy(cmd->instr, "excp", CR16_INSTR_MAXLEN - 1);
			snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
					"0x%x", (c >> 1) & 0xF);
			cmd->type = CR16_TYPE_EXCP;
			break;
		default:
			ret = -1;
		}
	}

	return ret;
}

static int cr16_decode_bal(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 4;
	ut16 c, disp16;
	ut32 disp32;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);
	r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "bal");

	switch (c >> 9) {
	case CR16_BAL:
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,0x%x",
			cr16_regs_names[cr16_get_dstreg(c)], disp16);
		break;
	case CR16_TBIT_R_R:
		disp32 = disp16 | (((c >> 1) & 0xF) << 16);
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "(%s,%s),0x%08x",
			cr16_regs_names[cr16_get_dstreg(c) + 1],
			cr16_regs_names[cr16_get_dstreg(c)], disp32);
		break;
	default:
		return -1;
	}

	return ret;
}

int cr16_decode_loadm_storm(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut16 c;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if ((c & 0x1F) != 4)
		return -1;

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s",
			instrs_4bit[c >> 7]);
	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "$0x%x",
			((c >> 5) & 0x3) + 1);

	cmd->type = CR16_TYPE_MOV;

	return ret;
}

int cr16_decode_movz(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut16 c;
	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if (c & 1)
		return -1;

	switch (c >> 9) {
	case CR16_MOVXB:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "movxb");
		break;
	case CR16_MOVZB:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "movzb");
		break;
	default:
		return -1;
	}

	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,%s",
			cr16_regs_names[cr16_get_srcreg(c)],
			cr16_regs_names[cr16_get_dstreg(c)]);

	return ret;
}

int cr16_decode_movd(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 4;
	ut16 c;
	ut16 imm;
	ut32 imm32;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);
	r_mem_copyendian((ut8*)&imm, instr + 2, 2, LIL_ENDIAN);

	if (c & 1)
		return -1;

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "movd");

	imm32 = imm | (((c >> 4) & 1) << 16) | (((c >> 9) & 1) << 20) | (((c >> 1) & 0x7) << 17);
	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "$0x%08x,(%s,%s)",
			imm32, cr16_regs_names[((c >> 5) & 0xF) + 1],
			cr16_regs_names[(c >> 5) & 0xF]);

	return ret;
}

int cr16_decode_muls(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut16 c;
	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	switch (c >> 9) {
	case CR16_MULSB:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "mulsb");
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,%s",
			cr16_regs_names[cr16_get_srcreg(c)],
			cr16_regs_names[cr16_get_dstreg(c)]);
		break;
	case CR16_MULSW:
		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "mulsw");
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,(%s,%s)",
			cr16_regs_names[cr16_get_srcreg(c)],
			cr16_regs_names[cr16_get_dstreg(c) + 1],
			cr16_regs_names[cr16_get_dstreg(c)]);
		break;
	case CR16_MULUW:
		if (c & 0x000C)
			return -1;

		snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "muluw");
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s,(%s,%s)",
			cr16_regs_names[cr16_get_srcreg(c)],
			cr16_regs_names[cr16_get_dstreg(c) + 1],
			cr16_regs_names[cr16_get_dstreg(c)]);
		break;
	}

	return ret;
}

int cr16_decode_scond(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut16 c;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if (c & 1)
		return -1;

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "s%s",
			cr16_conds[cr16_get_dstreg(c)]);
	snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1, "%s",
			cr16_regs_names[cr16_get_srcreg(c)]);

	cmd->type = CR16_TYPE_SCOND;

	return ret;
}

int cr16_decode_biti(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret = 2;
	ut32 abs18;
	ut16 c, disp16;
	ut8 reg, position;

	r_mem_copyendian((ut8*)&c, instr, 2, LIL_ENDIAN);

	if (((c >> 6) & 0x3) == 0x3) {
		return -1;
	}

	reg = cr16_get_dstreg(c);
	position = cr16_get_srcreg(c);

	if (!(reg & 0x6)) {
		return -1;
	}

	snprintf(cmd->instr, CR16_INSTR_MAXLEN - 1, "%s%c",
			ops_biti[(c >> 6) & 0x3],
			cr16_get_opcode_i(c) ? 'w' : 'b');

	switch (((c >> 13) & 0x2) | (c & 0x1)) {
	case 0x0:
		ret = 4;
		r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);

		abs18 = disp16 | ((reg & 0x1) << 16) | ((reg >> 3) << 17);

		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
				"$0x%02x,0x%08x", position, abs18);

		break;
	case 0x1:
		ret = 4;

		r_mem_copyendian((ut8*)&disp16, instr + 2, 2, LIL_ENDIAN);

		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
				"$0x%02x,0x%04x(%s)", position,
				disp16, cr16_regs_names[reg & 0x9]);

		break;
	case 0x3:
		snprintf(cmd->operands, CR16_INSTR_MAXLEN - 1,
				"$0x%02x,0(%s)", position,
				cr16_regs_names[reg & 0x9]);
		break;
	default:
		ret = -1;
	}

	cmd->type = CR16_TYPE_BIT;
	return ret;
}

int cr16_decode_command(const ut8 *instr, struct cr16_cmd *cmd)
{
	int ret;
	ut16 in;
	r_mem_copyendian((ut8*)&in, instr, 2, LIL_ENDIAN);

	switch (cr16_get_opcode_low(in)) {
	case CR16_MOV:
	case CR16_ADD:
	case CR16_ADDU:
	case CR16_ADDC:
	case CR16_MUL:
	case CR16_SUB:
	case CR16_SUBC:
	case CR16_CMP:
	case CR16_AND:
	case CR16_OR:
	case CR16_XOR:
	case CR16_ASHU:
	case CR16_LSH:
		switch(cr16_get_opcode_hi(in)) {
		case CR16_I_R:
			ret = cr16_decode_i_r(instr, cmd);
			break;
		case CR16_R_R:
			ret = cr16_decode_r_r(instr, cmd);
			break;
		default:
			ret = -1;
		}
		if (ret == -1 && cr16_get_opcode_low(in) == CR16_CMP) {
			ret = cr16_decode_scond(instr, cmd);
		}
		break;
	case CR16_BCOND01:
		ret = cr16_decode_bcond01i(instr, cmd);
		break;
	case CR16_BITI:
		ret = cr16_decode_biti(instr, cmd);
		break;
	default:
		ret = -1;
	}

	if (ret != -1)
		return ret;

	switch ((in >> 13)) {
	case 0x2:
	case 0x0:
		ret = cr16_decode_bcond_br(instr, cmd);
		break;
	}

	if (ret != -1)
		return ret;

	switch (in >> 9) {
	case CR16_LPR:
	case CR16_SPR:
		ret = cr16_decode_slpr(instr, cmd);
		break;
	case CR16_TBIT_R_R:
		ret = cr16_decode_r_r(instr, cmd);
		if (ret == -1)
			ret = cr16_decode_bal(instr, cmd);
		break;
	case CR16_TBIT_I_R:
		ret = cr16_decode_i_r(instr, cmd);
		break;
	case CR16_BAL:
		ret = cr16_decode_bal(instr, cmd);
		break;
	case CR16_JUMP:
	case CR16_JAL:
	case 0x0B:
		ret = cr16_decode_jmp(instr, cmd);
		if (ret == -1)
			ret = cr16_decode_bcond_br(instr, cmd);
		break;
	case CR16_MOVXB:
	case CR16_MOVZB:
		ret = cr16_decode_movz(instr, cmd);
		break;
	case CR16_MULSB:
	case CR16_MULSW:
	case CR16_MULUW:
		ret = cr16_decode_muls(instr, cmd);
		break;
	}

	if (ret != -1)
		return ret;

	switch (in >> 7) {
	case CR16_PUSH:
	case CR16_POP:
	case CR16_POPRET_1:
	case CR16_POPRET_2:
		ret = cr16_decode_push_pop(instr, cmd);
		break;
	case CR16_LOADM:
	case CR16_STORM:
		ret = cr16_decode_loadm_storm(instr, cmd);
		break;
	}

	if (ret != -1)
		return ret;

	switch (in >> 10) {
	case CR16_MOVD:
		ret = cr16_decode_movd(instr, cmd);
		break;
	}

	if (ret != -1)
		return ret;

	ret = cr16_decode_misc(instr, cmd);

	if (ret != -1)
		return ret;

	switch (cr16_get_opcode_hi(in)) {
	case 0x2:
	case 0x3:
	case 0x1:
	case 0x0:
		ret = cr16_decode_ld_st(instr, cmd);
		break;
	}

	if (ret != -1)
		return ret;
	return ret;
}
