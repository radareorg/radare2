#include <r_types.h>
#include <r_util.h>

#include "msp430_disas.h"

static const char *two_op_instrs[] = {
	[MSP430_MOV]	= "mov",
	[MSP430_ADD]	= "add",
	[MSP430_ADDC]	= "addc",
	[MSP430_SUBC]	= "subc",
	[MSP430_SUB]	= "sub",
	[MSP430_CMP]	= "cmp",
	[MSP430_DADD]	= "dadd",
	[MSP430_BIT]	= "bit",
	[MSP430_BIC]	= "bic",
	[MSP430_BIS]	= "bis",
	[MSP430_XOR]	= "xor",
	[MSP430_AND]	= "and",
};

static const char *one_op_instrs[] = {
	[MSP430_RRC]	= "rrc",
	[MSP430_SWPB]	= "swpb",
	[MSP430_RRA]	= "rra",
	[MSP430_SXT]	= "sxt",
	[MSP430_PUSH]	= "push",
	[MSP430_CALL]	= "call",
	[MSP430_RETI]	= "reti",
};

static const char *jmp_instrs[] = {
	[MSP430_JEQ]	= "jeq",
	[MSP430_JNE]	= "jnz",
	[MSP430_JC]	= "jc",
	[MSP430_JNC]	= "jnc",
	[MSP430_JN]	= "jn",
	[MSP430_JGE]	= "jge",
	[MSP430_JL]	= "jl",
	[MSP430_JMP]	= "jmp",
};

static ut8 get_twoop_opcode(ut16 instr)
{
	return instr >> 12;
}

static ut8 get_as(ut16 instr)
{
	return (instr >> 4) & 3;
}

static ut8 get_bw(ut16 instr)
{
	return (instr >> 6) & 1;
}

static ut8 get_ad(ut16 instr)
{
	return (instr >> 7) & 1;
}

static int get_src(ut16 instr) {
	return (instr >> 8) & 0xF;
}

static int get_dst(ut16 instr) {
	return instr & 0xF;
}

static void remove_first_operand(struct msp430_cmd *cmd)
{
	if (strchr(cmd->operands, ',')) {
		memmove(cmd->operands, strchr(cmd->operands, ',') + 2,
				strlen(strchr(cmd->operands, ',') + 2) + 1);
	}
}

static void remove_second_operand(struct msp430_cmd *cmd)
{
	if (strchr(cmd->operands, ','))
		*strchr(cmd->operands, ',') = '\0';
}

/* TODO: This is ugly as hell */
static int decode_emulation(ut16 instr, ut16 op1, struct msp430_cmd *cmd)
{
	int ret = -1;
	ut8 as, ad, src, dst, bw, opcode;

	as = get_as(instr);
	ad = get_ad(instr);
	src = get_src(instr);
	dst = get_dst(instr);
	bw = get_bw(instr);
	opcode = get_twoop_opcode(instr);

	if (opcode == MSP430_ADDC && as == 0 && src == MSP430_R3) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "adc.b" : "adc");
		snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "r%d", dst);
	} else if (opcode == MSP430_MOV && as == 0 && src == MSP430_R3) {
		if (ad == 0 && dst == MSP430_R3) {
			snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "nop");
			cmd->operands[0] = '\0';
		} else {
			snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "clr.b" : "clr");
			remove_first_operand(cmd);
		}
	} else if (opcode == MSP430_MOV && as == 3 && src == MSP430_SP) {
		if (dst == MSP430_PC) {
			snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "ret");
       			cmd->type = MSP430_ONEOP;
			cmd->opcode = MSP430_RETI;
			cmd->operands[0] = '\0';
		} else {
			snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "pop.b" : "pop");
			remove_first_operand(cmd);
		}
	} else if (opcode == MSP430_MOV && ad == 0 && dst == MSP430_PC) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "br");
		remove_second_operand(cmd);
	} else if (opcode == MSP430_BIC && as == 2 && src == MSP430_SR && dst == MSP430_SR && ad == 0) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "clrn");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIC && as == 2 && src == MSP430_R3 && dst == MSP430_SR && ad == 0) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "clrz");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIC && as == 3 && src == MSP430_SR && dst == MSP430_SR && ad == 0) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "dint");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIS && as == 3 && src == MSP430_SR && dst == MSP430_SR && ad == 0) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "eint");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_DADD && as == 0 && src == MSP430_R3) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "dadc.b" : "dadc");
		remove_first_operand(cmd);
	} else if (opcode == MSP430_SUB && as == 1 && src == MSP430_R3) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "dec.b" : "dec");
		remove_first_operand(cmd);
	} else if (opcode == MSP430_SUB && as == 2 && src == MSP430_R3) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "decd.b" : "decd");
		remove_first_operand(cmd);
	} else if (opcode == MSP430_ADD && as == 1 && src == MSP430_R3) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "inc.b" : "inc");
		remove_first_operand(cmd);
	} else if (opcode == MSP430_ADD && as == 2 && src == MSP430_R3) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "incd.b" : "incd");
		remove_first_operand(cmd);
	} else if (opcode == MSP430_XOR && as == 3 && src == MSP430_R3) { 
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "inv.b" : "inv");
		remove_first_operand(cmd);
	} else if (opcode == MSP430_ADD && src == dst) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "rla.b" : "rla");
		remove_second_operand(cmd);
	} else if (opcode == MSP430_ADDC && src == dst) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "rlc.b" : "rlc");
		remove_second_operand(cmd);
	} else if (opcode == MSP430_SUBC && as == 0 && src == MSP430_R3) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "sbc.b" : "sbc");
		remove_first_operand(cmd);
	} else if (opcode == MSP430_BIS && as == 1 && src == MSP430_R3 && dst == MSP430_SR && ad == 0) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "setc");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIS && as == 2 && src == MSP430_SR && dst == MSP430_SR && ad == 0) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "setn");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIS && as == 2 && src == MSP430_R3 && dst == MSP430_SR && ad == 0) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "setz");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_CMP && as == 0 && src == MSP430_R3) {
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", bw ? "tst.b" : "tst");
		remove_first_operand(cmd);
	}

	return ret;
}

/* return #byte of instruction */
static int decode_addressing_mode(ut16 instr, ut16 op1, ut16 op2, struct msp430_cmd *cmd)
{
	int ret, cg;
	ut8 as, ad, src, dst;
	ut16 op;
	char dstbuf[16];

	memset(dstbuf, 0, sizeof(dstbuf));

	as = get_as(instr);
	ad = get_ad(instr);
	src = get_src(instr);
	dst = get_dst(instr);
	cg = 0;

	/* addressing mode of source operand */
	switch (as) {
	case 0:
		switch (src) {
		case MSP430_R3: /* CG2 */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#0");
			cg = 1;
			break;
		default: /* register mode */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "r%d", src);
		}
		ret = 2;
		break;
	case 1:
		ret = 4;
		switch (src) {
		case MSP430_PC: /* symbolic mode */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "0x%04x", op1);
			break;
		case MSP430_R3: /* CG2 */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "%s", "#1");
			cg = 1;
			ret = 2;
			break;
		case MSP430_SR: /* absolute mode */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "&0x%04x", op1);
			break;
		default: /* indexed mode */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "0x%x(r%d)", op1, src);
		}
		break;
	case 2:
		switch (src) {
		case MSP430_SR: /* CG1 */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#4");
			cg = 1;
			break;
		case MSP430_R3: /* CG2 */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#2");
			cg = 1;
			break;
		default: /* indirect register mode */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "@r%d", src);
		}
		ret = 2;
		break;
	case 3:
		ret = 2;
		switch (src) {
		case MSP430_SR: /* CG1 */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#8");
			cg = 1;
			break;
		case MSP430_R3: /* CG2 */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#-1");
			cg = 1;
			break;
		case MSP430_PC: /* immediate mode */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#0x%04x", op1);
			ret = 4;
			break;
		default: /* indirect autoincrement mode */
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "@r%d+", src);
		}
		break;
	default:
		ret = -1;
	}

	if (ret < 0)
		return ret;

	/* addressing mode of destination operand */
	switch (ad) {
	case 0: /* register mode */
		snprintf(dstbuf, 15, ", r%d", dst); 
		break;
	case 1:
		/* check addr. mode of source operand */
		if ((as == 1 || as == 3) && cg == 0) {
		    op = op2;
		    ret = 6;
		} else {
		    op = op1;
		    ret = 4;
		}
		switch (get_dst(instr)) {
		case MSP430_PC: /* symbolic mode */
			snprintf(dstbuf, 15, ", 0x%04x", op);
			break;
		case MSP430_SR: /* absolute mode */
		    	snprintf(dstbuf, 15, ", &0x%04x", op);
			break;
		default: /* indexed mode */
			snprintf(dstbuf, 15, ", 0x%x(r%d)", op, dst);
		}
		break;
	default:
		ret = -1;
	}

	strncat(cmd->operands, dstbuf, MSP430_INSTR_MAXLEN - 1 - strlen(cmd->operands));
	decode_emulation(instr, op1, cmd);
	return ret;
}

static int decode_twoop_opcode(ut16 instr, ut16 op1, ut16 op2, struct msp430_cmd *cmd)
{
	int ret;
	ut8 opcode;

	opcode = get_twoop_opcode(instr);

	snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", two_op_instrs[opcode]);
	if (get_bw(instr)) {
		strncat(cmd->instr, ".b", MSP430_INSTR_MAXLEN - 1 - strlen(cmd->instr));
	}

	cmd->opcode = get_twoop_opcode(instr);
	ret = decode_addressing_mode(instr, op1, op2, cmd);

	return ret;
}

static ut8 get_jmp_opcode(ut16 instr)
{
	return instr >> 13;
}

static ut8 get_jmp_cond(ut16 instr)
{
	return (instr >> 10 ) & 7;
}

static int decode_jmp(ut16 instr, struct msp430_cmd *cmd)
{
	ut16 addr;
	if (get_jmp_opcode(instr) != MSP430_JMP_OPC)
		return -1;

	snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", jmp_instrs[get_jmp_cond(instr)]);

	addr = instr & 0x3FF;

	cmd->jmp_addr = addr >= 0x300 ? (st16)((0xFE00 | addr) * 2 + 2) : (addr & 0x1FF) * 2 + 2;
	snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1,
			"$%c0x%04x", addr >= 0x300 ? '-' : '+',
			addr >= 0x300 ? 0x400 - ((addr & 0x1FF) * 2 + 2) : (addr & 0x1FF) * 2 + 2);

	cmd->jmp_cond = get_jmp_cond(instr);
	cmd->opcode = get_jmp_opcode(instr);
	cmd->type = MSP430_JUMP;

	return 2;
}


static int get_oneop_opcode(ut16 instr)
{
	return (instr >> 7) & 0x7;
}

static int decode_oneop_opcode(ut16 instr, ut16 op, struct msp430_cmd *cmd)
{
	int ret = 2;
	ut8 as, opcode;

	if ((instr >> 10) != 4)
		return -1;

	opcode = get_oneop_opcode(instr);

	as = get_as(instr);

	snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
			one_op_instrs[opcode]);

	cmd->opcode = get_oneop_opcode(instr);

	switch (get_oneop_opcode(instr)) {
	case MSP430_RRC:
	case MSP430_SWPB:
	case MSP430_RRA:
	case MSP430_SXT:
	case MSP430_PUSH:
	case MSP430_CALL:
		switch (as) {
		case 0:
			switch (get_dst(instr)) {
			case MSP430_R3:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#0");
				break;
			default:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"r%d", get_dst(instr));
			}
			ret = 2;
			break;
		case 1:
			/* most of these instructions take another word as an immediate */
			ret = 4;
			switch (get_dst(instr)) {
			case MSP430_R3:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#1");
				/* this is an unusual encoding in that there's no index word */
				ret = 2;
				break;
			case MSP430_PC:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"0x%04x", op);
				break;
			case MSP430_SR:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"&0x%04x", op);
				break;
			default:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"0x%x(r%d)", op, get_dst(instr));
			}

			break;
		case 2:
			switch (get_dst(instr)) {
			case MSP430_SR:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#4");
				break;
			case MSP430_R3:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "#2");
				break;
			default:
				snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"@r%d", get_dst(instr));
			}

			ret = 2;
			break;
		case 3:
			snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1,
					"#0x%04x", op);
			ret = 4;
			break;
		default:
			ret = -1;
		}
		break;
	case MSP430_RETI:
		cmd->operands[0] = '\0';
		break;
	}

	cmd->type = MSP430_ONEOP;

	return ret;
}

int msp430_decode_command(const ut8 *in, struct msp430_cmd *cmd)
{
	int ret = -1;
	ut16 instr;
	ut16 operand1, operand2;
	ut8 opcode;

	instr = r_read_le16 (in);

	opcode = get_twoop_opcode(instr);

	switch (opcode) {
	case MSP430_MOV:
	case MSP430_ADD:
	case MSP430_ADDC:
	case MSP430_SUBC:
	case MSP430_SUB:
	case MSP430_CMP:
	case MSP430_DADD:
	case MSP430_BIT:
	case MSP430_BIC:
	case MSP430_BIS:
	case MSP430_XOR:
	case MSP430_AND:
		cmd->type = MSP430_TWOOP;
		operand1 = r_read_at_le16 (in, 2);
		operand2 = r_read_at_le16 (in, 4);
		ret = decode_twoop_opcode(instr, operand1, operand2, cmd);
	break;
	}

	if (ret > 0) {
		return ret;
	}

	ret = decode_jmp(instr, cmd);

	if (ret > 0)
		return ret;

	operand1 = r_read_at_le16 (in, 2);
	ret = decode_oneop_opcode(instr, operand1, cmd);

	/* if ret < 0, it's an invalid opcode.Say so and return 2 since
	 * all MSP430 opcodes are of 16 bits,valid or invalid */
	if (ret < 0) {
		cmd->type = MSP430_INV;
		snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "invalid opcode");
		ret = 2;
	}

	return ret;
}
