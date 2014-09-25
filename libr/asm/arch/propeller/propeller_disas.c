#include <r_types.h>
#include <r_util.h>

#include "propeller_disas.h"

static const char *instrs[] = {
	[PROP_ABS]		= "abs",
	[PROP_ABSNEG]	= "absneg",
	[PROP_ADD]		= "add",
	[PROP_ADDABS]	= "addabs",
	[PROP_ADDS]		= "adds",
	[PROP_ADDSX]	= "addsx",
	[PROP_ADDX]		= "addx",
	[PROP_AND]		= "and",
	[PROP_ANDN]		= "andn",
	[PROP_CALL]		= "call",
	[PROP_CMP]		= "cmp",
	[PROP_CMPS]		= "cmps",
	[PROP_CMPSUB]	= "cmpsub",
	[PROP_CMPSX]	= "cmpsx",
	[PROP_CMPX]		= "cmpx",
	[PROP_DJNZ]		= "djnz",
	[PROP_HUBOP]	= "hubop",
	[PROP_MOV]		= "mov",
	[PROP_MAX]		= "max",
	[PROP_MAXS]		= "maxs",
	[PROP_MIN]		= "min",
	[PROP_MINS]		= "mins",
	[PROP_MOVD]		= "movd",
	[PROP_MOVI]		= "movi",
	[PROP_MOVS]		= "movs",
	[PROP_MUXC]		= "muxc",
	[PROP_MUXNC]	= "muxnc",
	[PROP_MUXNZ]	= "muxnz",
	[PROP_MUXZ]		= "muxz",
	[PROP_NEG]		= "neg",
	[PROP_NEGC]		= "negc",
	[PROP_NEGNC]	= "negnc",
	[PROP_NEGNZ]	= "negnz",
	[PROP_NEGZ]		= "negz",
	[PROP_OR]		= "or",
	[PROP_RCL]		= "rcl",
	[PROP_RCR]		= "rcr",
	[PROP_RDBYTE]	= "rdbyte",
	[PROP_RDLONG]	= "rdlong",
	[PROP_RDWORD]	= "rdword",
	[PROP_RET]		= "ret",
	[PROP_REV]		= "rev",
	[PROP_ROL]		= "rol",
	[PROP_ROR]		= "ror",
	[PROP_SAR]		= "sar",
	[PROP_SHL]		= "shl",
	[PROP_SHR]		= "shr",
	[PROP_SUBABS]	= "subabs",
	[PROP_SUBS]		= "subs",
	[PROP_SUBSX]	= "subsx",
	[PROP_SUMC]		= "sumc",
	[PROP_SUMNC]	= "sumnc",
	[PROP_SUMNZ]	= "sumnz",
	[PROP_SUMZ]		= "sumz",
	[PROP_TEST]		= "test",
	[PROP_TESTN]	= "testn",
	[PROP_TJZ]		= "tjz",
	[PROP_WAITCNT]	= "waitcnt",
	[PROP_WAITVID]	= "waitvid",
	[PROP_XOR]		= "xor",
};

static const char *ext_instrs[] = {
	[PROP_CLKSET]	= "clkset",
	[PROP_COGID]	= "cogid",
	[PROP_COGINIT]	= "coginit",
	[PROP_COGSTOP]	= "cogstop",
	[PROP_LOCKCLR]	= "lockclr",
	[PROP_LOCKNEW]	= "locknew",
	[PROP_LOCKRET]	= "lockret",
	[PROP_LOCKSET]	= "lockset",
};

static const char *conditions[] = {
	[PROP_IF_ALWAYS]	= "",
	[PROP_IF_NEVER]		= "",
	[PROP_IF_E]			= "if_e",
	[PROP_IF_NE]		= "if_ne",
	[PROP_IF_A]			= "if_a",
	[PROP_IF_B]			= "if_b",
	[PROP_IF_AE]		= "if_ae",
	[PROP_IF_BE]		= "if_be",
	[PROP_IF_C_EQ_Z]	= "if_c_eq_z",
	[PROP_IF_C_NE_Z]	= "if_c_ne_z",
	[PROP_IF_C_AND_Z]	= "if_c_and_z",
	[PROP_IF_C_AND_NZ]	= "if_c_and_nz",
	[PROP_IF_NC_AND_Z]	= "if_nc_and_z",
	[PROP_IF_NZ_OR_NC]	= "if_nc_or_nz",
	[PROP_IF_NZ_OR_C]	= "if_nz_or_c",
	[PROP_IF_Z_OR_NC]	= "if_z_or_c",
};

static ut16 get_opcode (ut32 instr) {
	return instr >> 26;
}

static ut16 get_opcode_ext (ut32 instr) {
	return (instr & 0x7) | (instr >> 23);
}

static ut16 get_src (ut32 instr) {
	return instr & 0x1FF;
}

static ut16 get_dst (ut32 instr) {
	return ((instr >> 9) & 0x1FF) << 2;
}

static int is_immediate (ut32 instr) {
	return instr & 0x00400000;
}

static int decode_ext_cmd (struct propeller_cmd *cmd, ut32 instr) {
	ut16 opcode;

	opcode = get_opcode_ext (instr);

	switch (opcode) {
		case PROP_CLKSET:
		case PROP_COGID:
		case PROP_COGINIT:
		case PROP_COGSTOP:
		case PROP_LOCKCLR:
		case PROP_LOCKNEW:
		case PROP_LOCKRET:
		case PROP_LOCKSET:
			snprintf (cmd->instr, PROP_INSTR_MAXLEN - 1,
					"%s", ext_instrs[PROP_CLKSET]);
			snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1,
					"%d", get_dst (instr));
			return 4;
			break;
	}

	return -1;
}

static ut8 get_zcri (ut32 instr) {
	return (instr >> 22) & 0xf;
}

static ut8 get_con (ut32 instr) {
	return (instr >> 18) & 0xf;
}

static void decode_prefix (struct propeller_cmd *cmd, ut32 instr) {
	ut8 prefix = (instr >> 18) & 0xF;

	snprintf (cmd->prefix, 15, "%s", conditions[prefix]);
	cmd->prefix[15] = '\0';
}

static int decode_jmp (struct propeller_cmd *cmd, ut32 instr) {
	ut16 opcode;
	ut8 zcri;
	int ret = 1;
	opcode = get_opcode (instr);
	switch (opcode) {
		case PROP_JMP:
			zcri = get_zcri (instr);
			if (zcri & 0x2) {
				snprintf (cmd->instr, PROP_INSTR_MAXLEN - 1,
						"%s", "jmpret");
				if (zcri & 1) {
					cmd->dst = get_dst (instr) << 2;
					cmd->src = get_src (instr) << 2;

					snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1,
							"0x%x, #0x%x", get_dst (instr), get_src (instr) << 2);
				} else {
					cmd->src = get_src (instr) << 2;
					cmd->dst = get_dst (instr) << 2;
					snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1,
							"0x%x, 0x%x", get_dst (instr), get_src (instr) << 2);
				}
			} else {
				snprintf (cmd->instr, PROP_INSTR_MAXLEN - 1,
						"%s", "jmp");
				if (zcri & 1) {
					cmd->src = get_src (instr) << 2;
					cmd->immed = 1;
					snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1,
							"#0x%x", get_src (instr) << 2);
				} else {
					cmd->immed = 0;
					cmd->src = get_src (instr) << 2; 
					snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1,
							"0x%x", get_src (instr) << 2);
				}
			}

			ret = 4;
			break;
	}


	return ret;
}

int propeller_decode_command(const ut8 *instr, struct propeller_cmd *cmd)
{
	int ret = -1;
	ut32 in;
	ut16 opcode;

	r_mem_copyendian((ut8*)&in, instr, sizeof (ut32), LIL_ENDIAN);

	opcode = get_opcode (in);

	if (!get_con (in)) {
		snprintf (cmd->instr, PROP_INSTR_MAXLEN, "nop");
		cmd->operands[0] = '\0';
		return 4;
	}

	switch (opcode) {
		case PROP_ABS:
		case PROP_ABSNEG:
		case PROP_ADD:
		case PROP_ADDABS:
		case PROP_ADDS:
		case PROP_ADDSX:
		case PROP_ADDX:
		case PROP_AND:
		case PROP_ANDN:
		case PROP_CMP:
		case PROP_CMPS:
		case PROP_CMPSUB:
		case PROP_CMPSX:
		case PROP_CMPX:
		case PROP_DJNZ:
		case PROP_MAX:
		case PROP_MAXS:
		case PROP_MIN:
		case PROP_MINS:
		case PROP_MOV:
		case PROP_MOVD:
		case PROP_MOVI:
		case PROP_MOVS:
		case PROP_MUXC:
		case PROP_MUXNC:
		case PROP_MUXNZ:
		case PROP_MUXZ:
		case PROP_NEG:
		case PROP_NEGC:
		case PROP_NEGNC:
		case PROP_NEGNZ:
		case PROP_NEGZ:
		case PROP_OR:
		case PROP_RCL:
		case PROP_RCR:
		case PROP_RDBYTE:
		case PROP_RDLONG:
		case PROP_RDWORD:
			//case PROP_RET:
		case PROP_REV:
		case PROP_ROL:
		case PROP_ROR:
		case PROP_SAR:
		case PROP_SHL:
		case PROP_SHR:
		case PROP_SUBABS:
		case PROP_SUBS:
		case PROP_SUBSX:
			//case PROP_SUBX:
		case PROP_SUMC:
		case PROP_SUMNC:
		case PROP_SUMNZ:
		case PROP_SUMZ:
			//case PROP_TEST:
		case PROP_TJZ:
		case PROP_WAITCNT:
		case PROP_WAITPEQ:
		case PROP_WAITPNE:
		case PROP_WAITVID:
		case PROP_XOR:
			snprintf (cmd->instr, PROP_INSTR_MAXLEN - 1, "%s",
					instrs[opcode]);

			if ((opcode == PROP_RDBYTE || opcode == PROP_RDLONG ||
						opcode == PROP_RDWORD) && (!(get_zcri (in) & 0x2))) {
				cmd->instr[0] = 'w';
				cmd->instr[1] = 'r';
			}

			if (opcode == PROP_SUB && in & 0x08000000) {
				snprintf (cmd->instr, PROP_INSTR_MAXLEN - 1, "sub");
			} else if (opcode == PROP_SUBX && in & 0x08000000) {
				snprintf (cmd->instr, PROP_INSTR_MAXLEN - 1, "subx");
			}

			if (is_immediate (in)) {
				cmd->src = get_src (in);
				cmd->dst = get_dst (in);
				snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1, "0x%x, #%d",
						get_dst (in), get_src (in));
			} else {
				cmd->src = get_src (in) << 2;
				cmd->dst = get_dst (in);
				snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1, "0x%x, 0x%x",
						get_dst (in), get_src (in) << 2);
			}

			ret = 4;
			break;
		case PROP_HUBOP:
			ret = decode_ext_cmd (cmd, in);
			if (ret == -1) {
				snprintf (cmd->instr, PROP_INSTR_MAXLEN - 1, "%s",
						instrs[opcode]);

				if (is_immediate (in)) {
					cmd->src = get_src (in);
					cmd->dst = get_dst (in);

					snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1, "0x%x, #%d",
							get_dst (in) << 2, get_src (in));
				} else {
					cmd->src = get_src (in);
					cmd->dst = get_dst (in);

					snprintf (cmd->operands, PROP_INSTR_MAXLEN - 1, "0x%x, 0x%x",
							get_dst (in), get_src (in));
				}

				ret = 4;
			}
			break;
		case PROP_JMP:
			ret = decode_jmp (cmd, in);
			break;
	}

	cmd->opcode = opcode;

	if (ret > 0) {
		decode_prefix (cmd, in);
	}

	return ret;
}
