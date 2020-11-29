#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "sysregs.h"
#include "operations.h"
#include "encodings.h"
#include "arm64dis.h"
#include "pcode.h"

void print_decoded_struct(Instruction *dec)
{
	//printf("sizeof(struct decoded): 0x%lX\n", sizeof(*dec));
	//printf(" insword: 0x%08X\n", dec->insword);
	printf("encoding: %d (%s)\n", dec->encoding, enc_to_str(dec->encoding));
	//printf("operation: %d (%s)\n", dec->operation, get_operation(dec->operation));

	char buf[256];
	strcpy(buf, enc_to_xml(dec->encoding));
	//printf("      xml: /Users/andrewl/Downloads/A64_ISA_xml_v86A-2020-03/ISA_A64_xml_v86A-2020-03/%s\n", buf);
	strcpy(buf + strlen(buf)-3, "html");
	printf("     html: /Users/andrewl/Downloads/A64_ISA_xml_v86A-2020-03/ISA_A64_xml_v86A-2020-03/xhtml/%s\n", buf);

//	if(1) {
//		for(auto it=dec->dec->begin(); it!=dec->dec->end(); it++) {
//			string key = it->first;
//			uint64_t value = it->second;
//			printf("fields->%s: 0x%llx\n", key.c_str(), value);
//		}
//	}
}

//-----------------------------------------------------------------------------
// registers (non-system)
//-----------------------------------------------------------------------------

static const char *RegisterString[] =
{
	"NONE",
	"w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
	"w8",  "w9",  "w10", "w11", "w12", "w13", "w14", "w15",
	"w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
	"w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr", "wsp",
	"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
	"x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
	"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
	"x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr", "sp",
	"v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",
	"v8",  "v9",  "v10", "v11", "v12", "v13", "v14", "v15",
	"v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
	"v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "v31",
	"b0",  "b1",  "b2",  "b3",  "b4",  "b5",  "b6",  "b7",
	"b8",  "b9",  "b10", "b11", "b12", "b13", "b14", "b15",
	"b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
	"b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31", "b31",
	"h0",  "h1",  "h2",  "h3",  "h4",  "h5",  "h6",  "h7",
	"h8",  "h9",  "h10", "h11", "h12", "h13", "h14", "h15",
	"h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23",
	"h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31", "h31",
	"s0",  "s1",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
	"s8",  "s9",  "s10", "s11", "s12", "s13", "s14", "s15",
	"s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
	"s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31", "s31",
	"d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",
	"d8",  "d9",  "d10", "d11", "d12", "d13", "d14", "d15",
	"d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
	"d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31", "d31",
	"q0",  "q1",  "q2",  "q3",  "q4",  "q5",  "q6",  "q7",
	"q8",  "q9",  "q10", "q11", "q12", "q13", "q14", "q15",
	"q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
	"q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31", "q31",
	"z0",  "z1",  "z2",  "z3",  "z4",  "z5",  "z6",  "z7",
	"z8",  "z9",  "z10", "z11", "z12", "z13", "z14", "z15",
	"z16", "z17", "z18", "z19", "z20", "z21", "z22", "z23",
	"z24", "z25", "z26", "z27", "z28", "z29", "z30", "z31", "z31",
	/* scalable predicate registers */
	"p0",  "p1",  "p2",  "p3",  "p4",  "p5",  "p6",  "p7",
	"p8",  "p9",  "p10", "p11", "p12", "p13", "p14", "p15",
	"p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23",
	"p24", "p25", "p26", "p27", "p28", "p29", "p30", "p31",
	/* prefetch operations (TODO: remove these as registers) */
	"pldl1keep", "pldl1strm", "pldl2keep", "pldl2strm",
	"pldl3keep", "pldl3strm", "#0x6",	  "#0x7",
	"plil1keep", "plil1strm", "plil2keep", "plil2strm",
	"plil3keep", "plil3strm", "#0xe",		"#0xf",
	"pstl1keep", "pstl1strm", "pstl2keep", "pstl2strm",
	"pstl3keep", "pstl3strm", "#0x16", "#0x17",
	"#0x18", "#0x19", "#0x1a", "#0x1b",
	"#0x1c", "#0x1d", "#0x1e", "#0x1f",
	"END"
};

const char *get_register_name(uint32_t reg)
{
	Register r = REG_ENUM(reg);

	if(r>REG_NONE && r<REG_END)
		return RegisterString[r];

	if(r>SYSREG_NONE && r<SYSREG_END)
		return get_system_register_name((enum SystemReg)r);

	return "";
}

const char *get_register_arrspec(uint32_t reg)
{
	switch(REG_ARRSPEC(reg)) {
		case 0b00000000001: return ".b";
		case 0b00000000010: return ".h";
		case 0b00000000100: return ".s";
		case 0b00000001000: return ".d";
		case 0b00000010000: return ".q";
		case 0b00001000001: return ".1b";
		case 0b00010000001: return ".2b";
		case 0b00100000001: return ".4b";
		case 0b01000000001: return ".8b";
		case 0b10000000001: return ".16b";
		case 0b00001000010: return ".1h";
		case 0b00010000010: return ".2h";
		case 0b00100000010: return ".4h";
		case 0b01000000010: return ".8h";
		case 0b10000000010: return ".16h";
		case 0b00001000100: return ".1s";
		case 0b00010000100: return ".2s";
		case 0b00100000100: return ".4s";
		case 0b01000000100: return ".8s";
		case 0b10000000100: return ".16s";
		case 0b00001001000: return ".1d";
		case 0b00010001000: return ".2d";
		case 0b00100001000: return ".4d";
		case 0b01000001000: return ".8d";
		case 0b10000001000: return ".16d";
		case 0b00001010000: return ".1q";
		case 0b00010010000: return ".2q";
		case 0b00100010000: return ".4q";
		case 0b01000010000: return ".8q";
		case 0b10000010000: return ".16q";
		default:
			return "";
	}
}

int get_register_full(uint32_t reg, char *result)
{
	strcpy(result, get_register_name(reg));

	if(result[0] == '\0')
		return -1;

	strcat(result, get_register_arrspec(reg));
	return 0;
}

unsigned get_register_size(uint32_t reg)
{
	Register r = REG_ENUM(reg);

	//Comparison done in order of likelyhood to occur
	if ((r >= REG_X0 && r <= REG_SP) || (r >= REG_D0 && r <= REG_D31))
		return 8;
	else if ((r >= REG_W0 && r <= REG_WSP) || (r >= REG_S0 && r <= REG_S31))
		return 4;
	else if (r >= REG_B0 && r <= REG_B31)
		return 1;
	else if (r >= REG_H0 && r <= REG_H31)
		return 2;
	else if ((r >= REG_Q0 && r <= REG_Q31) || (r >= REG_V0 && r <= REG_V31))
		return 16;
	return 0;
}

//-----------------------------------------------------------------------------
// decode or decompose
//-----------------------------------------------------------------------------

int decode_spec(context *ctx, Instruction *dec); // decode0.cpp
int decode_scratchpad(context *ctx, Instruction *dec); // decode_scratchpad.cpp

int aarch64_decompose(uint32_t instructionValue, Instruction *instr, uint64_t address)
{
	context ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.halted = 1; // enabled disassembly of exception instructions like DCPS1
	ctx.insword = instructionValue;
	ctx.address = address;
	ctx.features0 = 0xFFFFFFFFFFFFFFFF;
	ctx.features1 = 0xFFFFFFFFFFFFFFFF;

	/* have the spec-generated code populate all the pcode variables */
	int rc = decode_spec(&ctx, instr);
	if(rc != DECODE_STATUS_OK)
		return rc;

	/* convert the pcode variables to list of operands, etc. */
	return decode_scratchpad(&ctx, instr);
}

//-----------------------------------------------------------------------------
// disassemble helpers
//-----------------------------------------------------------------------------

static const char *ConditionString[] = {
	"eq", "ne", "cs", "cc",
	"mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt",
	"gt", "le", "al", "nv"
};

const char *get_condition(Condition cond)
{
	if (cond >= END_CONDITION)
		return NULL;

	return ConditionString[cond];
}

static const char *ShiftString[] = {
	"NONE", "lsl", "lsr", "asr",
	"ror",  "uxtw", "sxtw", "sxtx",
	"uxtx", "sxtb", "sxth", "uxth",
	"uxtb", "msl"
};

const char *get_shift(ShiftType shift)
{
	if (shift == ShiftType_NONE || shift >= ShiftType_END)
		return NULL;

	return ShiftString[shift];
}

static inline uint32_t get_shifted_register(
	const InstructionOperand *instructionOperand,
	uint32_t registerNumber,
	char *outBuffer,
	uint32_t outBufferSize)
{
	char immBuff[32] = {0};
	char shiftBuff[64] = {0};

	char reg[16];
	if(get_register_full((Register)instructionOperand->reg[registerNumber], reg))
		return FAILED_TO_DISASSEMBLE_REGISTER;

	if (instructionOperand->shiftType != ShiftType_NONE)
	{
		if (instructionOperand->shiftValueUsed != 0)
		{
			if (snprintf(immBuff, sizeof(immBuff), " #%#x", instructionOperand->shiftValue) < 0)
			{
				return FAILED_TO_DISASSEMBLE_REGISTER;
			}
		}
		const char *shiftStr = get_shift(instructionOperand->shiftType);
		if (shiftStr == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;
		snprintf(
				shiftBuff,
				sizeof(shiftBuff),
				", %s%s",
				shiftStr,
				immBuff);
	}
	if (snprintf(outBuffer, outBufferSize, "%s%s", reg, shiftBuff) < 0)
		return FAILED_TO_DISASSEMBLE_REGISTER;
	return DISASM_SUCCESS;
}

uint32_t get_memory_operand(
	const InstructionOperand *instructionOperand,
	char *outBuffer,
	uint32_t outBufferSize)
{
	char immBuff[64]= {0};
	char extendBuff[48] = {0};
	char paramBuff[32] = {0};

	char reg0[16]={'\0'}, reg1[16]={'\0'};
	if(get_register_full((Register)instructionOperand->reg[0], reg0))
		return FAILED_TO_DISASSEMBLE_REGISTER;

	const char *sign = "";
	int64_t imm = instructionOperand->immediate;
	if (instructionOperand->signedImm && (int64_t)imm < 0)
	{
		sign = "-";
		imm = -imm;
	}

	switch (instructionOperand->operandClass)
	{
		case MEM_REG:
			if (snprintf(outBuffer, outBufferSize, "[%s]", reg0) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;

		case MEM_PRE_IDX:
			if (snprintf(outBuffer, outBufferSize, "[%s, #%s%#" PRIx64 "]!", reg0, sign, (uint64_t)imm) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;

		case MEM_POST_IDX: // [<reg>], <reg|imm>
			if (instructionOperand->reg[1] != REG_NONE) {
				if(get_register_full((Register)instructionOperand->reg[1], reg1))
					return FAILED_TO_DISASSEMBLE_REGISTER;

				snprintf(paramBuff, sizeof(paramBuff), ", %s", reg1);
			}
			else if (snprintf(paramBuff, sizeof(paramBuff), ", #%s%#" PRIx64, sign, (uint64_t)imm) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			if (snprintf(outBuffer, outBufferSize, "[%s]%s", reg0, paramBuff) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			break;

		case MEM_OFFSET: // [<reg> optional(imm)]
			if (instructionOperand->immediate != 0) {
				const char *mul_vl = instructionOperand->mul_vl ? ", mul vl" : "";
				if(snprintf(immBuff, sizeof(immBuff), ", #%s%#" PRIx64 "%s", sign, (uint64_t)imm, mul_vl) < 0) {
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
			}

			if (snprintf(outBuffer, outBufferSize, "[%s%s]", reg0, immBuff) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;

		case MEM_EXTENDED:
			if(get_register_full((Register)instructionOperand->reg[1], reg1))
				return FAILED_TO_DISASSEMBLE_REGISTER;

			if (reg0[0] == '\0' || reg1[0] == '\0') {
				return FAILED_TO_DISASSEMBLE_OPERAND;
			}

			// immBuff, like "#0x0"
			if (instructionOperand->shiftValueUsed)
				if(snprintf(immBuff, sizeof(immBuff), " #%#x", instructionOperand->shiftValue) < 0)
					return FAILED_TO_DISASSEMBLE_OPERAND;

			// extendBuff, like "lsl #0x0"
			if (instructionOperand->shiftType != ShiftType_NONE)
			{
				if (snprintf(extendBuff, sizeof(extendBuff), ", %s%s",
				  ShiftString[instructionOperand->shiftType], immBuff) < 0)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
			}

			// together, like "[x24, x30, lsl #0x0]"
			if (snprintf(outBuffer, outBufferSize, "[%s, %s%s]", reg0, reg1, extendBuff) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			break;
		default:
			return NOT_MEMORY_OPERAND;
	}
	return DISASM_SUCCESS;
}

uint32_t get_register(const InstructionOperand *operand, uint32_t registerNumber, char *outBuffer, uint32_t outBufferSize)
{

	/* 1) handle system registers */
	if(operand->operandClass == SYS_REG)
	{
		if (snprintf(outBuffer, outBufferSize, "%s",
		  get_system_register_name((SystemReg)operand->reg[registerNumber])) < 0)
			return FAILED_TO_DISASSEMBLE_REGISTER;
		return 0;
	}

	if(operand->operandClass != REG && operand->operandClass != MULTI_REG)
		return OPERAND_IS_NOT_REGISTER;

	/* 2) handle shifted registers */
	if (operand->shiftType != ShiftType_NONE)
	{
		return get_shifted_register(operand, registerNumber, outBuffer, outBufferSize);
	}

	char reg_buf[16];
	if(get_register_full((Register)operand->reg[registerNumber], reg_buf))
		return FAILED_TO_DISASSEMBLE_REGISTER;

	/* 3) handle predicate registers */
	if(operand->operandClass == REG && operand->pred_qual && operand->reg[0] >= REG_P0 && operand->reg[0] <= REG_P31)
	{
		if(snprintf(outBuffer, outBufferSize, "%s/%c", reg_buf, operand->pred_qual) < 0)
			return FAILED_TO_DISASSEMBLE_REGISTER;
		return 0;
	}

	/* 4) handle other registers */
	char scale[32] = {0};
	if (operand->scale != 0)
		snprintf(scale, sizeof(scale), "[%u]", 0x7fffffff & operand->scale);

	char index[32] = {0};
	if(operand->operandClass == REG && operand->indexUsed)
		snprintf(index, sizeof(scale), "[%u]", operand->index);

	if(snprintf(outBuffer, outBufferSize, "%s%s%s", reg_buf, scale, index) < 0)
		return FAILED_TO_DISASSEMBLE_REGISTER;

	return 0;
}

uint32_t get_multireg_operand(const InstructionOperand *operand, char *outBuffer, uint32_t outBufferSize)
{
	char indexBuff[32] = {0};
	char regBuff[4][32];
	uint32_t elementCount = 0;
	memset(&regBuff, 0, sizeof(regBuff));

	for (; elementCount < 4 && operand->reg[elementCount] != REG_NONE; elementCount++)
	{
		if (get_register(operand, elementCount, regBuff[elementCount], 32) != 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}

	if(operand->indexUsed)
	{
		snprintf(indexBuff, sizeof(indexBuff), "[%d]", operand->index);
	}
	int32_t result = 0;
	switch (elementCount)
	{
		case 1:
			result = snprintf(outBuffer, outBufferSize, "{%s}%s",
				regBuff[0],
				indexBuff);
			break;
		case 2:
			result = snprintf(outBuffer, outBufferSize, "{%s, %s}%s",
				regBuff[0],
				regBuff[1],
				indexBuff);
			break;
		case 3:
			result = snprintf(outBuffer, outBufferSize, "{%s, %s, %s}%s",
				regBuff[0],
				regBuff[1],
				regBuff[2],
				indexBuff);
			break;
		case 4:
			result = snprintf(outBuffer, outBufferSize, "{%s, %s, %s, %s}%s",
				regBuff[0],
				regBuff[1],
				regBuff[2],
				regBuff[3],
				indexBuff);
			break;
		default:
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}

	return result < 0 ? FAILED_TO_DISASSEMBLE_OPERAND : DISASM_SUCCESS;
}

uint32_t get_shifted_immediate(const InstructionOperand *instructionOperand, char *outBuffer, uint32_t outBufferSize, uint32_t type)
{
	char shiftBuff[48] = {0};
	char immBuff[32] = {0};
	const char *sign = "";
	if (instructionOperand == NULL)
		return FAILED_TO_DISASSEMBLE_OPERAND;

	uint64_t imm = instructionOperand->immediate;
	if (instructionOperand->signedImm == 1 && ((int64_t)imm) < 0)
	{
		sign = "-";
		imm = -(int64_t)imm;
	}
	if (instructionOperand->shiftType != ShiftType_NONE)
	{
		if (instructionOperand->shiftValueUsed != 0)
		{
			if (snprintf(immBuff, sizeof(immBuff), " #%#x", instructionOperand->shiftValue) < 0)
			{
				return FAILED_TO_DISASSEMBLE_REGISTER;
			}
		}
		const char *shiftStr = get_shift(instructionOperand->shiftType);
		if (shiftStr == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;
		snprintf(
				shiftBuff,
				sizeof(shiftBuff),
				", %s%s",
				shiftStr,
				immBuff);
	}
	if (type == FIMM32)
	{
		float f = *(const float*)&instructionOperand->immediate;
		if (snprintf(outBuffer, outBufferSize, "#%.08f%s", f, shiftBuff) < 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else if (type == IMM32)
	{
		if (snprintf(outBuffer, outBufferSize, "#%s%#x%s", sign, (uint32_t)imm, shiftBuff) < 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else if (type == LABEL)
	{
		if (snprintf(outBuffer, outBufferSize, "0x%" PRIx64, (uint64_t)imm) < 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else if (type == STR_IMM)
	{
		if (snprintf(outBuffer, outBufferSize, "%s #0x%" PRIx64, instructionOperand->name, (uint64_t)imm) < 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else
	{
		if (snprintf(outBuffer, outBufferSize, "#%s%#" PRIx64 "%s",
					sign,
					imm,
					shiftBuff) < 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	return DISASM_SUCCESS;
}

uint32_t get_implementation_specific(const InstructionOperand *operand, char *outBuffer, uint32_t outBufferSize)
{
	return snprintf(outBuffer,
			outBufferSize,
			"s%d_%d_c%d_c%d_%d",
			operand->reg[0],
			operand->reg[1],
			operand->reg[2],
			operand->reg[3],
			operand->reg[4]) < 0;
}

const char *get_operation(const Instruction *inst)
{
	return operation_to_str(inst->operation);
}

//-----------------------------------------------------------------------------
// disassemble (decoded Instruction -> string)
//-----------------------------------------------------------------------------

int aarch64_disassemble(Instruction *instruction, char *buf, size_t buf_sz)
{
	char operandStrings[MAX_OPERANDS][130];
	char tmpOperandString[128];
	const char *operand = tmpOperandString;
	if (instruction == NULL || buf_sz == 0 || buf == NULL)
		return INVALID_ARGUMENTS;

	memset(operandStrings, 0, sizeof(operandStrings));
	const char *operation = get_operation(instruction);
	if (operation == NULL)
		return FAILED_TO_DISASSEMBLE_OPERATION;

	for(int i=0; i<MAX_OPERANDS; i++)
		memset(&(operandStrings[i][0]), 0, 128);

	for(int i=0; i<MAX_OPERANDS && instruction->operands[i].operandClass != NONE; i++)
	{
		switch (instruction->operands[i].operandClass)
		{
			case FIMM32:
			case IMM32:
			case IMM64:
			case LABEL:
			case STR_IMM:
				if (get_shifted_immediate(
							&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString),
							instruction->operands[i].operandClass) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case REG:
				if (get_register(
						&instruction->operands[i],
						0,
						tmpOperandString,
						sizeof(tmpOperandString)) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case SYS_REG:
				operand = get_system_register_name((SystemReg)instruction->operands[i].reg[0]);
				if (operand == NULL)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				break;
			case MULTI_REG:
				if (get_multireg_operand(
							&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString)) != DISASM_SUCCESS)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				operand = tmpOperandString;
				break;
			case IMPLEMENTATION_SPECIFIC:
				if (get_implementation_specific(
						&instruction->operands[i],
						tmpOperandString,
						sizeof(tmpOperandString)) != DISASM_SUCCESS)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				operand = tmpOperandString;
				break;
			case MEM_REG:
			case MEM_OFFSET:
			case MEM_EXTENDED:
			case MEM_PRE_IDX:
			case MEM_POST_IDX:
				if (get_memory_operand(&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString)) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case CONDITION:
				if (snprintf(tmpOperandString, sizeof(tmpOperandString), "%s", get_condition((Condition)instruction->operands[i].reg[0])) < 0)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case NAME:
				operand = instruction->operands[i].name;
				break;
			case NONE:
				break;
		}
		snprintf(operandStrings[i], sizeof(operandStrings[i]), i==0?"\t%s":", %s", operand);
	}
	memset(buf, 0, buf_sz);
	if (snprintf(buf, buf_sz, "%s%s%s%s%s%s",
			get_operation(instruction),
			operandStrings[0],
			operandStrings[1],
			operandStrings[2],
			operandStrings[3],
			operandStrings[4]) < 0)
		return OUTPUT_BUFFER_TOO_SMALL;
	return DISASM_SUCCESS;
}

void print_instruction(Instruction *instr)
{
	//printf("print_instruction (TODO)\n");
}
