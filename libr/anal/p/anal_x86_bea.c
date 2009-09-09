/* radare - LGPL - Copyright 2009 - nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_anal.h>

#include "x86/bea/BeaEngine.h"


static int aop(struct r_anal_t *anal, struct r_anal_aop_t *aop, void *data)
{
	DISASM disasm_obj;
	ARGTYPE *argptr = NULL;
	char category[1024], argtype[1024];
	int i;

	memset(&disasm_obj, '\0', sizeof(DISASM));
	disasm_obj.EIP = (long long)data;
	disasm_obj.VirtualAddr = anal->pc;
	disasm_obj.Archi = ((anal->bits == 64) ? 64 : 0);
	disasm_obj.SecurityBlock = 128;

	memset(aop, 0, sizeof(aop));
	aop->length = Disasm(&disasm_obj);

	IFDBG {
		printf( "[Instruction]\n"
				"  Opcode: %lx\n"
				"  Mnemonic: %s\n"
				"  AddrValue: 0x%llx\n"
				"  Immediate: 0x%llx\n",
				disasm_obj.Instruction.Opcode,
				disasm_obj.Instruction.Mnemonic,
				disasm_obj.Instruction.AddrValue,
				disasm_obj.Instruction.Immediat);
		
		category[0] = '\0';
		if (disasm_obj.Instruction.Category & GENERAL_PURPOSE_INSTRUCTION)
			strcat(category, "GENERAL_PURPOSE_INSTRUCTION ");
		if (disasm_obj.Instruction.Category & FPU_INSTRUCTION) {
			strcat(category, "FPU_INSTRUCTION ");
			aop->family = R_ANAL_AOP_FAMILY_FPU;
		}
		if (disasm_obj.Instruction.Category & MMX_INSTRUCTION) {
			strcat(category, "MMX_INSTRUCTION ");
			aop->family = R_ANAL_AOP_FAMILY_MMX;
		}
		if (disasm_obj.Instruction.Category & SSE_INSTRUCTION) {
			strcat(category, "SSE_INSTRUCTION ");
			aop->family = R_ANAL_AOP_FAMILY_MMX;
		}
		if (disasm_obj.Instruction.Category & SSE2_INSTRUCTION) {
			strcat(category, "SSE2_INSTRUCTION ");
			aop->family = R_ANAL_AOP_FAMILY_MMX;
		}
		if (disasm_obj.Instruction.Category & SSE3_INSTRUCTION) {
			strcat(category, "SSE3_INSTRUCTION ");
			aop->family = R_ANAL_AOP_FAMILY_MMX;
		}
		if (disasm_obj.Instruction.Category & SSSE3_INSTRUCTION) {
			strcat(category, "SSSE3_INSTRUCTION ");
			aop->family = R_ANAL_AOP_FAMILY_MMX;
		}
		if (disasm_obj.Instruction.Category & SSE41_INSTRUCTION) {
			strcat(category, "SSE41_INSTRUCTION ");
			aop->family = R_ANAL_AOP_FAMILY_MMX;
		}
		if (disasm_obj.Instruction.Category & SSE42_INSTRUCTION) {
			strcat(category, "SSE42_INSTRUCTION ");
			aop->family = R_ANAL_AOP_FAMILY_MMX;
		}
		if (disasm_obj.Instruction.Category & SYSTEM_INSTRUCTION)
			strcat(category, "SYSTEM_INSTRUCTION ");
		if (disasm_obj.Instruction.Category & VM_INSTRUCTION)
			strcat(category, "VM_INSTRUCTION ");
		if (disasm_obj.Instruction.Category & UNDOCUMENTED_INSTRUCTION)
			strcat(category, "UNDOCUMENTED_INSTRUCTION ");
		if (disasm_obj.Instruction.Category & AMD_INSTRUCTION)
			strcat(category, "AMD_INSTRUCTION ");
		if (disasm_obj.Instruction.Category & ILLEGAL_INSTRUCTION)
			strcat(category, "ILLEGAL_INSTRUCTION ");
		if (disasm_obj.Instruction.Category & INCOMPATIBLE_TYPE)
			strcat(category, "INCOMPATIBLE_TYPE ");
		disasm_obj.Instruction.Category &= 0xFFFF;

		switch (disasm_obj.Instruction.Category) {
		case DATA_TRANSFER:
			strcat(category, "DATA_TRANSFER ");
			if (argptr && argptr[1].ArgMnemonic[0] == '\0') {
				// PUSH OR POP
			} else {
				// MOV
			}
			break;
		case ARITHMETIC_INSTRUCTION:
			strcat(category, "ARITHMETIC_INSTRUCTION ");
			break;
		case LOGICAL_INSTRUCTION:
			strcat(category, "LOGICAL_INSTRUCTION ");
			break;
		case SHIFT_ROTATE:
			strcat(category, "SHIFT_ROTATE ");
			break;
		case BIT_BYTE:
			strcat(category, "BIT_BYTE ");
			break;
		case CONTROL_TRANSFER:
			strcat(category, "CONTROL_TRANSFER ");
			break;
		case STRING_INSTRUCTION:
			strcat(category, "STRING_INSTRUCTION ");
			break;
		case InOutINSTRUCTION:
			strcat(category, "InOutINSTRUCTION ");
			break;
		case ENTER_LEAVE_INSTRUCTION:
			strcat(category, "ENTER_LEAVE_INSTRUCTION ");
			break;
		case FLAG_CONTROL_INSTRUCTION:
			strcat(category, "FLAG_CONTROL_INSTRUCTION ");
			break;
		case SEGMENT_REGISTER:
			strcat(category, "SEGMENT_REGISTER ");
			break;
		case MISCELLANEOUS_INSTRUCTION:
			strcat(category, "MISCELLANEOUS_INSTRUCTION ");
			break;
		case COMPARISON_INSTRUCTION:
			strcat(category, "COMPARISON_INSTRUCTION ");
			break;
		case LOGARITHMIC_INSTRUCTION:
			strcat(category, "LOGARITHMIC_INSTRUCTION ");
			break;
		case TRIGONOMETRIC_INSTRUCTION:
			strcat(category, "TRIGONOMETRIC_INSTRUCTION ");
			break;
		case UNSUPPORTED_INSTRUCTION:
			strcat(category, "UNSUPPORTED_INSTRUCTION ");
			break;
		case LOAD_CONSTANTS:
			strcat(category, "LOAD_CONSTANTS ");
			break;
		case FPUCONTROL:
			strcat(category, "FPUCONTROL ");
			break;
		case STATE_MANAGEMENT:
			strcat(category, "STATE_MANAGEMENT ");
			break;
		case CONVERSION_INSTRUCTION:
			strcat(category, "CONVERSION_INSTRUCTION ");
			break;
		case SHUFFLE_UNPACK:
			strcat(category, "SHUFFLE_UNPACK ");
			break;
		case PACKED_SINGLE_PRECISION:
			strcat(category, "PACKED_SINGLE_PRECISION ");
			break;
		case SIMD128bits:
			strcat(category, "SIMD128bits ");
			break;
		case SIMD64bits:
			strcat(category, "SIMD64bits ");
			break;
		case CACHEABILITY_CONTROL:
			strcat(category, "CACHEABILITY_CONTROL ");
			break;
		case FP_INTEGER_CONVERSION:
			strcat(category, "FP_INTEGER_CONVERSION ");
			aop->family = R_ANAL_AOP_FAMILY_FPU;
			break;
		case SPECIALIZED_128bits:
			strcat(category, "SPECIALIZED_128bits ");
			break;
		case SIMD_FP_PACKED:
			strcat(category, "SIMD_FP_PACKED ");
			break;
		case SIMD_FP_HORIZONTAL :
			strcat(category, "SIMD_FP_HORIZONTAL  ");
			break;
		case AGENT_SYNCHRONISATION:
			strcat(category, "AGENT_SYNCHRONISATION ");
			break;
		case PACKED_ALIGN_RIGHT  :
			strcat(category, "PACKED_ALIGN_RIGHT   ");
			break;
		case PACKED_SIGN:
			strcat(category, "PACKED_SIGN ");
			break;
		case PACKED_BLENDING_INSTRUCTION:
			strcat(category, "PACKED_BLENDING_INSTRUCTION ");
			break;
		case PACKED_TEST:
			strcat(category, "PACKED_TEST ");
			break;
		case PACKED_MINMAX:
			strcat(category, "PACKED_MINMAX ");
			break;
		case HORIZONTAL_SEARCH:
			strcat(category, "HORIZONTAL_SEARCH ");
			break;
		case PACKED_EQUALITY:
			strcat(category, "PACKED_EQUALITY ");
			break;
		case STREAMING_LOAD:
			strcat(category, "STREAMING_LOAD ");
			break;
		case INSERTION_EXTRACTION:
			strcat(category, "INSERTION_EXTRACTION ");
			break;
		case DOT_PRODUCT:
			strcat(category, "DOT_PRODUCT ");
			break;
		case SAD_INSTRUCTION:
			strcat(category, "SAD_INSTRUCTION ");
			break;
		case ACCELERATOR_INSTRUCTION:
			strcat(category, "ACCELERATOR_INSTRUCTION ");
			break;
		case ROUND_INSTRUCTION:
			strcat(category, "ROUND_INSTRUCTION ");
			break;
		default:
			strcat(category, "UNKNOWN_INSTRUCTION ");
		}
		printf("  Category: %s\n", category);

		switch (disasm_obj.Instruction.BranchType) {
		case JO:
		case JC:
		case JE:
		case JA:
		case JS:
		case JP:
		case JL:
		case JG:
		case JB:
		case JNO:
		case JNC:
		case JNE:
		case JNA:
		case JNS:
		case JNP:
		case JNL:
		case JNG:
		case JNB:
		case JECXZ:
			aop->type = R_ANAL_AOP_TYPE_CJMP;
			aop->jump = disasm_obj.Instruction.AddrValue;
			aop->fail = disasm_obj.Instruction.AddrValue + aop->length;
			printf("  BranchType: JO\n");
			break;
		case JmpType:
			aop->type = R_ANAL_AOP_TYPE_JMP;
			aop->jump = disasm_obj.Instruction.AddrValue;
			printf("  BranchType: JmpType\n");
			break;
		case CallType:
			aop->type = R_ANAL_AOP_TYPE_CALL;
			aop->jump = disasm_obj.Instruction.AddrValue;
			aop->fail = disasm_obj.Instruction.AddrValue + aop->length;
			printf("  BranchType: CallType\n");
			break;
		case RetType:
			aop->type = R_ANAL_AOP_TYPE_RET;
			printf("  BranchType: RetType\n");
			break;
		default:
			printf("  BranchType: Unknown (0x%lx)\n", disasm_obj.Instruction.BranchType);
		}


		for(argptr = &disasm_obj.Argument1, i = 0; i< 3; i++) {
			if (argptr[i].ArgMnemonic[0] == '\0')
				continue;

			printf( "[ARG%i]\n"
					"  Mnemonic: %s\n"
					"  ArgSize: 0x%lx\n"
					"  BaseRegister: 0x%lx\n"
					"  IndexRegister: 0x%lx\n"
					"  Scale: 0x%lx\n"
					"  Displacement: 0x%llx\n"
					"  SegmentReg: 0x%lx\n",
					i + 1,
					argptr[i].ArgMnemonic,
					argptr[i].ArgSize,
					argptr[i].Memory.BaseRegister,
					argptr[i].Memory.IndexRegister,
					argptr[i].Memory.Scale,
					argptr[i].Memory.Displacement,
					argptr[i].SegmentReg
				  );

			printf("  AccesMode: ");
			if (argptr[i].AccessMode == 0x1)
				printf("READ\n");
			else if (argptr[i].AccessMode == 0x2)
				printf("WRITE\n");
			else printf("UNKNOWN\n");

			argtype[0] = '\0';
			if (argptr[i].ArgType & NO_ARGUMENT)
				strcat(argtype, "NO_ARGUMENT ");
			if (argptr[i].ArgType & REGISTER_TYPE)
				strcat(argtype, "REGISTER_TYPE ");
			if (argptr[i].ArgType & MEMORY_TYPE)
				strcat(argtype, "MEMORY_TYPE ");
			if (argptr[i].ArgType & CONSTANT_TYPE)
				strcat(argtype, "CONSTANT_TYPE ");
			if (argptr[i].ArgType & MMX_REG) {
				aop->family = R_ANAL_AOP_FAMILY_MMX;
				strcat(argtype, "MMX_REG ");
			}
			if (argptr[i].ArgType & GENERAL_REG)
				strcat(argtype, "GENERAL_REG ");
			if (argptr[i].ArgType & FPU_REG) {
				aop->family = R_ANAL_AOP_FAMILY_FPU;
				strcat(argtype, "FPU_REG ");
			}
			if (argptr[i].ArgType & SSE_REG) {
				aop->family = R_ANAL_AOP_FAMILY_MMX;
				strcat(argtype, "SSE_REG ");
			}
			if (argptr[i].ArgType & CR_REG)
				strcat(argtype, "CR_REG ");
			if (argptr[i].ArgType & DR_REG)
				strcat(argtype, "DR_REG ");
			if (argptr[i].ArgType & SPECIAL_REG)
				strcat(argtype, "SPECIAL_REG ");
			if (argptr[i].ArgType & MEMORY_MANAGEMENT_REG)
				strcat(argtype, "MEMORY_MANAGEMENT_REG ");
			if (argptr[i].ArgType & SEGMENT_REG)
				strcat(argtype, "SEGMENT_REG ");
			if (argptr[i].ArgType & RELATIVE_)
				strcat(argtype, "RELATIVE_ ");
			if (argptr[i].ArgType & ABSOLUTE_)
				strcat(argtype, "ABSOLUTE_ ");
			if (argptr[i].ArgType & REG0)
				strcat(argtype, "REG0 ");
			if (argptr[i].ArgType & REG1)
				strcat(argtype, "REG1 ");
			if (argptr[i].ArgType & REG2)
				strcat(argtype, "REG2 ");
			if (argptr[i].ArgType & REG3)
				strcat(argtype, "REG3 ");
			if (argptr[i].ArgType & REG4)
				strcat(argtype, "REG4 ");
			if (argptr[i].ArgType & REG5)
				strcat(argtype, "REG5 ");
			if (argptr[i].ArgType & REG6)
				strcat(argtype, "REG6 ");
			if (argptr[i].ArgType & REG7)
				strcat(argtype, "REG7 ");
			if (argptr[i].ArgType & REG8)
				strcat(argtype, "REG8 ");
			if (argptr[i].ArgType & REG9)
				strcat(argtype, "REG9 ");
			if (argptr[i].ArgType & REG10)
				strcat(argtype, "REG10 ");
			if (argptr[i].ArgType & REG11)
				strcat(argtype, "REG11 ");
			if (argptr[i].ArgType & REG12)
				strcat(argtype, "REG12 ");
			if (argptr[i].ArgType & REG13)
				strcat(argtype, "REG13 ");
			if (argptr[i].ArgType & REG14)
				strcat(argtype, "REG14 ");
			if (argptr[i].ArgType & REG15)
				strcat(argtype, "REG15 ");
			printf("  ArgType: %s\n", argtype);
		}

		printf("\n");
	}
	printf("InternalAOP:\n");
	printf("Type: %d\n", aop->type);
	printf("EOB: %d\n", aop->eob);
	printf("Family: %d\n", aop->family);
	printf("Stackop: %d\n", aop->stackop);
	printf("True: 0x%08llx\n", aop->jump);
	printf("Fail: 0x%08llx\n", aop->fail);

	return aop->length;
}

static struct r_anal_handle_t r_anal_plugin_x86_bea = {
	.name = R_ANAL_NAME("x86_bea"),
	.desc = "X86 analysis plugin (Bea engine)",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_bea
};
