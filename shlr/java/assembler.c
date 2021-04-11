// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "assembler.h"
#include "bytecode.h"
#include "const.h"

#define return_error_if_size_lt(a, b) \
	do { \
		if (a < b) { \
			R_LOG_ERROR("[!] java_assembler: no enough output buffer (requires %d bytes).\n", b); \
			return false; \
		} \
	} while (0)

#define return_error_if_empty_input(a, b) \
	do { \
		if (R_STR_ISEMPTY(a) || b < 1) { \
			R_LOG_ERROR("[!] java_assembler: the input is empty.\n"); \
			return false; \
		} \
	} while (0)

typedef bool (*AsmEncoder)(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written);

typedef struct _jasm {
	const char *opcode;
	st32 length;
	ut8 bytecode;
	AsmEncoder encode;
} JavaAsm;

static bool encode_not_implemented(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	R_LOG_ERROR("[!] java_assembler: not implemented.\n");
	return false;
}

static bool encode_only_bcode(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 1);

	*written = 1;
	output[0] = bytecode;
	return true;
}

static bool encode_st8(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 2);
	return_error_if_empty_input(input, input_size);

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between %d and %d (inclusive).\n", input, INT8_MIN, INT8_MAX);
		return false;
	}

	*written = 2;
	output[0] = bytecode;
	((st8 *)output)[1] = (st8)strtoll(input, NULL, 0);
	return true;
}

static bool encode_ut8(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 2);
	return_error_if_empty_input(input, input_size);

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between %d and %d (inclusive).\n", input, INT8_MIN, INT8_MAX);
		return false;
	}

	*written = 2;
	output[0] = bytecode;
	output[1] = (ut8)strtoll(input, NULL, 0);
	return true;
}

static bool encode_addr32(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 5);
	return_error_if_empty_input(input, input_size);

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between %d and %d (inclusive).\n", input, INT16_MIN, INT16_MAX);
		return false;
	}

	*written = 5;
	output[0] = bytecode;
	st64 n = strtoll(input, NULL, 0);
	st32 addr = n - pc;
	r_write_be32(output + 1, addr);
	return true;
}

static bool encode_addr16(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 3);
	return_error_if_empty_input(input, input_size);

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between %d and %d (inclusive).\n", input, INT16_MIN, INT16_MAX);
		return false;
	}

	*written = 3;
	output[0] = bytecode;
	st64 n = strtoll(input, NULL, 0);
	st16 addr = n - pc;
	r_write_be16(output + 1, addr);
	return true;
}

static bool encode_st16(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 3);
	return_error_if_empty_input(input, input_size);

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between %d and %d (inclusive).\n", input, INT16_MIN, INT16_MAX);
		return false;
	}

	*written = 3;
	output[0] = bytecode;
	st16 n = strtoll(input, NULL, 0);
	r_write_be16(output + 1, n);
	return true;
}

static bool encode_const_pool8(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 2);
	return_error_if_empty_input(input, input_size);

	ut32 cpool_len = strlen(JAVA_ASM_CONSTANT_POOL_STR);
	if (!strncmp(input, JAVA_ASM_CONSTANT_POOL_STR, cpool_len)) {
		input += cpool_len;
	}

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between 0 and %u (inclusive).\n", input, UINT8_MAX);
		return false;
	}

	*written = 2;
	output[0] = bytecode;
	output[1] = (ut8)strtoll(input, NULL, 0);
	return true;
}

static bool encode_const_pool16(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 3);
	return_error_if_empty_input(input, input_size);

	ut32 cpool_len = strlen(JAVA_ASM_CONSTANT_POOL_STR);
	if (!strncmp(input, JAVA_ASM_CONSTANT_POOL_STR, cpool_len)) {
		input += cpool_len;
	}

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between 0 and %u (inclusive).\n", input, UINT16_MAX);
		return false;
	}

	*written = 3;
	output[0] = bytecode;
	ut16 n = (ut16)strtoll(input, NULL, 0);
	r_write_be16(output + 1, n);
	return true;
}

static bool encode_const_pool16_ut8(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 4);
	return_error_if_empty_input(input, input_size);

	ut32 cpool_len = strlen(JAVA_ASM_CONSTANT_POOL_STR);
	if (!strncmp(input, JAVA_ASM_CONSTANT_POOL_STR, cpool_len)) {
		input += cpool_len;
	}

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between 0 and %u (inclusive).\n", input, UINT16_MAX);
		return false;
	}

	const char *next = NULL;
	char *tmp = NULL;
	ut16 cpool = (ut16)strtoll(input, &tmp, 0);
	if (!tmp || tmp == (input + input_size) || !(next = r_str_trim_head_ro(tmp))) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between 0 and %u (inclusive).\n", tmp, UINT8_MAX);
	}

	if (!r_is_valid_input_num_value(NULL, next)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between 0 and %u (inclusive).\n", input, UINT8_MAX);
		return false;
	}
	ut8 num = (ut8)strtoll(next, NULL, 0);

	*written = 4;
	output[0] = bytecode;
	r_write_be16(output + 1, cpool);
	output[3] = num;
	return true;
}

static bool encode_ut8x2(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 3);
	return_error_if_empty_input(input, input_size);

	if (!r_is_valid_input_num_value(NULL, input)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between 0 and %u (inclusive).\n", input, UINT8_MAX);
		return false;
	}

	const char *next = NULL;
	char *tmp = NULL;
	ut16 arg0 = (ut16)strtoll(input, &tmp, 0);
	if (!tmp || tmp == (input + input_size) || !(next = r_str_trim_head_ro(tmp))) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between 0 and %u (inclusive).\n", tmp, UINT8_MAX);
	}

	if (!r_is_valid_input_num_value(NULL, next)) {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid number between 0 and %u (inclusive).\n", input, UINT8_MAX);
		return false;
	}
	ut8 arg1 = (ut8)strtoll(next, NULL, 0);

	*written = 3;
	output[0] = bytecode;
	output[1] = arg0;
	output[2] = arg1;
	return true;
}

static bool encode_atype(ut8 bytecode, const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	return_error_if_size_lt(output_size, 2);
	return_error_if_empty_input(input, input_size);

	ut8 byte = 0;
	/* bool 4, char 5, float 6, double 7, byte 8, short 9, int 10, long 11 */
	if (!strncmp(input, "bool", strlen("bool"))) {
		byte = 4;
	} else if (!strncmp(input, "char", strlen("char"))) {
		byte = 5;
	} else if (!strncmp(input, "float", strlen("float"))) {
		byte = 6;
	} else if (!strncmp(input, "double", strlen("double"))) {
		byte = 7;
	} else if (!strncmp(input, "byte", strlen("byte"))) {
		byte = 8;
	} else if (!strncmp(input, "short", strlen("short"))) {
		byte = 9;
	} else if (!strncmp(input, "int", strlen("int"))) {
		byte = 10;
	} else if (!strncmp(input, "long", strlen("long"))) {
		byte = 11;
	} else {
		R_LOG_ERROR("[!] java_assembler: '%s' is not a valid native type (accepted: bool, char, float, double, byte, short, int, long).\n", input);
		return false;
	}

	*written = 2;
	output[0] = bytecode;
	output[1] = byte;
	return true;
}

#define NS(x) x, (sizeof(x) - 1)
static const JavaAsm instructions[205] = {
	{ NS("wide") /*           */, BYTECODE_C4_WIDE /*           */, encode_only_bcode },
	{ NS("tableswitch") /*    */, BYTECODE_AA_TABLESWITCH /*    */, encode_not_implemented },
	{ NS("swap") /*           */, BYTECODE_5F_SWAP /*           */, encode_only_bcode },
	{ NS("sipush") /*         */, BYTECODE_11_SIPUSH /*         */, encode_st16 },
	{ NS("sastore") /*        */, BYTECODE_56_SASTORE /*        */, encode_only_bcode },
	{ NS("saload") /*         */, BYTECODE_35_SALOAD /*         */, encode_only_bcode },
	{ NS("return") /*         */, BYTECODE_B1_RETURN /*         */, encode_only_bcode },
	{ NS("ret") /*            */, BYTECODE_A9_RET /*            */, encode_ut8 },
	{ NS("putstatic") /*      */, BYTECODE_B3_PUTSTATIC /*      */, encode_const_pool16 },
	{ NS("putfield") /*       */, BYTECODE_B5_PUTFIELD /*       */, encode_const_pool16 },
	{ NS("pop2") /*           */, BYTECODE_58_POP2 /*           */, encode_only_bcode },
	{ NS("pop") /*            */, BYTECODE_57_POP /*            */, encode_only_bcode },
	{ NS("nop") /*            */, BYTECODE_00_NOP /*            */, encode_only_bcode },
	{ NS("newarray") /*       */, BYTECODE_BC_NEWARRAY /*       */, encode_atype },
	{ NS("new") /*            */, BYTECODE_BB_NEW /*            */, encode_const_pool16 },
	{ NS("multianewarray") /* */, BYTECODE_C5_MULTIANEWARRAY /* */, encode_const_pool16_ut8 },
	{ NS("monitorexit") /*    */, BYTECODE_C3_MONITOREXIT /*    */, encode_only_bcode },
	{ NS("monitorenter") /*   */, BYTECODE_C2_MONITORENTER /*   */, encode_only_bcode },
	{ NS("lxor") /*           */, BYTECODE_83_LXOR /*           */, encode_only_bcode },
	{ NS("lushr") /*          */, BYTECODE_7D_LUSHR /*          */, encode_only_bcode },
	{ NS("lsub") /*           */, BYTECODE_65_LSUB /*           */, encode_only_bcode },
	{ NS("lstore_3") /*       */, BYTECODE_42_LSTORE_3 /*       */, encode_only_bcode },
	{ NS("lstore_2") /*       */, BYTECODE_41_LSTORE_2 /*       */, encode_only_bcode },
	{ NS("lstore_1") /*       */, BYTECODE_40_LSTORE_1 /*       */, encode_only_bcode },
	{ NS("lstore_0") /*       */, BYTECODE_3F_LSTORE_0 /*       */, encode_only_bcode },
	{ NS("lstore") /*         */, BYTECODE_37_LSTORE /*         */, encode_ut8 },
	{ NS("lshr") /*           */, BYTECODE_7B_LSHR /*           */, encode_only_bcode },
	{ NS("lshl") /*           */, BYTECODE_79_LSHL /*           */, encode_only_bcode },
	{ NS("lreturn") /*        */, BYTECODE_AD_LRETURN /*        */, encode_only_bcode },
	{ NS("lrem") /*           */, BYTECODE_71_LREM /*           */, encode_only_bcode },
	{ NS("lor") /*            */, BYTECODE_81_LOR /*            */, encode_only_bcode },
	{ NS("lookupswitch") /*   */, BYTECODE_AB_LOOKUPSWITCH /*   */, encode_not_implemented },
	{ NS("lneg") /*           */, BYTECODE_75_LNEG /*           */, encode_only_bcode },
	{ NS("lmul") /*           */, BYTECODE_69_LMUL /*           */, encode_only_bcode },
	{ NS("lload_3") /*        */, BYTECODE_21_LLOAD_3 /*        */, encode_only_bcode },
	{ NS("lload_2") /*        */, BYTECODE_20_LLOAD_2 /*        */, encode_only_bcode },
	{ NS("lload_1") /*        */, BYTECODE_1F_LLOAD_1 /*        */, encode_only_bcode },
	{ NS("lload_0") /*        */, BYTECODE_1E_LLOAD_0 /*        */, encode_only_bcode },
	{ NS("lload") /*          */, BYTECODE_16_LLOAD /*          */, encode_ut8 },
	{ NS("ldiv") /*           */, BYTECODE_6D_LDIV /*           */, encode_only_bcode },
	{ NS("ldc_w") /*          */, BYTECODE_13_LDC_W /*          */, encode_const_pool16 },
	{ NS("ldc2_w") /*         */, BYTECODE_14_LDC2_W /*         */, encode_const_pool16 },
	{ NS("ldc") /*            */, BYTECODE_12_LDC /*            */, encode_const_pool8 },
	{ NS("lconst_1") /*       */, BYTECODE_0A_LCONST_1 /*       */, encode_only_bcode },
	{ NS("lconst_0") /*       */, BYTECODE_09_LCONST_0 /*       */, encode_only_bcode },
	{ NS("lcmp") /*           */, BYTECODE_94_LCMP /*           */, encode_only_bcode },
	{ NS("lastore") /*        */, BYTECODE_50_LASTORE /*        */, encode_only_bcode },
	{ NS("land") /*           */, BYTECODE_7F_LAND /*           */, encode_only_bcode },
	{ NS("laload") /*         */, BYTECODE_2F_LALOAD /*         */, encode_only_bcode },
	{ NS("ladd") /*           */, BYTECODE_61_LADD /*           */, encode_only_bcode },
	{ NS("l2i") /*            */, BYTECODE_88_L2I /*            */, encode_only_bcode },
	{ NS("l2f") /*            */, BYTECODE_89_L2F /*            */, encode_only_bcode },
	{ NS("l2d") /*            */, BYTECODE_8A_L2D /*            */, encode_only_bcode },
	{ NS("jsr_w") /*          */, BYTECODE_C9_JSR_W /*          */, encode_addr32 },
	{ NS("jsr") /*            */, BYTECODE_A8_JSR /*            */, encode_addr16 },
	{ NS("ixor") /*           */, BYTECODE_82_IXOR /*           */, encode_only_bcode },
	{ NS("iushr") /*          */, BYTECODE_7C_IUSHR /*          */, encode_only_bcode },
	{ NS("isub") /*           */, BYTECODE_64_ISUB /*           */, encode_only_bcode },
	{ NS("istore_3") /*       */, BYTECODE_3E_ISTORE_3 /*       */, encode_only_bcode },
	{ NS("istore_2") /*       */, BYTECODE_3D_ISTORE_2 /*       */, encode_only_bcode },
	{ NS("istore_1") /*       */, BYTECODE_3C_ISTORE_1 /*       */, encode_only_bcode },
	{ NS("istore_0") /*       */, BYTECODE_3B_ISTORE_0 /*       */, encode_only_bcode },
	{ NS("istore") /*         */, BYTECODE_36_ISTORE /*         */, encode_ut8 },
	{ NS("ishr") /*           */, BYTECODE_7A_ISHR /*           */, encode_only_bcode },
	{ NS("ishl") /*           */, BYTECODE_78_ISHL /*           */, encode_only_bcode },
	{ NS("ireturn") /*        */, BYTECODE_AC_IRETURN /*        */, encode_only_bcode },
	{ NS("irem") /*           */, BYTECODE_70_IREM /*           */, encode_only_bcode },
	{ NS("ior") /*            */, BYTECODE_80_IOR /*            */, encode_only_bcode },
	{ NS("invokevirtual") /*  */, BYTECODE_B6_INVOKEVIRTUAL /*  */, encode_const_pool16 },
	{ NS("invokestatic") /*   */, BYTECODE_B8_INVOKESTATIC /*   */, encode_const_pool16 },
	{ NS("invokespecial") /*  */, BYTECODE_B7_INVOKESPECIAL /*  */, encode_const_pool16 },
	{ NS("invokeinterface") /**/, BYTECODE_B9_INVOKEINTERFACE /**/, encode_const_pool16_ut8 },
	{ NS("invokedynamic") /*  */, BYTECODE_BA_INVOKEDYNAMIC /*  */, encode_const_pool16_ut8 },
	{ NS("instanceof") /*     */, BYTECODE_C1_INSTANCEOF /*     */, encode_const_pool16 },
	{ NS("ineg") /*           */, BYTECODE_74_INEG /*           */, encode_only_bcode },
	{ NS("imul") /*           */, BYTECODE_68_IMUL /*           */, encode_only_bcode },
	{ NS("impdep2") /*        */, BYTECODE_FF_IMPDEP2 /*        */, encode_only_bcode },
	{ NS("impdep1") /*        */, BYTECODE_FE_IMPDEP1 /*        */, encode_only_bcode },
	{ NS("iload_3") /*        */, BYTECODE_1D_ILOAD_3 /*        */, encode_only_bcode },
	{ NS("iload_2") /*        */, BYTECODE_1C_ILOAD_2 /*        */, encode_only_bcode },
	{ NS("iload_1") /*        */, BYTECODE_1B_ILOAD_1 /*        */, encode_only_bcode },
	{ NS("iload_0") /*        */, BYTECODE_1A_ILOAD_0 /*        */, encode_only_bcode },
	{ NS("iload") /*          */, BYTECODE_15_ILOAD /*          */, encode_ut8 },
	{ NS("iinc") /*           */, BYTECODE_84_IINC /*           */, encode_ut8x2 },
	{ NS("ifnull") /*         */, BYTECODE_C6_IFNULL /*         */, encode_addr16 },
	{ NS("ifnonnull") /*      */, BYTECODE_C7_IFNONNULL /*      */, encode_addr16 },
	{ NS("ifne") /*           */, BYTECODE_9A_IFNE /*           */, encode_addr16 },
	{ NS("iflt") /*           */, BYTECODE_9B_IFLT /*           */, encode_addr16 },
	{ NS("ifle") /*           */, BYTECODE_9E_IFLE /*           */, encode_addr16 },
	{ NS("ifgt") /*           */, BYTECODE_9D_IFGT /*           */, encode_addr16 },
	{ NS("ifge") /*           */, BYTECODE_9C_IFGE /*           */, encode_addr16 },
	{ NS("ifeq") /*           */, BYTECODE_99_IFEQ /*           */, encode_addr16 },
	{ NS("if_icmpne") /*      */, BYTECODE_A0_IF_ICMPNE /*      */, encode_addr16 },
	{ NS("if_icmplt") /*      */, BYTECODE_A1_IF_ICMPLT /*      */, encode_addr16 },
	{ NS("if_icmple") /*      */, BYTECODE_A4_IF_ICMPLE /*      */, encode_addr16 },
	{ NS("if_icmpgt") /*      */, BYTECODE_A3_IF_ICMPGT /*      */, encode_addr16 },
	{ NS("if_icmpge") /*      */, BYTECODE_A2_IF_ICMPGE /*      */, encode_addr16 },
	{ NS("if_icmpeq") /*      */, BYTECODE_9F_IF_ICMPEQ /*      */, encode_addr16 },
	{ NS("if_acmpne") /*      */, BYTECODE_A6_IF_ACMPNE /*      */, encode_addr16 },
	{ NS("if_acmpeq") /*      */, BYTECODE_A5_IF_ACMPEQ /*      */, encode_addr16 },
	{ NS("idiv") /*           */, BYTECODE_6C_IDIV /*           */, encode_only_bcode },
	{ NS("iconst_m1") /*      */, BYTECODE_02_ICONST_M1 /*      */, encode_only_bcode },
	{ NS("iconst_5") /*       */, BYTECODE_08_ICONST_5 /*       */, encode_only_bcode },
	{ NS("iconst_4") /*       */, BYTECODE_07_ICONST_4 /*       */, encode_only_bcode },
	{ NS("iconst_3") /*       */, BYTECODE_06_ICONST_3 /*       */, encode_only_bcode },
	{ NS("iconst_2") /*       */, BYTECODE_05_ICONST_2 /*       */, encode_only_bcode },
	{ NS("iconst_1") /*       */, BYTECODE_04_ICONST_1 /*       */, encode_only_bcode },
	{ NS("iconst_0") /*       */, BYTECODE_03_ICONST_0 /*       */, encode_only_bcode },
	{ NS("iastore") /*        */, BYTECODE_4F_IASTORE /*        */, encode_only_bcode },
	{ NS("iand") /*           */, BYTECODE_7E_IAND /*           */, encode_only_bcode },
	{ NS("iaload") /*         */, BYTECODE_2E_IALOAD /*         */, encode_only_bcode },
	{ NS("iadd") /*           */, BYTECODE_60_IADD /*           */, encode_only_bcode },
	{ NS("i2s") /*            */, BYTECODE_93_I2S /*            */, encode_only_bcode },
	{ NS("i2l") /*            */, BYTECODE_85_I2L /*            */, encode_only_bcode },
	{ NS("i2f") /*            */, BYTECODE_86_I2F /*            */, encode_only_bcode },
	{ NS("i2d") /*            */, BYTECODE_87_I2D /*            */, encode_only_bcode },
	{ NS("i2c") /*            */, BYTECODE_92_I2C /*            */, encode_only_bcode },
	{ NS("i2b") /*            */, BYTECODE_91_I2B /*            */, encode_only_bcode },
	{ NS("goto_w") /*         */, BYTECODE_C8_GOTO_W /*         */, encode_addr32 },
	{ NS("goto") /*           */, BYTECODE_A7_GOTO /*           */, encode_addr16 },
	{ NS("getstatic") /*      */, BYTECODE_B2_GETSTATIC /*      */, encode_const_pool16 },
	{ NS("getfield") /*       */, BYTECODE_B4_GETFIELD /*       */, encode_const_pool16 },
	{ NS("fsub") /*           */, BYTECODE_66_FSUB /*           */, encode_only_bcode },
	{ NS("fstore_3") /*       */, BYTECODE_46_FSTORE_3 /*       */, encode_only_bcode },
	{ NS("fstore_2") /*       */, BYTECODE_45_FSTORE_2 /*       */, encode_only_bcode },
	{ NS("fstore_1") /*       */, BYTECODE_44_FSTORE_1 /*       */, encode_only_bcode },
	{ NS("fstore_0") /*       */, BYTECODE_43_FSTORE_0 /*       */, encode_only_bcode },
	{ NS("fstore") /*         */, BYTECODE_38_FSTORE /*         */, encode_ut8 },
	{ NS("freturn") /*        */, BYTECODE_AE_FRETURN /*        */, encode_only_bcode },
	{ NS("frem") /*           */, BYTECODE_72_FREM /*           */, encode_only_bcode },
	{ NS("fneg") /*           */, BYTECODE_76_FNEG /*           */, encode_only_bcode },
	{ NS("fmul") /*           */, BYTECODE_6A_FMUL /*           */, encode_only_bcode },
	{ NS("fload_3") /*        */, BYTECODE_25_FLOAD_3 /*        */, encode_only_bcode },
	{ NS("fload_2") /*        */, BYTECODE_24_FLOAD_2 /*        */, encode_only_bcode },
	{ NS("fload_1") /*        */, BYTECODE_23_FLOAD_1 /*        */, encode_only_bcode },
	{ NS("fload_0") /*        */, BYTECODE_22_FLOAD_0 /*        */, encode_only_bcode },
	{ NS("fload") /*          */, BYTECODE_17_FLOAD /*          */, encode_ut8 },
	{ NS("fdiv") /*           */, BYTECODE_6E_FDIV /*           */, encode_only_bcode },
	{ NS("fconst_2") /*       */, BYTECODE_0D_FCONST_2 /*       */, encode_only_bcode },
	{ NS("fconst_1") /*       */, BYTECODE_0C_FCONST_1 /*       */, encode_only_bcode },
	{ NS("fconst_0") /*       */, BYTECODE_0B_FCONST_0 /*       */, encode_only_bcode },
	{ NS("fcmpl") /*          */, BYTECODE_95_FCMPL /*          */, encode_only_bcode },
	{ NS("fcmpg") /*          */, BYTECODE_96_FCMPG /*          */, encode_only_bcode },
	{ NS("fastore") /*        */, BYTECODE_51_FASTORE /*        */, encode_only_bcode },
	{ NS("faload") /*         */, BYTECODE_30_FALOAD /*         */, encode_only_bcode },
	{ NS("fadd") /*           */, BYTECODE_62_FADD /*           */, encode_only_bcode },
	{ NS("f2l") /*            */, BYTECODE_8C_F2L /*            */, encode_only_bcode },
	{ NS("f2i") /*            */, BYTECODE_8B_F2I /*            */, encode_only_bcode },
	{ NS("f2d") /*            */, BYTECODE_8D_F2D /*            */, encode_only_bcode },
	{ NS("dup_x2") /*         */, BYTECODE_5B_DUP_X2 /*         */, encode_only_bcode },
	{ NS("dup_x1") /*         */, BYTECODE_5A_DUP_X1 /*         */, encode_only_bcode },
	{ NS("dup2_x2") /*        */, BYTECODE_5E_DUP2_X2 /*        */, encode_only_bcode },
	{ NS("dup2_x1") /*        */, BYTECODE_5D_DUP2_X1 /*        */, encode_only_bcode },
	{ NS("dup2") /*           */, BYTECODE_5C_DUP2 /*           */, encode_only_bcode },
	{ NS("dup") /*            */, BYTECODE_59_DUP /*            */, encode_only_bcode },
	{ NS("dsub") /*           */, BYTECODE_67_DSUB /*           */, encode_only_bcode },
	{ NS("dstore_3") /*       */, BYTECODE_4A_DSTORE_3 /*       */, encode_only_bcode },
	{ NS("dstore_2") /*       */, BYTECODE_49_DSTORE_2 /*       */, encode_only_bcode },
	{ NS("dstore_1") /*       */, BYTECODE_48_DSTORE_1 /*       */, encode_only_bcode },
	{ NS("dstore_0") /*       */, BYTECODE_47_DSTORE_0 /*       */, encode_only_bcode },
	{ NS("dstore") /*         */, BYTECODE_39_DSTORE /*         */, encode_ut8 },
	{ NS("dreturn") /*        */, BYTECODE_AF_DRETURN /*        */, encode_only_bcode },
	{ NS("drem") /*           */, BYTECODE_73_DREM /*           */, encode_only_bcode },
	{ NS("dneg") /*           */, BYTECODE_77_DNEG /*           */, encode_only_bcode },
	{ NS("dmul") /*           */, BYTECODE_6B_DMUL /*           */, encode_only_bcode },
	{ NS("dload_3") /*        */, BYTECODE_29_DLOAD_3 /*        */, encode_only_bcode },
	{ NS("dload_2") /*        */, BYTECODE_28_DLOAD_2 /*        */, encode_only_bcode },
	{ NS("dload_1") /*        */, BYTECODE_27_DLOAD_1 /*        */, encode_only_bcode },
	{ NS("dload_0") /*        */, BYTECODE_26_DLOAD_0 /*        */, encode_only_bcode },
	{ NS("dload") /*          */, BYTECODE_18_DLOAD /*          */, encode_ut8 },
	{ NS("ddiv") /*           */, BYTECODE_6F_DDIV /*           */, encode_only_bcode },
	{ NS("dconst_1") /*       */, BYTECODE_0F_DCONST_1 /*       */, encode_only_bcode },
	{ NS("dconst_0") /*       */, BYTECODE_0E_DCONST_0 /*       */, encode_only_bcode },
	{ NS("dcmpl") /*          */, BYTECODE_97_DCMPL /*          */, encode_only_bcode },
	{ NS("dcmpg") /*          */, BYTECODE_98_DCMPG /*          */, encode_only_bcode },
	{ NS("dastore") /*        */, BYTECODE_52_DASTORE /*        */, encode_only_bcode },
	{ NS("daload") /*         */, BYTECODE_31_DALOAD /*         */, encode_only_bcode },
	{ NS("dadd") /*           */, BYTECODE_63_DADD /*           */, encode_only_bcode },
	{ NS("d2l") /*            */, BYTECODE_8F_D2L /*            */, encode_only_bcode },
	{ NS("d2i") /*            */, BYTECODE_8E_D2I /*            */, encode_only_bcode },
	{ NS("d2f") /*            */, BYTECODE_90_D2F /*            */, encode_only_bcode },
	{ NS("checkcast") /*      */, BYTECODE_C0_CHECKCAST /*      */, encode_const_pool16 },
	{ NS("castore") /*        */, BYTECODE_55_CASTORE /*        */, encode_only_bcode },
	{ NS("caload") /*         */, BYTECODE_34_CALOAD /*         */, encode_only_bcode },
	{ NS("breakpoint") /*     */, BYTECODE_CA_BREAKPOINT /*     */, encode_only_bcode },
	{ NS("bipush") /*         */, BYTECODE_10_BIPUSH /*         */, encode_st8 },
	{ NS("bastore") /*        */, BYTECODE_54_BASTORE /*        */, encode_only_bcode },
	{ NS("baload") /*         */, BYTECODE_33_BALOAD /*         */, encode_only_bcode },
	{ NS("athrow") /*         */, BYTECODE_BF_ATHROW /*         */, encode_only_bcode },
	{ NS("astore_3") /*       */, BYTECODE_4E_ASTORE_3 /*       */, encode_only_bcode },
	{ NS("astore_2") /*       */, BYTECODE_4D_ASTORE_2 /*       */, encode_only_bcode },
	{ NS("astore_1") /*       */, BYTECODE_4C_ASTORE_1 /*       */, encode_only_bcode },
	{ NS("astore_0") /*       */, BYTECODE_4B_ASTORE_0 /*       */, encode_only_bcode },
	{ NS("astore") /*         */, BYTECODE_3A_ASTORE /*         */, encode_ut8 },
	{ NS("arraylength") /*    */, BYTECODE_BE_ARRAYLENGTH /*    */, encode_only_bcode },
	{ NS("areturn") /*        */, BYTECODE_B0_ARETURN /*        */, encode_only_bcode },
	{ NS("anewarray") /*      */, BYTECODE_BD_ANEWARRAY /*      */, encode_const_pool16 },
	{ NS("aload_3") /*        */, BYTECODE_2D_ALOAD_3 /*        */, encode_only_bcode },
	{ NS("aload_2") /*        */, BYTECODE_2C_ALOAD_2 /*        */, encode_only_bcode },
	{ NS("aload_1") /*        */, BYTECODE_2B_ALOAD_1 /*        */, encode_only_bcode },
	{ NS("aload_0") /*        */, BYTECODE_2A_ALOAD_0 /*        */, encode_only_bcode },
	{ NS("aload") /*          */, BYTECODE_19_ALOAD /*          */, encode_ut8 },
	{ NS("aconst_null") /*    */, BYTECODE_01_ACONST_NULL /*    */, encode_only_bcode },
	{ NS("aastore") /*        */, BYTECODE_53_AASTORE /*        */, encode_only_bcode },
	{ NS("aaload") /*         */, BYTECODE_32_AALOAD /*         */, encode_only_bcode }
};
#undef NS

R_API bool r_java_assemblerz(const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written) {
	r_return_val_if_fail(input && output && input_size > 0 && output_size > 0, false);

	for (ut32 i = 0; i < R_ARRAY_SIZE(instructions); ++i) {
		if (input_size < instructions[i].length) {
			continue;
		}
		if (!r_str_ncasecmp(input, instructions[i].opcode, instructions[i].length)) {
			const char *p = r_str_trim_head_ro(input + instructions[i].length);
			st32 used = p ? (p - input) : input_size;
			return instructions[i].encode(instructions[i].bytecode, p, input_size - used, output, output_size, pc, written);
		}
	}

	R_LOG_ERROR("[!] java_assembler: invalid assembly.\n");
	return false;
}
