/*
 * TMS320 disassembly engine
 *
 * Written by Ilya V. Matveychikov <i.matveychikov@milabs.ru>
 *
 * Distributed under LGPL
 */

#include <stdio.h>
#include <string.h>

/* public headers */
#include <r_util.h>
#include <r_types.h>

// TODO: wtf?
#define ht_(name)	r_hashtable_##name

/* private headers */
#include "tms320_p.h"
#include "tms320_dasm.h"

#include "c55x_plus/c55plus.h"

/*
 * TMS320 disassembly engine implementation
 */

int run_f_list(tms320_dasm_t * dasm)
{
	ut32 temp;
	insn_flag_t * flag;

	if (!dasm->insn->f_list)
		return 1;

	for (flag = dasm->insn->f_list; !f_list_last(flag); flag++) {
		switch (flag->v) {
		case TMS320_FLAG_E:
			temp = get_bits(dasm->opcode64, flag->f, 1);
			set_field_value(dasm, E, temp);
			break;
		case TMS320_FLAG_R:
			temp = get_bits(dasm->opcode64, flag->f, 1);
			set_field_value(dasm, R, temp);
			break;
		case TMS320_FLAG_U:
			temp = get_bits(dasm->opcode64, flag->f, 1);
			set_field_value(dasm, U, temp);
			break;
		case TMS320_FLAG_u:
			temp = get_bits(dasm->opcode64, flag->f, 1);
			set_field_value(dasm, u, temp);
			break;
		case TMS320_FLAG_g:
			temp = get_bits(dasm->opcode64, flag->f, 1);
			set_field_value(dasm, g, temp);
			break;
		case TMS320_FLAG_r:
			temp = get_bits(dasm->opcode64, flag->f, 1);
			set_field_value(dasm, r, temp);
			break;
		case TMS320_FLAG_t:
			temp = get_bits(dasm->opcode64, flag->f, 1);
			set_field_value(dasm, t, temp);
			break;

		case TMS320_FLAG_k3:
			temp = get_bits(dasm->opcode64, flag->f, 3);
			set_field_value(dasm, k3, temp);
			break;
		case TMS320_FLAG_k4:
			temp = get_bits(dasm->opcode64, flag->f, 4);
			set_field_value(dasm, k4, temp);
			break;
		case TMS320_FLAG_k5:
			temp = get_bits(dasm->opcode64, flag->f, 5);
			set_field_value(dasm, k5, temp);
			break;
		case TMS320_FLAG_k6:
			temp = get_bits(dasm->opcode64, flag->f, 6);
			set_field_value(dasm, k6, temp);
			break;
		case TMS320_FLAG_k8:
			temp = get_bits(dasm->opcode64, flag->f, 8);
			set_field_value(dasm, k8, temp);
			break;
		case TMS320_FLAG_k12:
			temp = get_bits(dasm->opcode64, flag->f, 12);
			set_field_value(dasm, k12, temp);
			break;
		case TMS320_FLAG_k16:
			temp = get_bits(dasm->opcode64, flag->f, 16);
			set_field_value(dasm, k16, temp);
			break;

		case TMS320_FLAG_l1:
			temp = get_bits(dasm->opcode64, flag->f, 1);
			set_field_value(dasm, l1, temp);
			break;
		case TMS320_FLAG_l3:
			temp = get_bits(dasm->opcode64, flag->f, 3);
			set_field_value(dasm, l3, temp);
			break;
		case TMS320_FLAG_l7:
			temp = get_bits(dasm->opcode64, flag->f, 7);
			set_field_value(dasm, l7, temp);
			break;
		case TMS320_FLAG_l16:
			temp = get_bits(dasm->opcode64, flag->f, 16);
			set_field_value(dasm, l16, temp);
			break;

		case TMS320_FLAG_K8:
			temp = get_bits(dasm->opcode64, flag->f, 8);
			set_field_value(dasm, K8, temp);
			break;
		case TMS320_FLAG_K16:
			temp = get_bits(dasm->opcode64, flag->f, 16);
			set_field_value(dasm, K16, temp);
			break;

		case TMS320_FLAG_L7:
			temp = get_bits(dasm->opcode64, flag->f, 7);
			set_field_value(dasm, L7, temp);
			break;
		case TMS320_FLAG_L8:
			temp = get_bits(dasm->opcode64, flag->f, 8);
			set_field_value(dasm, L8, temp);
			break;
		case TMS320_FLAG_L16:
			temp = get_bits(dasm->opcode64, flag->f, 16);
			set_field_value(dasm, L16, temp);
			break;

		case TMS320_FLAG_P8:
			temp = get_bits(dasm->opcode64, flag->f, 8);
			set_field_value(dasm, P8, temp);
			break;
		case TMS320_FLAG_P24:
			temp = get_bits(dasm->opcode64, flag->f, 24);
			set_field_value(dasm, P24, temp);
			break;

		case TMS320_FLAG_D16:
			temp = get_bits(dasm->opcode64, flag->f, 16);
			set_field_value(dasm, D16, temp);
			break;

		case TMS320_FLAG_SHFT:
			temp = get_bits(dasm->opcode64, flag->f, 4);
			set_field_value(dasm, SHFT, temp);
			break;
		case TMS320_FLAG_SHIFTW:
			temp = get_bits(dasm->opcode64, flag->f, 6);
			set_field_value(dasm, SHIFTW, temp);
			break;

		case TMS320_FLAG_CCCCCCC:
			temp = get_bits(dasm->opcode64, flag->f, 7);
			set_field_value(dasm, CCCCCCC, temp);
			break;
		case TMS320_FLAG_AAAAAAAI:
			temp = get_bits(dasm->opcode64, flag->f, 8);
			set_field_value(dasm, AAAAAAAI, temp);
			break;

		case TMS320_FLAG_uu:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			set_field_value(dasm, uu, temp);
			break;
		case TMS320_FLAG_cc:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			set_field_value(dasm, cc, temp);
			break;
		case TMS320_FLAG_ss:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			set_field_value(dasm, ss, temp);
			break;
		case TMS320_FLAG_dd:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			set_field_value(dasm, dd, temp);
			break;
		case TMS320_FLAG_mm:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			set_field_value(dasm, mm, temp);
			break;
		case TMS320_FLAG_vv:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			set_field_value(dasm, vv, temp);
			break;
		case TMS320_FLAG_tt:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			set_field_value(dasm, tt, temp);
			break;

		case TMS320_FLAG_XSSS:
			temp = get_bits(dasm->opcode64, flag->f, 4);
			set_field_value(dasm, XSSS, temp);
			break;
		case TMS320_FLAG_XDDD:
			temp = get_bits(dasm->opcode64, flag->f, 4);
			set_field_value(dasm, XDDD, temp);
			break;
		case TMS320_FLAG_FSSS:
			temp = get_bits(dasm->opcode64, flag->f, 4);
			set_field_value(dasm, FSSS, temp);
			break;
		case TMS320_FLAG_FDDD:
			temp = get_bits(dasm->opcode64, flag->f, 4);
			set_field_value(dasm, FDDD, temp);
			break;
		case TMS320_FLAG_XACS:
			temp = get_bits(dasm->opcode64, flag->f, 4);
			set_field_value(dasm, XACS, temp);
			break;
		case TMS320_FLAG_XACD:
			temp = get_bits(dasm->opcode64, flag->f, 4);
			set_field_value(dasm, XACD, temp);
			break;

		case TMS320_FLAG_SS:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			if (!field_valid(dasm, SS)) {
				set_field_value(dasm, SS, temp);
			} else {
				set_field_value(dasm, SS2, temp);
			}
			break;
		case TMS320_FLAG_DD:
			temp = get_bits(dasm->opcode64, flag->f, 2);
			if (!field_valid(dasm, DD)) {
				set_field_value(dasm, DD, temp);
			} else {
				set_field_value(dasm, DD2, temp);
			}
			break;

		case TMS320_FLAG_XXX:
			temp = get_bits(dasm->opcode64, flag->f, 3);
			set_field_value(dasm, Xmem_reg, temp);
			break;
		case TMS320_FLAG_MMM:
			temp = get_bits(dasm->opcode64, flag->f, 3);
			if (!field_valid(dasm, Xmem_mmm)) {
				set_field_value(dasm, Xmem_mmm, temp);
			} else {
				set_field_value(dasm, Ymem_mmm, temp);
			}
			break;
		case TMS320_FLAG_Y:
			temp = get_bits(dasm->opcode64, flag->f, 1) << 0;
			if (!field_valid(dasm, Ymem_reg)) {
				set_field_value(dasm, Ymem_reg, temp);
			} else {
				field_value(dasm, Ymem_reg) |= temp;
			}
			break;
		case TMS320_FLAG_YY:
			temp = get_bits(dasm->opcode64, flag->f, 2) << 1;
			if (!field_valid(dasm, Ymem_reg)) {
				set_field_value(dasm, Ymem_reg, temp);
			} else {
				field_value(dasm, Ymem_reg) |= temp;
			}
			break;

		default:
			printf("TODO: unknown opcode flag %02x\n", flag->v);
			return 0;
		}
	}

	return 1;
}

int run_m_list(tms320_dasm_t * dasm)
{
	insn_mask_t * mask;

	if (!dasm->insn->m_list)
		return 1;

	for (mask = dasm->insn->m_list; !m_list_last(mask); mask++) {
		/* match bits in range [f, f + n] with mask's value */
		if (get_bits(dasm->opcode64, mask->f, mask->n) != mask->v)
			return 0;
	}

	return 1;
}

int vreplace(char * string, const char * token, const char * fmt, va_list args)
{
	char data[64];
	char * pos;

	pos = strstr(string, token);
	if (!pos)
		return 0;

	vsnprintf(data, sizeof(data), fmt, args);

	memmove(pos + strlen(data), pos + strlen(token), strlen(pos + strlen(token)) + 1);
	memmove(pos, data, strlen(data));

	return 1;
}

int replace(char * string, const char * token, const char * fmt, ...)
{
	int result;
	va_list args;

	va_start(args, fmt);
	result = vreplace(string, token, fmt, args);
	va_end(args);

	return result;
}

void substitute(char * string, const char * token, const char * fmt, ...)
{
	int result;
	va_list args;

	do {
		va_start(args, fmt);
		result = vreplace(string, token, fmt, args);
		va_end(args);
	} while (result);
}

const char * get_xreg_str(ut8 key, char * str)
{
	static const char * table[16] = {
		"AC0", "AC1", "AC2", "AC3", "XSP", "XSSP", "XDP", "XCDP",
		"XAR0", "XAR1", "XAR2", "XAR3", "XAR4", "XAR5", "XAR6", "XAR7",
	};

	return table[ key & 15 ];
}

const char * get_freg_str(ut8 key, char * str)
{
	static const char * table[16] = {
		"AC0", "AC1", "AC2", "AC3", "T0", "T1", "T2", "T3",
		"AR0", "AR1", "AR2", "AR3", "AR4", "AR5", "AR6", "AR7",
	};

	return table[ key & 15 ];
}

const char * get_swap_str(ut8 key, char * str)
{
	switch (key) {
	case 0: return "SWAP AC0, AC2";
	case 1: return "SWAP AC1, AC3";
	case 4: return "SWAP T0, T2";
	case 5: return "SWAP T1, T3";
	case 8: return "SWAP AR0, AR2";
	case 9: return "SWAP AR1, AR3";
	case 12: return "SWAP AR4, T0";
	case 13: return "SWAP AR5, T1";
	case 14: return "SWAP AR6, T2";
	case 15: return "SWAP AR7, T3";
	case 16: return "SWAPP AC0, AC2";
	case 20: return "SWAPP T0, T2";
	case 24: return "SWAPP AR0, AR2";
	case 28: return "SWAPP AR4, T0";
	case 30: return "SWAPP AR6, T2";
	case 44: return "SWAP4 AR4, T0";
	case 56: return "SWAP AR0, AR1";
	}

	return "invalid";
}

const char * get_relop_str(ut8 key, char * str)
{
	static const char * table[] = {
		"==", "<", ">=", "!="
	};

	return table[ key & 3 ];
}

const char * get_cond_str(ut8 key, char * str)
{
	/* 000 FSSS ... 101 FSSS */
	if ((key >> 4) <= 5) {
		static const char * op[6] = { "==", "!=", "<", "<=", ">", ">=" };
		sprintf(str, "%s %s 0", get_freg_str(key & 15, NULL), op[(key >> 4) & 7]);
		return str;
	}

	/* 110 00SS */
	if ((key >> 2) == 0x18) {
		sprintf(str, "overflow(AC%d)", key & 3);
		return str;
	}

	/* 111 00SS */
	if ((key >> 2) == 0x1C) {
		sprintf(str, "!overflow(AC%d)", key & 3);
		return str;
	}

	switch (key) {
	case 0x64: return "TC1";
	case 0x65: return "TC2";
	case 0x66: return "CARRY";
	case 0x74: return "!TC1";
	case 0x75: return "!TC2";
	case 0x76: return "!CARRY";
		/* "&" operation */
	case 0x68: return "TC1 & TC2";
	case 0x69: return "TC1 & !TC2";
	case 0x6A: return "!TC1 & TC2";
	case 0x6B: return "!TC1 & !TC2";
		/* "|" operation */
	case 0x78: return "TC1 | TC2";
	case 0x79: return "TC1 | !TC2";
	case 0x7A: return "!TC1 | TC2";
	case 0x7B: return "!TC1 | !TC2";
		/* "^" operation */
	case 0x7C: return "TC1 ^ TC2";
	case 0x7D: return "TC1 ^ !TC2";
	case 0x7E: return "!TC1 ^ TC2";
	case 0x7F: return "!TC1 ^ !TC2";
	}

	return "invalid";
}

const char * get_v_str(ut8 key, char * str)
{
	static const char * table[2] = {
		"CARRY", "TC2",
	};

	return table[ key & 1 ];
}

const char * get_t_str(ut8 key, char * str)
{
	static const char * table[2] = {
		"TC1", "TC2",
	};

	return table[ key & 1 ];
}

const char * get_cmem_str(ut8 key, char * str)
{
	static const char * table[4] = {
		"*CDP", "*CDP+", "*CDP-", "*(CDP+T0)",
	};

	return table[ key & 3 ];
}

const char * get_smem_str(ut8 key, char * str)
{
	// direct memory

	if ((key & 0x01) == 0) {
#ifdef IDA_COMPATIBLE_MODE
		sprintf(str, "*SP(#%Xh)", key >> 1);
#else
		sprintf(str, "@0x%02X", key >> 1);
#endif
		return str;
	}

	// indirect memory

	switch (key) {
	case 0x11: return "ABS16(k16)";
	case 0x31: return "*(k23)";
	case 0x51: return "port(k16)";
	case 0x71: return "*CDP";
	case 0x91: return "*CDP+";
	case 0xB1: return "*CDP-";
	case 0xD1: return "*CDP(K16)";
	case 0xF1: return "*+CDP(K16)";
	}

	switch (key & 0x1F) {
	case 0x01: return "*ARn";
	case 0x03: return "*ARn+";
	case 0x05: return "*ARn-";
		// TODO:
		//	C54CM:0 => *(ARn + T0)
		//	C54CM:1 => *(ARn + AR0)
	case 0x07: return "*(ARn + T0)";
		// TODO:
		//	C54CM:0 => *(ARn - T0)
		//	C54CM:1 => *(ARn - AR0)
	case 0x09: return "*(ARn - T0)";
		// TODO:
		//	C54CM:0 => *ARn(T0)
		//	C54CM:1 => *ARn(AR0)
	case 0x0B: return "*ARn(T0)";
	case 0x0D: return "*ARn(K16)";
	case 0x0F: return "*+ARn(K16)";
		// TODO:
		//	ARMS:0 => *(ARn + T1)
		//	ARMS:1 => *ARn(short(1))
	case 0x13: return "*(ARn + T1)";
		// TODO:
		//	ARMS:0 => *(ARn - T1)
		//	ARMS:1 => *ARn(short(2))
	case 0x15: return "*(ARn - T1)";
		// TODO:
		//	ARMS:0 => *ARn(T1)
		//	ARMS:1 => *ARn(short(3))
	case 0x17: return "*ARn(T1)";
		// TODO:
		//	ARMS:0 => *+ARn
		//	ARMS:1 => *ARn(short(4))
	case 0x19: return "*+ARn";
		// TODO:
		//	ARMS:0 => *-ARn
		//	ARMS:1 => *ARn(short(5))
	case 0x1B: return "*-ARn";
		// TODO:
		//	ARMS:0 => *(ARn + T0B)
		//	ARMS:1 => *ARn(short(6))
	case 0x1D: return "*(ARn + T0B)";
		// TODO:
		//	ARMS:0 => *(ARn - T0B)
		//	ARMS:1 => *ARn(short(7))
	case 0x1F: return "*(ARn - T0B)";
	}

	return "invalid";
}

const char * get_mmm_str(ut8 key, char * str)
{
	switch (key & 7) {
	default:
	case 0x00: return "*ARn";
	case 0x01: return "*ARn+";
	case 0x02: return "*ARn-";
		// TODO:
		//	C54CM:0 => *(ARn + T0)
		//	C54CM:1 => *(ARn + AR0)
	case 0x03: return "*(ARn + T0)";
	case 0x04: return "*(ARn + T1)";
		// TODO:
		//	C54CM:0 => *(ARn - T0)
		//	C54CM:1 => *(ARn - AR0)
	case 0x05: return "*(ARn - T0)";
	case 0x06: return "*(ARn - T1)";
		// TODO:
		//	C54CM:0 => *ARn(T0)
		//	C54CM:1 => *ARn(AR0)
	case 0x07: return "*ARn(T0)";
	};
}

/*
 * syntax decoders
 */

void decode_bits(tms320_dasm_t * dasm)
{
	// rounding
	if (field_valid(dasm, R))
		substitute(dasm->syntax, "[R]", "%s", field_value(dasm, R) ? "R" : "");

	// unsigned
	if (field_valid(dasm, u))
		substitute(dasm->syntax, "[U]", "%s", field_value(dasm, u) ? "U" : "");

	// 40 keyword
	if (field_valid(dasm, g))
		substitute(dasm->syntax, "[40]", "%s", field_value(dasm, g) ? "40" : "");

	// T3 update
	if (field_valid(dasm, U))
		substitute(dasm->syntax, "[T3 = ]", "%s", field_value(dasm, U) ? "T3=" : "");
}

void decode_braces(tms320_dasm_t * dasm)
{
	char * pos;

	pos = strstr(dasm->syntax, "[(saturate]");
	if (pos) {
		replace(pos, "[)", ")[");
		replace(dasm->syntax, "[(saturate]", "%s", "(saturate");
	}

	if (field_valid(dasm, R)) {
		pos = strstr(dasm->syntax, "[rnd(]");
		if (pos) {
			replace(pos, "[)", "%s", field_value(dasm, R) ? ")[" : "[");
			replace(dasm->syntax, "[rnd(]", "%s", field_value(dasm, R) ? "rnd(" : "");
		}
	}

	if (field_valid(dasm, u)) {
		pos = strstr(dasm->syntax, "[uns(]");
		if (pos) {
			replace(pos, "[)", "%s", field_value(dasm, u) ? ")[" : "[");
			replace(dasm->syntax, "[uns(]", "%s", field_value(dasm, u) ? "uns(" : "");
		}
	}

	if (field_valid(dasm, uu)) {
		boolt parallel = !!strstr(dasm->syntax, "::");

		// first
		replace(dasm->syntax, "[uns(]", "%s", field_value(dasm, uu) & 2 ? "uns(" : "");
		replace(dasm->syntax, "[)]", "%s", field_value(dasm, uu) & 2 ? ")" : "");

		if (parallel) {
			replace(dasm->syntax, "[uns(]", "%s", field_value(dasm, uu) & 2 ? "uns(" : "");
			replace(dasm->syntax, "[)]", "%s", field_value(dasm, uu) & 2 ? ")" : "");
		}

		// second
		replace(dasm->syntax, "[uns(]", "%s", field_value(dasm, uu) & 1 ? "uns(" : "");
		replace(dasm->syntax, "[)]", "%s", field_value(dasm, uu) & 1 ? ")" : "");

		if (parallel) {
			replace(dasm->syntax, "[uns(]", "%s", field_value(dasm, uu) & 1 ? "uns(" : "");
			replace(dasm->syntax, "[)]", "%s", field_value(dasm, uu) & 1 ? ")" : "");
		}
	}

	// remove rudiments

	substitute(dasm->syntax, "[]", "%s", "");
}

void decode_constants(tms320_dasm_t * dasm)
{
	// signed constant

	if (field_valid(dasm, K8))
		substitute(dasm->syntax, "K8", "0x%02X", field_value(dasm, K8));
	if (field_valid(dasm, K16))
		substitute(dasm->syntax, "K16", "0x%04X", be16(field_value(dasm, K16)));

	// unsigned constant

	if (field_valid(dasm, k4))
		substitute(dasm->syntax, "k4", "0x%01X", field_value(dasm, k4));
	if (field_valid(dasm, k5))
		substitute(dasm->syntax, "k5", "0x%02X", field_value(dasm, k5));
	if (field_valid(dasm, k8))
		substitute(dasm->syntax, "k8", "0x%02X", field_value(dasm, k8));

	if (field_valid(dasm, k12))
		substitute(dasm->syntax, "k12", "0x%03X", be16(field_value(dasm, k12)));
	if (field_valid(dasm, k16))
		substitute(dasm->syntax, "k16", "0x%04X", be16(field_value(dasm, k16)));

	if (field_valid(dasm, k4) && field_valid(dasm, k3))
		substitute(dasm->syntax, "k7", "0x%02X", (field_value(dasm, k3) << 4) | field_value(dasm, k4));
	if (field_valid(dasm, k4) && field_valid(dasm, k5))
		substitute(dasm->syntax, "k9", "0x%03X", (field_value(dasm, k5) << 4) | field_value(dasm, k4));
	if (field_valid(dasm, k4) && field_valid(dasm, k8))
		substitute(dasm->syntax, "k12", "0x%03X", (field_value(dasm, k8) << 4) | field_value(dasm, k4));

	// dasm address label

	if (field_valid(dasm, D16))
		substitute(dasm->syntax, "D16", "0x%04X", be16(field_value(dasm, D16)));

	// immediate shift value

	if (field_valid(dasm, SHFT))
		substitute(dasm->syntax, "#SHFT", "0x%01X", field_value(dasm, SHFT));
	if (field_valid(dasm, SHIFTW))
		substitute(dasm->syntax, "#SHIFTW", "0x%02X", field_value(dasm, SHIFTW));
}

void decode_addresses(tms320_dasm_t * dasm)
{
	// program address label

	if (field_valid(dasm, L7))
		substitute(dasm->syntax, "L7", "0x%02X", field_value(dasm, L7));
	if (field_valid(dasm, L8))
		substitute(dasm->syntax, "L8", "0x%02X", field_value(dasm, L8));
	if (field_valid(dasm, L16))
		substitute(dasm->syntax, "L16", "0x%04X", be16(field_value(dasm, L16)));

	// program address label

	if (field_valid(dasm, l1) && field_valid(dasm, l3))
		substitute(dasm->syntax, "l4", "0x%01X", (field_value(dasm, l3) << 1) | field_value(dasm, l1));

	// program memory address

	if (field_valid(dasm, l7))
		substitute(dasm->syntax, "pmad", "0x%02X", field_value(dasm, l7));
	if (field_valid(dasm, l16))
		substitute(dasm->syntax, "pmad", "0x%04X", be16(field_value(dasm, l16)));

	// program or dasm address label

	if (field_valid(dasm, P8))
		substitute(dasm->syntax, "P8", "0x%02X", field_value(dasm, P8));
	if (field_valid(dasm, P24))
		substitute(dasm->syntax, "P24", "0x%06X", be24(field_value(dasm, P24)));
}

void decode_swap(tms320_dasm_t * dasm)
{
	char tmp[64];

	if (field_valid(dasm, k6))
		substitute(dasm->syntax, "SWAP ( )", get_swap_str(field_value(dasm, k6), tmp));
}

void decode_relop(tms320_dasm_t * dasm)
{
	if (field_valid(dasm, cc))
		substitute(dasm->syntax, "RELOP", get_relop_str(field_value(dasm, cc), NULL));
}

void decode_cond(tms320_dasm_t * dasm)
{
	char tmp[64];

	if (field_valid(dasm, CCCCCCC))
		substitute(dasm->syntax, "cond", "%s", get_cond_str(field_value(dasm, CCCCCCC), tmp));

	substitute(dasm->syntax, "[label, ]", "");
}

void decode_registers(tms320_dasm_t * dasm)
{
	ut8 code = 0;

	// transition register

	if (field_valid(dasm, r))
		substitute(dasm->syntax, "TRNx", "TRN%d", field_value(dasm, r));

	// source and destination temporary registers

	if (field_valid(dasm, ss))
		substitute(dasm->syntax, "Tx", "T%d", field_value(dasm, ss));

	if (field_valid(dasm, dd))
		substitute(dasm->syntax, "Tx", "T%d", field_value(dasm, dd));

	// shifted in/out bit values

	if (field_valid(dasm, vv)) {
		substitute(dasm->syntax, "BitIn", "%s", get_v_str(field_value(dasm, vv) >> 1, NULL));
		substitute(dasm->syntax, "BitOut", "%s", get_v_str(field_value(dasm, vv) >> 0, NULL));
	}

	// source and destination of CRC instruction

	if (field_valid(dasm, t))
		substitute(dasm->syntax, "TCx", "%s", get_t_str(field_value(dasm, t), NULL));

	if (field_valid(dasm, tt)) {
		substitute(dasm->syntax, "TCx", "%s", get_t_str(field_value(dasm, tt) >> 0, NULL));
		substitute(dasm->syntax, "TCy", "%s", get_t_str(field_value(dasm, tt) >> 1, NULL));
	}

	// source or destination accumulator or extended register

	if (field_valid(dasm, XSSS)) {
		substitute(dasm->syntax, "xsrc", "%s", get_xreg_str(field_value(dasm, XSSS), NULL));
		substitute(dasm->syntax, "XAsrc", "%s", get_xreg_str(field_value(dasm, XSSS), NULL));
	}

	if (field_valid(dasm, XDDD)) {
		substitute(dasm->syntax, "xdst", "%s", get_xreg_str(field_value(dasm, XDDD), NULL));
		substitute(dasm->syntax, "XAdst", "%s", get_xreg_str(field_value(dasm, XDDD), NULL));
	}

	// source or destination accumulator, auxiliary or temporary register

	if (field_valid(dasm, FSSS) && field_valid(dasm, FDDD)) {
		if (field_value(dasm, FSSS) == field_value(dasm, FDDD))
			substitute(dasm->syntax, "[src,] dst", "dst");
		else
			substitute(dasm->syntax, "[src,] dst", "src, dst");
	}

	if (field_valid(dasm, FSSS) && field_valid(dasm, FDDD)) {
		substitute(dasm->syntax, "src1", "%s", get_freg_str(field_value(dasm, FSSS), NULL));
		substitute(dasm->syntax, "src2", "%s", get_freg_str(field_value(dasm, FDDD), NULL));

		substitute(dasm->syntax, "dst1", "%s", get_freg_str(field_value(dasm, FSSS), NULL));
		substitute(dasm->syntax, "dst2", "%s", get_freg_str(field_value(dasm, FDDD), NULL));
	}


	code &= 0;
	code |= field_valid(dasm, FSSS) ? 0x01 : 0x00;
	code |= field_valid(dasm, FDDD) ? 0x02 : 0x00;

	switch (code) {
	case 0x01:	// FSSS
		substitute(dasm->syntax, "TAx", "%s", get_freg_str(field_value(dasm, FSSS), NULL));
		break;
	case 0x02:	//      FDDD
		substitute(dasm->syntax, "TAx", "%s", get_freg_str(field_value(dasm, FDDD), NULL));
		substitute(dasm->syntax, "TAy", "%s", get_freg_str(field_value(dasm, FDDD), NULL));
		break;
	case 0x03:	// FSSS FDDD
		substitute(dasm->syntax, "TAx", "%s", get_freg_str(field_value(dasm, FSSS), NULL));
		substitute(dasm->syntax, "TAy", "%s", get_freg_str(field_value(dasm, FDDD), NULL));
		break;
	}

	if (field_valid(dasm, FSSS)) {
		substitute(dasm->syntax, "src", "%s", get_freg_str(field_value(dasm, FSSS), NULL));
	}

	if (field_valid(dasm, FDDD)) {
		substitute(dasm->syntax, "dst", "%s", get_freg_str(field_value(dasm, FDDD), NULL));
	}

	if (field_valid(dasm, XACS))
		substitute(dasm->syntax, "XACsrc", "%s", get_xreg_str(field_value(dasm, XACS), NULL));

	if (field_valid(dasm, XACD))
		substitute(dasm->syntax, "XACdst", "%s", get_xreg_str(field_value(dasm, XACD), NULL));


	// source and destination accumulator registers

	code &= 0;
	code |= field_valid(dasm, SS) ? 0x01 : 0x00;
	code |= field_valid(dasm, SS2) ? 0x02 : 0x00;
	code |= field_valid(dasm, DD) ? 0x10 : 0x00;
	code |= field_valid(dasm, DD2) ? 0x20 : 0x00;

	switch (code) {
	case 0x01:	// SS
		substitute(dasm->syntax, "ACx", "AC%d", field_value(dasm, SS));
		break;
	case 0x03:	// SSSS
		substitute(dasm->syntax, "ACx", "AC%d", field_value(dasm, SS));
		substitute(dasm->syntax, "ACy", "AC%d", field_value(dasm, SS2));
		break;
	case 0x11:	// SS   DD
		if (field_value(dasm, SS) == field_value(dasm, DD)) {
			substitute(dasm->syntax, "[, ACy]", "");
			substitute(dasm->syntax, "[ACx,] ACy", "ACy");
		} else {
			substitute(dasm->syntax, "[, ACy]", ", ACy");
			substitute(dasm->syntax, "[ACx,] ACy", "ACx, ACy");
		}
		substitute(dasm->syntax, "ACx", "AC%d", field_value(dasm, SS));
		substitute(dasm->syntax, "ACy", "AC%d", field_value(dasm, DD));
		break;
	case 0x33:	// SSSS DDDD
		substitute(dasm->syntax, "ACx", "AC%d", field_value(dasm, SS));
		substitute(dasm->syntax, "ACy", "AC%d", field_value(dasm, SS2));
		substitute(dasm->syntax, "ACz", "AC%d", field_value(dasm, DD));
		substitute(dasm->syntax, "ACw", "AC%d", field_value(dasm, DD2));
		break;
	case 0x10:	//      DD
		substitute(dasm->syntax, "ACx", "AC%d", field_value(dasm, DD));
		break;
	case 0x30:	//      DDDD
		substitute(dasm->syntax, "ACx", "AC%d", field_value(dasm, DD));
		substitute(dasm->syntax, "ACy", "AC%d", field_value(dasm, DD2));
		break;
	}
}

void decode_addressing_modes(tms320_dasm_t * dasm)
{
	// Cmem

	if (field_valid(dasm, mm))
		substitute(dasm->syntax, "Cmem", "%s", get_cmem_str(field_value(dasm, mm), NULL));

	// Xmem and Ymem

	if (field_valid(dasm, Xmem_reg) && field_valid(dasm, Xmem_mmm)) {
		substitute(dasm->syntax, "Xmem", "%s", get_mmm_str(field_value(dasm, Xmem_mmm), NULL));
		substitute(dasm->syntax, "ARn", "AR%d", field_value(dasm, Xmem_reg));
	}

	if (field_valid(dasm, Ymem_reg) && field_valid(dasm, Ymem_mmm)) {
		substitute(dasm->syntax, "Ymem", "%s", get_mmm_str(field_value(dasm, Ymem_mmm), NULL));
		substitute(dasm->syntax, "ARn", "AR%d", field_value(dasm, Ymem_reg));
	}

	// Lmem and Smem

	if (field_valid(dasm, AAAAAAAI)) {
		char str[64], tmp[64];

		snprintf(tmp, sizeof(tmp), "%s", get_smem_str(field_value(dasm, AAAAAAAI), str));

		if (field_value(dasm, AAAAAAAI) & 1) {
			if (strstr(tmp, "k16")) {
				substitute(tmp, "k16", "0x%04X", be16(*(ut16 *)(dasm->stream + dasm->length)));
				dasm->length += 2;
			} else if (strstr(tmp, "k23")) {
				substitute(tmp, "k23", "0x%06X", be24(*(ut32 *)(dasm->stream + dasm->length) & 0x7FFFFF));
				dasm->length += 3;
			} else if (strstr(tmp, "K16")) {
				substitute(tmp, "K16", "0x%04X", be16(*(ut16 *)(dasm->stream + dasm->length)));
				dasm->length += 2;
			}

			substitute(tmp, "ARn", "AR%d", field_value(dasm, AAAAAAAI) >> 5);
		}

		substitute(dasm->syntax, "Smem", "%s", tmp);
		substitute(dasm->syntax, "Lmem", "%s", tmp);
	}
}

void decode_qualifiers(tms320_dasm_t * dasm)
{
	switch (dasm->stream[dasm->length]) {
	case 0x98:
		// 1001 1000 - mmap
		break;

	case 0x99:
		// 1001 1001 - port(Smem)
		break;
	case 0x9a:
		// 1001 1010 - port(Smem)
		break;

	case 0x9c:
		// 1001 1100 - <insn>.LR
		set_field_value(dasm, q_lr, 1);
		break;
	case 0x9d:
		// 1001 1101 - <insn>.CR
		set_field_value(dasm, q_cr, 1);
		break;
	}
}

static insn_item_t * finalize(tms320_dasm_t * dasm)
{
	// remove odd spaces

	substitute(dasm->syntax, "  ", "%s", " ");

	// add some qualifiers

	if (field_value(dasm, q_lr))
		replace(dasm->syntax, " ", ".LR ");
	if (field_value(dasm, q_cr))
		replace(dasm->syntax, " ", ".CR ");

	return dasm->insn;
}

insn_item_t * decode_insn(tms320_dasm_t * dasm)
{
	dasm->length = dasm->head->size;

	snprintf(dasm->syntax, sizeof(dasm->syntax), \
		 field_valid(dasm, E) && field_value(dasm, E) ? "|| %s" : "%s", dasm->insn->syntax);

	decode_bits(dasm);
	decode_braces(dasm);
	decode_qualifiers(dasm);

	decode_constants(dasm);
	decode_addresses(dasm);

	decode_swap(dasm);
	decode_relop(dasm);
	decode_cond(dasm);

	decode_registers(dasm);
	decode_addressing_modes(dasm);

	return finalize(dasm);

}

insn_item_t * decode_insn_head(tms320_dasm_t * dasm)
{
	run_f_list(dasm);

	if (dasm->insn->i_list) {
		dasm->insn = dasm->insn->i_list;
		while (!i_list_last(dasm->insn)) {
			if (run_m_list(dasm) && run_f_list(dasm))
				break;
			dasm->insn++;
		}
	}

	if (!i_list_last(dasm->insn))
		return decode_insn(dasm);

	return NULL;
}

static ut8 c55x_e_list[] = {
	0xF8, 0x60,	/* 0110 0lll */
	0xF0, 0xA0,	/* 1010 FDDD */
	0xFC, 0xB0,	/* 1011 00DD */
	0xF0, 0xC0,	/* 1100 FSSS */
	0xFC, 0xBC,	/* 1011 11SS */
	0x00, 0x00,
};

insn_head_t * lookup_insn_head(tms320_dasm_t * dasm)
{
	ut8 * e_list = NULL;

	/* handle some exceptions */

	if (tms320_f_get_cpu(dasm) == TMS320_F_CPU_C55X)
		e_list = c55x_e_list;

	while (e_list && (e_list[0] && e_list[1])) {
		if ((dasm->opcode & e_list[0]) == e_list[1]) {
			dasm->head = ht_(lookup)(dasm->map, e_list[1]);
			break;
		}
		e_list += 2;
	}

	if (!dasm->head) {
		dasm->head = ht_(lookup)(dasm->map, dasm->opcode);
		if (!dasm->head)
			dasm->head = ht_(lookup)(dasm->map, dasm->opcode & 0xfe);
	}

	dasm->insn = dasm->head ? &dasm->head->insn : NULL;

	return dasm->head;
}

static void init_dasm(tms320_dasm_t * dasm, const ut8 * stream, int len)
{
	strcpy(dasm->syntax, "invalid");
	memcpy(dasm->stream, stream, min(sizeof(dasm->stream), len));

	dasm->status = 0;
	dasm->length = 0;

	memset(&dasm->f, 0, sizeof(dasm->f));

	dasm->head = NULL;
	dasm->insn = NULL;
}

static int full_insn_size(tms320_dasm_t * dasm)
{
	int qualifier_size = 0;

	if (field_value(dasm, q_cr))
		qualifier_size = 1;
	if (field_value(dasm, q_lr))
		qualifier_size = 1;

	return dasm->length + qualifier_size;
}

/*
 * TMS320 disassembly engine public interface
 */

int tms320_dasm(tms320_dasm_t * dasm, const ut8 * stream, int len)
{
	init_dasm(dasm, stream, len);

	if (tms320_f_get_cpu(dasm) != TMS320_F_CPU_C55X_PLUS) {
		if (lookup_insn_head(dasm) && decode_insn_head(dasm)) {
			if (dasm->length > len)
				dasm->status |= TMS320_S_INVAL;
		}
	} else {
		c55x_plus_disassemble(dasm, stream, len);
	}

	if (strstr(dasm->syntax, "invalid"))
		dasm->status |= TMS320_S_INVAL;

	if (dasm->status & TMS320_S_INVAL)
		strcpy(dasm->syntax, "invalid"), dasm->length = 1;

	return full_insn_size(dasm);
}

static insn_head_t c55x_list[] = {
#  include "c55x/table.h"
};

int tms320_dasm_init(tms320_dasm_t * dasm) {
	int i = 0;

	dasm->map = ht_(new)();

	for (i = 0; i < ARRAY_SIZE(c55x_list); i++)
		ht_(insert)(dasm->map, c55x_list[i].byte, &c55x_list[i]);

	tms320_f_set_cpu(dasm, TMS320_F_CPU_C55X);

	return 0;
}

int tms320_dasm_fini(tms320_dasm_t * dasm) {
	if (dasm) {
		if (dasm->map)
			ht_(free)(dasm->map);
	/* avoid double free */
		memset (dasm, 0, sizeof (tms320_dasm_t));
	}
	return 0;
}
