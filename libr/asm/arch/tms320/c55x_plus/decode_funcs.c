/* c55plus - LGPL3 - Copyright 2013 - th0rpe */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ins.h"
#include "utils.h"

st8 *get_tc2_tc1(ut32 ins_bits) {
	st8 *res = "TC1";
	if (ins_bits) {
		if (ins_bits != 1) {
			fprintf(stderr, "Invalid instruction TC2 or TC1 (%d)\n", ins_bits);
			return NULL;
		}
		res = "TC2";
	}
	return strdup (res);
}

st8 *get_trans_reg(ut32 ins_bits) {
	st8 *res = NULL;

	switch (ins_bits) {
	case 6:
		res = "TRN0";
		break;
	case 7:
		res = "TRN1";
		break;
	case 4:
		res = "TRN2";
		break;
	case 5:
		res = "TRN3";
		break;
	case 2:
		res = "TRN4";
		break;
	case 3:
		res = "TRN5";
		break;
	case 0:
		res = "TRN6";
		break;
	case 1:
		res = "TRN7";
		break;

	default:
		fprintf(stderr, "Invalid transaction instruction 0x%x\n", ins_bits);
	}
	if(res != NULL)
		res = strdup(res);

	return res;
}

st8 *get_AR_regs_class1(ut32 ins_bits) {
	ut32 op = (ins_bits >> 4) & 7;
	st8 *res = (st8 *)malloc(50);
	if (res == NULL)
		return NULL;
	memset (res, 0, 50);
	switch (op) {
	case 0:
		sprintf(res, "*AR-%ld", (long int)ins_bits & 0xF);
		break;
	case 1:
		sprintf(res, "*AR+%ld", (long int)ins_bits & 0xF);
		break;
	case 2:
		sprintf(res, "*AR%ld(T0)", (long int)ins_bits & 0xF);
		break;
	case 3:
		sprintf(res, "*AR%ld", (long int)ins_bits & 0xF);
		break;
	case 4:
		sprintf(res, "*(AR%ld-T0)", (long int)ins_bits & 0xF);
		break;
	case 5:
		sprintf(res, "*(AR%ld-T1)", (long int)ins_bits & 0xF);
		break;
	case 6:
		sprintf(res, "*(AR%ld+T0)", (long int)ins_bits & 0xF);
		break;
	case 7:
		sprintf(res, "*(AR%ld+T1)", (long int)ins_bits & 0xF);
		break;
	}
	return res;
}

st8 *get_AR_regs_class2(ut32 ins_bits, ut32 *ret_len, ut32 ins_pos, ut32 idx) {
	ut8 op, op2, reg_num, type;
	st8 *res = NULL;

	op = ins_bits >> 6;
	op2 = ins_bits & 3;

	reg_num = (ins_bits >> 2) & 0xF;

	if (ret_len)
		*ret_len = 0;

	//printf("OP1 %x OP2 0x%x %x\n", op, op2, reg_num);

	res = (st8 *)malloc(50);
	if(op2 == 2) {
		if(op) sprintf(res, "*AR%ld(short(#0x%lx))",
			(long int)reg_num, (long int)idx * op);
		else sprintf(res, "*AR%ld", (long int)reg_num);
	} else {
		type = (op >> 3 | 2 * op2);
		if(type == 6) {
			sprintf(res, "@#0x%lx", (long int)idx * (reg_num | 16 * (op & 7)));

		} else if(type == 7) {
			sprintf(res, "*SP(#0x%lx)", (long int)idx * (reg_num | 16 * (op & 7)));
		} else {
			type = idx | 16 * op;
			switch(type) {
				case 0:
					sprintf(res, "*AR%ld-", (long int)reg_num);
					break;
				case 1:
					sprintf(res, "*AR%ld+", (long int)reg_num);
					break;
				case 2:
					sprintf(res, "*AR%ld(T0)", (long int)reg_num);
					break;
				case 3:
					sprintf(res, "*AR%ld(T1)", (long int)reg_num);
					break;
				case 4:
					sprintf(res, "*(AR%ld-T0)", (long int)reg_num);
					break;
				case 5:
					sprintf(res, "*(AR%ld-T1)", (long int)reg_num);
					break;
				case 6:
					sprintf(res, "*(AR%ld+T0)", (long int)reg_num);
					break;
				case 7:
					sprintf(res, "*(AR%ld+T1)", (long int)reg_num);
					break;
				case 8:
					sprintf(res, "*-AR%ld", (long int)reg_num);
					break;
				case 9:
					sprintf(res, "*+AR%ld", (long int)reg_num);
					break;
				case 10:
					sprintf(res, "*AR%ld(T2)", (long int)reg_num);
					break;
				case 11:
					sprintf(res, "*AR%ld(T3)", (long int)reg_num);
					break;
				case 12:
					sprintf(res, "*(AR%ld-T2)", (long int)reg_num);
					break;
				case 13:
					sprintf(res, "*(AR%ld-T3)", (long int)reg_num);
					break;
				case 14:
					sprintf(res, "*(AR%ld+T2)", (long int)reg_num);
					break;
				case 15:
					sprintf(res, "*(AR%ld+T3)", (long int)reg_num);
					break;
				case 16:
					sprintf(res, "*(AR%ld-T0B)", (long int)reg_num);
					break;
				case 17:
					sprintf(res, "*(AR%ld+T0B)", (long int)reg_num);
					break;
				case 18:
					sprintf(res, "*AR%ld(T0<<#1)", (long int)reg_num);
					break;
				case 19:
					sprintf(res, "*AR%ld(T1<<#1)", (long int)reg_num);
					break;
				case 23:
					sprintf(res, "*AR%ld(XAR15)", (long int)reg_num);
					break;

				case 24:
				case 25:
				case 26:
				case 27:
					idx = get_ins_part(ins_pos, 2);
					if(*ret_len)
						*ret_len = 2;

					if(type == 24) {
						sprintf(res, "*AR%ld(#%ld)", (long int)reg_num, (long int)op * idx);
					} else if(type == 25) {
						sprintf(res, "*+AR%ld(#%ld)", (long int)reg_num, (long int)op * idx);
					} else if(type == 26) {
						sprintf(res, "*abs16(#0x%lx)", (long int)idx);
					} else {
						sprintf(res, "*port(#0x%lx)",  (long int)idx);
					}
					break;

				case 28:
				case 29:
				case 30:

					idx = get_ins_part(ins_pos, 3);
					if(ret_len)
						*ret_len = 3;

					if(type == 28) {
						sprintf(res, "*AR%ld(#0x%lx)", (long int)reg_num, (long int)idx * op);

					} else if(type == 29) {
						sprintf(res, "*+AR%ld(#0x%lx)", (long int)reg_num, (long int)idx * op);
					} else {
						sprintf(res, "*(#0x%lx)", (long int)idx);
					}

					break;
			}
		}
	}

	return res;
}

st8 *get_reg_pair(ut32 idx) {
	st8 *res = NULL;

	switch (idx) {
	case 1: res = "AC0, AC2"; break;
	case 2: res = "AC1, AC3"; break;
	case 3: res = "pair(AC0), pair(AC2)"; break;
	case 4: res = "AR0, AR1"; break;
	case 5: res = "AR0, AR2"; break;
	case 6: res = "AR1, AR3"; break;
	case 7: res = "pair(AR0), pair(AR2)"; break;
	case 9: res = "T0, T2"; break;
	case 10: res = "T1, T3"; break;
	case 11: res = "pair(T0), pair(T2)"; break;
	case 21: res = "AR4, T0"; break;
	case 22: res = "AR5, T1"; break;
	case 23: res = "pair(AR4), pair(T0)"; break;
	case 25: res = "AR6, T2"; break;
	case 26: res = "AR7, T3"; break;
	case 27: res = "pair(AR6), pair(T2)"; break;
	case 31: res = "block(AR4), block(T0)"; break;
	default: res = NULL;
	}

	if(res != NULL)
		res = strdup(res);

	return res;
}

st8 *get_reg_name_3(ut32 idx) {
	st8 *res = NULL;

	switch (idx) {
	case 0: res = "AC0"; break;
	case 1: res = "AC1"; break;
	case 2: res = "AC2"; break;
	case 3: res = "AC3"; break;
	case 4: res = "AC4"; break;
	case 5: res = "AC5"; break;
	case 6: res = "AC6"; break;
	case 7: res = "AC7"; break;
	case 8: res = "AC8"; break;
	case 9: res = "AC9"; break;
	case 10: res = "AC10"; break;
	case 11: res = "AC11"; break;
	case 12: res = "AC12"; break;
	case 13: res = "AC13"; break;
	case 14: res = "AC14"; break;
	case 15: res = "AC15"; break;
	case 16: res = "AC16"; break;
	case 17: res = "AC17"; break;
	case 18: res = "AC18"; break;
	case 19: res = "AC19"; break;
	case 20: res = "AC20"; break;
	case 21: res = "AC21"; break;
	case 22: res = "AC22"; break;
	case 23: res = "AC23"; break;
	case 24: res = "AC24"; break;
	case 25: res = "AC25"; break;
	case 26: res = "AC26"; break;
	case 27: res = "AC27"; break;
	case 28: res = "AC28"; break;
	case 29: res = "AC29"; break;
	case 30: res = "AC30"; break;
	case 31: res = "AC31"; break;
	case 32: res = "XAR0"; break;
	case 33: res = "XAR1"; break;
	case 34: res = "XAR2"; break;
	case 35: res = "XAR3"; break;
	case 36: res = "XAR4"; break;
	case 37: res = "XAR5"; break;
	case 38: res = "XAR6"; break;
	case 39: res = "XAR7"; break;
	case 40: res = "XAR8"; break;
	case 41: res = "XAR9"; break;
	case 42: res = "XAR10"; break;
	case 43: res = "XAR11"; break;
	case 44: res = "XAR12"; break;
	case 45: res = "XAR13"; break;
	case 46: res = "XAR14"; break;
	case 47: res = "XAR15"; break;
	case 52: res = "XSSP"; break;
	case 53: res = "XSP"; break;
	case 54: res = "XDP"; break;
	default: res = NULL;
	}

	if (res != NULL)
		res = strdup(res);
	return res;
}


st8 *get_reg_name_2(ut32 idx) {
	st8 *res = NULL;

	switch (idx) {
	case 0: res = "AR0"; break;
	case 1: res = "AR1"; break;
	case 2: res = "AR2"; break;
	case 3: res = "AR3"; break;
	case 4: res = "AR4"; break;
	case 5: res = "AR5"; break;
	case 6: res = "AR6"; break;
	case 7: res = "AR7"; break;
	case 8: res = "AR8"; break;
	case 9: res = "AR9"; break;
	case 10: res = "AR10"; break;
	case 11: res = "AR11"; break;
	case 12: res = "AR12"; break;
	case 13: res = "AR13"; break;
	case 14: res = "AR14"; break;
	case 15: res = "AR15"; break;
	case 16: res = "T0"; break;
	case 17: res = "T1"; break;
	case 18: res = "T2"; break;
	case 19: res = "T3"; break;
	case 20: res = "SSP"; break;
	case 21: res = "SP"; break;
	case 22: res = "DP"; break;
	case 32: res = "XAR0"; break;
	case 33: res = "XAR1"; break;
	case 34: res = "XAR2"; break;
	case 35: res = "XAR3"; break;
	case 36: res = "XAR4"; break;
	case 37: res = "XAR5"; break;
	case 38: res = "XAR6"; break;
	case 39: res = "XAR7"; break;
	case 40: res = "XAR8"; break;
	case 41: res = "XAR9"; break;
	case 42: res = "XAR10"; break;
	case 43: res = "XAR11"; break;
	case 44: res = "XAR12"; break;
	case 45: res = "XAR13"; break;
	case 46: res = "XAR14"; break;
	case 47: res = "XAR15"; break;
	case 52: res = "XSSP"; break;
	case 53: res = "XSP"; break;
	case 54: res = "XDP"; break;
	default: res = NULL;
	}

	if(res != NULL)
		res = strdup(res);

	return res;
}

st8 *get_reg_name_1(ut32 idx) {
	st8 *res = NULL;

	switch (idx) {
	case 0: res = "AC0"; break;
	case 1: res = "AC1"; break;
	case 2: res = "AC2"; break;
	case 3: res = "AC3"; break;
	case 4: res = "AC4"; break;
	case 5: res = "AC5"; break;
	case 6: res = "AC6"; break;
	case 7: res = "AC7"; break;
	case 8: res = "AC8"; break;
	case 9: res = "AC9"; break;
	case 10: res = "AC10"; break;
	case 11: res = "AC11"; break;
	case 12: res = "AC12"; break;
	case 13: res = "AC13"; break;
	case 14: res = "AC14"; break;
	case 15: res = "AC15"; break;
	case 16: res = "AC16"; break;
	case 17: res = "AC17"; break;
	case 18: res = "AC18"; break;
	case 19: res = "AC19"; break;
	case 20: res = "AC20"; break;
	case 21: res = "AC21"; break;
	case 22: res = "AC22"; break;
	case 23: res = "AC23"; break;
	case 24: res = "AC24"; break;
	case 25: res = "AC25"; break;
	case 26: res = "AC26"; break;
	case 27: res = "AC27"; break;
	case 28: res = "AC28"; break;
	case 29: res = "AC29"; break;
	case 30: res = "AC30"; break;
	case 31: res = "AC31"; break;
	case 32: res = "AR0"; break;
	case 33: res = "AR1"; break;
	case 34: res = "AR2"; break;
	case 35: res = "AR3"; break;
	case 36: res = "AR4"; break;
	case 37: res = "AR5"; break;
	case 38: res = "AR6"; break;
	case 39: res = "AR7"; break;
	case 40: res = "AR8"; break;
	case 41: res = "AR9"; break;
	case 42: res = "AR10"; break;
	case 43: res = "AR11"; break;
	case 44: res = "AR12"; break;
	case 45: res = "AR13"; break;
	case 46: res = "AR14"; break;
	case 47: res = "AR15"; break;
	case 48: res = "T0"; break;
	case 49: res = "T1"; break;
	case 50: res = "T2"; break;
	case 51: res = "T3"; break;
	case 52: res = "SSP"; break;
	case 53: res = "SP"; break;
	case 54: res = "DP"; break;
	case 56: res = "CSR"; break;
	case 57: res = "RPTC"; break;
	case 58: res = "BRC0"; break;
	case 59: res = "BRC1"; break;
	case 62: res = "CONFIG"; break;
	case 63: res = "CPUREV"; break;
	case 64: res = "AC0.H"; break;
	case 65: res = "AC1.H"; break;
	case 66: res = "AC2.H"; break;
	case 67: res = "AC3.H"; break;
	case 68: res = "AC4.H"; break;
	case 69: res = "AC5.H"; break;
	case 70: res = "AC6.H"; break;
	case 71: res = "AC7.H"; break;
	case 72: res = "AC8.H"; break;
	case 73: res = "AC9.H"; break;
	case 74: res = "AC10.H"; break;
	case 75: res = "AC11.H"; break;
	case 76: res = "AC12.H"; break;
	case 77: res = "AC13.H"; break;
	case 78: res = "AC14.H"; break;
	case 79: res = "AC15.H"; break;
	case 80: res = "AC16.H"; break;
	case 81: res = "AC17.H"; break;
	case 82: res = "AC18.H"; break;
	case 83: res = "AC19.H"; break;
	case 84: res = "AC20.H"; break;
	case 85: res = "AC21.H"; break;
	case 86: res = "AC22.H"; break;
	case 87: res = "AC23.H"; break;
	case 88: res = "AC24.H"; break;
	case 89: res = "AC25.H"; break;
	case 90: res = "AC26.H"; break;
	case 91: res = "AC27.H"; break;
	case 92: res = "AC28.H"; break;
	case 93: res = "AC29.H"; break;
	case 94: res = "AC30.H"; break;
	case 95: res = "AC31.H"; break;
	case 96: res = "AC0.L"; break;
	case 97: res = "AC1.L"; break;
	case 98: res = "AC2.L"; break;
	case 99: res = "AC3.L"; break;
	case 100: res = "AC4.L"; break;
	case 101: res = "AC5.L"; break;
	case 102: res = "AC6.L"; break;
	case 103: res = "AC7.L"; break;
	case 104: res = "AC8.L"; break;
	case 105: res = "AC9.L"; break;
	case 106: res = "AC10.L"; break;
	case 107: res = "AC11.L"; break;
	case 108: res = "AC12.L"; break;
	case 109: res = "AC13.L"; break;
	case 110: res = "AC14.L"; break;
	case 111: res = "AC15.L"; break;
	case 112: res = "AC16.L"; break;
	case 113: res = "AC17.L"; break;
	case 114: res = "AC18.L"; break;
	case 115: res = "AC19.L"; break;
	case 116: res = "AC20.L"; break;
	case 117: res = "AC21.L"; break;
	case 118: res = "AC22.L"; break;
	case 119: res = "AC23.L"; break;
	case 120: res = "AC24.L"; break;
	case 121: res = "AC25.L"; break;
	case 122: res = "AC26.L"; break;
	case 123: res = "AC27.L"; break;
	case 124: res = "AC28.L"; break;
	case 125: res = "AC29.L"; break;
	case 126: res = "AC30.L"; break;
	case 127: res = "AC31.L"; break;
	case 128: res = "XAR0"; break;
	case 129: res = "XAR1"; break;
	case 130: res = "XAR2"; break;
	case 131: res = "XAR3"; break;
	case 132: res = "XAR4"; break;
	case 133: res = "XAR5"; break;
	case 134: res = "XAR6"; break;
	case 135: res = "XAR7"; break;
	case 136: res = "XAR8"; break;
	case 137: res = "XAR9"; break;
	case 138: res = "XAR10"; break;
	case 139: res = "XAR11"; break;
	case 140: res = "XAR12"; break;
	case 141: res = "XAR13"; break;
	case 142: res = "XAR14"; break;
	case 143: res = "XAR15"; break;
	case 148: res = "XSSP"; break;
	case 149: res = "XSP"; break;
	case 150: res = "XDP"; break;
	case 152: res = "RSA0"; break;
	case 153: res = "RSA1"; break;
	case 154: res = "REA0"; break;
	case 155: res = "REA1"; break;
	case 156: res = "DBGPADDR"; break;
	case 157: res = "DBGPDATA"; break;
	case 159: res = "RETA"; break;
	case 160: res = "XAR0.H"; break;
	case 161: res = "XAR1.H"; break;
	case 162: res = "XAR2.H"; break;
	case 163: res = "XAR3.H"; break;
	case 164: res = "XAR4.H"; break;
	case 165: res = "XAR5.H"; break;
	case 166: res = "XAR6.H"; break;
	case 167: res = "XAR7.H"; break;
	case 168: res = "XAR8.H"; break;
	case 169: res = "XAR9.H"; break;
	case 170: res = "XAR10.H"; break;
	case 171: res = "XAR11.H"; break;
	case 172: res = "XAR12.H"; break;
	case 173: res = "XAR13.H"; break;
	case 174: res = "XAR14.H"; break;
	case 175: res = "XAR15.H"; break;
	case 180: res = "XSSP.H"; break;
	case 181: res = "XSP.H"; break;
	case 182: res = "XDP.H"; break;
	case 183: res = "PDP"; break;
	case 184: res = "BSA01"; break;
	case 185: res = "BSA23"; break;
	case 186: res = "BSA45"; break;
	case 187: res = "BSA67"; break;
	case 188: res = "BSAC"; break;
	case 189: //res = (st8 *)&off_42FBE8;
		res = "BKC";
		break;
	case 190: res = "BK03"; break;
	case 191: res = "BK47"; break;
	case 192: res = "AC0.G"; break;
	case 193: res = "AC1.G"; break;
	case 194: res = "AC2.G"; break;
	case 195: res = "AC3.G"; break;
	case 196: res = "AC4.G"; break;
	case 197: res = "AC5.G"; break;
	case 198: res = "AC6.G"; break;
	case 199: res = "AC7.G"; break;
	case 200: res = "AC8.G"; break;
	case 201: res = "AC9.G"; break;
	case 202: res = "AC10.G"; break;
	case 203: res = "AC11.G"; break;
	case 204: res = "AC12.G"; break;
	case 205: res = "AC13.G"; break;
	case 206: res = "AC14.G"; break;
	case 207: res = "AC15.G"; break;
	case 208: res = "AC16.G"; break;
	case 209: res = "AC17.G"; break;
	case 210: res = "AC18.G"; break;
	case 211: res = "AC19.G"; break;
	case 212: res = "AC20.G"; break;
	case 213: res = "AC21.G"; break;
	case 214: res = "AC22.G"; break;
	case 215: res = "AC23.G"; break;
	case 216: res = "AC24.G"; break;
	case 217: res = "AC25.G"; break;
	case 218: res = "AC26.G"; break;
	case 219: res = "AC27.G"; break;
	case 220: res = "AC28.G"; break;
	case 221: res = "AC29.G"; break;
	case 222: res = "AC30.G"; break;
	case 223: res = "AC31.G"; break;
	case 224: res = "ST0"; break;
	case 225: res = "ST1"; break;
	case 226: res = "ST2"; break;
	case 227: res = "ST3"; break;
	case 228: res = "ST0_55"; break;
	case 229: res = "ST1_55"; break;
	case 231: res = "ST3_55"; break;
	case 232: res = "IER0"; break;
	case 233: res = "IER1"; break;
	case 234: res = "IFR0"; break;
	case 235: res = "IFR1"; break;
	case 236: res = "DBIER0"; break;
	case 237: res = "DBIER1"; break;
	case 238: res = "IVPD"; break;
	case 239: res = "IVPH"; break;
	case 240: res = "RSA0.H"; break;
	case 241: res = "RSA1.H"; break;
	case 242: res = "REA0.H"; break;
	case 243: res = "REA1.H"; break;
	case 244: res = "BIOS"; break;
	case 245: res = "BRS1"; break;
	case 246: res = "IIR"; break;
	case 247: res = "BER"; break;
	case 248: res = "RSA0.L"; break;
	case 249: res = "RSA1.L"; break;
	case 250: res = "REA0.L"; break;
	case 251: res = "REA1.L"; break;
	case 252: res = "TSDR"; break;
	default: res = NULL;
	}

	if(res != NULL)
		res = strdup(res);

	return res;
}


st8 *get_status_regs_and_bits(st8 *reg_arg, int reg_bit)
{
  st8 *res = NULL;

  if(!strncmp(reg_arg, "ST0", 3)) {
    switch(reg_bit) {
	case 0:
		res = "ST0_DP07";
		break;
	case 1:
		res = "ST0_DP08";
		break;
	case 2:
		res = "ST0_DP09";
		break;
	case 3:
		res = "ST0_DP10";
		break;
	case 4:
		res = "ST0_DP11";
		break;
	case 5:
		res = "ST0_DP12";
		break;
	case 6:
		res = "ST0_DP13";
		break;
	case 7:
		res = "ST0_DP14";
		break;
	case 8:
		res = "ST0_DP15";
		break;
	case 9:
		res = "ST0_ACOV1";
		break;
	case 10:
		res = "ST0_ACOV0";
		break;
	case 11:
		res = "ST0_CARRY";
		break;
	case 12:
		res = "ST0_TC2";
		break;
	case 13:
		res = "ST0_TC1";
		break;
	case 14:
		res = "ST0_ACOV3";
		break;
	case 15:
		res = "ST0_ACOV2";
		break;
    }
  } else if(!strncmp(reg_arg, "ST1", 3)) {
		switch(reg_bit) {
		case 0:
			res = "ST1_DR2_00";
			break;
		case 1:
			res =  "ST1_DR2_01";
			break;
		case 2:
			res = "ST1_DR2_02";
			break;
		case 3:
			res = "ST1_DR2_03";
			break;
		case 4:
			res = "ST1_DR2_04";
			break;
		case 5:
			res = "ST1_C54CM";
			break;
		case 6:
			res = "ST1_FRCT";
			break;
		case 7:
			res = "ST1_C16";
			break;
		case 8:
			res = "ST1_SXMD";
			break;
		case 9:
			res = "ST1_SATD";
			break;
		case 10:
			res = "ST1_M40";
			break;
		case 11:
			res = "ST1_INTM";
			break;
		case 12:
			res = "ST1_HM";
			break;
		case 13:
			res = "ST1_XF";
			break;
		case 14:
			res = "ST1_CPL";
			break;
		case 15:
			res = "ST1_BRAF";
			break;
      }
  } else if(!strncmp(reg_arg, "ST2", 3)) {
		switch ( reg_bit ) {
		case 0:
			res = "ST2_AR0LC";
			break;
		case 1:
			res = "ST2_AR1LC";
			break;
		case 2:
			res = "ST2_AR2LC";
			break;
		case 3:
			res = "ST2_AR3LC";
			break;
		case 4:
			res = "ST2_AR4LC";
			break;
		case 5:
			res = "ST2_AR5LC";
			break;
		case 6:
			res = "ST2_AR6LC";
			break;
		case 7:
			res = "ST2_AR7LC";
			break;
		case 8:
			res = "ST2_CDPLC";
			break;
		case 9:
			res = "ST2_GOVF";
			break;
		case 10:
			res = "ST2_RDM";
			break;
		case 11:
			res = "ST2_EALLOW";
			break;
		case 12:
			res = "ST2_DBGM";
			break;
		case 13:
			res = "ST2_XCND";
			break;
		case 14:
			res = "ST2_XCNA";
			break;
		case 15:
			res = "ST2_ARMS";
			break;
       }
  } else if (!strncmp(reg_arg, "ST3", 3)) {
		switch (reg_bit) {
		case 0:
			res = "ST3_SST";
			break;
		case 1:
			res = "ST3_SMUL";
			break;
		case 2:
			res = "ST3_CLKOFF";
			break;
		case 3:
			res = "ST3_BPTR";
			break;
		case 4:
			res = "ST3_AVIS";
			break;
		case 5:
			res = "ST3_SATA";
			break;
		case 6:
			res = "ST3_MPNMC";
			break;
		case 7:
			res = "ST3_CBERR";
			break;
		case 8:
			res = "ST3_HOMP";
			break;
		case 9:
			res = "ST3_HOMR";
			break;
		case 10:
			res = "ST3_HOMX";
			break;
		case 11:
			res = "ST3_HOMY";
			break;
		case 12:
			res = "ST3_HINT";
			break;
		case 13:
			res = "ST3_CACLR";
			break;
		case 14:
			res = "ST3_CAEN";
			break;
		case 15:
			res = "ST3_CAFRZ";
			break;
        }
  }

  if(res != NULL)
	res = strdup(res);

  return res;
}


st8 *get_reg_name_4(ut32 idx)
{
  st8 *res = NULL;

  switch(idx) {

    case 0:
      res = "AC0";
      break;
    case 1:
      res = "AC1";
      break;
    case 2:
      res = "AC2";
      break;
    case 3:
      res = "AC3";
      break;
    case 4:
      res = "AC4";
      break;
    case 5:
      res = "AC5";
      break;
    case 6:
      res = "AC6";
      break;
    case 7:
      res = "AC7";
      break;
    case 8:
      res = "T0";
      break;
    case 9:
      res = "T1";
      break;
    case 10:
      res = "T2";
      break;
    case 11:
      res = "T3";
      break;
    case 16:
      res = "AR0";
      break;
    case 17:
      res = "AR1";
      break;
    case 18:
      res = "AR2";
      break;
    case 19:
      res = "AR3";
      break;
    case 20:
      res = "AR4";
      break;
    case 21:
      res = "AR5";
      break;
    case 22:
      res = "AR6";
      break;
    case 23:
      res = "AR7";
      break;
    case 24:
      res = "AC0.L";
      break;
    case 25:
      res = "AC1.L";
      break;
    case 26:
      res = "AC2.L";
      break;
    case 27:
      res = "AC3.L";
      break;
    case 28:
      res = "AC4.L";
      break;
    case 29:
      res = "AC5.L";
      break;
    case 30:
      res = "AC6.L";
      break;
    case 31:
      res = "AC7.L";
      break;
  }

  if(res != NULL)
	res = strdup(res);

  return res;
}

st8 *get_opers(ut8 oper_byte)
{
  st8 *res;
  ut8 oper_type;
  st8 *reg_name;

  res = NULL;
  switch (oper_byte) {
    case 0xE0u:
      res = strdup("overflow(AC0)");
      break;

    case 0xE1u:
      res = strdup("overflow(AC1)");
      break;

    case 0xE2u:
      res = strdup("overflow(AC2)");
      break;

    case 0xE3u:
      res = strdup("overflow(AC3)");
      break;

    case 0xE4u:
      res = strdup("TC1");
      break;

    case 0xE5u:
      res = strdup("TC2");
      break;

    case 0xE6u:
      res = strdup("Carry");
      break;

    case 0xE7u:
      res = strdup("overflow(GOVF)");
      break;

    case 0xE8u:
      res = strdup("TC1 & TC2");
      break;

    case 0xE9u:
      res = strdup("TC1 & !TC2");
      break;

    case 0xEAu:
      res = strdup("!TC1 & TC2");
      break;

    case 0xEBu:
      res = strdup("!TC1 & !TC2");
      break;

    case 0xECu:
      res = strdup("word_mode");
      break;

    case 0xEDu:
      res = strdup("byte_mode");
      break;

    case 0xF0u:
      res = strdup("!overflow(AC0)");
      break;

    case 0xF1u:
      res = strdup("!overflow(AC1)");
      break;

    case 0xF2u:
      res = strdup("!overflow(AC2)");
      break;

    case 0xF3u:
      res = strdup("!overflow(AC3)");
      break;

    case 0xF4u:
      res = strdup("!TC1");
      break;

    case 0xF5u:
      res = strdup("!TC2");
      break;

    case 0xF6u:
      res = strdup("!Carry");
      break;

    case 0xF7u:
      res = strdup("!overflow(GOVF)");
      break;

    case 0xF8u:
      res = strdup("TC1 | TC2");
      break;

    case 0xF9u:
      res = strdup("TC1 | !TC2");
      break;

    case 0xFAu:
      res = strdup("!TC1 | TC2");
      break;

    case 0xFBu:
      res = strdup("!TC1 | !TC2");
      break;

    case 0xFCu:
      res = strdup("TC1 ^ TC2");
      break;

    case 0xFDu:
      res = strdup("TC1 ^ !TC2");
      break;

    case 0xFEu:
      res = strdup("!TC1 ^ TC2");
      break;

    case 0xFFu:
      res = strdup("!TC1 ^ !TC2");
      break;

	default:
		oper_type = oper_byte >> 5;
		if (oper_type != 6 ) {
			reg_name = get_reg_name_4(oper_byte & 0x1F);
		    switch (oper_type)
	        {
			case 1u:
				res = strcat_dup(reg_name, " != #0", 1);
				break;
			case 0u:
				res = strcat_dup(reg_name, " == #0", 1);
				break;
			case 2u:
				res =  strcat_dup(reg_name, " < #0", 1);
				break;
			case 3u:
				res =  strcat_dup(reg_name, " >= #0", 1);
				break;
			case 4u:
				res =  strcat_dup(reg_name, " > #0", 1);
				break;
			case 5u:
				res =  strcat_dup(reg_name, " <= #0", 1);
			}
			// free (reg_name); Causes segfault
			// TODO: still can leak
			return res;
		}
		reg_name = get_reg_name_1((oper_byte & 0xF) + 128);
		oper_type = (oper_byte >> 4) - 12;
		if (oper_type) {
			if ( oper_type != 1 ) {
				free (reg_name);
				return NULL;
			}
			res = strcat_dup(reg_name, " != #0", 1);
		} else {
			res = strcat_dup(reg_name, " == #0", 1);
		}
    }

    return res;
}

st8 *get_cmp_op(ut32 idx) {
	st8 *res = NULL;

	switch (idx) {
	case 0: res = "=="; break;
	case 1: res = "!="; break;
	case 2: res = "<"; break;
	case 3: res = ">="; break;
	}

	if (res != NULL)
		res = strdup(res);
	return res;
}

st8 *get_sim_reg(st8 *reg_arg, ut32 ins_bits) {
	st32 code;
	st8 *res = NULL;
	st8 *aux;

	code = ins_bits & 3;
	switch (code) {
	case 0:
		if(reg_arg && strchr(reg_arg, 'w')) {
			if(code == 62)
				return strdup("SIM0");

			if(code == 63)
				return strdup("SIM0");
		}
		aux = get_reg_name_1(ins_bits >> 2);
		res = strcat_dup("@", aux, 2);
		break;
	case 2:
		aux = (st8 *)malloc(50);
		if(aux == NULL)
			return NULL;

		sprintf(aux, "@#0x%x", code);
		res = aux;
		break;
	case 1:
	case 3:
		res = strdup("<reserved>");
		break;
	}

	return res;
}
