/* c55plus - LGPL3 - Copyright 2013 - th0rpe */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ins.h"
#include "utils.h"

char *get_tc2_tc1(ut32 ins_bits) {
	char *res = "tc1";
	if (ins_bits) {
		if (ins_bits != 1) {
			fprintf(stderr, "Invalid instruction TC2 or TC1 (%d)\n", ins_bits);
			return NULL;
		}
		res = "tc2";
	}
	return strdup (res);
}

char *get_trans_reg(ut32 ins_bits) {
	char *res = NULL;

	switch (ins_bits) {
	case 6:
		res = "trn0";
		break;
	case 7:
		res = "trn1";
		break;
	case 4:
		res = "trn2";
		break;
	case 5:
		res = "trn3";
		break;
	case 2:
		res = "trn4";
		break;
	case 3:
		res = "trn5";
		break;
	case 0:
		res = "trn6";
		break;
	case 1:
		res = "trn7";
		break;

	default:
		fprintf (stderr, "Invalid transaction instruction 0x%x\n", ins_bits);
	}
	return res? strdup (res): NULL;
}

char *get_AR_regs_class1(ut32 ins_bits) {
	ut32 op = (ins_bits >> 4) & 7;
	char *res = (char *)calloc (1, 50);
	if (!res) {
		return NULL;
	}
	switch (op) {
	case 0:
		sprintf(res, "*ar-%ld", (long int)ins_bits & 0xF);
		break;
	case 1:
		sprintf(res, "*ar+%ld", (long int)ins_bits & 0xF);
		break;
	case 2:
		sprintf(res, "*ar%ld(t0)", (long int)ins_bits & 0xF);
		break;
	case 3:
		sprintf(res, "*ar%ld", (long int)ins_bits & 0xF);
		break;
	case 4:
		sprintf(res, "*(ar%ld-t0)", (long int)ins_bits & 0xF);
		break;
	case 5:
		sprintf(res, "*(ar%ld-t1)", (long int)ins_bits & 0xF);
		break;
	case 6:
		sprintf(res, "*(ar%ld+t0)", (long int)ins_bits & 0xF);
		break;
	case 7:
		sprintf(res, "*(ar%ld+t1)", (long int)ins_bits & 0xF);
		break;
	}
	return res;
}

char *get_AR_regs_class2(ut32 ins_bits, ut32 *ret_len, ut32 ins_pos, ut32 idx) {
	ut8 op, op2, reg_num, type;
	char *res = NULL;

	op = ins_bits >> 6;
	op2 = ins_bits & 3;
	reg_num = (ins_bits >> 2) & 0xF;
	if (ret_len) {
		*ret_len = 0;
	}
	//printf("OP1 %x OP2 0x%x %x\n", op, op2, reg_num);
	res = malloc(50);
	if (!res) {
		return NULL;
	}	
	if(op2 == 2) {
		if(op) {
			sprintf (res, "*ar%ld(short(#0x%lx))",
				 (long int)reg_num, (long int)idx * op);
		} else {
			sprintf(res, "*ar%ld", (long int)reg_num);
		}
	} else {
		type = (op >> 3 | 2 * op2);
		if(type == 6) {
			sprintf(res, "@#0x%lx", (long int)idx * (reg_num | 16 * (op & 7)));
		} else if(type == 7) {
			sprintf(res, "*sp(#0x%lx)", (long int)idx * (reg_num | 16 * (op & 7)));
		} else {
			type = idx | 16 * op;
			switch(type) {
			case 0:
				sprintf(res, "*ar%ld-", (long int)reg_num);
				break;
			case 1:
				sprintf(res, "*ar%ld+", (long int)reg_num);
				break;
			case 2:
				sprintf(res, "*ar%ld(t0)", (long int)reg_num);
				break;
			case 3:
				sprintf(res, "*ar%ld(t1)", (long int)reg_num);
				break;
			case 4:
				sprintf(res, "*(ar%ld-t0)", (long int)reg_num);
				break;
			case 5:
				sprintf(res, "*(ar%ld-t1)", (long int)reg_num);
				break;
			case 6:
				sprintf(res, "*(ar%ld+t0)", (long int)reg_num);
				break;
			case 7:
				sprintf(res, "*(ar%ld+t1)", (long int)reg_num);
				break;
			case 8:
				sprintf(res, "*-ar%ld", (long int)reg_num);
				break;
			case 9:
				sprintf(res, "*+ar%ld", (long int)reg_num);
				break;
			case 10:
				sprintf(res, "*ar%ld(t2)", (long int)reg_num);
				break;
			case 11:
				sprintf(res, "*ar%ld(t3)", (long int)reg_num);
				break;
			case 12:
				sprintf(res, "*(ar%ld-t2)", (long int)reg_num);
				break;
			case 13:
				sprintf(res, "*(ar%ld-t3)", (long int)reg_num);
				break;
			case 14:
				sprintf(res, "*(ar%ld+t2)", (long int)reg_num);
				break;
			case 15:
				sprintf(res, "*(ar%ld+t3)", (long int)reg_num);
				break;
			case 16:
				sprintf(res, "*(ar%ld-t0b)", (long int)reg_num);
				break;
			case 17:
				sprintf(res, "*(ar%ld+t0b)", (long int)reg_num);
				break;
			case 18:
				sprintf(res, "*ar%ld(t0<<#1)", (long int)reg_num);
				break;
			case 19:
				sprintf(res, "*ar%ld(t1<<#1)", (long int)reg_num);
				break;
			case 23:
				sprintf(res, "*ar%ld(xar15)", (long int)reg_num);
				break;

			case 24:
			case 25:
			case 26:
			case 27:
				idx = get_ins_part(ins_pos, 2);
				if(ret_len) {
					*ret_len = 2;
				}
				switch (type) {
				case 24:
					sprintf(res, "*ar%ld(#%ld)", (long int)reg_num, (long int)op * idx);
					break;
				case 25:
					sprintf(res, "*+ar%ld(#%ld)", (long int)reg_num, (long int)op * idx);
					break;
				case 26:
					sprintf(res, "*abs16(#0x%lx)", (long int)idx);
					break;
				default:
					sprintf(res, "*port(#0x%lx)",  (long int)idx);
					break;
				}
				break;
			case 28:
			case 29:
			case 30:
				idx = get_ins_part(ins_pos, 3);
				if(ret_len) {
					*ret_len = 3;
				}
				switch (type) {
				case 28:
					sprintf(res, "*ar%ld(#0x%lx)", (long int)reg_num, (long int)idx * op);
					break;
				case 29:
					sprintf(res, "*+ar%ld(#0x%lx)", (long int)reg_num, (long int)idx * op);
					break;
				default:
					sprintf(res, "*(#0x%lx)", (long int)idx);
					break;
				}

				break;
			}
		}
	}

	return res;
}

char *get_reg_pair(ut32 idx) {
	char *res = NULL;

	switch (idx) {
	case 1: res = "ac0, ac2"; break;
	case 2: res = "ac1, ac3"; break;
	case 3: res = "pair(ac0), pair(ac2)"; break;
	case 4: res = "ar0, ar1"; break;
	case 5: res = "ar0, ar2"; break;
	case 6: res = "ar1, ar3"; break;
	case 7: res = "pair(ar0), pair(ar2)"; break;
	case 9: res = "t0, t2"; break;
	case 10: res = "t1, t3"; break;
	case 11: res = "pair(t0), pair(t2)"; break;
	case 21: res = "ar4, t0"; break;
	case 22: res = "ar5, t1"; break;
	case 23: res = "pair(ar4), pair(t0)"; break;
	case 25: res = "ar6, t2"; break;
	case 26: res = "ar7, t3"; break;
	case 27: res = "pair(ar6), pair(t2)"; break;
	case 31: res = "block(ar4), block(t0)"; break;
	default: res = NULL;
	}

	if (res != NULL) {
		res = strdup (res);
	}

	return res;
}

char *get_reg_name_3(ut32 idx) {
	char *res = NULL;

	switch (idx) {
	case 0: res = "ac0"; break;
	case 1: res = "ac1"; break;
	case 2: res = "ac2"; break;
	case 3: res = "ac3"; break;
	case 4: res = "ac4"; break;
	case 5: res = "ac5"; break;
	case 6: res = "ac6"; break;
	case 7: res = "ac7"; break;
	case 8: res = "ac8"; break;
	case 9: res = "ac9"; break;
	case 10: res = "ac10"; break;
	case 11: res = "ac11"; break;
	case 12: res = "ac12"; break;
	case 13: res = "ac13"; break;
	case 14: res = "ac14"; break;
	case 15: res = "ac15"; break;
	case 16: res = "ac16"; break;
	case 17: res = "ac17"; break;
	case 18: res = "ac18"; break;
	case 19: res = "ac19"; break;
	case 20: res = "ac20"; break;
	case 21: res = "ac21"; break;
	case 22: res = "ac22"; break;
	case 23: res = "ac23"; break;
	case 24: res = "ac24"; break;
	case 25: res = "ac25"; break;
	case 26: res = "ac26"; break;
	case 27: res = "ac27"; break;
	case 28: res = "ac28"; break;
	case 29: res = "ac29"; break;
	case 30: res = "ac30"; break;
	case 31: res = "ac31"; break;
	case 32: res = "xar0"; break;
	case 33: res = "xar1"; break;
	case 34: res = "xar2"; break;
	case 35: res = "xar3"; break;
	case 36: res = "xar4"; break;
	case 37: res = "xar5"; break;
	case 38: res = "xar6"; break;
	case 39: res = "xar7"; break;
	case 40: res = "xar8"; break;
	case 41: res = "xar9"; break;
	case 42: res = "xar10"; break;
	case 43: res = "xar11"; break;
	case 44: res = "xar12"; break;
	case 45: res = "xar13"; break;
	case 46: res = "xar14"; break;
	case 47: res = "xar15"; break;
	case 52: res = "xssp"; break;
	case 53: res = "xsp"; break;
	case 54: res = "xdp"; break;
	default: res = NULL;
	}

	if (res != NULL) {
		res = strdup (res);
	}
	return res;
}


char *get_reg_name_2(ut32 idx) {
	char *res = NULL;

	switch (idx) {
	case 0: res = "ar0"; break;
	case 1: res = "ar1"; break;
	case 2: res = "ar2"; break;
	case 3: res = "ar3"; break;
	case 4: res = "ar4"; break;
	case 5: res = "ar5"; break;
	case 6: res = "ar6"; break;
	case 7: res = "ar7"; break;
	case 8: res = "ar8"; break;
	case 9: res = "ar9"; break;
	case 10: res = "ar10"; break;
	case 11: res = "ar11"; break;
	case 12: res = "ar12"; break;
	case 13: res = "ar13"; break;
	case 14: res = "ar14"; break;
	case 15: res = "ar15"; break;
	case 16: res = "t0"; break;
	case 17: res = "t1"; break;
	case 18: res = "t2"; break;
	case 19: res = "t3"; break;
	case 20: res = "ssp"; break;
	case 21: res = "sp"; break;
	case 22: res = "dp"; break;
	case 32: res = "xar0"; break;
	case 33: res = "xar1"; break;
	case 34: res = "xar2"; break;
	case 35: res = "xar3"; break;
	case 36: res = "xar4"; break;
	case 37: res = "xar5"; break;
	case 38: res = "xar6"; break;
	case 39: res = "xar7"; break;
	case 40: res = "xar8"; break;
	case 41: res = "xar9"; break;
	case 42: res = "xar10"; break;
	case 43: res = "xar11"; break;
	case 44: res = "xar12"; break;
	case 45: res = "xar13"; break;
	case 46: res = "xar14"; break;
	case 47: res = "xar15"; break;
	case 52: res = "xssp"; break;
	case 53: res = "xsp"; break;
	case 54: res = "xdp"; break;
	default: res = NULL;
	}

	if (res != NULL) {
		res = strdup (res);
	}

	return res;
}

char *get_reg_name_1(ut32 idx) {
	char *res = NULL;

	switch (idx) {
	case 0: res = "ac0"; break;
	case 1: res = "ac1"; break;
	case 2: res = "ac2"; break;
	case 3: res = "ac3"; break;
	case 4: res = "ac4"; break;
	case 5: res = "ac5"; break;
	case 6: res = "ac6"; break;
	case 7: res = "ac7"; break;
	case 8: res = "ac8"; break;
	case 9: res = "ac9"; break;
	case 10: res = "ac10"; break;
	case 11: res = "ac11"; break;
	case 12: res = "ac12"; break;
	case 13: res = "ac13"; break;
	case 14: res = "ac14"; break;
	case 15: res = "ac15"; break;
	case 16: res = "ac16"; break;
	case 17: res = "ac17"; break;
	case 18: res = "ac18"; break;
	case 19: res = "ac19"; break;
	case 20: res = "ac20"; break;
	case 21: res = "ac21"; break;
	case 22: res = "ac22"; break;
	case 23: res = "ac23"; break;
	case 24: res = "ac24"; break;
	case 25: res = "ac25"; break;
	case 26: res = "ac26"; break;
	case 27: res = "ac27"; break;
	case 28: res = "ac28"; break;
	case 29: res = "ac29"; break;
	case 30: res = "ac30"; break;
	case 31: res = "ac31"; break;
	case 32: res = "ar0"; break;
	case 33: res = "ar1"; break;
	case 34: res = "ar2"; break;
	case 35: res = "ar3"; break;
	case 36: res = "ar4"; break;
	case 37: res = "ar5"; break;
	case 38: res = "ar6"; break;
	case 39: res = "ar7"; break;
	case 40: res = "ar8"; break;
	case 41: res = "ar9"; break;
	case 42: res = "ar10"; break;
	case 43: res = "ar11"; break;
	case 44: res = "ar12"; break;
	case 45: res = "ar13"; break;
	case 46: res = "ar14"; break;
	case 47: res = "ar15"; break;
	case 48: res = "t0"; break;
	case 49: res = "t1"; break;
	case 50: res = "t2"; break;
	case 51: res = "t3"; break;
	case 52: res = "ssp"; break;
	case 53: res = "sp"; break;
	case 54: res = "dp"; break;
	case 56: res = "csr"; break;
	case 57: res = "rptc"; break;
	case 58: res = "brc0"; break;
	case 59: res = "brc1"; break;
	case 62: res = "config"; break;
	case 63: res = "cpurev"; break;
	case 64: res = "ac0.h"; break;
	case 65: res = "ac1.h"; break;
	case 66: res = "ac2.h"; break;
	case 67: res = "ac3.h"; break;
	case 68: res = "ac4.h"; break;
	case 69: res = "ac5.h"; break;
	case 70: res = "ac6.h"; break;
	case 71: res = "ac7.h"; break;
	case 72: res = "ac8.h"; break;
	case 73: res = "ac9.h"; break;
	case 74: res = "ac10.h"; break;
	case 75: res = "ac11.h"; break;
	case 76: res = "ac12.h"; break;
	case 77: res = "ac13.h"; break;
	case 78: res = "ac14.h"; break;
	case 79: res = "ac15.h"; break;
	case 80: res = "ac16.h"; break;
	case 81: res = "ac17.h"; break;
	case 82: res = "ac18.h"; break;
	case 83: res = "ac19.h"; break;
	case 84: res = "ac20.h"; break;
	case 85: res = "ac21.h"; break;
	case 86: res = "ac22.h"; break;
	case 87: res = "ac23.h"; break;
	case 88: res = "ac24.h"; break;
	case 89: res = "ac25.h"; break;
	case 90: res = "ac26.h"; break;
	case 91: res = "ac27.h"; break;
	case 92: res = "ac28.h"; break;
	case 93: res = "ac29.h"; break;
	case 94: res = "ac30.h"; break;
	case 95: res = "ac31.h"; break;
	case 96: res = "ac0.l"; break;
	case 97: res = "ac1.l"; break;
	case 98: res = "ac2.l"; break;
	case 99: res = "ac3.l"; break;
	case 100: res = "ac4.l"; break;
	case 101: res = "ac5.l"; break;
	case 102: res = "ac6.l"; break;
	case 103: res = "ac7.l"; break;
	case 104: res = "ac8.l"; break;
	case 105: res = "ac9.l"; break;
	case 106: res = "ac10.l"; break;
	case 107: res = "ac11.l"; break;
	case 108: res = "ac12.l"; break;
	case 109: res = "ac13.l"; break;
	case 110: res = "ac14.l"; break;
	case 111: res = "ac15.l"; break;
	case 112: res = "ac16.l"; break;
	case 113: res = "ac17.l"; break;
	case 114: res = "ac18.l"; break;
	case 115: res = "ac19.l"; break;
	case 116: res = "ac20.l"; break;
	case 117: res = "ac21.l"; break;
	case 118: res = "ac22.l"; break;
	case 119: res = "ac23.l"; break;
	case 120: res = "ac24.l"; break;
	case 121: res = "ac25.l"; break;
	case 122: res = "ac26.l"; break;
	case 123: res = "ac27.l"; break;
	case 124: res = "ac28.l"; break;
	case 125: res = "ac29.l"; break;
	case 126: res = "ac30.l"; break;
	case 127: res = "ac31.l"; break;
	case 128: res = "xar0"; break;
	case 129: res = "xar1"; break;
	case 130: res = "xar2"; break;
	case 131: res = "xar3"; break;
	case 132: res = "xar4"; break;
	case 133: res = "xar5"; break;
	case 134: res = "xar6"; break;
	case 135: res = "xar7"; break;
	case 136: res = "xar8"; break;
	case 137: res = "xar9"; break;
	case 138: res = "xar10"; break;
	case 139: res = "xar11"; break;
	case 140: res = "xar12"; break;
	case 141: res = "xar13"; break;
	case 142: res = "xar14"; break;
	case 143: res = "xar15"; break;
	case 148: res = "xssp"; break;
	case 149: res = "xsp"; break;
	case 150: res = "xdp"; break;
	case 152: res = "rsa0"; break;
	case 153: res = "rsa1"; break;
	case 154: res = "rea0"; break;
	case 155: res = "rea1"; break;
	case 156: res = "dbgpaddr"; break;
	case 157: res = "dbgpdata"; break;
	case 159: res = "reta"; break;
	case 160: res = "xar0.h"; break;
	case 161: res = "xar1.h"; break;
	case 162: res = "xar2.h"; break;
	case 163: res = "xar3.h"; break;
	case 164: res = "xar4.h"; break;
	case 165: res = "xar5.h"; break;
	case 166: res = "xar6.h"; break;
	case 167: res = "xar7.h"; break;
	case 168: res = "xar8.h"; break;
	case 169: res = "xar9.h"; break;
	case 170: res = "xar10.h"; break;
	case 171: res = "xar11.h"; break;
	case 172: res = "xar12.h"; break;
	case 173: res = "xar13.h"; break;
	case 174: res = "xar14.h"; break;
	case 175: res = "xar15.h"; break;
	case 180: res = "xssp.h"; break;
	case 181: res = "xsp.h"; break;
	case 182: res = "xdp.h"; break;
	case 183: res = "pdp"; break;
	case 184: res = "bsa01"; break;
	case 185: res = "bsa23"; break;
	case 186: res = "bsa45"; break;
	case 187: res = "bsa67"; break;
	case 188: res = "bsac"; break;
	case 189: //res = (char *)&off_42FBE8;
		res = "bkc";
		break;
	case 190: res = "bk03"; break;
	case 191: res = "bk47"; break;
	case 192: res = "ac0.g"; break;
	case 193: res = "ac1.g"; break;
	case 194: res = "ac2.g"; break;
	case 195: res = "ac3.g"; break;
	case 196: res = "ac4.g"; break;
	case 197: res = "ac5.g"; break;
	case 198: res = "ac6.g"; break;
	case 199: res = "ac7.g"; break;
	case 200: res = "ac8.g"; break;
	case 201: res = "ac9.g"; break;
	case 202: res = "ac10.g"; break;
	case 203: res = "ac11.g"; break;
	case 204: res = "ac12.g"; break;
	case 205: res = "ac13.g"; break;
	case 206: res = "ac14.g"; break;
	case 207: res = "ac15.g"; break;
	case 208: res = "ac16.g"; break;
	case 209: res = "ac17.g"; break;
	case 210: res = "ac18.g"; break;
	case 211: res = "ac19.g"; break;
	case 212: res = "ac20.g"; break;
	case 213: res = "ac21.g"; break;
	case 214: res = "ac22.g"; break;
	case 215: res = "ac23.g"; break;
	case 216: res = "ac24.g"; break;
	case 217: res = "ac25.g"; break;
	case 218: res = "ac26.g"; break;
	case 219: res = "ac27.g"; break;
	case 220: res = "ac28.g"; break;
	case 221: res = "ac29.g"; break;
	case 222: res = "ac30.g"; break;
	case 223: res = "ac31.g"; break;
	case 224: res = "st0"; break;
	case 225: res = "st1"; break;
	case 226: res = "st2"; break;
	case 227: res = "st3"; break;
	case 228: res = "st0_55"; break;
	case 229: res = "st1_55"; break;
	case 231: res = "st3_55"; break;
	case 232: res = "ier0"; break;
	case 233: res = "ier1"; break;
	case 234: res = "ifr0"; break;
	case 235: res = "ifr1"; break;
	case 236: res = "dbier0"; break;
	case 237: res = "dbier1"; break;
	case 238: res = "ivpd"; break;
	case 239: res = "ivph"; break;
	case 240: res = "rsa0.h"; break;
	case 241: res = "rsa1.h"; break;
	case 242: res = "rea0.h"; break;
	case 243: res = "rea1.h"; break;
	case 244: res = "bios"; break;
	case 245: res = "brs1"; break;
	case 246: res = "iir"; break;
	case 247: res = "ber"; break;
	case 248: res = "rsa0.l"; break;
	case 249: res = "rsa1.l"; break;
	case 250: res = "rea0.l"; break;
	case 251: res = "rea1.l"; break;
	case 252: res = "tsdr"; break;
	default: res = NULL;
	}

	if (res != NULL) {
		res = strdup (res);
	}

	return res;
}


char *get_status_regs_and_bits(char *reg_arg, int reg_bit) {
  char *res = NULL;
  if(!strncmp(reg_arg, "ST0", 3)) {
    switch(reg_bit) {
	case 0:
		res = "st0_dp07";
		break;
	case 1:
		res = "st0_dp08";
		break;
	case 2:
		res = "st0_dp09";
		break;
	case 3:
		res = "st0_dp10";
		break;
	case 4:
		res = "st0_dp11";
		break;
	case 5:
		res = "st0_dp12";
		break;
	case 6:
		res = "st0_dp13";
		break;
	case 7:
		res = "st0_dp14";
		break;
	case 8:
		res = "st0_dp15";
		break;
	case 9:
		res = "st0_acov1";
		break;
	case 10:
		res = "st0_acov0";
		break;
	case 11:
		res = "st0_carry";
		break;
	case 12:
		res = "st0_tc2";
		break;
	case 13:
		res = "st0_tc1";
		break;
	case 14:
		res = "st0_acov3";
		break;
	case 15:
		res = "st0_acov2";
		break;
    }
  } else if(!strncmp(reg_arg, "ST1", 3)) {
		switch(reg_bit) {
		case 0:
			res = "st1_dr2_00";
			break;
		case 1:
			res =  "st1_dr2_01";
			break;
		case 2:
			res = "st1_dr2_02";
			break;
		case 3:
			res = "st1_dr2_03";
			break;
		case 4:
			res = "st1_dr2_04";
			break;
		case 5:
			res = "st1_c54cm";
			break;
		case 6:
			res = "st1_frct";
			break;
		case 7:
			res = "st1_c16";
			break;
		case 8:
			res = "st1_sxmd";
			break;
		case 9:
			res = "st1_satd";
			break;
		case 10:
			res = "st1_m40";
			break;
		case 11:
			res = "st1_intm";
			break;
		case 12:
			res = "st1_hm";
			break;
		case 13:
			res = "st1_xf";
			break;
		case 14:
			res = "st1_cpl";
			break;
		case 15:
			res = "st1_braf";
			break;
      }
  } else if(!strncmp(reg_arg, "ST2", 3)) {
		switch ( reg_bit ) {
		case 0:
			res = "st2_ar0lc";
			break;
		case 1:
			res = "st2_ar1lc";
			break;
		case 2:
			res = "st2_ar2lc";
			break;
		case 3:
			res = "st2_ar3lc";
			break;
		case 4:
			res = "st2_ar4lc";
			break;
		case 5:
			res = "st2_ar5lc";
			break;
		case 6:
			res = "st2_ar6lc";
			break;
		case 7:
			res = "st2_ar7lc";
			break;
		case 8:
			res = "st2_cdplc";
			break;
		case 9:
			res = "st2_govf";
			break;
		case 10:
			res = "st2_rdm";
			break;
		case 11:
			res = "st2_eallow";
			break;
		case 12:
			res = "st2_dbgm";
			break;
		case 13:
			res = "st2_xcnd";
			break;
		case 14:
			res = "st2_xcna";
			break;
		case 15:
			res = "st2_arms";
			break;
       }
  } else if (!strncmp(reg_arg, "ST3", 3)) {
		switch (reg_bit) {
		case 0:
			res = "st3_sst";
			break;
		case 1:
			res = "st3_smul";
			break;
		case 2:
			res = "st3_clkoff";
			break;
		case 3:
			res = "st3_bptr";
			break;
		case 4:
			res = "st3_avis";
			break;
		case 5:
			res = "st3_sata";
			break;
		case 6:
			res = "st3_mpnmc";
			break;
		case 7:
			res = "st3_cberr";
			break;
		case 8:
			res = "st3_homp";
			break;
		case 9:
			res = "st3_homr";
			break;
		case 10:
			res = "st3_homx";
			break;
		case 11:
			res = "st3_homy";
			break;
		case 12:
			res = "st3_hint";
			break;
		case 13:
			res = "st3_caclr";
			break;
		case 14:
			res = "st3_caen";
			break;
		case 15:
			res = "st3_cafrz";
			break;
        }
  }

  if (res != NULL) {
	  res = strdup (res);
  }

  return res;
}


char *get_reg_name_4(ut32 idx) {
	char *res = NULL;

	switch (idx) {
	case 0:
		res = "ac0";
		break;
	case 1:
		res = "ac1";
		break;
	case 2:
		res = "ac2";
		break;
	case 3:
		res = "ac3";
		break;
	case 4:
		res = "ac4";
		break;
	case 5:
		res = "ac5";
		break;
	case 6:
		res = "ac6";
		break;
	case 7:
		res = "ac7";
		break;
	case 8:
		res = "t0";
		break;
	case 9:
		res = "t1";
		break;
	case 10:
		res = "t2";
		break;
	case 11:
		res = "t3";
		break;
	case 16:
		res = "ar0";
		break;
	case 17:
		res = "ar1";
		break;
	case 18:
		res = "ar2";
		break;
	case 19:
		res = "ar3";
		break;
	case 20:
		res = "ar4";
		break;
	case 21:
		res = "ar5";
		break;
	case 22:
		res = "ar6";
		break;
	case 23:
		res = "ar7";
		break;
	case 24:
		res = "ac0.l";
		break;
	case 25:
		res = "ac1.l";
		break;
	case 26:
		res = "ac2.l";
		break;
	case 27:
		res = "ac3.l";
		break;
	case 28:
		res = "ac4.l";
		break;
	case 29:
		res = "ac5.l";
		break;
	case 30:
		res = "ac6.l";
		break;
	case 31:
		res = "ac7.l";
		break;
	}
	return res? strdup (res): NULL;
}

char *get_opers(ut8 oper_byte) {
	switch (oper_byte) {
	case 0xE0u:
		return strdup ("overflow(ac0)");
	case 0xE1u:
		return strdup ("overflow(ac1)");
	case 0xE2u:
		return strdup ("overflow(ac2)");
	case 0xE3u:
		return strdup ("overflow(ac3)");
	case 0xE4u:
		return strdup ("tc1");
	case 0xE5u:
		return strdup ("tc2");
	case 0xE6u:
		return strdup ("carry");
	case 0xE7u:
		return strdup ("overflow(govf)");
	case 0xE8u:
		return strdup ("tc1 & tc2");
	case 0xE9u:
		return strdup ("tc1 & !tc2");
	case 0xEAu:
		return strdup ("!tc1 & tc2");
	case 0xEBu:
		return strdup ("!tc1 & !tc2");
	case 0xECu:
		return strdup ("word_mode");
	case 0xEDu:
		return strdup ("byte_mode");
	case 0xF0u:
		return strdup ("!overflow(ac0)");
	case 0xF1u:
		return strdup ("!overflow(ac1)");
	case 0xF2u:
		return strdup ("!overflow(ac2)");
	case 0xF3u:
		return strdup ("!overflow(ac3)");
	case 0xF4u:
		return strdup ("!tc1");
	case 0xF5u:
		return strdup ("!tc2");
	case 0xF6u:
		return strdup ("!carry");
	case 0xF7u:
		return strdup ("!overflow(govf)");
	case 0xF8u:
		return strdup ("tc1 | tc2");
	case 0xF9u:
		return strdup ("tc1 | !tc2");
	case 0xFAu:
		return strdup ("!tc1 | tc2");
	case 0xFBu:
		return strdup ("!tc1 | !tc2");
	case 0xFCu:
		return strdup ("tc1 ^ tc2");
	case 0xFDu:
		return strdup ("tc1 ^ !tc2");
	case 0xFEu:
		return strdup ("!tc1 ^ tc2");
	case 0xFFu:
		return strdup("!tc1 ^ !tc2");
	default: {
		ut8 oper_type = oper_byte >> 5;
		if (oper_type != 6) {
			char *reg_name = get_reg_name_4 (oper_byte & 0x1F);
			switch (oper_type) {
			case 1u:
				return strcat_dup (reg_name, " != #0", 1);
			case 0u:
				return strcat_dup (reg_name, " == #0", 1);
			case 2u:
				return strcat_dup (reg_name, " < #0", 1);
			case 3u:
				return strcat_dup (reg_name, " >= #0", 1);
			case 4u:
				return strcat_dup (reg_name, " > #0", 1);
			case 5u:
				return strcat_dup (reg_name, " <= #0", 1);
			default:
				free (reg_name);
				return NULL;
			}
		}
		char *reg_name = get_reg_name_1 ((oper_byte & 0xF) + 128);
		oper_type = (oper_byte >> 4) - 12;
		if (oper_type) {
			if (oper_type != 1) {
				free (reg_name);
				return NULL;
			}
			return strcat_dup (reg_name, " != #0", 1);
		} else {
			// coverity may complain but strcat_dup set to null
			// reg_name when free
			return strcat_dup (reg_name, " == #0", 1);
		}
	}
	}
}

char *get_cmp_op(ut32 idx) {
	const char *res = NULL;
	switch (idx) {
	case 0: res = "=="; break;
	case 1: res = "!="; break;
	case 2: res = "<"; break;
	case 3: res = ">="; break;
	}
	return res? strdup (res): NULL;
}

char *get_sim_reg (char *reg_arg, ut32 ins_bits) {
	st32 code;
	char *res = NULL;
	char *aux;
	code = ins_bits & 3;
	switch (code) {
	case 0:
		if(reg_arg && strchr (reg_arg, 'w')) {
			if(code == 62) {
				return strdup ("sim0");
			}
			if(code == 63) {
				return strdup ("sim0");
			}
		}
		aux = get_reg_name_1 (ins_bits >> 2);
		res = strcat_dup ("@", aux, 2);
		break;
	case 2:
		aux = (char *)calloc (1, 50);
		if (!aux) {
			return NULL;
		}
		sprintf (aux, "@#0x%x", code);
		res = aux;
		break;
	case 1:
	case 3:
		res = strdup ("<reserved>");
		break;
	}
	return res;
}
