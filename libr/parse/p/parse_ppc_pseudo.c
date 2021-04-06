/* radare - LGPL - Copyright 2015-2017 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

#ifndef PFMT32x
#define PFMT32x "lx"
#endif

#define SPR_MQ          0x0
#define SPR_XER         0x1
#define SPR_RTCU        0x4
#define SPR_RTCL        0x5
#define SPR_LR          0x8
#define SPR_CTR         0x9
#define SPR_DSISR       0x12
#define SPR_DAR         0x13
#define SPR_DEC         0x16
#define SPR_SDR1        0x19
#define SPR_SRR0        0x1a
#define SPR_SRR1        0x1b
#define SPR_VRSAVE      0x100
#define SPR_TBRL        0x10c
#define SPR_TBRU        0x10d
#define SPR_SPRG0       0x110
#define SPR_SPRG1       0x111
#define SPR_SPRG2       0x112
#define SPR_SPRG3       0x113
#define SPR_EAR         0x11a
#define SPR_TBL         0x11c
#define SPR_TBU         0x11d
#define SPR_PVR         0x11f
#define SPR_SPEFSCR     0x200
#define SPR_IBAT0U      0x210
#define SPR_IBAT0L      0x211
#define SPR_IBAT1U      0x212
#define SPR_IBAT1L      0x213
#define SPR_IBAT2U      0x214
#define SPR_IBAT2L      0x215
#define SPR_IBAT3U      0x216
#define SPR_IBAT3L      0x217
#define SPR_DBAT0U      0x218
#define SPR_DBAT0L      0x219
#define SPR_DBAT1U      0x21a
#define SPR_DBAT1L      0x21b
#define SPR_DBAT2U      0x21c
#define SPR_DBAT2L      0x21d
#define SPR_DBAT3U      0x21e
#define SPR_DBAT3L      0x21f
#define SPR_UMMCR0      0x3a8
#define SPR_UMMCR1      0x3ac
#define SPR_UPMC1       0x3a9
#define SPR_UPMC2       0x3aa
#define SPR_USIA        0x3ab
#define SPR_UPMC3       0x3ad
#define SPR_UPMC4       0x3ae
#define SPR_MMCR0       0x3b8
#define SPR_PMC1        0x3b9
#define SPR_PMC2        0x3ba
#define SPR_SIA         0x3bb
#define SPR_MMCR1       0x3bc
#define SPR_PMC3        0x3bd
#define SPR_PMC4        0x3be
#define SPR_SDA         0x3bf
#define SPR_DMISS       0x3d0
#define SPR_DCMP        0x3d1
#define SPR_HASH1       0x3d2
#define SPR_HASH2       0x3d3
#define SPR_IMISS       0x3d4
#define SPR_ICMP        0x3d5
#define SPR_RPA         0x3d6
#define SPR_HID0        0x3f0 /* Hardware Implementation Register 0 */
#define SPR_HID1        0x3f1 /* Hardware Implementation Register 1 */
#define SPR_IABR        0x3f2
#define SPR_HID2        0x3f3 /* Hardware Implementation Register 2 */
#define SPR_HID4        0x3f4 /* Hardware Implementation Register 4 */
#define SPR_DABR        0x3f5
#define SPR_HID5        0x3f6 /* Hardware Implementation Register 5 */
#define SPR_HID6        0x3f9 /* Hardware Implementation Register 6 */
//#define SPR_L2CR        0x3f9
#define SPR_ICTC        0x3fb
#define SPR_THRM1       0x3fc
#define SPR_THRM2       0x3fd
#define SPR_THRM3       0x3fe
#define SPR_PIR         0x3ff

#define PPC_UT64(x) (strtol(x, NULL, 16))
#define PPC_UT32(x) ((ut32)PPC_UT64(x))

static ut64 mask64(ut64 mb, ut64 me) {
	ut64 maskmb = UT64_MAX >> mb;
	ut64 maskme = UT64_MAX << (63 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

static ut32 mask32(ut32 mb, ut32 me) {
	ut32 maskmb = UT32_MAX >> mb;
	ut32 maskme = UT32_MAX << (31 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

static int can_replace(const char *str, int idx, int max_operands) {
	if (str[idx] < 'A' || str[idx] > 'J') {
		return false;
	}
	if (str[idx + 1] != '\x00' && str[idx + 1] <= 'J' && str[idx + 1] >= 'A') {
		return false;
	}
	if ((int)((int)str[idx] - 0x41) > max_operands) {
		return false;
	}
	return true;
}

static const char* getspr(const char *reg) {
	static char cspr[16];
	ut32 spr = 0;
	if (!reg) {
		return NULL;
	}
	spr = strtol(reg, NULL, 16);
	if (spr > 9999) {
		return NULL; //just to avoid overflows..
	}

	switch (spr) {
		case SPR_MQ:
			return "mq";
		case SPR_XER:
			return "xer";
		case SPR_RTCU:
			return "rtcu";
		case SPR_RTCL:
			return "rtcl";
		case SPR_LR:
			return "lr";
		case SPR_CTR:
			return "ctr";
		case SPR_DSISR:
			return "dsisr";
		case SPR_DAR:
			return "dar";
		case SPR_DEC:
			return "dec";
		case SPR_SDR1:
			return "sdr1";
		case SPR_SRR0:
			return "srr0";
		case SPR_SRR1:
			return "srr1";
		case SPR_VRSAVE:
			return "vrsave";
		case SPR_TBRL:
			return "tbrl";
		case SPR_TBRU:
			return "tbru";
		case SPR_SPRG0:
			return "sprg0";
		case SPR_SPRG1:
			return "sprg1";
		case SPR_SPRG2:
			return "sprg2";
		case SPR_SPRG3:
			return "sprg3";
		case SPR_EAR:
			return "ear";
		case SPR_TBL:
			return "tbl";
		case SPR_TBU:
			return "tbu";
		case SPR_PVR:
			return "pvr";
		case SPR_SPEFSCR:
			return "spefscr";
		case SPR_IBAT0U:
			return "ibat0u";
		case SPR_IBAT0L:
			return "ibat0l";
		case SPR_IBAT1U:
			return "ibat1u";
		case SPR_IBAT1L:
			return "ibat1l";
		case SPR_IBAT2U:
			return "ibat2u";
		case SPR_IBAT2L:
			return "ibat2l";
		case SPR_IBAT3U:
			return "ibat3u";
		case SPR_IBAT3L:
			return "ibat3l";
		case SPR_DBAT0U:
			return "dbat0u";
		case SPR_DBAT0L:
			return "dbat0l";
		case SPR_DBAT1U:
			return "dbat1u";
		case SPR_DBAT1L:
			return "dbat1l";
		case SPR_DBAT2U:
			return "dbat2u";
		case SPR_DBAT2L:
			return "dbat2l";
		case SPR_DBAT3U:
			return "dbat3u";
		case SPR_DBAT3L:
			return "dbat3l";
		case SPR_UMMCR0:
			return "ummcr0";
		case SPR_UMMCR1:
			return "ummcr1";
		case SPR_UPMC1:
			return "upmc1";
		case SPR_UPMC2:
			return "upmc2";
		case SPR_USIA:
			return "usia";
		case SPR_UPMC3:
			return "upmc3";
		case SPR_UPMC4:
			return "upmc4";
		case SPR_MMCR0:
			return "mmcr0";
		case SPR_PMC1:
			return "pmc1";
		case SPR_PMC2:
			return "pmc2";
		case SPR_SIA:
			return "sia";
		case SPR_MMCR1:
			return "mmcr1";
		case SPR_PMC3:
			return "pmc3";
		case SPR_PMC4:
			return "pmc4";
		case SPR_SDA:
			return "sda";
		case SPR_DMISS:
			return "dmiss";
		case SPR_DCMP:
			return "dcmp";
		case SPR_HASH1:
			return "hash1";
		case SPR_HASH2:
			return "hash2";
		case SPR_IMISS:
			return "imiss";
		case SPR_ICMP:
			return "icmp";
		case SPR_RPA:
			return "rpa";
		case SPR_HID0:
			return "hid0";
		case SPR_HID1:
			return "hid1";
		case SPR_IABR:
			return "iabr";
		case SPR_HID2:
			return "hid2";
		case SPR_HID4:
			return "hid4";
		case SPR_DABR:
			return "dabr";
		case SPR_HID5:
			return "hid5";
		case SPR_HID6:
			return "hid6";
//		case SPR_L2CR:
//			return "l2cr";
		case SPR_ICTC:
			return "ictc";
		case SPR_THRM1:
			return "thrm1";
		case SPR_THRM2:
			return "thrm2";
		case SPR_THRM3:
			return "thrm3";
		case SPR_PIR:
			return "pir";
		default:
			snprintf(cspr, sizeof(cspr), "spr_%u", spr);
			break;
	}
	return cspr;
}

static int replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		const char *op;
		const char *str;
		int max_operands;
	} ops[] = {
		{ "cmpb", "A = ((byte) B == (byte) C)", 3}, //0
		{ "cmpd", "A = (B == C)", 3},
		{ "cmpdi", "A = (B == C)", 3},
		{ "cmpld", "A = ((unsigned) B == (unsigned) C)", 3},
		{ "cmpldi", "A = ((unsigned) B == (unsigned) C)", 3},
		{ "cmplw", "A = ((unsigned) B == (unsigned) C)", 3},
		{ "cmplwi", "A = ((unsigned) B == (unsigned) C)", 3},
		{ "cmpw", "A = (B == C)", 3},
		{ "cmpwi", "A = (B == C)", 3},
		{ "beq", "if (A & FLG_EQ) goto B", 2},
		{ "beq-", "if (A & FLG_EQ) goto B", 2},
		{ "beq+", "if (A & FLG_EQ) goto B", 2},
		{ "bge", "if (A & FLG_GE) goto B", 2},
		{ "bge-", "if (A & FLG_GE) goto B", 2},
		{ "bge+", "if (A & FLG_GE) goto B", 2},
		{ "bgt", "if (A & FLG_GT) goto B", 2},
		{ "bgt-", "if (A & FLG_GT) goto B", 2},
		{ "bgt+", "if (A & FLG_GT) goto B", 2},
		{ "ble", "if (A & FLG_LE) goto B", 2},
		{ "ble-", "if (A & FLG_LE) goto B", 2},
		{ "ble+", "if (A & FLG_LE) goto B", 2},
		{ "blt", "if (A & FLG_LT) goto B", 2},
		{ "blt-", "if (A & FLG_LT) goto B", 2},
		{ "blt+", "if (A & FLG_LT) goto B", 2},
		{ "bne", "if (A & FLG_NE) goto B", 2},
		{ "bne-", "if (A & FLG_NE) goto B", 2},
		{ "bne+", "if (A & FLG_NE) goto B", 2}, //26
		{ "rldic", "A = rol64(B, C) & D", 4}, //27
		{ "rldcl", "A = rol64(B, C) & D", 4}, //28
		{ "rldicl", "A = rol64(B, C) & D", 4}, //29
		{ "rldcr", "A = rol64(B, C) & D", 4}, //30
		{ "rldicr", "A = rol64(B, C) & D", 4}, //31
		{ "rldimi", "A = (rol64(B, C) & D) | (A & E)", 5}, //32
		{ "rlwimi", "A = (rol32(B, C) & D) | (A & E)", 5}, //33
		{ "rlwimi.", "A = (rol32(B, C) & D) | (A & E)", 5}, //33
		{ "rlwinm", "A = rol32(B, C) & D", 5}, //34
		{ "rlwinm.", "A = rol32(B, C) & D", 5}, //34
		{ "rlwnm", "A = rol32(B, C) & D", 5}, //35
		{ "rlwnm.", "A = rol32(B, C) & D", 5}, //35
		{ "td", "if (B A C) trap", 3}, //36
		{ "tdi", "if (B A C) trap", 3},
		{ "tdu", "if (B A C) trap", 3},
		{ "tdui", "if (B A C) trap", 3},
		{ "tw", "if ((word) B A (word) C) trap", 3},
		{ "twi", "if ((word) B A (word) C) trap", 3},
		{ "twu", "if ((word) B A (word) C) trap", 3},
		{ "twui", "if ((word) B A (word) C) trap", 3}, //43
		{ "mfspr", "A = B", 2}, //44
		{ "mtspr", "A = B", 2}, //45
		{ "add", "A = B + C", 3},
		{ "addc", "A = B + C", 3},
		{ "adde", "A = B + C", 3},
		{ "addi", "A = B + C", 3},
		{ "addic", "A = B + C", 3},
		{ "addis", "A = B + (C << 16)", 3},
		{ "addme", "A = B - A", 2},
		{ "addze", "A = zero extended(B)", 2},
		{ "and", "A = B & C", 3},
		{ "andc", "A = B & C", 3},
		{ "andi", "A = B & C", 3},
		{ "andis", "A = B & (C << 16)", 3},
		{ "attn", "attention A", 1},
		{ "b", "goto A", 1},
		{ "ba", "goto A", 1},
		//{ "bc", "if (a ?? b) goto C", 3},
		//{ "bca", "if (a ?? b) goto C", 3},
		//{ "bcctr", "if (a ?? b) goto ctr", 2},
		//{ "bcctrl", "if (a ?? b) goto ctr", 2},
		//{ "bcl", "if (a ?? b) call C", 3},
		//{ "bcla", "if (a ?? b) call C", 3},
		//{ "bclr", "if (a ?? b) goto C", 3},
		//{ "bclrl", "if (a ?? b) call C", 3},
		{ "bct", "goto ct", 0},
		{ "bctr", "goto ctr", 3},
		{ "bctrl", "call ctr", 3},
		{ "bdnz", "if (ctr != 0) goto A", 1},
		{ "bdnza", "if (ctr != 0) goto A", 1},
		{ "bdnzf", "if (ctr != 0 && !cond) goto A", 1},
		{ "bdnzfa", "if (ctr != 0 && !cond) goto A", 1},
		{ "bdnzfl", "if (ctr != 0 && !cond) call A", 1},
		{ "bdnzfla", "if (ctr != 0 && !cond) call A", 1},
		{ "bdnzflrl", "if (ctr != 0 && !cond) call A", 1},
		{ "bdnzl", "if (ctr != 0) call A", 1},
		{ "bdnzla", "if (ctr != 0) call A", 1},
		{ "bdnzlr", "if (ctr != 0) call A", 1},
		{ "bdnzlrl", "if (ctr != 0) call A", 1},
		{ "bdnzt", "if (ctr != 0 && cond) goto A", 1},
		{ "bdnzta", "if (ctr != 0 && cond) goto A", 1},
		{ "bdnztl", "if (ctr != 0 && cond) call A", 1},
		{ "bdnztla", "if (ctr != 0 && cond) call A", 1},
		{ "bdnztlr", "if (ctr != 0 && cond) call A", 1},
		{ "bdnztlrl", "if (ctr != 0 && cond) call A", 1},
		{ "bdz", "if (ctr == 0) goto A", 1},
		{ "bdza", "if (ctr == 0) goto A", 1},
		{ "bdzf", "if (ctr == 0 && !cond) goto A", 1},
		{ "bdzfa", "if (ctr == 0 && !cond) goto A", 1},
		{ "bdzfl", "if (ctr == 0 && !cond) call A", 1},
		{ "bdzfla", "if (ctr == 0 && !cond) call A", 1},
		{ "bdzflr", "if (ctr == 0 && !cond) call A", 1},
		{ "bdzflrl", "if (ctr == 0 && !cond) call A", 1},
		{ "bdzl", "if (ctr == 0) call A", 1},
		{ "bdzla", "if (ctr == 0) call A", 1},
		{ "bdzlr", "if (ctr == 0) call A", 1},
		{ "bdzlrl", "if (ctr == 0) call A", 1},
		{ "bdzt", "if (ctr == 0 && cond) goto A", 1},
		{ "bdzta", "if (ctr == 0 && cond) goto A", 1},
		{ "bdztl", "if (ctr == 0 && cond) call A", 1},
		{ "bdztla", "if (ctr == 0 && cond) call A", 1},
		{ "bdztlr", "if (ctr == 0 && cond) call A", 1},
		{ "bdztlrl", "if (ctr == 0 && cond) call A", 1},
		{ "bf", "if (!cond) goto A", 1},
		{ "bfa", "if (!cond) goto A", 1},
		{ "bfctr", "if (!cond) goto ctr", 0},
		{ "bfctrl", "if (!cond) call ctr", 0},
		{ "bfl", "if (!cond) call A", 1},
		{ "bfla", "if (!cond) call A", 1},
		{ "bflr", "if (!cond) call A", 1},
		{ "bflrl", "if (!cond) call A", 1},
		{ "bl", "call A", 1},
		{ "bla", "call A", 1},
		{ "blr", "return", 0},
		{ "blrl", "return", 0},
		{ "bltlr", "if (A & FLG_LT) return", 1},
		{ "blelr", "if (A & FLG_LE) return", 1},
		{ "bgtlr", "if (A & FLG_GT) return", 1},
		{ "bgelr", "if (A & FLG_GE) return", 1},
		{ "bnelr", "if (A & FLG_NE) return", 1},
		{ "beqlr", "if (A & FLG_EQ) return", 1},
		{ "brinc", "A = bit_revese(B, C)", 3},
		{ "bt", "if (cond) goto A", 1},
		{ "bta", "if (cond) goto A", 1},
		{ "btctr", "if (cond) goto ctr", 1},
		{ "btctrl", "if (cond) call ctr", 1},
		{ "btl", "if (cond) call A", 1},
		{ "btla", "if (cond) call A", 1},
		{ "btlr", "if (cond) call A", 1},
		{ "btlrl", "if (cond) call A", 1},
		{ "clrldi", "A = B & mask(0, C)", 2},
		{ "clrlwi", "A = B & mask(0, C)", 2},
		{ "cntlzd", "A = cnt_leading_zeros(B)", 2},
		{ "cntlzw", "A = cnt_leading_zeros(B)", 2},
		{ "crand", "A = B & C", 3},
		{ "crandc", "A = B & C", 3},
		{ "crclr", "A = A ^ A", 1},
		{ "creqv", "A = B == C", 3},
		{ "crmove", "A = B", 2},
		{ "crnand", "A = B & !C", 3},
		{ "crnor", "A = B | !C", 3},
		{ "crnot", "A = !B", 2},
		{ "cror", "A = B | C", 3},
		{ "crorc", "A = B | C", 3},
		{ "crset", "A = B", 2},
		{ "crxor", "A = B ^ C", 3},
		{ "dcba", "dcb_alloc(A,B)", 2},
		{ "dcbf", "dcb_flush(A,B)", 2},
		{ "dcbi", "dcb_inval(A,B)", 2},
		{ "dcbst", "dcb_store(A,B)", 2},
		{ "dcbt", "dcb_touch(A,B)", 2},
		{ "dcbtst", "dcb_touch_store(A, B)", 2},
		{ "dcbz", "dcb_zero(A,B)", 2},
		{ "dcbzl", "dcb_zero_line(A, B)", 2},
		{ "dccci", "dcc_inval(A, B)", 3}, // Data Cache Congruence Class Invalidate
		{ "divd", "A = B / C", 3},
		{ "divdu", "A = (unsigned) B / C", 3},
		{ "divw", "A = (word) B / C", 3},
		{ "divwu", "A = (word unsigned) B / C", 3},
		{ "dss", "altivec_ds_stop(A)", 1},
		{ "dssall", "altivec_ds_stop_all", 0},
		{ "dst", "altivec_ds_touch(A,B,C)", 3},
		{ "dstst", "altivec_ds_touch_store(A, B, C)", 3},
		{ "dststt", "altivec_ds_touch_store_tran(A, B, C)", 3},
		{ "dstt", "altivec_ds_touch_tran(A, B, C)", 3},
		{ "eieio", "enforce_in_order_exec_io", 0},
		{ "eqv", "A = B ^ C", 3},
		{ "evabs", "A = (vector) abs(B)", 2},
		{ "evaddiw", "A =  (vector) B + C", 3},
		{ "evaddsmiaaw", "A =  (vector) B + C", 3},
		{ "evaddssiaaw", "A = (vector) B + C", 3},
		{ "evaddumiaaw", "A = (vector) B + C", 3},
		{ "evaddusiaaw", "A = (vector) B + C", 3},
		{ "evaddw", "A = (vector) B + C", 3},
		{ "evand", "A = (vector) B + C", 3},
		{ "evandc", "A = (vector) B + C", 3},
		{ "evcmpeq", "A = (vector) B == C", 3},
		{ "evcmpgts", "A = (vector) B > C", 3},
		{ "evcmpgtu", "A = (unsigned vector) B > C", 3},
		{ "evcmplts", "A = (vector) B < C", 3},
		{ "evcmpltu", "A =  (unsigned vector) B <> C", 3},
		{ "evcntlsw", "A = (vector) cnt_sign_bits(B)", 2},
		{ "evcntlzw", "A = (vector) cnt_zero_bits(B)", 2},
		{ "evdivws", "A = (vector) B / C", 3},
		{ "evdivwu", "A = (unsigned vector) B + C", 3},
		{ "eveqv", "A = (vector) B ^ C", 3},
		//{ "evextsb", "", 0}, //extend sign byte
		//{ "evextsh", "", 0}, //extend sign half
		{ "evldd", "A = vector[C + B]", 3},
		{ "evlddx", "A = vector[C + B]", 3},
		{ "evldh", "A = vector[C + B]", 3},
		{ "evldhx", "A = vector[C + B]", 3},
		{ "evldw", "A = vector[C + B]", 3},
		{ "evldwx", "A = vector[C + B]", 3},
		//Vector Load Half Word into Half Words Even and Splat  ??
		/*
		   { "evlhhesplat", "A = B + C", 3},
		   { "evlhhesplatx", "A = B + C", 3},
		   { "evlhhossplat", "A = B + C", 3},
		   { "evlhhossplatx", "A = B + C", 3},
		   { "evlhhousplat", "A = B + C", 3},
		   { "evlhhousplatx", "A = B + C", 3},
		 */
		{ "evlwhe", "A = vector[C + B]", 3},
		{ "evlwhex", "A = vector[C + B]", 3},
		{ "evlwhos", "A = vector[C + B]", 3},
		{ "evlwhosx", "A = vector[C + B]", 3},
		{ "evlwhou", "A = vector[C + B]", 3},
		{ "evlwhoux", "A = vector[C + B]", 3},
		/*
		   { "evlwhsplat", "A = vector[C + B]", 3},
		   { "evlwhsplatx", "A = vector[C + B]", 3},
		   { "evlwwsplat", "A = vector[C + B]", 3},
		   { "evlwwsplatx", "A = vector[C + B]", 3},
		   { "evmergehi", "A = lo | hi", 3},
		   { "evmergehilo", "A = B + C", 3},
		   { "evmergelo", "A = B + C", 3},
		   { "evmergelohi", "A = B + C", 3},
		   { "evmhegsmfaa", "A = B + C", 3},
		   { "evmhegsmfan", "A = B + C", 3},
		   { "evmhegsmiaa", "A = B + C", 3},
		   { "evmhegsmian", "A = B + C", 3},
		   { "evmhegumiaa", "A = B + C", 3},
		   { "evmhegumian", "A = B + C", 3},
		   { "evmhesmf", "A = B + C", 3},
		   { "evmhesmfa", "A = B + C", 3},
		   { "evmhesmfaaw", "A = B + C", 3},
		   { "evmhesmfanw", "A = B + C", 3},
		   { "evmhesmi", "A = B + C", 3},
		   { "evmhesmia", "A = B + C", 3},
		   { "evmhesmiaaw", "A = B + C", 3},
		   { "evmhesmianw", "A = B + C", 3},
		   { "evmhessf", "A = B + C", 3},
		   { "evmhessfa", "A = B + C", 3},
		   { "evmhessfaaw", "A = B + C", 3},
		   { "evmhessfanw", "A = B + C", 3},
		   { "evmhessiaaw", "A = B + C", 3},
		   { "evmhessianw", "A = B + C", 3},
		   { "evmheumi", "A = B + C", 3},
		   { "evmheumia", "A = B + C", 3},
		   { "evmheumiaaw", "A = B + C", 3},
		   { "evmheumianw", "A = B + C", 3},
		   { "evmheusiaaw", "A = B + C", 3},
		   { "evmheusianw", "A = B + C", 3},
		   { "evmhogsmfaa", "A = B + C", 3},
		   { "evmhogsmfan", "A = B + C", 3},
		   { "evmhogsmiaa", "A = B + C", 3},
		   { "evmhogsmian", "A = B + C", 3},
		   { "evmhogumiaa", "A = B + C", 3},
		   { "evmhogumian", "A = B + C", 3},
		   { "evmhosmf", "A = B + C", 3},
		   { "evmhosmfa", "A = B + C", 3},
		   { "evmhosmfaaw", "A = B + C", 3},
		   { "evmhosmfanw", "A = B + C", 3},
		   { "evmhosmi", "A = B + C", 3},
		   { "evmhosmia", "A = B + C", 3},
		   { "evmhosmiaaw", "A = B + C", 3},
		   { "evmhosmianw", "A = B + C", 3},
		   { "evmhossf", "A = B + C", 3},
		   { "evmhossfa", "A = B + C", 3},
		   { "evmhossfaaw", "A = B + C", 3},
		   { "evmhossfanw", "A = B + C", 3},
		   { "evmhossiaaw", "A = B + C", 3},
		   { "evmhossianw", "A = B + C", 3},
		   { "evmhoumi", "A = B + C", 3},
		   { "evmhoumia", "A = B + C", 3},
		   { "evmhoumiaaw", "A = B + C", 3},
		   { "evmhoumianw", "A = B + C", 3},
		   { "evmhousiaaw", "A = B + C", 3},
		   { "evmhousianw", "A = B + C", 3},
		   { "evmra", "A = B + C", 3},
		   { "evmwhsmf", "A = B + C", 3},
		   { "evmwhsmfa", "A = B + C", 3},
		   { "evmwhsmi", "A = B + C", 3},
		   { "evmwhsmia", "A = B + C", 3},
		   { "evmwhssf", "A = B + C", 3},
		   { "evmwhssfa", "A = B + C", 3},
		   { "evmwhumi", "A = B + C", 3},
		   { "evmwhumia", "A = B + C", 3},
		   { "evmwlsmiaaw", "A = B + C", 3},
		{ "evmwlsmianw", "A = B + C", 3},
		{ "evmwlssiaaw", "A = B + C", 3},
		{ "evmwlssianw", "A = B + C", 3},
		{ "evmwlumi", "A = B + C", 3},
		{ "evmwlumia", "A = B + C", 3},
		{ "evmwlumiaaw", "A = B + C", 3},
		{ "evmwlumianw", "A = B + C", 3},
		{ "evmwlusiaaw", "A = B + C", 3},
		{ "evmwlusianw", "A = B + C", 3},
		{ "evmwsmf", "A = B + C", 3},
		{ "evmwsmfa", "A = B + C", 3},
		{ "evmwsmfaa", "A = B + C", 3},
		{ "evmwsmfan", "A = B + C", 3},
		{ "evmwsmi", "A = B + C", 3},
		{ "evmwsmia", "A = B + C", 3},
		{ "evmwsmiaa", "A = B + C", 3},
		{ "evmwsmian", "A = B + C", 3},
		{ "evmwssf", "A = B + C", 3},
		{ "evmwssfa", "A = B + C", 3},
		{ "evmwssfaa", "A = B + C", 3},
		{ "evmwssfan", "A = B + C", 3},
		{ "evmwumi", "A = B + C", 3},
		{ "evmwumia", "A = B + C", 3},
		{ "evmwumiaa", "A = B + C", 3},
		{ "evmwumian", "A = B + C", 3},
		{ "evnand", "A = B + C", 3},
		{ "evneg", "A = B + C", 3},
		{ "evnor", "A = B + C", 3},
		{ "evor", "A = B + C", 3},
		{ "evorc", "A = B + C", 3},
		{ "evrlw", "A = B + C", 3},
		{ "evrlwi", "A = B + C", 3},
		{ "evrndw", "A = B + C", 3},
		{ "evslw", "A = B + C", 3},
		{ "evslwi", "A = B + C", 3},
		{ "evsplatfi", "A = B + C", 3},
		{ "evsplati", "A = B + C", 3},
		{ "evsrwis", "A = B + C", 3},
		{ "evsrwiu", "A = B + C", 3},
		{ "evsrws", "A = B + C", 3},
		{ "evsrwu", "A = B + C", 3},
		{ "evstdd", "A = B + C", 3},
		{ "evstddx", "A = B + C", 3},
		{ "evstdh", "A = B + C", 3},
		{ "evstdhx", "A = B + C", 3},
		{ "evstdw", "A = B + C", 3},
		{ "evstdwx", "A = B + C", 3},
		{ "evstwhe", "A = B + C", 3},
		{ "evstwhex", "A = B + C", 3},
		{ "evstwho", "A = B + C", 3},
		{ "evstwhox", "A = B + C", 3},
		{ "evstwwe", "A = B + C", 3},
		{ "evstwwex", "A = B + C", 3},
		{ "evstwwo", "A = B + C", 3},
		{ "evstwwox", "A = B + C", 3},
		{ "evsubfsmiaaw", "A = B + C", 3},
		{ "evsubfssiaaw", "A = B + C", 3},
		{ "evsubfumiaaw", "A = B + C", 3},
		{ "evsubfusiaaw", "A = B + C", 3},
		{ "evsubfw", "A = B + C", 3},
		{ "evsubifw", "A = B + C", 3},
		{ "evxor", "A = B + C", 3},
		*/
		{ "extsb", "A = extend_sign(B)", 2},
		{ "extsh", "A = extend_sign(B)", 2},
		{ "extsw", "A = extend_sign(B)", 2},
		{ "fabs", "A = abs(B)", 2},
		{ "fadd", "A = B + C", 3},
		{ "fadds", "A = (float) B + C", 3},
		{ "fcfid", "A = (double) B", 2},
		{ "fcfids", "A = (float) B", 2},
		{ "fcfidu", "A = (double) B", 2},
		{ "fcfidus", "A = (float) B", 2},
		{ "fcmpu", "A = B == C", 3},
		// This should copy the sign of bit 0 of reg B & c
		{ "fcpsgn", "A = flt_copy_sign(B,C)", 3},
		{ "fctid", "A = (int64) B", 2},
		{ "fctiduz", "A = (uint64) B + C", 3},
		{ "fctidz", "A = (int64) B + C", 3},
		{ "fctiw", "A = (int32) B + C", 3},
		{ "fctiwuz", "A = (uint32) B + C", 3},
		{ "fctiwz", "A = (int32) B + C", 3},
		{ "fdiv", "A = B / C", 3},
		{ "fdivs", "A = (float) B / C", 3},
		{ "fmadd", "A = (B * C) + D", 4},
		{ "fmadds", "A = (float) (B * C) + D", 3},
		{ "fmr", "A = B", 2},
		{ "fmsub", "A = (B * C) - d", 4},
		{ "fmsubs", "A = (float) (B * C) - D", 4},
		{ "fmul", "A = B * C", 3},
		{ "fmuls", "A = (float) B * C", 3},
		{ "fnabs", "A = - abs(B)", 2},
		{ "fneg", "A = - B", 2},
		{ "fnmadd", "A = -((B * C) + D)", 4},
		{ "fnmadds", "A = (float) -((B * C) + D)", 4},
		{ "fnmsub", "A = -((B * C) - D)", 4},
		{ "fnmsubs", "A = (float) -((B * C) - D)", 4},
		{ "fre", "A = 1/B", 2},
		{ "fres", "A = (float) 1/B", 2},
		{ "frim", "A = trunc(B)", 2},
		{ "frin", "A = floor(B)", 2},
		{ "frip", "A = ceil(B)", 2},
		{ "friz", "A = trunc(B)", 2},
		{ "frsp", "A = (float) B", 3},
		{ "frsqrte", "A = 1/sqrt(B)", 2},
		{ "frsqrtes", "A = (float) 1/sqrt(B)", 2},
		{ "fsel", "if (B >= 0.0) A = C; else A = D", 4},
		{ "fsqrt", "A = sqrt(B)", 2},
		{ "fsqrts", "A = (float) sqrt(B)", 3},
		{ "fsub", "A = B - C", 3},
		{ "fsubs", "A = (float) B - C", 3},
		{ "icbi", "inst_cache_block_inval", 0},
		{ "icbt", "inst_cache_block_touch", 3},
		{ "iccci", "inst_cache_inval(A,B)", 2},
		// isel lt   Rx,Ry,Rz (equivalent to: isel Rx,Ry,Rz,0)
		// isel gt  Rx,Ry,Rz (equivalent to: isel Rx,Ry,Rz,1)
		// isel eq Rx,Ry,Rz (equivalent to: isel Rx,Ry,Rz,2)
		//  { "isel", "", 4},
		{ "isync", "sync_instr_cache", 0},
		{ "la", "A = C + B", 3},
		{ "lbz", "A = byte[C + B]", 3},
		{ "lbzcix", "A = byte[C + B]", 3},
		{ "lbzu", "A = byte[C + B]", 3},
		{ "lbzux", "A = Byte[C + B]", 3},
		{ "lbzx", "A = byte[C + B]", 3},
		{ "ld", "A = [C + B]", 3},
		// No clue how to represent them since they are kinda complex..
		//  { "ldarx", "A = [C + B]", 3},
		//  { "ldbrx", "A = [C + B]", 3},
		//  { "ldcix", "A = B + C", 3},
		{ "ldu", "A = [C + B]", 3},
		{ "ldux", "A = [C + B]", 3},
		{ "ldx", "A = [C + B]", 3},
		{ "lfd", "A = double[C + B]", 3},
		{ "lfdu", "A = double[C + B]", 3},
		{ "lfdux", "A = double[C + B]", 3},
		{ "lfdx", "A = double[C + B]", 3},
		{ "lfiwax", "A = float[C + B]", },
		{ "lfiwzx", "A = float[C + B]", 3},
		{ "lfs", "A = float[C + B]", 3},
		{ "lfsu", "A = float[C + B]", 3},
		{ "lfsux", "A = float[C + B]", 3},
		{ "lfsx", "A = float[C + B]", 3},
		{ "lha", "A = half[C + B]", 3},
		{ "lhau", "A = half[C + B]", 3},
		{ "lhaux", "A = half[C + B]", 3},
		{ "lhax", "A = half[C + B]", 3},
		{ "lhbrx", "A = half[C + B]", 3},
		{ "lhz", "A = half[C + B]", 3},
		{ "lhzcix", "A = half[C + B]", 3},
		{ "lhzu", "A = half[C + B]", 3},
		{ "lhzux", "A = half[C + B]", 3},
		{ "lhzx", "A = half[C + B]", 3},
		{ "li", "A = B", 2},
		{ "lis", "A = (B << 16)", 2},
		{ "lmw", "A = multiple word[C + B]", 3},
		{ "lswi", "A = string word[C + B]", 3},
		{ "lvebx", "A = vector[C + B]", 3},
		{ "lvehx", "A = vector[C + B]", 3},
		{ "lvewx", "A = vector[C + B]", 3},
		{ "lvsl", "A = vector[C + B]", 3},
		{ "lvsr", "A = vector[C + B]", 3},
		{ "lvx", "A = vector[C + B]", 3},
		{ "lvxl", "A = vector[C + B]", 3},
		{ "lwa", "A = word[C + B]", 3},
		{ "lwarx", "A = word[C + B]", 3},
		{ "lwaux", "A = word[C + B]", 3},
		{ "lwax", "A = word[C + B]", 3},
		{ "lwbrx", "A = word[C + B]", 3},
		{ "lwsync", "sync_load_store", 0},
		{ "lwz", "A = word[C + B]", 3},
		{ "lwzcix", "A = word[C + B]", 3},
		{ "lwzu", "A = word[C + B]", 3},
		{ "lwzux", "A = word[C + B]", 3},
		{ "lwzx", "A = word[C + B]", 3},
		//      { "lxsdx", "A = ???[C + B]", 3},
		{ "lxvdbx", "A = vector[C + B]", 3},
		{ "lxvdsx", "A = vector[C + B]", 3},
		{ "lxvwdx", "A = vector[C + B]", 3},
		{ "mbar", "memory_barrier(A)", 1},
		{ "mcrf", "A = B", 2},
		{ "mcrfs", "A = B", 2},
		{ "mfamr", "A = amr", 1},
		{ "mfasr", "A = asr", 1},
		{ "mfbr0", "A = br0", 1},
		{ "mfbra", "A = br1", 1},
		{ "mfbrb", "A = br2", 1},
		{ "mfbrc", "A = br3", 1},
		{ "mfbrd", "A = br4", 1},
		{ "mfbr5", "A = br5", 1},
		{ "mfbr6", "A = br6", 1},
		{ "mfbr7", "A = br7", 1},
		{ "mfcfar", "A = cfar", 3},
		{ "mfcr", "A = crB", 2},
		{ "mfctr", "A = ctr", 3},
		{ "mfdar", "A = dar", 1},
		{ "mfdbatl", "A = dbatBl", 1},
		{ "mfdbatu", "A = dbatBu", 1},
		{ "mfdccr", "A = dccr", 1},
		{ "mfdcr", "A = dcr", 1},
		{ "mfdear", "A = dear", 1},
		{ "mfdscr", "A = dscr", 1},
		{ "mfdsisr", "A = dsisr", 1},
		{ "mfesr", "A = esr", 1},
		{ "mffs", "A = fs", 1},
		{ "mfibatl", "A = ibatBl", 2},
		{ "mfibatu", "A = ibatBu", 2},
		{ "mficcr", "A = iccr", 1},
		{ "mflr", "A = lr", 1},
		{ "mfmsr", "A = msr", 1},
		{ "mfocrf", "A = ocrf", 1},
		{ "mfpid", "A = pid", 1},
		{ "mfpvr", "A = pvr", 1},
		{ "mfrtcl", "A = rtc_lo", 1},
		{ "mfrtcu", "A = rtc_hi", 1},
		{ "mfspefscr", "A = fscr",1},
		{ "mfsr", "A = srB", 3},
		{ "mfsrin", "A = sr_indirect(B)", 2},
		{ "mfsrr2", "A = srr2", 1},
		{ "mfsrr3", "A = srr3", 1},
		{ "mftb", "A = tb(B)", 2},
		{ "mftbhi", "A = tb_hi(B)", 2},
		{ "mftblo", "A = tb_lo(B)", 2},
		{ "mftbu", "A = tbu", 1},
		{ "mftcr", "A = tcr", 1},
		{ "mfvscr", "A = vscr", 1},
		{ "mfxer", "A = xer", 1},
		{ "mr", "A = B", 2},
		{ "msync", "sync_memory", 3},
		{ "mtamr", "amr = A", 1},
		{ "mtbr0", "br0 = A", 1},
		{ "mtbr1", "br1 = A", 1},
		{ "mtbr2", "br2 = A", 1},
		{ "mtbr3", "br3 = A", 1},
		{ "mtbr4", "br4 = A", 1},
		{ "mtbr5", "br5 = A", 1},
		{ "mtbr6", "br6 = A", 1},
		{ "mtbr7", "br7 = A", 1},
		{ "mtcfar", "cfar = A", 1},
		{ "mtcr", "tcr = A", 1},
		{ "mtcrf", "crf = A", 1},
		{ "mtctr", "ctr = A", 1},
		{ "mtdar", "dar = A", 1},
		{ "mtdbatl", "dbatBl = A", 2},
		{ "mtdbatu", "dbatBu = A", 2},
		{ "mtdccr", "dccr = A", 1},
		{ "mtdcr", "dcr = A", 1},
		{ "mtdear", "dear = A", 1},
		{ "mtdscr", "dscr = A", 1},
		{ "mtdsisr", "dsisr = A", 1},
		{ "mtesr", "esr = A", 1},
		{ "mtfsb0", "fsb0 = A", 1},
		{ "mtfsb1", "fsb1 = A", 1},
		{ "mtfsf", "fsf = A", 1},
		{ "mtfsfi", "fsfi = A", 1},
		{ "mtibatl", "ibatBl = A", 2},
		{ "mtibatu", "ibatBu = A", 2},
		{ "mticcr", "iccr = A", 1},
		{ "mtlr", "lr = A", 1},
		{ "mtmsr", "msr = A", 1},
		{ "mtmsrd", "msr = A", 1},
		{ "mtocrf", "cr0 = B & fxm_mask(A)", 2},
		{ "mtpid", "pid = A", 1},
		{ "mtspefscr", "fscr = A", 1},
		{ "mtsr", "srA = B", 2},
		{ "mtsrin", "sr_indirect(A) = B", 2},
		{ "mtsrr2", "srr2 = A", 1},
		{ "mtsrr3", "srr3 = A ", 1},
		{ "mttbhi", "tb_hi(A) = B", 2},
		{ "mttbl", "tbl(A) = B", 2},
		{ "mttblo", "tb_lo(A) = B", 2},
		{ "mttbu", "tbu = A", 1},
		{ "mtvscr", "vscr = A", 1},
		{ "mtxer", "xer = A", 1},
		{ "mulhd", "A = hi(B) * hi(C)", 3},
		{ "mulhdu", "A = (unsigned) hi(B) * hi(C)", 3},
		{ "mulhw", "A = (word) hi(B) * hi(C)", 3},
		{ "mulhwu", "A = (unsigned word) hi(B) * hi(C)", 3},
		{ "mulld", "A = lo(B) * lo(C)", 3},
		{ "mulli", "A = lo(B) * lo(C)", 3},
		{ "mullw", "A = (word) lo(B) * lo(C)", 3},
		{ "nand", "A = B & !C", 3},
		{ "neg", "A = -B", 2},
		{ "nop", "", 0},
		{ "nor", "A = B | !C", 3},
		{ "not", "A = !B", 2},
		{ "or", "A = B | C", 3},
		{ "orc", "A = B | C", 3},
		{ "ori", "A = B | C", 3},
		{ "oris", "A = B | (C << 16)", 3},
		{ "popcntd", "A = count_bits(B)", 2},
		{ "popcntw", "A = count_bits(B)", 2},
		{ "ptesync", "sync_page_tbl", 0},
		// Are you kidding? QPX Architecture totally NO.
		/*
		   { "qvaligni", "A = B + C", 3},
		   { "qvesplati", "A = B + C", 3},
		   { "qvfabs", "A = B + C", 3},
		   { "qvfadd", "A = B + C", 3},
		   { "qvfadds", "A = B + C", 3},
		   { "qvfand", "A = B + C", 3},
		   { "qvfandc", "A = B + C", 3},
		   { "qvfcfid", "A = B + C", 3},
		   { "qvfcfids", "A = B + C", 3},
		   { "qvfcfidu", "A = B + C", 3},
		   { "qvfcfidus", "A = B + C", 3},
		   { "qvfclr", "A = B + C", 3},
		   { "qvfcmpeq", "A = B + C", 3},
		   { "qvfcmpgt", "A = B + C", 3},
		   { "qvfcmplt", "A = B + C", 3},
		   { "qvfcpsgn", "A = B + C", 3},
		   { "qvfctfb", "A = B + C", 3},
		   { "qvfctid", "A = B + C", 3},
		   { "qvfctidu", "A = B + C", 3},
		   { "qvfctiduz", "A = B + C", 3},
		   { "qvfctidz", "A = B + C", 3},
		   { "qvfctiw", "A = B + C", 3},
		   { "qvfctiwu", "A = B + C", 3},
		   { "qvfctiwuz", "A = B + C", 3},
		   { "qvfctiwz", "A = B + C", 3},
		   { "qvfequ", "A = B + C", 3},
		   { "qvflogical", "A = B + C", 3},
		   { "qvfmadd", "A = B + C", 3},
		   { "qvfmadds", "A = B + C", 3},
		   { "qvfmr", "A = B + C", 3},
		   { "qvfmsub", "A = B + C", 3},
		   { "qvfmsubs", "A = B + C", 3},
		   { "qvfmul", "A = B + C", 3},
		   { "qvfmuls", "A = B + C", 3},
		   { "qvfnabs", "A = B + C", 3},
		   { "qvfnand", "A = B + C", 3},
		   { "qvfneg", "A = B + C", 3},
		   { "qvfnmadd", "A = B + C", 3},
		   { "qvfnmadds", "A = B + C", 3},
		   { "qvfnmsub", "A = B + C", 3},
		   { "qvfnmsubs", "A = B + C", 3},
		   { "qvfnor", "A = B + C", 3},
		   { "qvfnot", "A = B + C", 3},
		   { "qvfor", "A = B + C", 3},
		   { "qvforc", "A = B + C", 3},
		   { "qvfperm", "A = B + C", 3},
		   { "qvfre", "A = B + C", 3},
		   { "qvfres", "A = B + C", 3},
		   { "qvfrim", "A = B + C", 3},
		   { "qvfrin", "A = B + C", 3},
		   { "qvfrip", "A = B + C", 3},
		   { "qvfriz", "A = B + C", 3},
		   { "qvfrsp", "A = B + C", 3},
		   { "qvfrsqrte", "A = B + C", 3},
		   { "qvfrsqrtes", "A = B + C", 3},
		   { "qvfsel", "A = B + C", 3},
		   { "qvfset", "A = B + C", 3},
		   { "qvfsub", "A = B + C", 3},
		   { "qvfsubs", "A = B + C", 3},
		   { "qvftstnan", "A = B + C", 3},
		   { "qvfxmadd", "A = B + C", 3},
		   { "qvfxmadds", "A = B + C", 3},
		   { "qvfxmul", "A = B + C", 3},
		   { "qvfxmuls", "A = B + C", 3},
		   { "qvfxor", "A = B + C", 3},
		   { "qvfxxcpnmadd", "A = B + C", 3},
		   { "qvfxxcpnmadds", "A = B + C", 3},
		   { "qvfxxmadd", "A = B + C", 3},
		   { "qvfxxmadds", "A = B + C", 3},
		   { "qvfxxnpmadd", "A = B + C", 3},
		{ "qvfxxnpmadds", "A = B + C", 3},
		{ "qvgpci", "A = B + C", 3},
		{ "qvlfcdux", "A = B + C", 3},
		{ "qvlfcduxa", "A = B + C", 3},
		{ "qvlfcdx", "A = B + C", 3},
		{ "qvlfcdxa", "A = B + C", 3},
		{ "qvlfcsux", "A = B + C", 3},
		{ "qvlfcsuxa", "A = B + C", 3},
		{ "qvlfcsx", "A = B + C", 3},
		{ "qvlfcsxa", "A = B + C", 3},
		{ "qvlfdux", "A = B + C", 3},
		{ "qvlfduxa", "A = B + C", 3},
		{ "qvlfdx", "A = B + C", 3},
		{ "qvlfdxa", "A = B + C", 3},
		{ "qvlfiwax", "A = B + C", 3},
		{ "qvlfiwaxa", "A = B + C", 3},
		{ "qvlfiwzx", "A = B + C", 3},
		{ "qvlfiwzxa", "A = B + C", 3},
		{ "qvlfsux", "A = B + C", 3},
		{ "qvlfsuxa", "A = B + C", 3},
		{ "qvlfsx", "A = B + C", 3},
		{ "qvlfsxa", "A = B + C", 3},
		{ "qvlpcldx", "A = B + C", 3},
		{ "qvlpclsx", "A = B + C", 3},
		{ "qvlpcrdx", "A = B + C", 3},
		{ "qvlpcrsx", "A = B + C", 3},
		{ "qvstfcdux", "A = B + C", 3},
		{ "qvstfcduxa", "A = B + C", 3},
		{ "qvstfcduxi", "A = B + C", 3},
		{ "qvstfcduxia", "A = B + C", 3},
		{ "qvstfcdx", "A = B + C", 3},
		{ "qvstfcdxa", "A = B + C", 3},
		{ "qvstfcdxi", "A = B + C", 3},
		{ "qvstfcdxia", "A = B + C", 3},
		{ "qvstfcsux", "A = B + C", 3},
		{ "qvstfcsuxa", "A = B + C", 3},
		{ "qvstfcsuxi", "A = B + C", 3},
		{ "qvstfcsuxia", "A = B + C", 3},
		{ "qvstfcsx", "A = B + C", 3},
		{ "qvstfcsxa", "A = B + C", 3},
		{ "qvstfcsxi", "A = B + C", 3},
		{ "qvstfcsxia", "A = B + C", 3},
		{ "qvstfdux", "A = B + C", 3},
		{ "qvstfduxa", "A = B + C", 3},
		{ "qvstfduxi", "A = B + C", 3},
		{ "qvstfduxia", "A = B + C", 3},
		{ "qvstfdx", "A = B + C", 3},
		{ "qvstfdxa", "A = B + C", 3},
		{ "qvstfdxi", "A = B + C", 3},
		{ "qvstfdxia", "A = B + C", 3},
		{ "qvstfiwx", "A = B + C", 3},
		{ "qvstfiwxa", "A = B + C", 3},
		{ "qvstfsux", "A = B + C", 3},
		{ "qvstfsuxa", "A = B + C", 3},
		{ "qvstfsuxi", "A = B + C", 3},
		{ "qvstfsuxia", "A = B + C", 3},
		{ "qvstfsx", "A = B + C", 3},
		{ "qvstfsxa", "A = B + C", 3},
		{ "qvstfsxi", "A = B + C", 3},
		{ "qvstfsxia", "A = B + C", 3},
		*/
		{ "rfci", "msr = csrr1; nia = csrr0; ret", 0},
		{ "rfdi", "msr = drr1; nia = drr0; ret", 0},
		{ "rfi", "msr = srr1; nia = srr0; ret", 0},
		{ "rfid", "msr = srr1; nia = srr0; ret", 0},
		{ "rfmci", "msr = mcrr1; nia = mcrr0; ret", 3},
		{ "rotld", "A = rot64(B,C)", 3},
		{ "rotldi", "A = rot64(B,C)", 3},
		{ "rotlw", "A = rot32(B,C)", 3},
		{ "rotlwi", "A = rot32(B,C)", 3},
		{ "sc", "syscall", 0},
		{ "slbia", "slb_inval_all", 0},
		{ "slbie", "slb_inval_entry(A)", 1},
		{ "slbmfee", "A = slb[B]", 2},
		{ "slbmte", "slb[A] = B", 2},
		{ "sld", "A = B << C", 3},
		{ "sldi", "A = B << C", 3},
		{ "slw", "A = (word) B << C", 3},
		{ "slwi", "A = (word) B << C", 3},
		{ "srad", "A = B >> C", 3},
		{ "sradi", "A = B >> C", 3},
		{ "sraw", "A = (word) B >> C", 3},
		{ "srawi", "A = (word) B >> C", 3},
		{ "srd", "A = B >> C", 3},
		{ "srw", "A = (word) B >> C", 3},
		{ "srwi", "A = (word) B >> C", 3},
		{ "stb", "byte[C + B] = A", 3},
		{ "stbcix", "byte[C + B] = A", 3},
		{ "stbu", "byte[C + B] = A", 3},
		{ "stbux", "byte[C + B] = A", 3},
		{ "stbx", "byte[C + B] = A", 3},
		{ "std", "[C + B] = A", 3},
		{ "stdbrx", "[C + B] = A", 3},
		{ "stdcix", "[C + B] = A", 3},
		{ "stdcx", "[C + B] = A", 3},
		{ "stdu", "[C + B] = A", 3},
		{ "stdux", "[C + B] = A", 3},
		{ "stdx", "[C + B] = A", 3},
		{ "stfd", "float[C + B] = A", 3},
		{ "stfdu", "float[C + B] = A", 3},
		{ "stfdux", "float[C + B] = A", 3},
		{ "stfdx", "float[C + B] = A", 3},
		{ "stfiwx", "float[C + B] = A", 3},
		{ "stfs", "float[C + B] = A", 3},
		{ "stfsu", "float[C + B] = A", 3},
		{ "stfsux", "float[C + B] = A", 3},
		{ "stfsx", "float[C + B] = A", 3},
		{ "sth", "half[C + B] = A", 3},
		{ "sthbrx", "half[C + B] = A", 3},
		{ "sthcix", "half[C + B] = A", 3},
		{ "sthu", "half[C + B] = A", 3},
		{ "sthux", "half[C + B] = A", 3},
		{ "sthx", "half[C + B] = A", 3},
		{ "stmw", "multiple word[C + B] = A", 3},
		{ "stswi", "string word[C + B] = A", 3},
		{ "stvebx", "vector byte[C + B] = A", 3},
		{ "stvehx", "vector half[C + B] = A", 3},
		{ "stvewx", "vector word[C + B] = A", 3},
		{ "stvx", "vector[C + B] = A", 3},
		{ "stvxl", "vector[C + B] = A", 3},
		{ "stw", "word[C + B] = A", 3},
		{ "stwbrx", "word[C + B] = A", 3},
		{ "stwcix", "word[C + B] = A", 3},
		{ "stwcx", "word[C + B] = A", 3},
		{ "stwu", "word[C + B] = A", 3},
		{ "stwux", "word[C + B] = A", 3},
		{ "stwx", "word[C + B] = A", 3},
		{ "stxsdx", "vsx[C + B] = A", 3},
		{ "stxvdbx", "vector double[C + B] = A", 3},
		{ "stxvwdx", "vector word[C + B] = A", 3},
		{ "sub", "A = C - B", 3},
		{ "subc", "A = C - B", 3},
		{ "subf", "A = C - B", 3},
		{ "subfc", "A = C - B", 3},
		{ "subfe", "A = C - B", 3},
		{ "subfic", "A = C - B", 3},
		{ "subfme", "A = C - B", 3},
		{ "subfze", "A = C - B", 3},
		{ "sync", "sync_instr_cache", 0},
		{ "tdeq", "if (A == B) trap", 2},
		{ "tdeqi", "if (A == B) trap",2},
		{ "tdgt", "if (A > B) trap", 2},
		{ "tdgti", "if (A > B) trap", 2},
		{ "tdlgt", "if (A > B) trap", 2},
		{ "tdlgti", "if (A > B) trap", 2},
		{ "tdllt", "if (A < B) trap", 2},
		{ "tdllti", "if (A < B) trap", 2},
		{ "tdlt", "if (A < B) trap", 2},
		{ "tdlti", "if (A < B) trap", 2},
		{ "tdne", "if (A != B) trap", 2},
		{ "tdnei", "if (A != B) trap", 2},
		{ "tlbia", "inval_all_tlb", 0},
		{ "tlbie", "inval_tbl(A, B)", 2},
		{ "tlbiel", "inval_tbl(A)", 1},
		{ "tlbivax", "inval_va(A, B)", 2},
		{ "tlbld", "tlb_data_load(A)", 1},
		{ "tlbli", "tlb_instr_load(A)", 1},
		{ "tlbre", "A = tlb_read_entry(B,C)", 3},
		{ "tlbrehi", "A = tlb_read_entry_hi(B)", 2},
		{ "tlbrelo", "A = tlb_read_entry_lo(B)", 2},
		{ "tlbsx", "A = tlb_search(B)", 2},
		{ "tlbsync", "sync_tlb", 3},
		{ "tlbwe", "tlb_write_entry(B,C) = A", 3},
		{ "tlbwehi", "tlb_write_entry_hi(B) = A", 2},
		{ "tlbwelo", "tlb_write_entry_lo(B) = A", 2},
		{ "trap", "trap", 3},
		{ "tweq", "if ((word) A == (word) B) trap", 2},
		{ "tweqi", "if ((word) A == (word) B) trap",2},
		{ "twgt", "if ((word) A > (word) B) trap", 2},
		{ "twgti", "if ((word) A > (word) B) trap", 2},
		{ "twlgt", "if ((word) A > (word) B) trap", 2},
		{ "twlgti", "if ((word) A > (word) B) trap", 2},
		{ "twllt", "if ((word) A < (word) B) trap", 2},
		{ "twllti", "if ((word) A < (word) B) trap", 2},
		{ "twlt", "if ((word) A < (word) B) trap", 2},
		{ "twlti", "if ((word) A < (word) B) trap", 2},
		{ "twne", "if ((word) A != (word) B) trap", 2},
		{ "twnei", "if ((word) A != (word) B) trap", 2},
		{ "vaddcuw", "A = (unsigned vector) B + C", 3},
		{ "vaddfp", "A =  (float vector) B + C", 3},
		{ "vaddsbs", "A = (byte vector) B + C", 3},
		{ "vaddshs", "A = (half vector) B + C", 3},
		{ "vaddsws", "A = (word vector) B + C", 3},
		/* too much complexity to represent
		   { "vaddubm", "A = (byte vector) B + C + (modulo?)", 3},
		   { "vaddubs", "A = (byte vector) B + C", 3},
		   { "vaddudm", "A = (vector) B + C + (modulo?)", 3},
		   { "vadduhm", "A = (half vector) B + C", 3},
		   { "vadduhs", "A = (half vector) B + C", 3},
		   { "vadduwm", "A = (word vector) B + C", 3},
		   { "vadduws", "A = (word vector) B + C", 3},
		 */
		{ "vand", "A = B & C", 3},
		{ "vandc", "A = B & C", 3},
		{ "vavgsb", "A = (byte vector) avg(B, C)", 3},
		{ "vavgsh", "A = (half vector) avg(B, C)", 3},
		{ "vavgsw", "A = (word vector) avg(B, C)", 3},
		{ "vavgub", "A = (unsigned byte vector) avg(B, C)", 3},
		{ "vavguh", "A = (unsigned  half vector) avg(B, C)", 3},
		{ "vavguw", "A = (unsigned word vector) avg(B, C)", 3},
		{ "vcfsx", "A = (float vector) B", 2},
		{ "vcfux", "A = (float vector) B", 2},
		{ "vclzb", "A = (byte vector) count_zeros(B)", 2},
		{ "vclzd", "A = (vector) count_zeros(B)", 2},
		{ "vclzh", "A = (half vector) count_zeros(B)", 2},
		{ "vclzw", "A = (word vector) count_zeros(B)", 2},
		{ "vcmpbfp", "A = !(B < C) | (B == C) | !(B > C)", 3},
		{ "vcmpeqfp", "A = (float) B == (float) C", 3},
		{ "vcmpequb", "A = (unsigned byte) B == (byte) C", 3},
		{ "vcmpequd", "A = (unsigned) B ==  (unsigned) C", 3},
		{ "vcmpequh", "A = (unsigned half) B == (unsigned half) C", 3},
		{ "vcmpequw", "A = (unsigned word) B == (unsigned word) C", 3},
		{ "vcmpgefp", "A = (float) B >= (float) C", 3},
		{ "vcmpgtsb", "A = (byte) B > (byte) C", 3},
		{ "vcmpgtsd", "A = B > C", 3},
		{ "vcmpgtsh", "A = (half) B > (half) C", 3},
		{ "vcmpgtsw", "A = (word) B > (word) C", 3},
		{ "vcmpgtub", "A = (unsigned byte) B > (byte) C", 3},
		{ "vcmpgtud", "A = (unsigned) B >  (unsigned) C", 3},
		{ "vcmpgtuh", "A = (unsigned half) B > (unsigned half) C", 3},
		{ "vcmpgtuw", "A = (unsigned word) B > (unsigned word) C", 3},
		{ "vctsxs", "A = (word) B", 2},
		{ "vctuxs", "A = (unsigned word) B", 2},
		{ "veqv", "A = (vector) B ^ C", 3},
		{ "vexptefp", "A = (float vector) pow(2, B)", 2},
		{ "vlogefp", "A = (float vector)  log2(B)", 2},
		{ "vmaddfp", "A = (float vector)  (B * C) + round(D)", 4},
		{ "vmaxfp", "A = (float vector) max(B, C)", 3},
		{ "vmaxsb", "A = (byte vector) max(B, C)", 3},
		{ "vmaxsd", "A = (vector) max(B, C)", 3},
		{ "vmaxsh", "A = (half vector) max(B, C)", 3},
		{ "vmaxsw", "A = (word vector) max(B, C)", 3},
		{ "vmaxub", "A = (unsigned byte vector) max(B, C)", 3},
		{ "vmaxud", "A = (vector) max(B, C)", 3},
		{ "vmaxuh", "A = (unsigned half vector) max(B, C)", 3},
		{ "vmaxuw", "A = (unsigned word vector) max(B, C)", 3},
		//    { "vmhaddshs", "A = (vector)  B + C + D", 4},
		//    { "vmhraddshs", "A = (vector) B + C + D", 4},
		{ "vminfp", "A = (float vector) min(B, C)", 3},
		{ "vminsb", "A = (byte vector) min(B, C)", 3},
		{ "vminsd", "A = (vector) min(B, C)", 3},
		{ "vminsh", "A = (half vector) min(B, C)", 3},
		{ "vminsw", "A = (word vector) min(B, C)", 3},
		{ "vminub", "A = (unsigned byte vector) min(B, C)", 3},
		{ "vminud", "A = (vector) min(B, C)", 3},
		{ "vminuh", "A = (unsigned half vector) min(B, C)", 3},
		{ "vminuw", "A = (unsigned word vector) min(B, C)", 3},
		//    { "vmladduhm", "A = (unsigned half vector) B + C", 3},
		{ "vmrghb", "A = (byte vector) merge_hi(B, C)", 3},
		{ "vmrghh", "A = (half vector) merge_hi(B, C)", 3},
		{ "vmrghw", "A = (word vector) merge_hi(B, C)", 3},
		{ "vmrglb", "A = (byte vector) merge_lo(B, C)", 3},
		{ "vmrglh", "A = (half vector) merge_lo(B, C)", 3},
		{ "vmrglw", "A = (word vector) merge_lo(B, C)", 3},
		{ "vmsummbm", "A = (byte vector) B + C", 3},
		{ "vmsumshm", "A = (half vector) B + C", 3},
		{ "vmsumshs", "A = (half vector) B + C", 3},
		{ "vmsumubm", "A = (unsigned byte vector) B + C", 3},
		{ "vmsumuhm", "A = (unsigned half vector) B + C", 3},
		{ "vmsumuhs", "A = (unsigned half vector) B + C", 3},
		{ "vmulesb", "A = (byte vector) B * C", 3},
		{ "vmulesh", "A = (half vector) B * C", 3},
		{ "vmulesw", "A = (word vector) B * C", 3},
		{ "vmuleub", "A = (unsigned byte vector) B * C", 3},
		{ "vmuleuh", "A = (unsigned half vector) B * C", 3},
		{ "vmuleuw", "A = (unsigned word vector) B * C", 3},
		{ "vmulosb", "A = (byte vector) B * C", 3},
		{ "vmulosh", "A = (byte vector) B * C", 3},
		{ "vmulosw", "A = (byte vector) B * C", 3},
		{ "vmuloub", "A = (byte vector) B * C", 3},
		{ "vmulouh", "A = (unsigned byte vector) B * C", 3},
		{ "vmulouw", "A = (unsigned byte vector) B * C", 3},
		{ "vmuluwm", "A = (unsigned word vector) B * C", 3},
		{ "vnand", "A = (vector) B & C", 3},
		{ "vnmsubfp", "A = (float vector) (B * C) - round(D)", 4},
		{ "vnor", "A = (vector) B | !C", 3},
		{ "vor", "A = (vector) B | C", 3},
		{ "vorc", "A = (vector) B | C", 3},
		// This should be represented as a for loop of bits comparing.. too much complex for pseudo
		//    { "vperm", "A = (vector) B + C", 3},
		{ "vpkpx", "A = (vector) pack_pixel(B, C)", 3},
		{ "vpkshss", "A = (half vector) pack_pixel_saturate(B, C)", 3},
		{ "vpkshus", "A = (unsigned half vector) pack_pixel_saturate(B, C)", 3},
		{ "vpkswss", "A = (word vector) pack_pixel_saturate(B, C)", 3},
		{ "vpkswus", "A = (unsigned word vector) pack_pixel_saturate(B, C)", 3},
		//    { "vpkuhum", "A = (vector) B + C", 3},
		//    { "vpkuhus", "A = (vector) B + C", 3},
		//    { "vpkuwum", "A = (vector) B + C", 3},
		//    { "vpkuwus", "A = (vector) B + C", 3},
		{ "vpopcntb", "A = (vector) count_8bits(B)", 2},
		{ "vpopcntd", "A = (vector) count_64bits(B)", 2},
		{ "vpopcnth", "A = (vector) count_16bits(B)", 2},
		{ "vpopcntw", "A = (vector) count_32bits(B)", 2},
		{ "vrefp", "A = (float vector) 1/B", 2},
		{ "vrfim", "A = (vector) floor(B)", 2},
		{ "vrfin", "A = (vector) near(B)", 2},
		{ "vrfip", "A = (vector) ceil(B)", 2},
		{ "vrfiz", "A = (vector) trunc(B)", 2},
		{ "vrlb", "A = (vector) rotl_byte(B, C)", 3},
		{ "vrld", "A = (vector) rotl(B, C)", 3},
		{ "vrlh", "A = (vector) rotl_half(B, C)", 3},
		{ "vrlw", "A = (vector) rotl_word(B, C)", 3},
		{ "vrsqrtefp", "A = (vector) sqrt(B)", 2},
		{ "vsel", "A = (vector) if (D & 1) B else C", 4},
		{ "vsl", "A = (vector) B << C", 3},
		{ "vslb", "A = (byte vector) B << C", 3},
		{ "vsld", "A = (vector) B << C", 3},
		{ "vsldoi", "A = (vector) B << (octet) C", 3},
		{ "vslh", "A = (half vector) B << C", 3},
		{ "vslo", "A = (vector) B <<< (octet) C", 3},
		{ "vslw", "A = (word vector) B + C", 3},
		{ "vspltb", "A = (vector) splat_byte(B, C)", 3},
		{ "vsplth", "A = (vector) splat_half(B, C)", 3},
		{ "vspltisb", "A = (vector) splat_byte(B, C)", 3},
		{ "vspltish", "A = (vector) splat_half(B, C)", 3},
		{ "vspltisw", "A = (vector) splat_word(B, C)", 3},
		{ "vspltw", "A = (vector) splat_word(B, C)", 3},
		{ "vsr", "A = (vector) B >> C", 3},
		{ "vsrab", "A = (byte vector) B >> C", 3},
		{ "vsrad", "A = (vector) B >> C", 3},
		{ "vsrah", "A = (half vector) B >> C", 3},
		{ "vsraw", "A = (word vector) B >> C", 3},
		{ "vsrb", "A = (byte vector) B >> C", 3},
		{ "vsrd", "A = (vector) B >> C", 3},
		{ "vsrh", "A = (half vector) B >> C", 3},
		{ "vsro", "A = (vector) B >> (octet) C", 3},
		{ "vsrw", "A = (word vector) B >> C", 3},
		{ "vsubcuw", "A = (unsigned word vector) (C - B) & 1", 3},
		{ "vsubfp", "A = (float vector) C - B", 3},
		{ "vsubsbs", "A = (byte vector) C - B", 3},
		{ "vsubshs", "A = (half vector) C - B", 3},
		{ "vsubsws", "A = (word vector) C - B", 3},
		{ "vsububm", "A = (byte vector) C - B", 3},
		{ "vsububs", "A = (byte vector) C - B", 3},
		{ "vsubudm", "A = (unsigned vector) C - B", 3},
		{ "vsubuhm", "A = (unsigned half vector) C - B", 3},
		{ "vsubuhs", "A = (unsigned half vector) C - B", 3},
		{ "vsubuwm", "A = (unsigned word vector) C - B", 3},
		{ "vsubuws", "A = (unsigned word vector) C - B", 3},
		{ "vsumbsws", "A = (word vector) B + C", 3},
		{ "vsumdsbs", "A = (byte vector) B + C", 3},
		{ "vsumdshs", "A = (half vector) B + C", 3},
		{ "vsumdubs", "A = (unsigned vector) B + C", 3},
		{ "vsumsws", "A = (word vector) B + C", 3},
		{ "vupkhpx", "A = (vector) unpack_hi_pixel(B)", 3},
		{ "vupkhsb", "A = (byte vector) unpack_hi_pixel(B)", 3},
		{ "vupkhsh", "A = (half vector) unpack_hi_pixel(B)", 3},
		{ "vupklpx", "A = (vector) unpack_lo_pixel(B)", 3},
		{ "vupklsb", "A = (byte vector) unpack_lo_pixel(B)", 3},
		{ "vupklsh", "A = (half vector) unpack_lo_pixel(B)", 3},
		{ "vxor", "A = (vector) B ^ C", 3},
		{ "wait", "wait_interrupt", 0},
		{ "waitimpl", "wait_interrupt_thread_reservation", 0},
		{ "waitrsv", "wait_interrupt_implemention", 0},
		{ "wrtee", "msr &= A", 1},
		{ "wrteei", "msr &= A", 1},
		{ "xnop", "", 0},
		{ "xor", "A = B ^ C", 3},
		{ "xori", "A = B ^ C", 3},
		{ "xoris", "A = B ^ (C << 16)", 3},
		{ "xsabsdp", "A = (double vector) abs(B)", 2},
		{ "xsadddp", "A = (double vector) B + C", 3},
		{ "xscmpodp", "A = (double vector) B == C", 3},
		{ "xscmpudp", "A = (double vector) B == C", 3},
		{ "xscpsgndp", "A = (double vector) copy_sign(B, C)", 3},
		{ "xscvdpsp", "A = (double vector) round(B)", 2},
		{ "xscvdpsxds", "A = (vector) ((double) B)", 2},
		{ "xscvdpsxws", "A = (word vector) ((double) B)", 2},
		{ "xscvdpuxds", "A = (unsigned vector) ((double) B)", 2},
		{ "xscvdpuxws", "A = (unsigned word vector) ((double) B)", 2},
		{ "xscvspdp", "A = (double vector) ((float) B)", 2},
		{ "xscvsxddp", "A = (double vector) B", 2},
		{ "xscvuxddp", "A = (double vector) ((unsigned) B)", 2},
		{ "xsdivdp", "A = (double vector) B / C", 3},
		// multiply add
		//    { "xsmaddadp", "A = (double vector) B * C + ?", 3},
		//    { "xsmaddmdp", "A = (double vector) B * C + ?", 3},
		{ "xsmaxdp", "A = (double vector) max(B, C)", 3},
		{ "xsmindp", "A = (double vector) min(B, C)", 3},
		// multiply sub
		//    { "xsmsubadp", "A = (double vector) B * C - ?", 3},
		//    { "xsmsubmdp", "A = (double vector) B * C - ?", 3},
		{ "xsmuldp", "A = (double vector) B * C", 3},
		{ "xsnabsdp", "A = (double vector) -abs(B)", 2},
		{ "xsnegdp", "A = (double vector) -B", 2},
		// negative multiply add
		//    { "xsnmaddadp", "A = (double vector) B * C + ?", 3},
		//    { "xsnmaddmdp", "A = (double vector) B + C + ?", 3},
		// negative multiply sub
		//    { "xsnmsubadp", "A = (double vector) B + C - ?", 3},
		//    { "xsnmsubmdp", "A = (double vector) B + C - ?", 3},
		{ "xsrdpi",  "A = (double vector) round(B)", 2},
		{ "xsrdpic", "A = (double vector) round(B)", 2},
		{ "xsrdpim", "A = (double vector) floor(B)", 2},
		{ "xsrdpip", "A = (double vector) ceil(B)", 2},
		{ "xsrdpiz", "A = (double vector) trunc(B)", 2},
		{ "xsredp", "A = (double vector) 1/B", 2},
		{ "xsrsqrtedp", "A = (double vector) 1/sqrt(B)", 2},
		{ "xssqrtdp", "A = sqrt(B)", 2},
		{ "xssubdp", "A = C - B", 3},
		{ "xstdivdp", "A = test_sw_divide(B, C)", 3},
		{ "xstsqrtdp", "A = test_sw_sqrt(B)", 2},
		{ "xvabsdp", "A = (double vector) abs(B)", 2},
		{ "xvabssp", "A = (float vector) abs(B)", 2},
		{ "xvadddp", "A = (double vector) B + C", 3},
		{ "xvaddsp", "A = (float vector) B + C", 3},
		{ "xvcmpeqdp", "A = (double vector) B == (double vector) C", 3},
		{ "xvcmpeqsp", "A = (float vector) B == (float vector) C", 3},
		{ "xvcmpgedp", "A = (double vector) B >= (double vector) C", 3},
		{ "xvcmpgesp", "A = (float vector) B >= (float vector) C", 3},
		{ "xvcmpgtdp", "A = (double vector) B > (double vector) C", 3},
		{ "xvcmpgtsp", "A = (float vector) B > (float vector) C", 3},
		{ "xvcpsgndp", "A = (double vector) copy_sign(B, C)", 3},
		{ "xvcpsgnsp", "A = (float vector) copy_sign(B, C)", 3},
		{ "xvcvdpsp", "A = (float vector) ((double vector)B)", 2},
		{ "xvcvdpsxds", "A = (vector) B", 2},
		{ "xvcvdpsxws", "A = (word vector) B", 2},
		{ "xvcvdpuxds", "A = (unsigned vector) B", 2},
		{ "xvcvdpuxws", "A = (unsigned word vector) B", 2},
		{ "xvcvspdp", "(double vector) ((float vector) B)", 2},
		{ "xvcvspsxds", "A = (vector) ((float vector) B)", 2},
		{ "xvcvspsxws", "A = (word vector) ((float vector) B)", 2},
		{ "xvcvspuxds", "A = (unsigned vector) ((float vector) B)", 2},
		{ "xvcvspuxws", "A = (unsigned word vector) ((float vector) B)", 2},
		{ "xvcvsxddp", "A = (double vector) B", 2},
		{ "xvcvsxdsp", "A = (float vector) B", 2},
		{ "xvcvsxwdp", "A = (double vector) ((word) B)", 2},
		{ "xvcvsxwsp", "A = (float vector) ((word) B)", 2},
		{ "xvcvuxddp", "A = (double vector) (unsigned) B", 2},
		{ "xvcvuxdsp", "A = (float vector) (unsigned) B", 2},
		{ "xvcvuxwdp", "A = (double vector) ((unsigned word) B)", 2},
		{ "xvcvuxwsp", "A = (float vector) ((unsigned word) B)", 2},
		{ "xvdivdp", "A = (double vector) B / C", 3},
		{ "xvdivsp", "A = (float vector) B / C", 3},
		//Multiply add (double & float)
		//    { "xvmaddadp", "A = B + C", 3},
		//    { "xvmaddasp", "A = B + C", 3},
		//    { "xvmaddmdp", "A = B + C", 3},
		//    { "xvmaddmsp", "A = B + C", 3},
		{ "xvmaxdp", "A = (double vector) max(B)", 2},
		{ "xvmaxsp", "A = (float vector) max(B)", 2},
		{ "xvmindp", "A = (double vector) min(B)", 2},
		{ "xvminsp", "A = (float vector) min(B)", 2},
		{ "xvmovdp", "A = (double vector) B", 2},
		{ "xvmovsp", "A = (float vector) B", 2},
		//Multiply sub (double & float)
		//    { "xvmsubadp", "A = B + C", 3},
		//    { "xvmsubasp", "A = B + C", 3},
		//    { "xvmsubmdp", "A = B + C", 3},
		//    { "xvmsubmsp", "A = B + C", 3},
		{ "xvmuldp", "A = (double vector) B * C", 3},
		{ "xvmulsp", "A = (float vector) B * C", 3},
		{ "xvnabsdp", "A = (double vector) -abs(B)", 2},
		{ "xvnabssp", "A = (float vector) -abs(B)", 2},
		{ "xvnegdp", "A = (double vector) -B", 2},
		{ "xvnegsp", "A = (float vector) -B", 2},
		//Negate multiply add (double & float)
		//    { "xvnmaddadp", "A = B + C", 3},
		//    { "xvnmaddasp", "A = B + C", 3},
		//    { "xvnmaddmdp", "A = B + C", 3},
		//    { "xvnmaddmsp", "A = B + C", 3},
		//Negate multiply sub (double & float)
		//    { "xvnmsubadp", "A = B + C", 3},
		//    { "xvnmsubasp", "A = B + C", 3},
		//    { "xvnmsubmdp", "A = B + C", 3},
		//    { "xvnmsubmsp", "A = B + C", 3},
		{ "xvrdpi", "A = (double vector) round(B)", 2},
		{ "xvrdpic", "A = (double vector) round(B)", 2},
		{ "xvrdpim", "A = (double vector) floor(B)", 2},
		{ "xvrdpip", "A = (double vector) ceil(B)", 2},
		{ "xvrdpiz", "A = (double vector) trunc(B)", 2},
		{ "xvredp", "A = (double vector) 1/B",2},
		{ "xvresp", "A = (float vector) B", 2},
		{ "xvrspi", "A = (float vector) round(B)", 2},
		{ "xvrspic", "A = (float vector) round(B)", 2},
		{ "xvrspim", "A = (float vector) floor(B)", 2},
		{ "xvrspip", "A = (float vector) ceil(B)", 2},
		{ "xvrspiz", "A = (float vector) trunc(B)", 2},
		{ "xvrsqrtedp", "A = (double vector) 1/sqrt(B)", 2},
		{ "xvrsqrtesp", "A = (float vector) 1/sqrt(B)", 2},
		{ "xvsqrtdp", "A = (double vector) sqrt(B)", 2},
		{ "xvsqrtsp", "A = (float vector) sqrt(B)", 2},
		{ "xvsubdp", "A = (double vector) C - B", 3},
		{ "xvsubsp", "A = (float vector) C - B", 3},
		{ "xvtdivdp", "A = (double vector) B / C", 3},
		{ "xvtdivsp", "A = (float vector) B / C", 3},
		{ "xvtsqrtdp", "A = (double vector) test_sw_sqrt(B)", 3},
		{ "xvtsqrtsp", "A = (float vector) test_sw_sqrt(B)", 3},
		{ "xxland", "A = B & C", 3},
		{ "xxlandc", "A = B & C", 3},
		{ "xxleqv", "A = B ^ C", 3},
		{ "xxlnand", "A = B & !C", 3},
		{ "xxlnor", "A = B + !C", 3},
		{ "xxlor", "A = B | C", 3},
		{ "xxlorc", "A = B | C", 3},
		{ "xxlxor", "A = B ^ C", 3},
		{ "xxmrghd", "A = hi(B) || hi(C)", 3},
		{ "xxmrghw", "A = (word vector) hi(B) || hi(C)", 3},
		{ "xxmrgld", "A = lo(B) || lo(C)", 3},
		{ "xxmrglw", "A = (word vector) lo(B) || lo(C)", 3},
		// Permute Doubleword Immediate
		//    { "xxpermdi", "A = B + C", 3},
		// Select (aka concat)
		//    { "xxsel", "A = B + C + D", 4},
		{ "xxsldwi", "A = B << C", 3},
		{ "xxspltd", "A = split(B)", 2},
		{ "xxspltw", "A = (word vector) split(B)", 2},
		{ "xxswapd", "swap(A,B)", 2},
		{ NULL }
	};

	char ppc_mask[32] = {0}; // enough to represent max val of 0xffffffffffffffff
	for (i = 0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr) {
				for (j = k = 0; ops[i].str[j] != '\0'; j++, k++) {
					if (can_replace(ops[i].str, j, ops[i].max_operands)) {
						if (i >= 0 && i <= 26 && argv[ops[i].max_operands][0] == 0) {
							char* tmp = (char*) argv[ops[i].max_operands];
							argv[ops[i].max_operands] = argv[ops[i].max_operands - 1];
							if (ops[i].max_operands == 3) {
								argv[2] = argv[1];
							}
							tmp[0] = 'c';
							tmp[1] = 'r';
							tmp[2] = '0';
							tmp[3] = '\0';
							argv[1] = tmp;
						}
						int letter = ops[i].str[j] - '@';
						const char *w = argv[letter];
						// eprintf("%s:%d %s\n", ops[i].op, letter, w);
						if (letter == 4 && !strncmp (argv[0], "rlwinm", 6)) {
							// { "rlwinm", "A = rol32(B, C) & D", 5},
							w = ppc_mask;
							//MASK(MB+32, ME+32)
							ut64 MB = PPC_UT64(argv[4]) + 32;
							ut64 ME = PPC_UT64(argv[5]) + 32;
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT64x"", mask64 (MB, ME));
						} else if (letter == 4 && (!strncmp (argv[0], "rldcl", 5) || !strncmp (argv[0], "rldicl", 6))) {
							// { "rld[i]cl", "A = rol64(B, C) & D", 4},
							w = ppc_mask;
							//MASK(MB, 63)
							ut64 MB = PPC_UT64(argv[4]);
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT64x"", mask64 (MB, 63));
						} else if (letter == 4 && !strncmp (argv[0], "rldic", 5)) {
							// { "rldic", "A = rol64(B, C) & D", 4},
							w = ppc_mask;
							//MASK(MB, 63 - SH)
							ut64 MB = PPC_UT64(argv[4]);
							ut64 ME = 63 - PPC_UT64(argv[3]);
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT64x"", mask64 (MB, ME));
						} else if (letter == 4 && (!strncmp (argv[0], "rldcr", 5) || !strncmp (argv[0], "rldicr", 6))) {
							// { "rld[i]cr", "A = rol64(B, C) & D", 4},
							w = ppc_mask;
							//MASK(0, ME)
							ut64 ME = PPC_UT64(argv[4]);
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT64x"", mask64 (0, ME));
						} else if (letter == 4 && !strncmp (argv[0], "rldimi", 6)) {
							// { "rldimi", "A = (rol64(B, C) & D) | (A & E)", 5}, //32
							// first mask (normal)
							w = ppc_mask;
							//MASK(MB, 63 - SH)
							ut64 MB = PPC_UT64(argv[4]);
							ut64 ME = 63 - PPC_UT64(argv[3]);
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT64x"", mask64 (MB, ME));
						} else if (letter == 5 && !strncmp (argv[0], "rldimi", 6)) {
							// { "rldimi", "A = (rol64(B, C) & D) | (A & E)", 5}, //32
							// second mask (inverted)
							w = ppc_mask;
							//MASK(MB, 63 - SH)
							ut64 MB = PPC_UT64(argv[4]);
							ut64 ME = 63 - PPC_UT64(argv[3]);
							ut64 inverted = ~ (mask64 (MB, ME));
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT64x"", inverted);
						} else if (letter == 4 && !strncmp (argv[0], "rlwimi", 6)) {
							// { "rlwimi", "A = (rol64(B, C) & D) | (A & E)", 5}, //32
							// first mask (normal)
							w = ppc_mask;
							//MASK(MB, ME)
							ut32 MB = PPC_UT32(argv[4]);
							ut32 ME = PPC_UT32(argv[5]);
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT32x"", mask32 (MB, ME));
						} else if (letter == 5 && !strncmp (argv[0], "rlwimi", 6)) {
							// { "rlwimi", "A = (rol32(B, C) & D) | (A & E)", 5}, //32
							// second mask (inverted)
							w = ppc_mask;
							//MASK(MB, ME)
							ut32 MB = PPC_UT32(argv[4]);
							ut32 ME = PPC_UT32(argv[5]);
							ut32 inverted = ~mask32 (MB, ME);
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT32x"", inverted);
						} else if (letter == 4 && !strncmp (argv[0], "rlwnm", 5)) {
							// { "rlwnm", "A = rol32(B, C) & D", 5}, //32
							w = ppc_mask;
							//MASK(MB, ME)
							ut32 MB = PPC_UT32(argv[4]);
							ut32 ME = PPC_UT32(argv[5]);
							snprintf (ppc_mask, sizeof (ppc_mask), "0x%"PFMT32x"", mask32 (MB, ME));
						} else if (letter == 1 && i >= 36 && i <= 43) {
							int to = atoi (w);
							switch(to) {
								case 4:
									w = "==";
									break;
								case 1:
								case 8:
									w = ">";
									break;
								case 5:
								case 12:
									w = ">=";
									break;
								case 2:
								case 16:
									w = "<";
									break;
								case 6:
								case 20:
									w = "<=";
									break;
								case 24:
									w = "!=";
									break;
								case 31:
									// If no parameters t[dw][i] 32, 0, 0 just TRAP
									w = "==";
									break;
								default:
									w = "?";
									break;
							}
						} else if ((i == 44 && letter == 2) || (i == 45 && letter == 1)) { //spr
							w = getspr (w);
						}
						if (w != NULL) {
							strcpy (newstr + k, w);
							k += strlen (w) - 1;
						}
					} else {
						newstr[k] = ops[i].str[j];
					}
				}
				newstr[k]='\0';
			}
			return true;
		}
	}

	/* TODO: this is slow */
	if (newstr) {
		newstr[0] = '\0';
		for (i = 0; i < argc; i++) {
			strcat (newstr, argv[i]);
			strcat (newstr, (i == 0 || i == argc - 1) ? " ":", ");
		}
	}

	return false;
}

#define WSZ 128
static int parse(RParse *p, const char *data, char *str) {
	int i, len = strlen (data);
	char w0[WSZ];
	char w1[WSZ];
	char w2[WSZ];
	char w3[WSZ];
	char w4[WSZ];
	char w5[WSZ];
	char *buf, *ptr, *optr;

	if (!strcmp (data, "jr ra")) {
		strcpy (str, "return");
		return true;
	}

	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return false;
	}
	memcpy (buf, data, len + 1);

	r_str_replace_char (buf, '(', ',');
	r_str_replace_char (buf, ')', ' ');
	r_str_trim (buf);
	if (*buf) {
		w0[0] = '\0';
		w1[0] = '\0';
		w2[0] = '\0';
		w3[0] = '\0';
		w4[0] = '\0';
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr == ' '; ptr++) {
				//nothing to see here
			}
			strncpy (w0, buf, WSZ - 1);
			strncpy (w1, ptr, WSZ - 1);

			optr = ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					//nothing to see here
				}
				strncpy (w1, optr, WSZ - 1);
				strncpy (w2, ptr, WSZ - 1);
				optr = ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr == ' '; ptr++) {
						//nothing to see here
					}
					strncpy (w2, optr, WSZ - 1);
					strncpy (w3, ptr, WSZ - 1);
					optr = ptr;
					// bonus
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						for (++ptr; *ptr == ' '; ptr++) {
							//nothing to see here
						}
						strncpy (w3, optr, WSZ - 1);
						strncpy (w4, ptr, WSZ - 1);
						optr = ptr;
						// bonus
						ptr = strchr (ptr, ',');
						if (ptr) {
							*ptr = '\0';
							for (++ptr; *ptr == ' '; ptr++) {
								//nothing to see here
							}
							strncpy (w4, optr, WSZ - 1);
							strncpy (w5, ptr, WSZ - 1);
						}
					}
				}
			}
		} else {
			strncpy (w0, buf, WSZ - 1);
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4, w5 };
			int nw = 0;
			for (i = 0; i < 4; i++) {
				if (wa[i][0] != '\0') {
					nw++;
				}
			}
			replace (nw, wa, str);
			{
				char *p = strdup (str);
				p = r_str_replace (p, "+ -", "- ", 0);
				p = r_str_replace (p, " + ]", "]  ", 0);
				//  p = r_str_replace (p, "if (r0 == r0) trap", "trap            ", 0);
#if EXPERIMENTAL_ZERO
				p = r_str_replace (p, "zero", "0", 0);
				if (!memcmp (p, "0 = ", 4)) *p = 0; // nop
#endif
				if (!strcmp (w1, w2)) {
					char a[64], b[64];
#define REPLACE(x,y) do { \
		int snprintf_len1_ = snprintf (a, 64, x, w1, w1); \
		int snprintf_len2_ = snprintf (b, 64, y, w1); \
		if (snprintf_len1_ < 64 && snprintf_len2_ < 64) { \
			p = r_str_replace (p, a, b, 0); \
		} \
	} while (0)

					// TODO: optimize
					REPLACE ("%s = %s +", "%s +=");
					REPLACE ("%s = %s -", "%s -=");
					REPLACE ("%s = %s &", "%s &=");
					REPLACE ("%s = %s |", "%s |=");
					REPLACE ("%s = %s ^", "%s ^=");
					REPLACE ("%s = %s >>", "%s >>=");
					REPLACE ("%s = %s <<", "%s <<=");
				}
				p = r_str_replace (p, ":", "0000", 0);
				strcpy (str, p);
				free (p);
			}
		}
	}
	free (buf);
	return true;
}

RParsePlugin r_parse_plugin_ppc_pseudo = {
	.name = "ppc.pseudo",
	.desc = "PowerPC pseudo syntax",
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_ppc_pseudo,
	.version = R2_VERSION
};
#endif
