// Sharp SM5xx MCU family disassembler
// Based on mame code licensed under BSD-3-Clause
// copyright-holders:hap, Jonathan Gevaryahu
// radare2 - 2023 - pancake

#include <r_arch.h>

#include "sm5xx.h"

// constructor

#if 0
sm510_common_disassembler_sm510_common_disassembler() {
	// init 6-bit lfsr pc lut
	ut32 i;
	for (i = 0, pc = 0; i < 0x3f; i++)
	{
		m_l2r6[i] = pc;
		m_r2l6[pc] = i;
		pc = increment_pc(pc, 6);
	}

	m_l2r6[0x3f] = 0x3f;
	m_r2l6[0x3f] = 0x3f;

	// init 7-bit lfsr pc lut
	for (i = 0, pc = 0; i < 0x7f; i++)
	{
		m_l2r7[i] = pc;
		m_r2l7[pc] = i;
		pc = increment_pc(pc, 7);
	}

	m_l2r7[0x7f] = 0x7f;
	m_r2l7[0x7f] = 0x7f;
}
#endif

static ut64 increment_pc(ut64 pc, ut8 pclen) {
	ut32 feed = ((pc >> 1 ^ pc) & 1) ? 0 : (1 << (pclen - 1));
	ut32 mask = (1 << pclen) - 1;
	return feed | (pc >> 1 & (mask >> 1)) | (pc & ~mask);
}

// common lookup tables
static const char *const s_mnemonics[] = {
	// SM510
	"?", "",
	"lb", "lbl", "sbm", "exbla", "incb", "decb",
	"atpl", "rtn0", "rtn1", "tl", "tml", "tm", "t",
	"exc", "bdc", "exci", "excd", "lda", "lax", "ptw", "wr", "ws",
	"kta", "atbp", "atx", "atl", "atfc", "atr",
	"add", "add11", "adx", "coma", "rot", "rc", "sc",
	"tb", "tc", "tam", "tmi", "ta0", "tabl", "tis", "tal", "tf1", "tf4",
	"rm", "sm",
	"pre", "sme", "rme", "tmel",
	"skip", "cend", "idiv", "dr", "dta", "clklo", "clkhi",

	// SM500
	"comcb", "rtn", "rtns", "ssr", "tr", "trs", "rbm",
	"addc", "pdtw", "tw", "dtw",
	"ats", "exksa", "exkfa",
	"rmf", "smf", "comcn",
	"ta", "tm", "tg",

	// SM530
	"sabm", "sabl", "exbl",
	"tg", "tba",
	"keta", "atf", "sds", "rds",
	"inis",

	// SM590
	"tax", "lblx", "mtr", "str", "inbm", "debm", "rta", "blta", "exax", "tba", "ads", "adc", "lbmx", "tls",
	"nop", "cctrl", "inbl", "debl", "xbla", "adcs", "tr"
};

// number of bits per opcode parameter, 8 or larger means 2-byte opcode
static const ut8 s_bits[] = {
	// SM510
	0, 8,
	4, 8, 0, 0, 0, 0,
	0, 0, 0, 4+8, 2+8, 6, 6,
	2, 0, 2, 2, 2, 4, 0, 0, 0,
	0, 0, 0, 0, 0, 0,
	0, 0, 4, 0, 0, 0, 0,
	0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
	2, 2,
	8, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0,

	// SM500
	0, 0, 0, 4, 6, 6, 0,
	0, 0, 0, 0,
	0, 0, 0,
	0, 0, 0,
	0, 2, 0,

	// SM530
	0, 0, 0,
	2, 0,
	0, 0, 0, 0,
	0,

	// SM590
	4, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 2+8,
	0, 0, 0, 0, 0, 0, 7
};

static const ut32 s_flags[] = {
	// SM510
	0, 0,
	0, 0, 0, 0, STEP_COND, STEP_COND,
	0, STEP_OUT, STEP_OUT, 0, STEP_OVER, STEP_OVER, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0,
	0, STEP_COND, STEP_COND, 0, 0, 0, 0,
	STEP_COND, STEP_COND, STEP_COND, STEP_COND, STEP_COND, STEP_COND, STEP_COND, STEP_COND, STEP_COND, STEP_COND,
	0, 0,
	0, 0, 0, 0,
	0, STEP_OVER, 0, 0, 0, 0, 0,

	// SM500
	0, STEP_OUT, STEP_OUT, 0, 0, STEP_OVER, 0,
	STEP_COND, 0, 0, 0,
	0, 0, 0,
	0, 0, 0,
	STEP_COND, STEP_COND, STEP_COND,

	// SM530
	0, 0, 0,
	STEP_COND, STEP_COND,
	0, 0, 0, 0,
	0,

	// SM590
	STEP_COND, 0, 0, 0, 0, 0, 0, 0, 0, STEP_COND, 0, 0, 0, STEP_OVER,
	0, 0, 0, 0, 0, 0, STEP_OVER
};


// common disasm

// ut64 sm510_common_disassembler
static ut64 common_disasm(const ut8 *lut_mnemonic, const ut8 *lut_extended, RStrBuf *stream, ut64 pc, const ut8 *opcodes, int *type) {
	// get raw opcode
	ut8 op = opcodes[pc];
	ut8 instr = lut_mnemonic[op];
	int len = 1;

	int bits = s_bits[instr];
	ut8 mask = op & ((1 << (bits & 7)) - 1);
	ut16 param = mask;
	if (bits >= 8) {
		pc = increment_pc (pc, 6); // could be 7 for sm590 // page_address_bits());
	//	param = params.r8 (pc);
		len++;
	}

	// extended opcode
	bool is_extended = (instr == mEXT);
	if (is_extended) {
		instr = lut_extended[param];
	}

	// disassemble it
	r_strbuf_appendf (stream, "%s", s_mnemonics[instr]);
	if (bits > 0) {
		if (bits <= 4) {
			if (param < 10) {
				r_strbuf_appendf (stream, " %d", param);
			} else {
				r_strbuf_appendf (stream, " 0x%x", param);
			}
		} else if (bits <= 8) {
			if (!is_extended) {
				r_strbuf_appendf (stream, " 0x%02x", param);
			}
		} else {
			ut16 address = (param << 4 & 0xc00) | (mask << 6 & 0x3c0) | (param & 0x03f);
			r_strbuf_appendf (stream, " 0x%03x", address);
		}
	}

	*type = s_flags[instr];
	// int res = len | s_flags[instr] | SUPPORTED; printf ("%d\n", res);
	return len;
}


// SM510 disasm

const ut8 sm510_mnemonic[0x100] =
{
//  0      1      2      3      4      5      6      7      8      9      A      B      C      D      E      F
	mSKIP, mATBP, mSBM,  mATPL, mRM,   mRM,   mRM,   mRM,   mADD,  mADD11,mCOMA, mEXBLA,mSM,   mSM,   mSM,   mSM,   // 0
	mEXC,  mEXC,  mEXC,  mEXC,  mEXCI, mEXCI, mEXCI, mEXCI, mLDA,  mLDA,  mLDA,  mLDA,  mEXCD, mEXCD, mEXCD, mEXCD, // 1
	mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  // 2
	mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  // 3 - note: $3A has synonym DC(decimal correct)

	mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   // 4
	0,     mTB,   mTC,   mTAM,  mTMI,  mTMI,  mTMI,  mTMI,  mTIS,  mATL,  mTA0,  mTABL, 0,     mCEND, mTAL,  mLBL,  // 5
	mATFC, mATR,  mWR,   mWS,   mINCB, mIDIV, mRC,   mSC,   mTF1,  mTF4,  mKTA,  mROT,  mDECB, mBDC,  mRTN0, mRTN1, // 6
	mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTML,  mTML,  mTML,  mTML,  // 7

	mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    // 8
	mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    // 9
	mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    // A
	mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    // B

	mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   // C
	mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   // D
	mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   // E
	mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM    // F
};

ut64 sm510_disassembler_disassemble(RStrBuf *stream, ut64 pc, const ut8 *opcodes, int *type) {
	return common_disasm(sm510_mnemonic, NULL, stream, pc, opcodes, type);
}


// SM511 disasm

const ut8 sm511_mnemonic[0x100] = {
//  0      1      2      3      4      5      6      7      8      9      A      B      C      D      E      F
	mROT,  mDTA,  mSBM,  mATPL, mRM,   mRM,   mRM,   mRM,   mADD,  mADD11,mCOMA, mEXBLA,mSM,   mSM,   mSM,   mSM,   // 0
	mEXC,  mEXC,  mEXC,  mEXC,  mEXCI, mEXCI, mEXCI, mEXCI, mLDA,  mLDA,  mLDA,  mLDA,  mEXCD, mEXCD, mEXCD, mEXCD, // 1
	mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  // 2
	mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  // 3

	mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   // 4
	mKTA,  mTB,   mTC,   mTAM,  mTMI,  mTMI,  mTMI,  mTMI,  mTIS,  mATL,  mTA0,  mTABL, mATX,  mCEND, mTAL,  mLBL,  // 5
	mEXT,  mPRE,  mWR,   mWS,   mINCB, mDR,   mRC,   mSC,   mTML,  mTML,  mTML,  mTML,  mDECB, mPTW,  mRTN0, mRTN1, // 6
	mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   // 7

	mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    // 8
	mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    // 9
	mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    // A
	mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    mT,    // B

	mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   // C
	mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   // D
	mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   // E
	mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM,   mTM    // F
};

static const ut8 sm511_extended[0x10] = {
	mRME,  mSME,  mTMEL, mATFC, mBDC,  mATBP, mCLKHI,mCLKLO,0,     0,     0,     0,     0,     0,     0,     0      // 60 3
};

#if 0
static ut64 sm511_disassembler_disassemble(RStrBuf *stream, ut64 pc, const ut8 *opcodes) {
	// create extended opcode table
	ut8 ext[0x100];
	memset(ext, 0, 0x100);
	memcpy(ext + 0x30, sm511_extended, 0x10);

	return common_disasm(sm511_mnemonic, ext, stream, pc, opcodes);
}
#endif


// SM500 disasm

static const ut8 sm500_mnemonic[0x100] = {
//  0      1      2      3      4      5      6      7      8      9      A      B      C      D      E      F
	mSKIP, mATR,  mEXKSA,mATBP, mRM,   mRM,   mRM,   mRM,   mADD,  mADDC, mCOMA, mEXBLA,mSM,   mSM,   mSM,   mSM,   // 0
	mEXC,  mEXC,  mEXC,  mEXC,  mEXCI, mEXCI, mEXCI, mEXCI, mLDA,  mLDA,  mLDA,  mLDA,  mEXCD, mEXCD, mEXCD, mEXCD, // 1
	mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  // 2
	mATS,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  // 3

	mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   // 4
	mTA,   mTB,   mTC,   mTAM,  mTM2,  mTM2,  mTM2,  mTM2,  mTG,   mPTW,  mTA0,  mTABL, mTW,   mDTW,  mEXT,  mLBL,  // 5
	mCOMCN,mPDTW, mWR,   mWS,   mINCB, mIDIV, mRC,   mSC,   mRMF,  mSMF,  mKTA,  mEXKFA,mDECB, mCOMCB,mRTN,  mRTNS, // 6
	mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  // 7

	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // 8
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // 9
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // A
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // B

	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // C
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // D
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // E
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS   // F
};

static const ut8 sm500_extended[0x10] = {
	mCEND, 0,     0,     0,     mDTA,  0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0      // 5E 0
};

#if 0
static ut64 sm500_disassembler_disassemble(RStrBuf *stream, ut64 pc, const ut8 *opcodes) {
	// create extended opcode table
	ut8 ext[0x100];
	memset(ext, 0, 0x100);
	memcpy(ext + 0x00, sm500_extended, 0x10);

	return common_disasm(sm500_mnemonic, ext, stream, pc, opcodes);
}
#endif

// SM5A disasm

static const ut8 sm5a_mnemonic[0x100] = {
//  0      1      2      3      4      5      6      7      8      9      A      B      C      D      E      F
	mSKIP, mATR,  mSBM,  mATBP, mRM,   mRM,   mRM,   mRM,   mADD,  mADDC, mCOMA, mEXBLA,mSM,   mSM,   mSM,   mSM,   // 0
	mEXC,  mEXC,  mEXC,  mEXC,  mEXCI, mEXCI, mEXCI, mEXCI, mLDA,  mLDA,  mLDA,  mLDA,  mEXCD, mEXCD, mEXCD, mEXCD, // 1
	mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  // 2
	mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  // 3

	mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   // 4
	mTA,   mTB,   mTC,   mTAM,  mTM2,  mTM2,  mTM2,  mTM2,  mTG,   mPTW,  mTA0,  mTABL, mTW,   mDTW,  mEXT,  mLBL,  // 5
	mCOMCN,mPDTW, mWR,   mWS,   mINCB, mIDIV, mRC,   mSC,   mRMF,  mSMF,  mKTA,  mRBM,  mDECB, mCOMCB,mRTN,  mRTNS, // 6
	mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  mSSR,  // 7

	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // 8
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // 9
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // A
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // B

	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // C
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // D
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // E
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS   // F
};

static const ut8 sm5a_extended[0x10] = {
	mCEND, 0,     0,     0,     mDTA,  0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0      // 5E 0
};

#if 0
static ut64 sm5a_disassembler_disassemble(RStrBuf *stream, ut64 pc, const ut8 *opcodes) {
	// create extended opcode table
	ut8 ext[0x100];
	memset(ext, 0, 0x100);
	memcpy(ext + 0x00, sm5a_extended, 0x10);

	return common_disasm(sm5a_mnemonic, ext, stream, pc, opcodes);
}
#endif

// SM530 disasm

static const ut8 sm530_mnemonic[0x100] = {
//  0      1      2      3      4      5      6      7      8      9      A      B      C      D      E      F
	mSKIP, mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  // 0
	mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  // 1
	mLDA,  mLDA,  mLDA,  mLDA,  mEXC,  mEXC,  mEXC,  mEXC,  mEXCI, mEXCI, mEXCI, mEXCI, mEXCD, mEXCD, mEXCD, mEXCD, // 2
	mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   mLB,   // 3

	mRM,   mRM,   mRM,   mRM,   mSM,   mSM,   mSM,   mSM,   mTM2,  mTM2,  mTM2,  mTM2,  mINCB, mDECB, mRDS,  mSDS,  // 4
	mKTA,  mKETA, mDTA,  mCOMA, mADD,  mADDC, mRC,   mSC,   mTABL, mTAM,  mEXBL, mTC,   mATS,  mATF,  mATBP, 0,     // 5
	mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mTL,   mRTN,  mRTNS, mATPL, mLBL,  mTG2,  mTG2,  mTG2,  mTG2,  // 6
	mIDIV, mINIS, mSABM, mSABL, mCEND, mTMEL, mRME,  mSME,  mPRE,  mTBA,  0,     0,     0,     0,     0,     0,     // 7

	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // 8
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // 9
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // A
	mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   mTR,   // B

	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // C
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // D
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  // E
	mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS,  mTRS   // F
};

#if 0
static ut64 sm530_disassembler_disassemble(RStrBuf *stream, ut64 pc, const ut8 *opcodes) {
	return common_disasm(sm530_mnemonic, NULL, stream, pc, opcodes);
}
#endif


// SM590 disasm

static const ut8 sm590_mnemonic[0x100] = {
//  0      1      2      3      4      5      6      7      8      9      A      B      C      D      E      F
	mNOP,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  mADX,  // 0
	mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  mTAX,  // 1
	mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, mLBLX, // 2
	mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  mLAX,  // 3

	mLDA,  mEXC,  mEXCI, mEXCD, mCOMA, mTAM,  mATR,  mMTR,  mRC,   mSC,   mSTR,  mCCTRL,mRTN,  mRTNS, 0,     0,     // 4
	mINBM, mDEBM, mINBL, mDEBL, mTC,   mRTA,  mBLTA, mXBLA, 0,     0,     0,     0,     mATX,  mEXAX, 0,     0,     // 5
	mTMI,  mTMI,  mTMI,  mTMI,  mTBA2, mTBA2, mTBA2, mTBA2, mRM,   mRM,   mRM,   mRM,   mSM,   mSM,   mSM,   mSM,   // 6
	mADD,  mADS,  mADC,  mADCS, mLBMX, mLBMX, mLBMX, mLBMX, mTL,   mTL,   mTL,   mTL,   mTLS,  mTLS,  mTLS,  mTLS,  // 7

	mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  // 8
	mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  // 9
	mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  // A
	mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  // B

	mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  // C
	mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  // D
	mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  // E
	mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7,  mTR7   // F
};

#if 0
static ut64 sm590_disassembler_disassemble(RStrBuf *stream, ut64 pc, const ut8 *opcodes) {
	return common_disasm (sm590_mnemonic, NULL, stream, pc, opcodes);
}
#endif

int sm5xx_disassemble(enum sm5xx_cpu cpu, RStrBuf *stream, ut64 pc, const ut8 *opcodes, int *type) {
	switch (cpu) {
	case CPU_SM590:
		return common_disasm (sm590_mnemonic, NULL, stream, pc, opcodes, type);
	case CPU_SM530:
		return common_disasm (sm530_mnemonic, NULL, stream, pc, opcodes, type);
	case CPU_SM5A:
		{
			ut8 ext[0x100];
			memset(ext, 0, 0x100);
			memcpy(ext + 0x00, sm5a_extended, 0x10);
			return common_disasm (sm5a_mnemonic, ext, stream, pc, opcodes, type);
		}
	case CPU_SM500:
		{
			ut8 ext[0x100];
			memset(ext, 0, 0x100);
			memcpy(ext + 0x00, sm500_extended, 0x10);
			return common_disasm (sm500_mnemonic, ext, stream, pc, opcodes, type);
		}
	case CPU_SM510:
		return common_disasm(sm510_mnemonic, NULL, stream, pc, opcodes, type);
	case CPU_SM511:
		{
			ut8 ext[0x100];
			memset(ext, 0, 0x100);
			memcpy(ext + 0x30, sm511_extended, 0x10);
			return common_disasm(sm511_mnemonic, ext, stream, pc, opcodes, type);
		}
	}
	return common_disasm(sm510_mnemonic, NULL, stream, pc, opcodes, type);
}

#if 0
int main() {
	enum sm5xx_cpu cpu = CPU_SM500;
	RStrBuf *sb = r_strbuf_new ("");
	sm5xx_disassemble (cpu, sb, 0, (const ut8 *)"90903");
	r_strbuf_append (sb, "\n");
	sm5xx_disassemble (cpu, sb, 0,  (const ut8 *)"32");
	r_strbuf_append (sb, "\n");
	sm5xx_disassemble (cpu, sb, 0,  (const ut8 *)"aa");
	r_strbuf_append (sb, "\n");
	char *s = r_strbuf_drain (sb);
	printf ("%s\n", s);
	free (s);
}
#endif
