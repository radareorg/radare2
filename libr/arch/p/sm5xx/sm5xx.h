// license:BSD-3-Clause
// copyright-holders:hap, Jonathan Gevaryahu
/*

  Sharp SM5xx MCU family disassembler

*/

#ifndef MAME_CPU_SM510_SM510D_H
#define MAME_CPU_SM510_SM510D_H

#define STEP_COND 0x10000000
#define STEP_OVER 0x20000000
#define STEP_OUT 0x40000000

#pragma once
typedef enum sm5xx_cpu {
	CPU_SM590,
	CPU_SM530,
	CPU_SM5A,
	CPU_SM500,
	CPU_SM510,
	CPU_SM511,
} sm5xx_cpu;

int sm5xx_disassemble(enum sm5xx_cpu cpu, RStrBuf *stream, ut64 pc, const ut8 *opcodes, int *type);

enum e_mnemonics {
	// SM510 common
	mILL /* 0! */, mEXT,
	mLB, mLBL, mSBM, mEXBLA, mINCB, mDECB,
	mATPL, mRTN0, mRTN1, mTL, mTML, mTM, mT,
	mEXC, mBDC, mEXCI, mEXCD, mLDA, mLAX, mPTW, mWR, mWS,
	mKTA, mATBP, mATX, mATL, mATFC, mATR,
	mADD, mADD11, mADX, mCOMA, mROT, mRC, mSC,
	mTB, mTC, mTAM, mTMI, mTA0, mTABL, mTIS, mTAL, mTF1, mTF4,
	mRM, mSM,
	mPRE, mSME, mRME, mTMEL,
	mSKIP, mCEND, mIDIV, mDR, mDTA, mCLKLO, mCLKHI,

	// SM500 common
	mCOMCB, mRTN, mRTNS, mSSR, mTR, mTRS, mRBM,
	mADDC, mPDTW, mTW, mDTW,
	mATS, mEXKSA, mEXKFA,
	mRMF, mSMF, mCOMCN,
	mTA, mTM2, mTG,

	// SM530 common
	mSABM, mSABL, mEXBL,
	mTG2, mTBA,
	mKETA, mATF, mSDS, mRDS,
	mINIS,

	// SM590 common
	mTAX, mLBLX, mMTR, mSTR, mINBM, mDEBM, mRTA, mBLTA, mEXAX, mTBA2, mADS, mADC, mLBMX, mTLS,
	mNOP, mCCTRL, mINBL, mDEBL, mXBLA, mADCS, mTR7 // aliases
};

#endif // MAME_CPU_SM510_SM510D_H
