//   
//    Copyright (c) 2008 Daniel Pistelli.
// 
/*
DisasMSIL
http://www.ntcore.com/utilities.php
Date: 30/04/2008  Author: Daniel Pistelli
DisasMSIL is a free/open disasm engine for the Microsoft Intermediate Language (MSIL). You can use it any context you wish. There are no license restrictions. The only thing I ask you to do is to send me your bug fixes (if any). For more information about this project, read the article.
*/

#include <stdio.h>
#include "demsil.h"
/* typedef */
#ifndef ut64
#define ut64 unsigned long long
#endif
#ifndef ut32
#define ut32 unsigned int
#endif

static ut32 hi_dword(ut64 Q) {
	ut64 qwBuf = Q >> 32;
	return (ut32) qwBuf;
}

static ut32 lo_dword(ut64 Q) {
	return (ut32) Q;
}

int GetSingleMSILInstr(const u8 *pMemory, ut32 MemorySize, DISASMSIL_OFFSET CodeBase, ILOPCODE_STRUCT *ilop) {
	u8 *pCurInstr = (u8 *) pMemory;
	DISASMSIL_OFFSET Base = CodeBase;
	ut32 CurInstr = 0;
	ut32 Token;
	u8 bBuf = 0;
	ut16 wBuf = 0;
	ut32 dwBuf = 0;
	ut64 qwBuf = 0;
	ut32 Prefix;

/* This macro makes a validity check on the requested space */
#define VALIDATE(p, size) \
	if ((MemorySize - (ut32 ) (((unsigned long*) p) - ((unsigned long*) pMemory))) < size) \
		return 0;

	// This little macro makes a validity check
	// on a request from the disassembler
	// when the request can't be satisfied, 
	// the function returns 0
#define demsil_get(p, var, type) { \
	ut32 typesize = sizeof (type);	\
	ut32 remsize = MemorySize - (ut32) (((unsigned long*) p) - ((unsigned long*) pMemory)); \
	if (typesize > remsize) return 0; \
	var = *((type *) p);	\
}

	//
	// This macro adds an instruction to the
	// current mnemonic string
	//
	
#define demsil_addi(i)	\
	if (ilop->Mnemonic[0] == 0)\
		snprintf(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s", i);\
	else snprintf(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s %s", ilop->Mnemonic, i);

	//
	// This macro adds a number to the
	// current mnemonic string
	//
#if 0
	/* XXX original code -stripped to skip warnings */
	case NUMBER_TYPE_BRANCH:                                                        \
		if (((ut32) n) <= 0x7FFFFFFF)                                    \
			snprintf(szNumber, 100, "0x%08X", (ut32) (Base + 5) + n);\
		else snprintf(szNumber, 100, "0x%08X", (ut32) (Base + 5) - (0 - (int) n));
#endif

#if __WINDOWS__
#define PFMT64x "I64x"
#define PFMT64d "I64d"
#define PFMT64o "I64o"
#else
#define PFMT64x "llx"
#define PFMT64d "lld"
#define PFMT64o "llo"
#endif

#define demsil_add_number(n, nt) {\
	char szNumber[100];\
	switch (nt) {	\
	case NUMBER_TYPE_TOKEN: snprintf(szNumber, 100, "0x%08X", (ut32) n); break;	\
	case NUMBER_TYPE_SMALL_BRANCH:								\
		if (((u8) n) <= 127)								\
			snprintf(szNumber, 100, "0x%08X", (ut32) ((Base + 2) + n));	\
		else										\
			snprintf(szNumber, 100, "0x%08X", (ut32) ((Base + 2) - (0 - (char) n)));	\
		break;									\
	case NUMBER_TYPE_BRANCH:							\
		snprintf(szNumber, 100, "0x%08X", (ut32)( (Base + 5) + n));\
		break;\
	case NUMBER_TYPE_U8: snprintf(szNumber, 100, "0x%02X", (u8) n); break;	\
	case NUMBER_TYPE_WORD: snprintf(szNumber, 100, "0x%04X", (ut16) n); break;\
	case NUMBER_TYPE_DWORD: snprintf(szNumber, 100, "0x%08X", (ut32) n); break;\
	case NUMBER_TYPE_QWORD: snprintf(szNumber, 100, "0x%08X%08X",		\
		hi_dword(n), lo_dword(n)); break;						\
	case NUMBER_TYPE_CHAR:	snprintf(szNumber, 100, "%d", (int) (u8) n); break;		\
	case NUMBER_TYPE_SHORT:	snprintf(szNumber, 100, "%hd", (short) n); break;		\
	case NUMBER_TYPE_INT: snprintf(szNumber, 100, "%d", (int) n); break;			\
	case NUMBER_TYPE_INT64: snprintf(szNumber, 100, "%"PFMT64d, (ut64) n); break;\
	case NUMBER_TYPE_UCHAR: snprintf(szNumber, 100, "%hu", (unsigned short) n); break;	\
	case NUMBER_TYPE_USHORT:	snprintf(szNumber, 100, "%hu", (short) n); break;	\
	case NUMBER_TYPE_UINT: snprintf(szNumber, 100, "%u", (int) n); break;		\
	case NUMBER_TYPE_FLOAT: snprintf(szNumber, 100, "%f", (float) n); break;		\
	case NUMBER_TYPE_DOUBLE: snprintf(szNumber, 100, "%g", (double) n); break;		\
	}											\
	if (ilop->Mnemonic[0] == 0)								\
		snprintf(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s", szNumber);		\
	else snprintf(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s %s", ilop->Mnemonic, szNumber); \
}

	//
	// This macro adds an instruction and a token to the
	// current mnemonic string
	//

#define demsil_addiT(i, t)\
	if (ilop->Mnemonic[0] == 0)\
		snprintf(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s 0x%08X", i, t);	\
	else snprintf(ilop->Mnemonic, MAX_DISASMMSIL_MNEMONIC, "%s %s 0x%08X", ilop->Mnemonic, i, t);

	if (MemorySize == 0) return 0;

	ilop->Offset = Base;
	ilop->Mnemonic[0] = 0;

	//
	// Check if it's a one-byte instr
	// (in that case don't check for prefix)
	//
	demsil_get(pCurInstr, CurInstr, u8);

	if (CurInstr <= 0xE0)
		goto getinstr;

	//
	// check for prefixes
	//
	demsil_get(pCurInstr, Prefix, ut16);

	switch (Prefix) {
	case ILOPCODE_CONSTRAINED_:
		demsil_get(pCurInstr + 2, Token, ut32);
		pCurInstr += 6;
		demsil_addiT("costrained", Token);
		break;
	case ILOPCODE_UNALIGNED_:
		demsil_get(pCurInstr + 2, bBuf, u8);
		pCurInstr += 3;
		demsil_addi("unaligned");
		demsil_add_number(bBuf, NUMBER_TYPE_UCHAR);
		break;
	case ILOPCODE_NO_:
		demsil_get(pCurInstr + 2, bBuf, u8);
		pCurInstr += 3;
		demsil_addi("unaligned");
		demsil_add_number(bBuf, NUMBER_TYPE_UCHAR);
		break;
	case ILOPCODE_TAIL_:
		pCurInstr += 2;
		demsil_addi("tail.");
		break;
	case ILOPCODE_VOLATILE_:
		pCurInstr += 2;
		demsil_addi("volatile.");
		break;
	case ILOPCODE_READONLY_:
		pCurInstr += 2;
		demsil_addi("readonly.");
		break;
	}


	//
	// get instruction
	//
getinstr:

	//
	// Check if it's a one-byte instr
	//

	//if (CurInstr >= 0x00 && CurInstr <= 0xE0) {
	if (CurInstr <= 0xE0) {
		pCurInstr += 1;

		switch (CurInstr) {
		case ILOPCODE_NOP:
			demsil_addi("nop");
			break;
		case ILOPCODE_BREAK:
			demsil_addi("break");
			break;
		case ILOPCODE_LDARG_0:
			demsil_addi("ldarg.0");
			break;
		case ILOPCODE_LDARG_1:
			demsil_addi("ldarg.1");
			break;
		case ILOPCODE_LDARG_2:
			demsil_addi("ldarg.2");
			break;
		case ILOPCODE_LDARG_3:
			demsil_addi("ldarg.3");
			break;
		case ILOPCODE_LDLOC_0:
			demsil_addi("ldloc.0");
			break;
		case ILOPCODE_LDLOC_1:
			demsil_addi("ldloc.1");
			break;
		case ILOPCODE_LDLOC_2:
			demsil_addi("ldloc.2");
			break;
		case ILOPCODE_LDLOC_3:
			demsil_addi("ldloc.3");
			break;
		case ILOPCODE_STLOC_0:
			demsil_addi("stloc.0");
			break;
		case ILOPCODE_STLOC_1:
			demsil_addi("stloc.1");
			break;
		case ILOPCODE_STLOC_2:
			demsil_addi("stloc.2");
			break;
		case ILOPCODE_STLOC_3:
			demsil_addi("stloc.3");
			break;
		case ILOPCODE_LDARG_S:
			demsil_addi("ldarg.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr++;
			demsil_add_number(bBuf, NUMBER_TYPE_UCHAR);
			break;
		case ILOPCODE_LDARGA_S:
			demsil_addi("ldarga.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr++;
			demsil_add_number(bBuf, NUMBER_TYPE_UCHAR);
			break;
		case ILOPCODE_STARG_S:
			demsil_addi("starg.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr++;
			demsil_add_number(bBuf, NUMBER_TYPE_UCHAR);
			break;
		case ILOPCODE_LDLOC_S:
			demsil_addi("ldloc.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr++;
			demsil_add_number(bBuf, NUMBER_TYPE_UCHAR);
			break;
		case ILOPCODE_LDLOCA_S:
			demsil_addi("ldloca.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr++;
			demsil_add_number(bBuf, NUMBER_TYPE_UCHAR);
			break;
		case ILOPCODE_STLOC_S:
			demsil_addi("stloc.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr++;
			demsil_add_number(bBuf, NUMBER_TYPE_UCHAR);
			break;
		case ILOPCODE_LDNULL:
			demsil_addi("ldnull");
			break;
		case ILOPCODE_LDC_I4_M1:
			demsil_addi("ldc.i4.m1");
			break;
		case ILOPCODE_LDC_I4_0:
			demsil_addi("ldc.i4.0");
			break;
		case ILOPCODE_LDC_I4_1:
			demsil_addi("ldc.i4.1");
			break;
		case ILOPCODE_LDC_I4_2:
			demsil_addi("ldc.i4.2");
			break;
		case ILOPCODE_LDC_I4_3:
			demsil_addi("ldc.i4.3");
			break;
		case ILOPCODE_LDC_I4_4:
			demsil_addi("ldc.i4.4");
			break;
		case ILOPCODE_LDC_I4_5:
			demsil_addi("ldc.i4.5");
			break;
		case ILOPCODE_LDC_I4_6:
			demsil_addi("ldc.i4.6");
			break;
		case ILOPCODE_LDC_I4_7:
			demsil_addi("ldc.i4.7");
			break;
		case ILOPCODE_LDC_I4_8:
			demsil_addi("ldc.i4.8");
			break;
		case ILOPCODE_LDC_I4_S:
			demsil_addi("ldc.i4.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr++;
			demsil_add_number(bBuf, NUMBER_TYPE_CHAR);
			break;
		case ILOPCODE_LDC_I4:
			{
				demsil_addi("ldc.i4");
				demsil_get(pCurInstr, dwBuf, ut32);
				pCurInstr += 4;
				demsil_add_number(dwBuf, NUMBER_TYPE_INT);
				break;
			}

		case ILOPCODE_LDC_I8:
			demsil_addi("ldc.i8");
			demsil_get(pCurInstr, qwBuf, ut64);
			pCurInstr += 8;
			demsil_add_number(qwBuf, NUMBER_TYPE_INT64);
			break;
		case ILOPCODE_LDC_R4:
			demsil_addi("ldc.r4");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_FLOAT);
			break;
		case ILOPCODE_LDC_R8:
			demsil_addi("ldc.r8");
			demsil_get(pCurInstr, qwBuf, ut64);
			pCurInstr += 8;
			demsil_add_number(qwBuf, NUMBER_TYPE_DOUBLE);
			break;
		case ILOPCODE_DUP:
			demsil_addi("dup");
			break;
		case ILOPCODE_POP:
			demsil_addi("pop");
			break;
		case ILOPCODE_JMP:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("jmp", dwBuf);
			break;
		case ILOPCODE_CALL:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("call", dwBuf);
			break;
		case ILOPCODE_CALLI:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("calli", dwBuf);
			break;
		case ILOPCODE_RET:
			demsil_addi("ret");
			break;
		case ILOPCODE_BR_S:
			demsil_addi("br.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
#if 0
		case ILOPCODE_BR0_S:
			demsil_addi("brfalse.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BR1_S:
			demsil_addi("brtrue.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
#endif
		case ILOPCODE_BEQ_S:
			demsil_addi("beq.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BGE_S:
			demsil_addi("bge.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BGT_S:
			demsil_addi("bgt.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BLE_S:
			demsil_addi("ble.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BLT_S:
			demsil_addi("blt.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BNE_UN_S:
			demsil_addi("bne.un.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BGE_UN_S:
			demsil_addi("bge.un.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BGT_UN_S:
			demsil_addi("bgt.un.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BLE_UN_S:
			demsil_addi("ble.un.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BLT_UN_S:
			demsil_addi("blt.un.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_BR:
			demsil_addi("br");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
			break;
#if 0
		case ILOPCODE_BR0:
			demsil_addi("brfalse");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
			break;
		case ILOPCODE_BR1:
			demsil_addi("brtrue");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
			break;
#endif
		case ILOPCODE_BEQ:
			demsil_addi("beq");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
			break;
		case ILOPCODE_BGE:
			demsil_addi("bge");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
			break;
		case ILOPCODE_BGT:
			demsil_addi("bgt");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
			break;
		case ILOPCODE_BLE:
			demsil_addi("ble");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
			break;
		case ILOPCODE_BLT:
			{
				demsil_addi("blt");
				demsil_get(pCurInstr, dwBuf, ut32);
				pCurInstr += 4;
				demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}
		case ILOPCODE_BNE_UN:
			{
				demsil_addi("bne.un");
				demsil_get(pCurInstr, dwBuf, ut32);
				pCurInstr += 4;
				demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}
		case ILOPCODE_BGE_UN:
			{
				demsil_addi("bge.un");
				demsil_get(pCurInstr, dwBuf, ut32);
				pCurInstr += 4;
				demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}
		case ILOPCODE_BGT_UN:
			{
				demsil_addi("bgt.un");
				demsil_get(pCurInstr, dwBuf, ut32);
				pCurInstr += 4;
				demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}
		case ILOPCODE_BLE_UN:
			{
				demsil_addi("ble.un");
				demsil_get(pCurInstr, dwBuf, ut32);
				pCurInstr += 4;
				demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}
		case ILOPCODE_BLT_UN:
			{
				demsil_addi("blt.un");
				demsil_get(pCurInstr, dwBuf, ut32);
				pCurInstr += 4;
				demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
				break;
			}
		case ILOPCODE_SWITCH:
			{
				//
				// The switch is followed by a dword and an array
				// of dwords, the first dword tells how many dwords will follow
				// every dword in the array represents an int32 offset
				//

				demsil_get(pCurInstr, dwBuf, ut32);
				VALIDATE(pCurInstr, (dwBuf + 1) * sizeof (ut32));
				demsil_addi("switch");
				pCurInstr += ((dwBuf + 1) * sizeof (ut32));
				break;
			}
		case ILOPCODE_LDIND_I1:
			demsil_addi("ldind.i1");
			break;
		case ILOPCODE_LDIND_U1:
			demsil_addi("ldind.u1");
			break;
		case ILOPCODE_LDIND_I2:
			demsil_addi("ldind.i2");
			break;
		case ILOPCODE_LDIND_U2:
			demsil_addi("ldind.u2");
			break;
		case ILOPCODE_LDIND_I4:
			demsil_addi("ldind.i4");
			break;
		case ILOPCODE_LDIND_U4:
			demsil_addi("ldind.u4");
			break;
		case ILOPCODE_LDIND_I8:
			demsil_addi("ldind.i8");
			break;
		case ILOPCODE_LDIND_I:
			demsil_addi("ldind.i");
			break;
		case ILOPCODE_LDIND_R4:
			demsil_addi("ldind.r4");
			break;
		case ILOPCODE_LDIND_R8:
			demsil_addi("ldind.r8");
			break;
		case ILOPCODE_LDIND_REF:
			demsil_addi("ldind.ref");
			break;
		case ILOPCODE_STIND_REF:
			demsil_addi("stind.ref");
			break;
		case ILOPCODE_STIND_I1:
			demsil_addi("stind.i1");
			break;
		case ILOPCODE_STIND_I2:
			demsil_addi("stind.i2");
			break;
		case ILOPCODE_STIND_I4:
			demsil_addi("stind.i4");
			break;
		case ILOPCODE_STIND_I8:
			demsil_addi("stind.i8");
			break;
		case ILOPCODE_STIND_R4:
			demsil_addi("stind.r4");
			break;
		case ILOPCODE_STIND_R8:
			demsil_addi("stind.r8");
			break;
		case ILOPCODE_ADD:
			demsil_addi("add");
			break;
		case ILOPCODE_SUB:
			demsil_addi("sub");
			break;
		case ILOPCODE_MUL:
			demsil_addi("mul");
			break;
		case ILOPCODE_DIV:
			demsil_addi("div");
			break;
		case ILOPCODE_DIV_UN:
			demsil_addi("div.un");
			break;
		case ILOPCODE_REM:
			demsil_addi("rem");
			break;
		case ILOPCODE_REM_UN:
			demsil_addi("rem.un");
			break;
		case ILOPCODE_AND:
			demsil_addi("and");
			break;
		case ILOPCODE_OR:
			demsil_addi("or");
			break;
		case ILOPCODE_XOR:
			demsil_addi("xor");
			break;
		case ILOPCODE_SHL:
			demsil_addi("shl");
			break;
		case ILOPCODE_SHR:
			demsil_addi("shr");
			break;
		case ILOPCODE_SHR_UN:
			demsil_addi("shr.un");
			break;
		case ILOPCODE_NEG:
			demsil_addi("neg");
			break;
		case ILOPCODE_NOT:
			demsil_addi("not");
			break;
		case ILOPCODE_CONV_I1:
			demsil_addi("conv.i1");
			break;
		case ILOPCODE_CONV_I2:
			demsil_addi("conv.i2");
			break;
		case ILOPCODE_CONV_I4:
			demsil_addi("conv.i4");
			break;
		case ILOPCODE_CONV_I8:
			demsil_addi("conv.i8");
			break;
		case ILOPCODE_CONV_R4:
			demsil_addi("conv.r4");
			break;
		case ILOPCODE_CONV_R8:
			demsil_addi("conv.r8");
			break;
		case ILOPCODE_CONV_U4:
			demsil_addi("conv.u4");
			break;
		case ILOPCODE_CONV_U8:
			demsil_addi("conv.u8");
			break;
		case ILOPCODE_CALLVIRT:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("callvirt", dwBuf);
			break;
		case ILOPCODE_CPOBJ:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("cpobj", dwBuf);
			break;
		case ILOPCODE_LDOBJ:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldobj", dwBuf);
			break;
		case ILOPCODE_LDSTR:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldstr", dwBuf);
			break;
		case ILOPCODE_NEWOBJ:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("newobj", dwBuf);
			break;
		case ILOPCODE_CASTCLASS:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("castclass", dwBuf);
			break;
		case ILOPCODE_ISINST:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("isinst", dwBuf);
			break;
		case ILOPCODE_CONV_R_UN:
			demsil_addi("conv.r.un");
			break;
		case ILOPCODE_UNBOX:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("unbox", dwBuf);
			break;
		case ILOPCODE_THROW:
			demsil_addi("throw");
			break;
		case ILOPCODE_LDFLD:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldfld", dwBuf);
			break;
		case ILOPCODE_LDFLDA:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldflda", dwBuf);
			break;
		case ILOPCODE_STFLD:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("stfld", dwBuf);
			break;
		case ILOPCODE_LDSFLD:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldsfld", dwBuf);
			break;
		case ILOPCODE_LDSFLDA:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldsflda", dwBuf);
			break;
		case ILOPCODE_STSFLD:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("stsfld", dwBuf);
			break;
		case ILOPCODE_STOBJ:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("stobj", dwBuf);
			break;
		case ILOPCODE_CONV_OVF_I1_UN:
			demsil_addi("conv.ovf.i1.un");
			break;
		case ILOPCODE_CONV_OVF_I2_UN:
			demsil_addi("conv.ovf.i2.un");
			break;
		case ILOPCODE_CONV_OVF_I4_UN:
			demsil_addi("conv.ovf.i4.un");
			break;
		case ILOPCODE_CONV_OVF_I8_UN:
			demsil_addi("conv.ovf.i8.un");
			break;
		case ILOPCODE_CONV_OVF_U1_UN:
			demsil_addi("conv.ovf.u1.un");
			break;
		case ILOPCODE_CONV_OVF_U2_UN:
			demsil_addi("conv.ovf.u2.un");
			break;
		case ILOPCODE_CONV_OVF_U4_UN:
			demsil_addi("conv.ovf.u4.un");
			break;
		case ILOPCODE_CONV_OVF_U8_UN:
			demsil_addi("conv.ovf.u8.un");
			break;
		case ILOPCODE_CONV_OVF_I_UN:
			demsil_addi("conv.ovf.i.un");
			break;
		case ILOPCODE_CONV_OVF_U_UN:
			demsil_addi("conv.ovf.u.un");
			break;
		case ILOPCODE_BOX:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("box", dwBuf);
			break;
		case ILOPCODE_NEWARR:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("newarr", dwBuf);
			break;
		case ILOPCODE_LDLEN:
			demsil_addi("ldlen");
			break;
		case ILOPCODE_LDELEMA:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldelema", dwBuf);
			break;
		case ILOPCODE_LDELEM_I1:
			demsil_addi("ldelem.i1");
			break;
		case ILOPCODE_LDELEM_U1:
			demsil_addi("ldelem.u1");
			break;
		case ILOPCODE_LDELEM_I2:
			demsil_addi("ldelem.i2");
			break;
		case ILOPCODE_LDELEM_U2:
			demsil_addi("ldelem.u2");
			break;
		case ILOPCODE_LDELEM_I4:
			demsil_addi("ldelem.i4");
			break;
		case ILOPCODE_LDELEM_U4:
			demsil_addi("ldelem.u4");
			break;
		case ILOPCODE_LDELEM_I8:
			demsil_addi("ldelem.i1");
			break;
		case ILOPCODE_LDELEM_I:
			demsil_addi("ldelem.i");
			break;
		case ILOPCODE_LDELEM_R4:
			demsil_addi("ldelem.r4");
			break;
		case ILOPCODE_LDELEM_R8:
			demsil_addi("ldelem.r8");
			break;
		case ILOPCODE_LDELEM_REF:
			demsil_addi("ldelem.ref");
			break;
		case ILOPCODE_STELEM_I:
			demsil_addi("stelem.i");
			break;
		case ILOPCODE_STELEM_I1:
			demsil_addi("stelem.i1");
			break;
		case ILOPCODE_STELEM_I2:
			demsil_addi("stelem.i2");
			break;
		case ILOPCODE_STELEM_I4:
			demsil_addi("stelem.i4");
			break;
		case ILOPCODE_STELEM_I8:
			demsil_addi("stelem.i8");
			break;
		case ILOPCODE_STELEM_R4:
			demsil_addi("stelem.r4");
			break;
		case ILOPCODE_STELEM_R8:
			demsil_addi("stelem.r8");
			break;
		case ILOPCODE_STELEM_REF:
			demsil_addi("stelem.ref");
			break;
		case ILOPCODE_LDELEM:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldelem", dwBuf);
			break;
		case ILOPCODE_STELEM:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("stelem", dwBuf);
			break;
		case ILOPCODE_UNBOX_ANY:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("unbox.any", dwBuf);
			break;
		case ILOPCODE_CONV_OVF_I1:
			demsil_addi("conv.ovf.i1");
			break;
		case ILOPCODE_CONV_OVF_U1:
			demsil_addi("conv.ovf.u1");
			break;
		case ILOPCODE_CONV_OVF_I2:
			demsil_addi("conv.ovf.i2");
			break;
		case ILOPCODE_CONV_OVF_U2:
			demsil_addi("conv.ovf.u2");
			break;
		case ILOPCODE_CONV_OVF_I4:
			demsil_addi("conv.ovf.i4");
			break;
		case ILOPCODE_CONV_OVF_U4:
			demsil_addi("conv.ovf.u4");
			break;
		case ILOPCODE_CONV_OVF_I8:
			demsil_addi("conv.ovf.i8");
			break;
		case ILOPCODE_CONV_OVF_U8:
			demsil_addi("conv.ovf.u8");
			break;
		case ILOPCODE_REFANYVAL:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("refanyval", dwBuf);
			break;
		case ILOPCODE_CKFINITE:
			demsil_addi("ckfinite");
			break;
		case ILOPCODE_MKREFANY:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("mkrefany", dwBuf);
			break;
		case ILOPCODE_LDTOKEN:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldtoken", dwBuf);
			break;
		case ILOPCODE_CONV_U2:
			demsil_addi("conv.u2");
			break;
		case ILOPCODE_CONV_U1:
			demsil_addi("conv.u1");
			break;
		case ILOPCODE_CONV_I:
			demsil_addi("conv.i");
			break;
		case ILOPCODE_CONV_OVF_I:
			demsil_addi("conv.ovf.i");
			break;
		case ILOPCODE_CONV_OVF_U:
			demsil_addi("conv.ovf.u");
			break;
		case ILOPCODE_ADD_OVF:
			demsil_addi("add.ovf");
			break;
		case ILOPCODE_ADD_OVF_UN:
			demsil_addi("add.ovf.un");
			break;
		case ILOPCODE_MUL_OVF:
			demsil_addi("mul.ovf");
			break;
		case ILOPCODE_MUL_OVF_UN:
			demsil_addi("mul.ovf.un");
			break;
		case ILOPCODE_SUB_OVF:
			demsil_addi("sub.ovf");
			break;
		case ILOPCODE_SUB_OVF_UN:
			demsil_addi("sub.ovf.un");
			break;
		case ILOPCODE_ENDFINALLY:
			demsil_addi("endfinally");
			break;
		case ILOPCODE_LEAVE:
			demsil_addi("leave");
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_add_number(dwBuf, NUMBER_TYPE_BRANCH);
			break;
		case ILOPCODE_LEAVE_S:
			demsil_addi("leave.s");
			demsil_get(pCurInstr, bBuf, u8);
			pCurInstr += 1;
			demsil_add_number(bBuf, NUMBER_TYPE_SMALL_BRANCH);
			break;
		case ILOPCODE_STIND_I:
			demsil_addi("stind.i");
			break;
		case ILOPCODE_CONV_U:
			demsil_addi("conv.u");
			break;
		default:
			return 0;
		} // end switch
	} else {
	//
	// Two bytes instruction
	//
		demsil_get(pCurInstr, CurInstr, ut16);

		pCurInstr += 2;

		switch (CurInstr) {
		case ILOPCODE_ARGLIST:
			demsil_addi("arglist");
			break;
		case ILOPCODE_CEQ:
			demsil_addi("ceq");
			break;
		case ILOPCODE_CGT:
			demsil_addi("cgt");
			break;
		case ILOPCODE_CGT_UN:
			demsil_addi("cgt.un");
			break;
		case ILOPCODE_CLT:
			demsil_addi("clt");
			break;
		case ILOPCODE_CLT_UN:
			demsil_addi("clt.un");
			break;
		case ILOPCODE_LDFTN:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldftn", dwBuf);
			break;
		case ILOPCODE_LDVIRTFTN:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("ldvirtftn", dwBuf);
			break;
		case ILOPCODE_LDARG:
			demsil_addi("ldarg");
			demsil_get(pCurInstr, wBuf, ut16);
			pCurInstr += 2;
			demsil_add_number(wBuf, NUMBER_TYPE_USHORT);
			break;
		case ILOPCODE_LDARGA:
			demsil_addi("ldarga");
			demsil_get(pCurInstr, wBuf, ut16);
			pCurInstr += 2;
			demsil_add_number(wBuf, NUMBER_TYPE_USHORT);
			break;
		case ILOPCODE_STARG:
			demsil_addi("starg");
			demsil_get(pCurInstr, wBuf, ut16);
			pCurInstr += 2;
			demsil_add_number(wBuf, NUMBER_TYPE_USHORT);
			break;
		case ILOPCODE_LDLOC:
			demsil_addi("ldloc");
			demsil_get(pCurInstr, wBuf, ut16);
			pCurInstr += 2;
			demsil_add_number(wBuf, NUMBER_TYPE_USHORT);
			break;
		case ILOPCODE_LDLOCA:
			demsil_addi("ldloca");
			demsil_get(pCurInstr, wBuf, ut16);
			pCurInstr += 2;
			demsil_add_number(wBuf, NUMBER_TYPE_USHORT);
			break;
		case ILOPCODE_STLOC:
			demsil_addi("stloc");
			demsil_get(pCurInstr, wBuf, ut16);
			pCurInstr += 2;
			demsil_add_number(wBuf, NUMBER_TYPE_USHORT);
			break;
		case ILOPCODE_LOCALLOC:
			demsil_addi("localloc");
			break;
		case ILOPCODE_ENDFILTER:
			demsil_addi("endfilter");
			break;
		case ILOPCODE_INITOBJ:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("initobj", dwBuf);
			break;
		case ILOPCODE_CPBLK:
			demsil_addi("cpblk");
			break;
		case ILOPCODE_INITBLK:
			demsil_addi("initblk");
			break;
		case ILOPCODE_RETHROW:
			demsil_addi("rethrow");
			break;
		case ILOPCODE_SIZEOF:
			demsil_get(pCurInstr, dwBuf, ut32);
			pCurInstr += 4;
			demsil_addiT("sizeof", dwBuf);
			break;
		case ILOPCODE_REFANYTYPE_V2:
			demsil_addi("refanytype.v2");
			break;
		default:
			return 0;
		}
	}

	ilop->Size = (ut32) (pCurInstr-pMemory);
	
	return ilop->Size;
}

int DisasMSIL(const u8 *pMemory, ut32 MemorySize, DISASMSIL_OFFSET CodeBase, ILOPCODE_STRUCT *iloparray, ut32 nOpcodeStructs, ut32 *nDisassembledInstr) {
	const u8 *pCurMem = pMemory;
	ut32 x, RemSize = MemorySize;
	DISASMSIL_OFFSET CurBase = CodeBase;
	int sz = 0;

	if (MemorySize == 0 || nOpcodeStructs == 0 || iloparray == NULL) 
		return 0;
	if (nDisassembledInstr) *nDisassembledInstr = 0;

	for (x = 0; x < nOpcodeStructs; x++) {
		int ret = GetSingleMSILInstr(pCurMem, RemSize, CurBase, &iloparray[x]);
		if (!ret) {
			if (x == 0) return 0;
			break;
		}
		sz += ret;
		pCurMem += iloparray[x].Size;
		CurBase += iloparray[x].Size;
		RemSize -= iloparray[x].Size;
		if (nDisassembledInstr)
			*nDisassembledInstr = x + 1;
		break;
	}

	return sz;
}
