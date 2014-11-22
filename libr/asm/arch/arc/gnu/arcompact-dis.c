/* Instruction printing code for the ARC.
   Copyright 1994, 1995, 1997, 1998, 2000, 2001, 2002, 2005, 2006, 2007, 2008, 2009
   Free Software Foundation, Inc.
   Contributed by Doug Evans (dje@cygnus.com).

   Copyright 2008-2012 Synopsys Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include <ctype.h>
#include <stdarg.h>
#include <ansidecl.h>
#include <string.h>

#include "dis-asm.h"
#include "arc.h"
#include "arc-ext.h"
#include "arc-dis.h"
#include "arcompact-dis.h"
#include "elf-bfd.h"

  /*
    warning: implicit declaration of function `printf_unfiltered'
    if dbg is 1 then this definition is required
  */
  void printf_unfiltered (const char *,...);
static bfd_vma bfd_getm32 (unsigned int);
static bfd_vma bfd_getm32_ac (unsigned int) ATTRIBUTE_UNUSED;


#ifndef dbg
#define dbg	(0)
#endif

  /*
    Ravi:
    : undefined reference to `printf_unfiltered'
    if dbg is 1 then this definition is required
  */
#if dbg
  void printf_unfiltered (const char *,...)
 {
   va_list args;
   va_start (args, format);
   vfprintf_unfiltered (gdb_stdout, format, args);
   va_end (args);
 }
#endif

#undef _NELEM
#define _NELEM(ary)	(sizeof(ary) / sizeof(ary[0]))

#define BIT(word,n)       ((word) & (1 << n))
/* START ARC LOCAL */
#define BITS(word,s,e)    (((word) << (sizeof(word)*8-1 - e)) >> (s+(sizeof(word)*8-1 - e)))
/* END ARC LOCAL */
#define OPCODE(word)      (BITS ((word), 27, 31))
#define FIELDA(word)      (BITS ((word), 0, 5))
#define FIELDb(word)      (BITS ((word), 24, 26))
#define FIELDB(word)      (BITS ((word), 12, 14))
#define FIELDC(word)      (BITS ((word), 6, 11))
#define OPCODE_AC(word)   (BITS ((word), 11, 15))
#define FIELDA_AC(word)   (BITS ((word), 0, 2))
#define FIELDB_AC(word)   (BITS ((word), 8, 10))
#define FIELDC_AC(word)   (BITS ((word), 5, 7))
#define FIELDU_AC(word)   (BITS ((word), 0, 4))

/*
 * FIELDS_AC is the 11-bit signed immediate value used for
 * GP-relative instructions.
 */
#define FIELDS_AC(word)   (BITS (((signed int) word), 0, 8))

/*
 * FIELDD is signed in all of its uses, so we make sure argument is
 * treated as signed for bit shifting purposes.
 */
#define FIELDD(word)      (BITS (((signed int) word), 16, 23))

/*
 * FIELDD9 is the 9-bit signed immediate value used for
 * load/store instructions.
 */
#define FIELDD9(word)     ((BITS(((signed int)word),15,15) << 8) | (BITS((word),16,23)))

/*
 * FIELDS is the 12-bit signed immediate value
 */
#define FIELDS(word)      ((BITS(((signed int)word),0,5) << 6) | (BITS((word),6,11)))					\

/*
 * FIELD S9 is the 9-bit signed immediate value used for
 * bbit0/bbit instruction
 */
#define FIELDS9(word)     (((BITS(((signed int)word),15,15) << 7) | (BITS((word),17,23))) << 1)
#define FIELDS9_FLAG(word)     (((BITS(((signed int)word),0,5) << 6) | (BITS((word),6,11))) )

#define PUT_NEXT_WORD_IN(a) {		\
	if (is_limm==1 && !NEXT_WORD(1))       	\
	  mwerror(state, "Illegal limm reference in last instruction!\n"); \
          if (info->endian == BFD_ENDIAN_LITTLE) { \
            a = ((state->words[1] & 0xff00) | (state->words[1] & 0xff)) << 16; \
            a |= ((state->words[1] & 0xff0000) | (state->words[1] & 0xff000000)) >> 16;	\
          } \
          else { \
            a = state->words[1]; \
          } \
	}

#define CHECK_NULLIFY() do{		\
	state->nullifyMode = BITS(state->words[0],5,5);	\
	}while(0)

#define CHECK_COND_NULLIFY() do {		\
	state->nullifyMode = BITS(state->words[0],5,5);	\
	cond = BITS(state->words[0],0,4);	\
	}while(0)

#define CHECK_FLAG_COND_NULLIFY() do{	\
	if (is_shimm == 0) {			\
	  flag = BIT(state->words[0],15);	\
	  state->nullifyMode = BITS(state->words[0],5,5); \
	  cond = BITS(state->words[0],0,4);	\
	}					\
	}while(0)

#define CHECK_FLAG_COND() {		\
	if (is_shimm == 0) {			\
	  flag = BIT(state->words[0],15);	\
	  cond = BITS(state->words[0],0,4);	\
	}					\
	}

#define CHECK_FLAG() {			\
	flag = BIT(state->words[0],15);	\
	}

#define CHECK_COND() {		                \
	if (is_shimm == 0) {			\
	  cond = BITS(state->words[0],0,4);	\
	}					\
	}

#define CHECK_FIELD(field) {			\
	if (field == 62) {			\
	  is_limm++;				\
	  field##isReg = 0;			\
	  PUT_NEXT_WORD_IN(field);		\
	}					\
	}

#define CHECK_FIELD_A() {			\
	fieldA = FIELDA(state->words[0]);	\
	if (fieldA == 62) {			\
	  fieldAisReg = 0;			\
	  fieldA = 0;				\
	}					\
	}

#define FIELD_B() {				\
	fieldB = (FIELDB(state->words[0]) << 3);\
	fieldB |= FIELDb(state->words[0]);	\
	if (fieldB == 62) {			\
	  fieldBisReg = 0;			\
	  fieldB = 0;				\
	}					\
	}

#define FIELD_C() {				\
	fieldC = FIELDC(state->words[0]);	\
	if (fieldC == 62) {  			\
	  fieldCisReg = 0; 			\
	}					\
	}
/********** Aurora SIMD ARC 8 - bit constant **********/
#define FIELD_U8() {                            \
                                                \
          fieldC  = BITS(state->words[0],15,16);\
          fieldC  = fieldC <<6;                 \
          fieldC |= FIELDC(state->words[0]);    \
          fieldCisReg = 0;                      \
        }

#define CHECK_FIELD_B() {			\
	fieldB = (FIELDB(state->words[0]) << 3);\
	fieldB |= FIELDb(state->words[0]);	\
	CHECK_FIELD(fieldB);			\
	}

#define CHECK_FIELD_C() {			\
	fieldC = FIELDC(state->words[0]);	\
	CHECK_FIELD(fieldC);			\
	}

#define FIELD_C_S() {				\
	fieldC_S = (FIELDC_S(state->words[0]) << 3);	\
	}

#define FIELD_B_S() {				\
	fieldB_S = (FIELDB_S(state->words[0]) << 3);	\
	}

#define CHECK_FIELD_H_AC() {			\
	fieldC = ((FIELDA_AC(state->words[0])) << 3);	\
	fieldC |= FIELDC_AC(state->words[0]);	\
	CHECK_FIELD(fieldC);			\
	}

#define FIELD_H_AC() {				\
	fieldC = ((FIELDA_AC(state->words[0])) << 3);	\
	fieldC |= FIELDC_AC(state->words[0]);	\
	if (fieldC > 60) {  			\
	  fieldCisReg = 0; 			\
	  fieldC = 0;				\
	}					\
	}

#define FIELD_C_AC() {				\
	fieldC = FIELDC_AC(state->words[0]);	\
	if (fieldC > 3) {  			\
	  fieldC += 8;  			\
	}				  	\
	}

#define FIELD_B_AC() {				\
	fieldB = FIELDB_AC(state->words[0]);	\
	if (fieldB > 3) {  			\
	  fieldB += 8; 				\
	}				  	\
	}

#define FIELD_A_AC() {				\
	fieldA = FIELDA_AC(state->words[0]);	\
	if (fieldA > 3) {  			\
	  fieldA += 8; 				\
	}				  	\
	}

#define IS_SMALL(x) (((field##x) < 256) && ((field##x) > -257))
#define IS_REG(x)   (field##x##isReg)
#define IS_SIMD_128_REG(x)  (usesSimdReg##x == 1)
#define IS_SIMD_16_REG(x)   (usesSimdReg##x == 2)
#define IS_SIMD_DATA_REG(x) (usesSimdReg##x == 3)
#define WRITE_FORMAT_LB_Rx_RB(x)     WRITE_FORMAT(x,"[","]","","")
#define WRITE_FORMAT_x_COMMA_LB(x)   WRITE_FORMAT(x,"",", [","",",[")
#define WRITE_FORMAT_COMMA_x_RB(x)   WRITE_FORMAT(x,", ","]",", ","]")
#define WRITE_FORMAT_x_RB(x)         WRITE_FORMAT(x,"","]","","]")
#define WRITE_FORMAT_COMMA_x(x)      WRITE_FORMAT(x,", ","",", ","")
#define WRITE_FORMAT_x_COMMA(x)      WRITE_FORMAT(x,"",", ","",", ")
#define WRITE_FORMAT_x(x)            WRITE_FORMAT(x,"","","","")
#define WRITE_FORMAT(x,cb1,ca1,cb,ca) strcat(formatString,              \
                                     (IS_SIMD_128_REG(x) ? cb1"%S"ca1:  \
                                      IS_SIMD_16_REG(x)  ? cb1"%I"ca1:  \
                                      IS_SIMD_DATA_REG(x)? cb1"%D"ca1:  \
                                      IS_REG(x)          ? cb1"%r"ca1:  \
                                      usesAuxReg         ?  cb"%a"ca :  \
                                      IS_SMALL(x) ? cb"%d"ca : cb"%h"ca))

#define WRITE_FORMAT_LB() strcat(formatString, "[")
#define WRITE_FORMAT_RB() strcat(formatString, "]")
#define WRITE_COMMENT(str)	(state->comm[state->commNum++] = (str))
#define WRITE_NOP_COMMENT() if (!fieldAisReg && !flag) WRITE_COMMENT("nop");

#define NEXT_WORD(x) (offset += 4, state->words[x])

#define NEXT_WORD_AC(x) (offset += 2, state->words[x])

#define add_target(x) 	(state->targets[state->tcnt++] = (x))

static short int enable_simd = 0;
static short int enable_insn_stream = 0;


static const char *
core_reg_name(struct arcDisState *state, int val)
{
  if (state->coreRegName)
    return (*state->coreRegName)(state->_this, val);
  return 0;
}

static const char *
aux_reg_name(struct arcDisState *state, int val)
{
  if (state->auxRegName)
    return (*state->auxRegName)(state->_this, val);
  return 0;
}

static const char *
cond_code_name(struct arcDisState *state, int val)
{
  if (state->condCodeName)
    return (*state->condCodeName)(state->_this, val);
  return 0;
}

static const char *
instruction_name(struct arcDisState *state, int op1, int op2, int *flags)
{
  if (state->instName)
    return (*state->instName)(state->_this, op1, op2, flags);
  return 0;
}

static void
mwerror(struct arcDisState *state, const char *msg)
{
  if (state->err != 0)
    (*state->err)(state->_this, (msg));
}

static const char *
post_address(struct arcDisState *state, int addr)
{
  static char id[3*_NELEM(state->addresses)];
  unsigned int j, i = state->acnt;
  if (i < _NELEM(state->addresses)) {
    state->addresses[i] = addr;
    ++state->acnt;
    j = i*3;
    id[j+0] = '@';
    id[j+1] = '0'+i;
    id[j+2] = 0;
    return id+j;
  }
  return "";
}

static void
my_sprintf (struct arcDisState *state, char *buf, const char*format, ...)
{
  char *bp;
  const char *p;
  int size, leading_zero, regMap[2];
  va_list ap;

  va_start(ap,format);
  bp = buf;
  *bp = 0;
  p = format;
  regMap[0] = 0;
  regMap[1] = 0;
  while (1)
    switch(*p++) {
    case 0: goto DOCOMM; /*(return) */
    default:
      *bp++ = p[-1];
      break;
    case '%':
      size = 0;
      leading_zero = 0;
    RETRY: ;
      switch(*p++)
	{
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	  {
	    /* size. */
	    size = p[-1]-'0';
	    if (size == 0) leading_zero = 1; /* e.g. %08x */
	    while (*p >= '0' && *p <= '9')
	      size = size*10+*p-'0', p++;
	    goto RETRY;
	  }
#define inc_bp() bp = bp+strlen(bp)

	case 'h':
	  {
	    unsigned u = va_arg(ap,int);
	    /*
	     * Hex.  We can change the format to 0x%08x in
	     * one place, here, if we wish.
	     * We add underscores for easy reading.
	     */
#define CDT_DEBUG
	    if (u > 65536)
#ifndef CDT_DEBUG
	      sprintf(bp,"0x%x_%04x",u >> 16, u & 0xffff);
#else
	      sprintf(bp,"0x%08x",u);
#endif // CDT_DEBUG
	    else
	      sprintf(bp,"0x%x",u);
	    inc_bp();
	  }
	  break;
	case 'X': case 'x':
	  {
	    int val = va_arg(ap,int);
	    if (size != 0)
	      if (leading_zero) sprintf(bp,"%0*x",size,val);
	      else sprintf(bp,"%*x",size,val);
	    else sprintf(bp,"%x",val);
	    inc_bp();
	  }
	  break;
	case 'd':
	  {
	    int val = va_arg(ap,int);
	    if (size != 0) sprintf(bp,"%*d",size,val);
	    else sprintf(bp,"%d",val);
	    inc_bp();
	  }
	  break;
	case 'r':
	  {
	    /* Register. */
	    int val = va_arg(ap,int);

#define REG2NAME(num, name) case num: sprintf(bp,""name); \
			regMap[(num<32)?0:1] |= 1<<(num-((num<32)?0:32)); break;
	    switch (val)
	      {
		REG2NAME(26, "gp");
		REG2NAME(27, "fp");
		REG2NAME(28, "sp");
		REG2NAME(29, "ilink1");
		REG2NAME(30, "ilink2");
		REG2NAME(31, "blink");
		REG2NAME(60, "lp_count");
		REG2NAME(63, "pcl");
	      default:
		{
		  const char *ext;
		  ext = core_reg_name(state, val);
		  if (ext) sprintf(bp, "%s", ext);
		  else     sprintf(bp,"r%d",val);
		}break;
	      }
	    inc_bp();
	  } break;

	case 'a':
	  {
	  /* Aux Register. */
	    int val = va_arg(ap,int);
	    char *ret;
	    ret = arc_aux_reg_name(val);
	    if(ret)
	      sprintf(bp,"%s",ret);
	    else
	      {
		const char *ext;
		  ext = aux_reg_name(state, val);
		  if (ext) sprintf(bp, "%s", ext);
		  else     my_sprintf(state, bp,"%h",val);
	      }

	    inc_bp();
	  }
	  break;
	case 's':
	  {
	    sprintf(bp,"%s",va_arg(ap,char*));
	    inc_bp();
	  }
	  break;
	case '*':
	  {
#if 0
	    va_arg(ap,char*);
	    inc_bp();
	    break;
#elif 1 /* used for prefetch to skip an argument.  */
        va_arg(ap,int);
        break;
#else
	    extern void abort (void);

	    abort ();
#endif
	  }

	  /* SIMD operands follow*/
	case 'S':
	  {
	    int val = va_arg (ap,int);

	    sprintf (bp, "vr%d",val);
	    inc_bp ();
	    break;
	  }
	case 'I':
	  {
	    int val = va_arg (ap,int);

	    sprintf (bp, "i%d",val);
	    inc_bp ();
	    break;
	  }
	case 'D':
	  {
	    int val = va_arg (ap,int);

	    sprintf (bp, "dr%d",val);
	    inc_bp ();
	    break;
	  }
	  /* SIMD operands end */
	default:
	  fprintf(stderr,"?? format %c\n",p[-1]);
	  break;
	}
    }


 DOCOMM:
  *bp = 0;
  va_end (ap);
}

static const char *condName[] =
{
  /* 0..15. */
  ""   , "z"  , "nz" , "p"  , "n"  , "c"  , "nc" , "v"  ,
  "nv" , "gt" , "ge" , "lt" , "le" , "hi" , "ls" , "pnz",
  "ss" , "sc"

};

static void
write_instr_name_(struct arcDisState *state,
		  const char *instrName,
		  int cond,
		  int condCodeIsPartOfName,
		  int flag,
		  int signExtend,
		  int addrWriteBack,
		  int directMem)
{
  if(!instrName)
	return;
  strncpy(state->instrBuffer, instrName, sizeof(state->instrBuffer)-1);
  if (cond > 0)
    {
      int condlim = 0; /* condition code limit*/
      const char *cc = 0;
      if (!condCodeIsPartOfName) strcat(state->instrBuffer, ".");
      condlim = 18;
      if (cond < condlim)
	cc = condName[cond];
      else
	cc = cond_code_name(state, cond);
      if (!cc) cc = "???";
      strcat(state->instrBuffer, cc);
    }
  if (flag) strcat(state->instrBuffer, ".f");
  if (state->nullifyMode)
    if (strstr(state->instrBuffer, ".d") == NULL)
      strcat(state->instrBuffer, ".d");
  if (signExtend)    strcat(state->instrBuffer, ".x");
  switch (addrWriteBack)
  {
    case 1: strcat(state->instrBuffer, ".a"); break;
    case 2: strcat(state->instrBuffer, ".ab"); break;
    case 3: strcat(state->instrBuffer, ".as"); break;
  }
  if (directMem)     strcat(state->instrBuffer, ".di");
}

#define write_instr_name()	{\
  write_instr_name_(state, instrName,cond, condCodeIsPartOfName, flag, signExtend, addrWriteBack, directMem); \
 formatString[0] = '\0'; \
}

enum
{
  op_BC = 0, op_BLC = 1, op_LD  = 2, op_ST = 3, op_MAJOR_4  = 4,
  /* START ARC LOCAL */
  op_MAJOR_5 = 5, op_MAJOR_6 = 6, op_SIMD=9,      op_LD_ADD = 12, op_ADD_SUB_SHIFT  = 13,
  /* END ARC LOCAL */
  op_ADD_MOV_CMP = 14, op_S = 15, op_LD_S = 16, op_LDB_S = 17,
  op_LDW_S = 18, op_LDWX_S  = 19, op_ST_S = 20, op_STB_S = 21,
  op_STW_S = 22, op_Su5     = 23, op_SP   = 24, op_GP    = 25, op_Pcl = 26,
  op_MOV_S = 27, op_ADD_CMP = 28, op_BR_S = 29, op_B_S   = 30, op_BL_S = 31
};

extern disassemble_info tm_print_insn_info;

/*
 * bfd_getm32 - To retrieve the upper 16-bits of the ARCtangent-A5
 *              basecase (32-bit) instruction
 */
static bfd_vma
bfd_getm32 (data)
     unsigned int data;
{
   bfd_vma value = 0;

   value = ((data & 0xff00) | (data & 0xff)) << 16;
   value |= ((data & 0xff0000) | (data & 0xff000000)) >> 16;
   return value;
}

/*
 * bfd_getm32_ac - To retrieve the upper 8-bits of the ARCompact
 *                 16-bit instruction
 */
static bfd_vma
bfd_getm32_ac (data)
     unsigned int data;
{
   bfd_vma value = 0;

   value = ((data & 0xff) << 8 | (data & 0xff00) >> 8);
   return value;
}

/*
 * sign_extend - Sign Extend the value
 *
 */
static int
sign_extend (int value, int bits)
{
  if (BIT(value, (bits-1)))
    value |= (0xffffffff << bits);
  return value;
}

/* dsmOneArcInst - This module is used to identify the instruction
 *		   and to decode them based on the ARCtangent-A5
 *                 instruction set architecture.
 *                 First, the major opcode is computed. Based on the
 *		   major opcode and sub opcode, the instruction is
 * 		   identified. The appropriate decoding class is assigned
 *		   based on the instruction.Further subopcode 2 is used in
 *                 cases where decoding upto subopcode1 is not possible.
 *
 *		   The instruction is then decoded accordingly.
 */
static int
dsmOneArcInst (bfd_vma addr, struct arcDisState *state, disassemble_info * info)
{

  int subopcode, mul;
  int condCodeIsPartOfName=0;
  int decodingClass;
  const char *instrName;
  int fieldAisReg=1, fieldBisReg=1, fieldCisReg=1;
  int fieldA=0, fieldB=0, fieldC=0;
  int flag=0, cond=0, is_shimm=0, is_limm=0;
  int signExtend=0, addrWriteBack=0, directMem=0;
  int is_linked=0;
  int offset=0;
  int usesAuxReg = 0;
  int usesSimdRegA= 0, usesSimdRegB=0, usesSimdRegC=0,simd_scale_u8=-1;
  int flags = !E_ARC_MACH_A4;
  char formatString[60];

  state->nullifyMode = BR_exec_when_no_jump;
  state->isBranch = 0;

  state->_mem_load = 0;
  state->_ea_present = 0;
  state->_load_len = 0;
  state->ea_reg1 = no_reg;
  state->ea_reg2 = no_reg;
  state->_offset = 0;

  state->sourceType = ARC_UNDEFINED;

  /* ARCtangent-A5 basecase instruction and little-endian mode */
  if ((info->endian == BFD_ENDIAN_LITTLE) && (state->instructionLen == 4))
    state->words[0] = bfd_getm32(state->words[0]);

  if (state->instructionLen == 4)
  {
    if (!NEXT_WORD(0))
      return 0;
    /* Get the major opcode of the ARCtangent-A5 32-bit instruction. */
    state->_opcode = OPCODE(state->words[0]);
  }
  else
  {
    /* ARCompact 16-bit instruction */
    if (!NEXT_WORD_AC(0))
      return 0;
    /* Get the major opcode of the ARCompact 16-bit instruction. */
    state->_opcode = OPCODE_AC(state->words[0]);
  }

  instrName = 0;
  decodingClass = 0; /* default! */
  mul = 0;
  condCodeIsPartOfName=0;
  state->commNum = 0;
  state->tcnt = 0;
  state->acnt = 0;
  state->flow = noflow;

  /* Find the match for the opcode. Once the major opcode category is
   * identified, get the subopcode to determine the exact instruction.
   * Based on the instruction identified, select the decoding class.
   * If condition code is part of the instruction name, then set the
   * flag 'condCodeIsPartOfName'.
   * For branch, jump instructions set 'isBranch' (state->isBranch).
   */

  switch (state->_opcode)
  {
    case op_BC:
    /* Branch Conditionally */
      instrName = "b";
      decodingClass = 13;
      condCodeIsPartOfName = 1;
      state->isBranch = 1;
      break;

    case op_BLC:
    /* Branch and Link, Compare and Branch  */
      decodingClass = 9;
      state->isBranch = 1;
      switch (BITS(state->words[0],16,16))
      {
	case 0:
	  if (!instrName)
	    instrName = "bl";
	  decodingClass = 13;
      	  condCodeIsPartOfName = 1;
	  break;
	case 1:
	  switch (BITS(state->words[0],0,3))
	  {
	    case 0: instrName = "breq"; break;
	    case 1: instrName = "brne"; break;
	    case 2: instrName = "brlt"; break;
	    case 3: instrName = "brge"; break;
	    case 4: instrName = "brlo"; break;
	    case 5: instrName = "brhs"; break;
	    case 14: instrName = "bbit0"; break;
	    case 15: instrName = "bbit1"; break;
	    default:
	      instrName = "??? (0[3])";
	      state->flow = invalid_instr;
	      break;
	  }
	  break;
	default:
	  instrName = "??? (0[3])";
	  state->flow = invalid_instr;
	  break;
      }
      break;

    case op_LD:
    /* Load register with offset [major opcode 2]  */
      decodingClass = 6;
      switch (BITS(state->words[0],7,8))
      {
	case 0: instrName  = "ld";  state->_load_len = 4; break;
	case 1: instrName  = "ldb"; state->_load_len = 1; break;
	case 2: instrName  = "ldw"; state->_load_len = 2; break;
	default:
	  instrName = "??? (0[3])";
	  state->flow = invalid_instr;
	  break;
      }
      break;

    case op_ST:
    /* Store register with offset [major opcode 0x03] */
      decodingClass = 7;
      switch (BITS(state->words[0],1,2))
      {
	case 0: instrName = "st";  break;
	case 1: instrName = "stb"; break;
  	case 2: instrName = "stw"; break;
	default:
	  instrName = "??? (2[3])";
	  state->flow = invalid_instr;
	  break;
      }
      break;

    case op_MAJOR_4:
    /* ARC 32-bit basecase instructions with 3 Operands */
      decodingClass = 0;  /* Default for 3 operand instructions */
      subopcode = BITS(state->words[0],16,21);
      switch (subopcode)
      {
        case 0: instrName = "add";  break;
        case 1: instrName = "adc";  break;
        case 2: instrName = "sub";  break;
        case 3: instrName = "sbc";  break;
        case 4: instrName = "and";  break;
        case 5: instrName = "or";   break;
        case 6: instrName = "bic";  break;
        case 7: instrName = "xor";  break;
      case 8: instrName = "max";  break;
      case 9: instrName = "min";  break;
      case 10:
	{
	  if(state->words[0] == 0x264a7000)
	    {
	      instrName = "nop";
	      decodingClass = 26;
	    }
	  else
	    {
	      instrName = "mov";
	      decodingClass = 12;
	    }
	  break;
	}
      case 11: instrName = "tst"; decodingClass = 2; break;
      case 12: instrName = "cmp"; decodingClass = 2; break;
      case 13: instrName = "rcmp"; decodingClass = 2; break;
      case 14: instrName = "rsub"; break;
      case 15: instrName = "bset"; break;
      case 16: instrName = "bclr"; break;
      case 17: instrName = "btst"; decodingClass = 2; break;
      case 18: instrName = "bxor"; break;
      case 19: instrName = "bmsk"; break;
      case 20: instrName = "add1"; break;
      case 21: instrName = "add2"; break;
      case 22: instrName = "add3"; break;
      case 23: instrName = "sub1"; break;
      case 24: instrName = "sub2"; break;
      case 25: instrName = "sub3"; break;
      case 30: instrName = "mpyw"; break;
      case 31: instrName = "mpyuw"; break;
        case 32:
        case 33:
	  instrName = "j";
        case 34:
        case 35:
	  if (!instrName) instrName = "jl";
	  decodingClass = 4;
	  condCodeIsPartOfName = 1;
          state->isBranch = 1;
	  break;
        case 40:
	  instrName = "lp";
	  decodingClass = 11;
	  condCodeIsPartOfName = 1;
          state->isBranch = 1;
	  break;
        case 41: instrName = "flag"; decodingClass = 3; break;
        case 42: instrName = "lr"; decodingClass = 10;  break;
        case 43: instrName = "sr"; decodingClass =  8;  break;
        case 47:
	  decodingClass = 1;
          switch (BITS(state->words[0],0,5)) /* Checking based on Subopcode2 */
	  {
	  case 0: instrName = "asl";  break;
	  case 1: instrName = "asr";  break;
	  case 2: instrName = "lsr";  break;
	  case 3: instrName = "ror";  break;
	  case 4: instrName = "rrc";  break;
	  case 5: instrName = "sexb"; break;
	  case 6: instrName = "sexw"; break;
	  case 7: instrName = "extb"; break;
	  case 8: instrName = "extw"; break;
	  case 9: instrName = "abs";  break;
	  case 10: instrName = "not"; break;
	  case 11: instrName = "rlc"; break;
	  case 12:  instrName = "ex";


	    decodingClass = 34;
	    break; // ramana adds

	  /* START ARC LOCAL */
	  case 16: instrName = "llock"; decodingClass = 34; break;
	  case 17: instrName = "scond"; decodingClass = 34; break;
	  /* END ARC LOCAL */

	  case 63:
	    decodingClass = 26;
	    switch (BITS(state->words[0],24,26))
	      {
	      case 1 : instrName = "sleep"; decodingClass = 32; break;
	      case 2 :
		if((info->mach) == ARC_MACH_ARC7)
		  instrName = "trap0";
		else
		  instrName = "swi";
		break;
	      case 3:

		if(BITS(state->words[0],22,23) == 1)
		  instrName = "sync" ;

		break;
	      case 4 : instrName = "rtie" ; break;
	      case 5 : instrName = "brk"; break;
	      default:

		instrName = "???";
		state->flow=invalid_instr;
		break;
	      }
	    break;
	  }
	  break;
      }

      if (!instrName)
      {
        subopcode = BITS(state->words[0],17,21);
	decodingClass = 5;
	switch (subopcode)
    	{
	  case 24: instrName  = "ld";   state->_load_len = 4; break;
	  case 25: instrName  = "ldb";  state->_load_len = 1; break;
	  case 26: instrName  = "ldw";  state->_load_len = 2; break;
	  default:
	    instrName = "??? (0[3])";
	    state->flow = invalid_instr;
	    break;
	}
      }
      break;

    case op_MAJOR_5:
    /* ARC 32-bit extension instructions */
      decodingClass = 0;  /* Default for Major opcode 5 ... */
      subopcode = BITS(state->words[0],16,21);
      switch (subopcode)
      {
	case 0: instrName = "asl"; break;
	case 1: instrName = "lsr"; break;
	case 2: instrName = "asr"; break;
	case 3: instrName = "ror"; break;
	case 4: instrName = "mul64"; mul =1; decodingClass = 2; break;
	case 5: instrName = "mulu64"; mul =1; decodingClass = 2; break;

	  /* ARC A700 */
      case 6: instrName = "adds" ;break;

      case 7: instrName = "subs"; break;
      case 8: instrName = "divaw"; break;
      case 0xA: instrName = "asls"; break;
      case 0xB: instrName = "asrs"; break;
      case 0x28: instrName = "addsdw";break;
      case 0x29: instrName = "subsdw"; break;

      case 47:
	switch(BITS(state->words[0],0,5))
	  {
	  case 0: instrName = "swap"; decodingClass = 1; break;
	  case 1: instrName = "norm"; decodingClass = 1; break;
	    /* ARC A700 DSP Extensions */
	  case 2: instrName = "sat16"; decodingClass = 1; break;
	  case 3: instrName = "rnd16"; decodingClass = 1; break;
	  case 4: instrName = "abssw"; decodingClass = 1; break;
	  case 5: instrName = "abss"; decodingClass = 1; break;
	  case 6: instrName = "negsw"; decodingClass = 1; break;
	  case 7: instrName = "negs"; decodingClass = 1; break;

	  case 8: instrName = "normw"; decodingClass = 1; break;

	  /* START ARC LOCAL */
	  case 9: instrName = "swape"; decodingClass = 1; break;
	  /* END ARC LOCAL */

	  default:
	    instrName = "???";
	    state->flow =invalid_instr;
	    break;

	  }
	break;
      default:
	instrName = "??? (2[3])";
	state->flow = invalid_instr;
	break;
      }
    break;

  /* START ARC LOCAL */
  case op_MAJOR_6:
      decodingClass = 44;  /* Default for Major opcode 6 ... */
      subopcode = BITS(state->words[0],0,5);
      switch (subopcode)
        {
	case 26: /* 0x1a */ instrName = "rtsc"; break;
        default:
	  instrName = "??? (2[3])";
	  state->flow = invalid_instr;
	  break;
	}
    break;
  /* END ARC LOCAL */

    /* Aurora SIMD instruction support*/
  case op_SIMD:

    if (enable_simd)
      {
	decodingClass = 42;
	subopcode     = BITS(state->words[0], 17, 23);

	switch (subopcode)
	  {

	  case 68:
	    instrName = "vld32";
	    decodingClass = 37;
	    usesSimdRegA=1;
	    usesSimdRegB=2;
	    usesSimdRegC=0;
	    simd_scale_u8 = 2;
	    break;

	  case 72:
	    instrName = "vld64";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 3;
	    break;

	  case 74:
	    instrName = "vld64w";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 3;
	    break;

	  case 70:
	    instrName = "vld32wl";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 2;
	    break;

	  case 66:
	    instrName = "vld32wh";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 2;
	    break;

	  case 76:
	    instrName = "vld128";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 4;
	    break;

	  case 78:
	    {
	      short  sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vld128r";
		  decodingClass = 38;
		  usesSimdRegA  = 1;
		  usesSimdRegB  = usesSimdRegC = 0;
		  break;
		default:
		  instrName = "SIMD";
		  state->flow = invalid_instr;
		}
	    }
	    break;
	  case 71:
	    instrName = "vst16_0";
	    decodingClass = 37;
	    usesSimdRegA = 1;
	    usesSimdRegB = 2;
	    usesSimdRegC = 0;
	    simd_scale_u8 = 1;
	    break;

	  case 81:
	    instrName = "vst16_1";
	    decodingClass = 37;
	    usesSimdRegA = 1;
	    usesSimdRegB = 2;
	    usesSimdRegC = 0;
	    simd_scale_u8 = 1;
	    break;

	  case 67:
	    instrName = "vst16_2";
	    decodingClass = 37;
	    usesSimdRegA = 1;
	    usesSimdRegB = 2;
	    usesSimdRegC = 0;
	    simd_scale_u8 = 1;
	    break;

	  case 75:
	    instrName = "vst16_3";
	    decodingClass = 37;
	    usesSimdRegA = 1;
	    usesSimdRegB = 2;
	    usesSimdRegC = 0;
	    simd_scale_u8 = 1;
	    break;

	  case 83:
	    instrName = "vst16_4";
	    decodingClass = 37;
	    usesSimdRegA = 1;
	    usesSimdRegB = 2;
	    usesSimdRegC = 0;
	    simd_scale_u8 = 1;
	    break;

	  case 89:
	    instrName = "vst16_5";
	    decodingClass = 37;
	    usesSimdRegA = 1;
	    usesSimdRegB = 2;
	    usesSimdRegC = 0;
	    simd_scale_u8 = 1;
	    break;

	  case 91:
	    instrName = "vst16_6";
	    decodingClass = 37;
	    usesSimdRegA = 1;
	    usesSimdRegB = 2;
	    usesSimdRegC = 0;
	    simd_scale_u8 = 1;
	    break;

	  case 93:
	    instrName = "vst16_7";
	    decodingClass = 37;
	    usesSimdRegA = 1;
	    usesSimdRegB = 2;
	    usesSimdRegC = 0;
	    simd_scale_u8 = 1;
	    break;

	  case 69:
	    instrName = "vst32_0";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 2;
	    break;

	  case 82:
	    instrName = "vst32_2";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 2;
	    break;

	  case 86:
	    instrName = "vst32_4";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 2;
	    break;

	  case 88:
	    instrName = "vst32_6";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 2;
	    break;

	  case 73:
	    instrName = "vst64";
	    decodingClass = 37 ;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 3;
	    break;

	  case 77:
	    instrName = "vst128";
	    decodingClass = 37;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = 2;
	    usesSimdRegC  = 0;
	    simd_scale_u8 = 4;
	    break;

	  case 79:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vst128r";
		  decodingClass = 38;
		  usesSimdRegA = 1;
		  usesSimdRegB = usesSimdRegC = 0;
		  break;

		default:
		  instrName = "SIMD";
		  state->flow = invalid_instr;
		}

	    }
	    break;
	  case 80:
	    instrName = "vmvw";
	    usesSimdRegA = usesSimdRegB = 1;
	    usesSimdRegC = 0;
	    decodingClass = 39;
	    break;

	  case 84:
	    instrName = "vmvzw";
	    decodingClass = 39;
	    usesSimdRegA = usesSimdRegB = 1;
	    usesSimdRegC = 0;
	    break;

	  case 90:
	    instrName = "vmovw";
	    decodingClass = 39;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = usesSimdRegC = 0;
	    break;

	  case 94:
	    instrName = "vmovzw";
	    decodingClass = 39;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = usesSimdRegC = 0;
	    break;

	  case 85:
	    instrName = "vmvaw";
	    decodingClass = 39;
	    usesSimdRegA  = usesSimdRegB = 1;
	    usesSimdRegC  = 0;
	    break;

	  case 95:
	    instrName = "vmovaw";
	    decodingClass = 39;
	    usesSimdRegA  = 1;
	    usesSimdRegB  = usesSimdRegC = 0;
	    break;

	  case 10:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vaddw"; decodingClass = 42;
		  usesSimdRegA = usesSimdRegB = usesSimdRegC =1;
		  break;

		case 1:
		  instrName = "vaddaw"; decodingClass = 42;
		  usesSimdRegA = usesSimdRegB = usesSimdRegC =1;
		  break;

		case 2:
		  instrName = "vbaddw"; decodingClass = 42;
		  usesSimdRegA = usesSimdRegB = 1;
		  usesSimdRegC = 0;
		  break;
		}
	      break;
	    }

	  case 11:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vsubw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;

		case 1:
		  instrName = "vsubaw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;

		case 2:
		  instrName = "vbsubw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		}
	    }
	    break;

	  case 12:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vmulw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;

		case 1:
		  instrName = "vmulaw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;

		case 2:
		  instrName = "vbmulw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;

		case 3:
		  instrName = "vbmulaw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		}
	    }
	    break;

	  case 13:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vmulfw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;

		case 1:
		  instrName = "vmulfaw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;

		case 2:
		  instrName = "vbmulfw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		}
	    }
	    break;

	  case 15:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vsummw";
		  decodingClass = 42;
		  usesSimdRegA = usesSimdRegB = usesSimdRegC = 1;
		  break;
		case 2:
		  instrName = "vbrsubw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		}
	    }
	    break;

	  case 23:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vmr7w";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;

		case 1:
		  instrName = "vmr7aw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;


		case 2:
		  switch (BITS(state->words[0], 0, 5))
		    {
		    case 0:
		      instrName = "vaddsuw";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;

		    case 1:
		      instrName = "vabsw";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;

		    case 2:
		      instrName = "vsignw";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;

		    case 3:
		      instrName = "vupbw";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;

		    case 4:
		      instrName = "vexch1";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;

		    case 5:
		      instrName = "vexch2";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;

		    case 6:
		      instrName = "vexch4";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;

		    case 7:
		      instrName = "vupsbw";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;

		    case 8:
		      instrName = "vdirun";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = usesSimdRegA = 0;
		      break;

		    case 9:
		      instrName = "vdorun";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = usesSimdRegA = 0;
		      break;

		    case 10:
		      instrName = "vdiwr";
		      decodingClass = 40;
		      usesSimdRegB  = 3;
		      usesSimdRegA  = usesSimdRegC = 0;
		      fieldCisReg   = 1;
		      break;

		    case 11:
		      instrName = "vdowr";
		      decodingClass = 40;
		      usesSimdRegB  = 3;
		      usesSimdRegA  = usesSimdRegC = 0;
		      fieldCisReg   = 1;
		      break;

		    case 12:
		      instrName = "vdird";
		      decodingClass = 40;
		      usesSimdRegB  = 1;
		      usesSimdRegC  = 3;
		      usesSimdRegA  = 0;
		      break;

		    case 13:
		      instrName = "vdord";
		      decodingClass = 40;
		      usesSimdRegB  = 1;
		      usesSimdRegC  = 3;
		      usesSimdRegA  = 0;
		      break;

		    case 63:
		      {
			switch (BITS(state->words[0], 24, 25))
			  {
			  case 0:
			    instrName = "vrec";
			    decodingClass = 43;
			    usesSimdRegC  = 0;
			    usesSimdRegB  = usesSimdRegA = 0;
			    break;

			  case 1:
			    instrName = "vrecrun";
			    decodingClass = 43;
			    usesSimdRegC  = 0;
			    usesSimdRegA  = usesSimdRegB = 0;
			    break;

			  case 2:
			    instrName = "vrun";
			    decodingClass = 43;
			    usesSimdRegC  = 0;
			    usesSimdRegB  = usesSimdRegA = 0;
			    break;

			  case 3:
			    instrName = "vendrec";
			    decodingClass = 43;
			    usesSimdRegC  = 0;
			    usesSimdRegB  = usesSimdRegA = 0;
			    break;
			  }
		      }
		      break;
		    }
		  break;

		case 3:
		  switch (BITS(state->words[0], 0, 2))
		    {
		    case 1:
		      instrName = "vabsaw";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;
		    case 3:
		      instrName = "vupbaw";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;
		    case 7:
		      instrName = "vupsbaw";
		      decodingClass = 40;
		      usesSimdRegC  = usesSimdRegB = 1;
		      usesSimdRegA  = 0;
		      break;
		    }
		  break;
		}
	    }
	    break;

	  case 16:
	    instrName = "vasrw";
	    decodingClass = 42;
	    usesSimdRegA  = usesSimdRegB = 1;
	    usesSimdRegC  = 2;
	    break;

	  case 48:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vasrwi";
		  decodingClass = 41;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		case 2:
		  instrName = "vasrrwi";
		  decodingClass = 41;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		}
	    }
	    break;

	  case 59:
	    instrName = "vasrsrwi";
	    decodingClass = 41;
	    usesSimdRegA  = usesSimdRegB = 1;
	    usesSimdRegC  = 0;
	    break;

	  case 18:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vmaxw";
		  usesSimdRegC = 1;
		  break;
		case 1:
		  instrName = "vmaxaw";
		  usesSimdRegC = 1;
		  break;
		case 2:
		  instrName = "vbmaxw";
		  usesSimdRegC = 0;
		  break;
		}
	      decodingClass = 42;
	      usesSimdRegA  = usesSimdRegB = 1;
	      break;
	    }

	  case 19:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vminw";
		  usesSimdRegC = 1;
		  break;
		case 1:
		  instrName = "vminaw";
		  usesSimdRegC = 0;
		  break;
		case 2:
		  instrName = "vbminw";
		  usesSimdRegC = 0;
		  break;
		}
	      decodingClass = 42;
	      usesSimdRegA  = usesSimdRegB = 1;
	      break;
	    }

	  case 14:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vdifw";
		  break;
		case 1:
		  instrName = "vdifaw";
		  break;
		case 2:
		  instrName = "vmrb";
		  break;
		}
	      decodingClass = 42;
	      usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	      break;
	    }

	  case 24:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vand";
		  decodingClass = 42;
		  usesSimdRegA = usesSimdRegB = usesSimdRegC = 1;
		  break;
		case 1:
		  instrName = "vandaw";
		  decodingClass = 42;
		  usesSimdRegA = usesSimdRegB = usesSimdRegC = 1;
		  break;
		}
	      break;
	    }

	  case 25:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vor";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
		  break;
		}
	      break;
	    }

	  case 26:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vxor";
		  break;
		case 1:
		  instrName = "vxoraw";
		  break;
		}
	      decodingClass = 42;
	      usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	      break;
	    }

	  case 27:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vbic";
		  break;
		case 1:
		  instrName = "vbicaw";
		  break;
		}
	      decodingClass = 42;
	      usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	      break;
	    }

	  case 4:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vavb";
		  break;
		case 2:
		  instrName = "vavrb";
		  break;
		}
	      decodingClass = 42;
	      usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	      break;
	    }

	  case 28:
	    instrName = "veqw";
	    decodingClass = 42;
	    usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	    break;

	  case 29:
	    instrName = "vnew";
	    decodingClass = 42;
	    usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	    break;

	  case 30:
	    instrName = "vlew";
	    decodingClass = 42;
	    usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	    break;

	  case 31:
	    instrName = "vltw";
	    decodingClass = 42;
	    usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	    break;

	  case 49:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vasrpwbi";
		  decodingClass = 41;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		case 2:
		  instrName = "vasrrpwbi";
		  decodingClass = 41;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		}
	      break;
	    }

	  case 5:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vsr8";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 2;
		  break;

		case 1:
		  instrName = "vsr8aw";
		  decodingClass = 42;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 2;
		  break;
		}
	      break;
	    }

	  case 37:
	    {
	      short sub_subopcode = BITS(state->words[0], 15, 16);
	      switch (sub_subopcode)
		{
		case 0:
		  instrName = "vsr8i";
		  decodingClass = 41;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;

		case 1:
		  instrName = "vsr8awi";
		  decodingClass = 41;
		  usesSimdRegA  = usesSimdRegB = 1;
		  usesSimdRegC  = 0;
		  break;
		}
	      break;
	    }

	  case 20:
	  case 21:
	  case 22:
	    {
	      short subopcode2 = BITS(state->words[0], 15, 18);
	      switch (subopcode2)
		{
		case 0:
		  instrName = "vmr1w";
		  break;

		case 2:
		  instrName = "vmr2w";
		  break;

		case 4:
		  instrName = "vmr3w";
		  break;

		case 6:
		  instrName = "vmr4w";
		  break;

		case 8:
		  instrName = "vmr5w";
		  break;

		case 10:
		  instrName = "vmr6w";
		  break;

		case 1:
		  instrName = "vmr1aw";
		  break;

		case 3:
		  instrName = "vmr2aw";
		  break;

		case 5:
		  instrName = "vmr3aw";
		  break;

		case 7:
		  instrName = "vmr4aw";
		  break;

		case 9:
		  instrName = "vmr5aw";
		  break;

		case 11:
		  instrName = "vmr6aw";
		  break;

		}

	      decodingClass = 42;
	      usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	      break;
	    }


	  case 7:
	  case 6:
	    {
	      switch (BITS(state->words[0], 16, 19))
		{
		case 15:
		  instrName = "vh264ft";
		  break;
		case 14:
		  instrName = "vh264f";
		  break;
		case 13:
		  instrName = "vvc1ft";
		  break;
		case 12:
		  instrName = "vvc1f";
		  break;
		}
	      decodingClass = 42;
	      usesSimdRegA  = usesSimdRegB = usesSimdRegC = 1;
	      break;

	    }

	  case 92:
	    instrName = "vd6tapf";
	    decodingClass = 39;
	    usesSimdRegA  = usesSimdRegB = 1;
	    usesSimdRegC  = 0;
	    break;

	  case 55:
	    instrName = "vinti";
	    decodingClass = 43;
	    usesSimdRegA  = usesSimdRegB = usesSimdRegC = 0;
	    break;

	  default:
	    instrName = "SIMD";
	    state->flow = invalid_instr;
	    break;
	  }
      }
    else
      {
	instrName = "???_SIMD";
	state->flow = invalid_instr;
      }
	break;


    case op_LD_ADD:
    /* Load/Add resister-register */
      decodingClass = 15;  /* default for Major opcode 12 ... */
      switch(BITS(state->words[0],3,4))
	{
	case 0: instrName = "ld_s"; break;
	case 1: instrName = "ldb_s"; break;
	case 2: instrName = "ldw_s"; break;
	case 3: instrName = "add_s"; break;
        default:
	  instrName = "??? (2[3])";
	  state->flow = invalid_instr;
	  break;
	}
      break;

  case op_ADD_SUB_SHIFT:
    /* Add/sub/shift immediate */
    decodingClass = 16;  /* default for Major opcode 13 ... */
    switch(BITS(state->words[0],3,4))
      {
      case 0: instrName = "add_s"; break;
      case 1: instrName = "sub_s"; break;
      case 2: instrName = "asl_s"; break;
      case 3: instrName = "asr_s"; break;
      default:
	instrName = "??? (2[3])";
	state->flow = invalid_instr;
	break;
      }
    break;

    case op_ADD_MOV_CMP:
    /* One Dest/Source can be any of r0 - r63 */
      decodingClass = 17;  /* default for Major opcode 14 ... */
      switch(BITS(state->words[0],3,4))
      {
	case 0: instrName = "add_s"; break;
	case 1:
	case 3: instrName = "mov_s"; decodingClass = 18; break;
	case 2: instrName = "cmp_s"; decodingClass = 18; break;
        default:
	  instrName = "??? (2[3])";
	  state->flow = invalid_instr;
	  break;
      }
      break;

    case op_S:
    /* ARCompact 16-bit instructions, General ops/ single ops */
      decodingClass = 22;  /* default for Major opcode 15 ... */
      switch(BITS(state->words[0],0,4))
      {
	case 0:
	  decodingClass = 27;
          switch(BITS(state->words[0],5,7))
	  {
            case 0 : instrName = "j_s";
            case 2 : if (!instrName) instrName = "jl_s";
	             state->isBranch = 1;
		     state->nullifyMode = BR_exec_when_no_jump;
		     break;
            case 1 : if (!instrName) instrName = "j_s.d";
            case 3 : if (!instrName) instrName = "jl_s.d";
          	     state->isBranch = 1;
		     state->nullifyMode = BR_exec_always;
		     break;
            case 6 : instrName = "sub_s.ne";
	             decodingClass = 35;
	             break;
            case 7 :
	      decodingClass = 26;
              switch(BITS(state->words[0],8,10))
	      {
              	case 0 : instrName = "nop_s"; break;

		  /* Unimplemented instruction reserved in ARC700 */
	        case 1: instrName = "unimp_s";break;


	        case 4: instrName = "jeq_s [blink]";
		case 5: if (!instrName) instrName = "jne_s [blink]";
		case 6:
		  if (!instrName)
		    instrName = "j_s [blink]";
		  state->isBranch = 1;
		  state->nullifyMode = BR_exec_when_no_jump;
		  break;
		case 7:
		  if (!instrName)
		    instrName = "j_s.d [blink]";
		  state->isBranch = 1;
		  state->nullifyMode = BR_exec_always;
		  break;
                default:
		  instrName = "??? (2[3])";
	      	  state->flow = invalid_instr;
		  break;
	      }
	      break;
            default:
	      instrName = "??? (2[3])";
	      state->flow = invalid_instr;
	      break;
	  }
	  break;
        case 2 : instrName = "sub_s"; break;
        case 4 : instrName = "and_s"; break;
        case 5 : instrName = "or_s"; break;
        case 6 : instrName = "bic_s"; break;
        case 7 : instrName = "xor_s"; break;
	case 11: instrName = "tst_s"; decodingClass = 14; break;
	case 12: instrName = "mul64_s"; mul =1; decodingClass = 14; break;
	case 13: instrName = "sexb_s"; decodingClass = 14; break;
	case 14: instrName = "sexw_s"; decodingClass = 14; break;
	case 15: instrName = "extb_s"; decodingClass = 14; break;
	case 16: instrName = "extw_s"; decodingClass = 14; break;
	case 17: instrName = "abs_s"; decodingClass = 14; break;
	case 18: instrName = "not_s"; decodingClass = 14; break;
	case 19: instrName = "neg_s"; decodingClass = 14; break;
        case 20: instrName = "add1_s"; break;
        case 21: instrName = "add2_s"; break;
        case 22: instrName = "add3_s"; break;
        case 24: instrName = "asl_s"; break;
        case 25: instrName = "lsr_s"; break;
        case 26: instrName = "asr_s"; break;
        case 27: instrName = "asl_s"; decodingClass = 14; break;
        case 28: instrName = "asr_s"; decodingClass = 14; break;
        case 29: instrName = "lsr_s"; decodingClass = 14; break;
      case 30: instrName = "trap_s"; decodingClass = 33; break;
      case 31: instrName = "brk_s"; decodingClass = 26; break;

        default:
	  instrName = "??? (2[3])";
	  state->flow = invalid_instr;
	  break;
      }
      break;

       case op_LD_S:
    /* ARCompact 16-bit Load with offset, Major Opcode 0x10 */
      instrName = "ld_s";
      decodingClass = 28;
      break;

    case op_LDB_S:
    /* ARCompact 16-bit Load with offset, Major Opcode 0x11 */
      instrName = "ldb_s";
      decodingClass = 28;
      break;

    case op_LDW_S:
    /* ARCompact 16-bit Load with offset, Major Opcode 0x12 */
      instrName = "ldw_s";
      decodingClass = 28;
      break;

    case op_LDWX_S:
    /* ARCompact 16-bit Load with offset, Major Opcode 0x13 */
      instrName = "ldw_s.x";
      decodingClass = 28;
      break;

    case op_ST_S:
    /* ARCompact 16-bit Store with offset, Major Opcode 0x14 */
      instrName = "st_s";
      decodingClass = 28;
      break;

    case op_STB_S:
    /* ARCompact 16-bit Store with offset, Major Opcode 0x15 */
      instrName = "stb_s";
      decodingClass = 28;
      break;

    case op_STW_S:
    /* ARCompact 16-bit Store with offset, Major Opcode 0x16 */
      instrName = "stw_s";
      decodingClass = 28;
      break;

    case op_Su5:
    /* ARCompact 16-bit involving unsigned 5-bit immediate operand */
      decodingClass = 23;  /* default for major opcode 0x17 ... */
      switch (BITS(state->words[0],5,7))
      {
	case 0: instrName = "asl_s"; break;
	case 1: instrName = "lsr_s"; break;
	case 2: instrName = "asr_s"; break;
	case 3: instrName = "sub_s"; break;
	case 4: instrName = "bset_s"; break;
	case 5: instrName = "bclr_s"; break;
	case 6: instrName = "bmsk_s"; break;
	case 7: instrName = "btst_s"; decodingClass = 21; break;
      }
      break;

    case op_SP:
    /* ARCompact 16-bit Stack pointer-based instructions */
      decodingClass = 19;  /* default for Stack pointer-based insns ... */
      switch (BITS(state->words[0],5,7))
      {
        case 0: instrName = "ld_s"; break;
        case 1: instrName = "ldb_s"; break;
        case 2: instrName = "st_s"; break;
        case 3: instrName = "stb_s"; break;
        case 4: instrName = "add_s"; break;
        case 5:
      	  if (!BITS(state->words[0],8,8))
	    instrName = "add_s";
	  else
	    instrName = "sub_s";
	  break;
        case 6: instrName = "pop_s"; decodingClass = 31; break;
        case 7: instrName = "push_s"; decodingClass = 31; break;
	default:
          instrName = "??? (2[3])";
          state->flow = invalid_instr;
	  break;
      }
    break;

    case op_GP:
    /* ARCompact 16-bit Gp-based ld/add (data aligned offset) */
      decodingClass = 20;  /* default for gp-relative insns ... */
      switch (BITS(state->words[0],9,10))
      {
        case 0: instrName = "ld_s"; break;
        case 1: instrName = "ldb_s"; break;
        case 2: instrName = "ldw_s"; break;
        case 3: instrName = "add_s"; break;
      }
      break;

    case op_Pcl:
    /* ARCompact 16-bit Pcl-based ld (32-bit aligned offset) */
      instrName = "ld_s";
      decodingClass = 29;
      break;

    case op_MOV_S:
    /* ARCompact 16-bit Move immediate */
      instrName = "mov_s";
      decodingClass = 30;
      break;

    case op_ADD_CMP:
    /* ARCompact 16-bit Add/compare immediate */
      decodingClass = 21;  /* default for major opcode 0x1c ... */
      if (BIT(state->words[0],7))
	instrName = "cmp_s";
      else
	instrName = "add_s";
      break;

    case op_BR_S:
    /* ARCompact 16-bit Branch conditionally on reg z/nz */
      decodingClass = 25; /* Default for BR_S instruction ... */
      if (BIT(state->words[0],7))
	instrName = "brne_s";
      else
	instrName = "breq_s";
      state->isBranch = 1;
      break;

    case op_B_S:
    /* ARCompact 16-bit Branch conditionally */
      decodingClass = 24; /* Default for B_S instruction ... */
      state->isBranch = 1;
      switch (BITS(state->words[0],9,10))
      {
	case 0: instrName = "b_s"; break;
	case 1: instrName = "beq_s"; break;
	case 2: instrName = "bne_s"; break;
	case 3:
          switch (BITS(state->words[0],6,8))
	  {
	    case 0: instrName = "bgt_s"; break;
	    case 1: instrName = "bge_s"; break;
	    case 2: instrName = "blt_s"; break;
	    case 3: instrName = "ble_s"; break;
	    case 4: instrName = "bhi_s"; break;
	    case 5: instrName = "bhs_s"; break;
	    case 6: instrName = "blo_s"; break;
	    case 7: instrName = "bls_s"; break;
	  }
	  break;
      }
      break;

    case op_BL_S:
    /* ARCompact 16-bit Branch and link unconditionally */
      decodingClass = 24; /* Default for B_S instruction ... */
      instrName = "bl_s";
      state->isBranch = 1;
      break;

    default:

      instrName = "???";
      state->flow=invalid_instr;
      break;
  }

  /* Maybe we should be checking for extension instructions over here
   * instead of all over this crazy switch case. */
  if (state->flow == invalid_instr)
    {
      if (!((state->_opcode == op_SIMD) && enable_simd))
	instrName = instruction_name(state,state->_opcode,
				     state->words[0],
				     &flags);

      if (state->instructionLen == 2)
	{
	  switch (flags)
	    {
	    case AC_SYNTAX_3OP:
	      decodingClass = 22;
	      break;
	    case AC_SYNTAX_2OP:
	      decodingClass = 14;
	      break;
	    case AC_SYNTAX_1OP:
	      decodingClass = 36;
	      break;
	    case AC_SYNTAX_NOP:
	      decodingClass = 26;
	      break;
	    default:
	      mwerror(state, "Invalid syntax class\n");
	    }
	}
      else
	{
/* Must do the above for this one too */
	  switch (flags)
	    {
	    case AC_SYNTAX_3OP:
	      decodingClass = 0;
	      break;
	    case AC_SYNTAX_2OP:
	      decodingClass = 1;
	      break;
	    case AC_SYNTAX_1OP:
	      decodingClass = 32;
	      break;
	    case AC_SYNTAX_NOP:
	      break;
	    case AC_SYNTAX_SIMD:
	      break;
	    default:
	      mwerror(state, "Invalid syntax class\n");
	    }
	}

      if (!instrName)
	{
	  instrName = "???";
	  state->flow=invalid_instr;
	}
    }

  fieldAisReg = fieldBisReg = fieldCisReg = 1; /* assume regs for now */
  flag = cond = is_shimm = is_limm = 0;
  state->nullifyMode = BR_exec_when_no_jump;	/* 0 */
  signExtend = addrWriteBack = directMem = 0;
  usesAuxReg = 0;

  /* The following module decodes the instruction */
  switch (decodingClass)
  {
    case 0:

      /* For ARCtangent 32-bit instructions with 3 operands */

      subopcode = BITS(state->words[0],22,23);
      switch (subopcode)
      {
	case 0:

          /* Either fieldB or fieldC or both can be a limm value;
	   * fieldA can be 0;
           */

          CHECK_FIELD_C();
     	  if (!is_limm)
	  {
	    /* If fieldC is not a limm, then fieldB may be a limm value */
            CHECK_FIELD_B();
	  }
      	  else
	  {
            FIELD_B();
      	    if (!fieldBisReg)
	      fieldB = fieldC;
	  }
      	  CHECK_FIELD_A();
      	  CHECK_FLAG();
	  break;

	case 1:

          /* fieldB may ba a limm value
	   * fieldC is a shimm (unsigned 6-bit immediate)
	   * fieldA can be 0
           */

          CHECK_FIELD_B();
          FIELD_C();
	  fieldCisReg = 0;
          /* Say ea is not present, so only one of us will do the
	     name lookup. */
	  state->_offset += fieldB, state->_ea_present = 0;
      	  CHECK_FIELD_A();
      	  CHECK_FLAG();
	  break;

	case 2:

          /* fieldB may ba a limm value
	   * fieldC is a shimm (signed 12-bit immediate)
	   * fieldA can be 0
           */

	  fieldCisReg = 0;
          fieldC = FIELDS(state->words[0]);
          CHECK_FIELD_B();
          /* Say ea is not present, so only one of us will do the
	     name lookup. */
	  state->_offset += fieldB, state->_ea_present = 0;
	  if (is_limm)
	    fieldAisReg = fieldA = 0;
	  else
	    fieldA = fieldB;
      	  CHECK_FLAG();
	  break;

	case 3:

          /* fieldB may ba a limm value
	   * fieldC may be a limm or a shimm (unsigned 6-bit immediate)
	   * fieldA can be 0
	   * Conditional instructions
           */

          CHECK_FIELD_B();
	  /* fieldC is a shimm (unsigned 6-bit immediate) */
	  if (is_limm)
	  {
	    fieldAisReg = fieldA = 0;
            FIELD_C();
            if (BIT(state->words[0],5))
	      fieldCisReg = 0;
	    else if (fieldC == 62)
	    {
              fieldCisReg = 0;
	      fieldC = fieldB;
	    }
	  }
	  else
	  {
	    fieldA = fieldB;
            if (BIT(state->words[0],5))
	    {
              FIELD_C();
              fieldCisReg = 0;
	    }
	    else
	    {
              CHECK_FIELD_C();
	    }
	  }
      	  CHECK_FLAG_COND();
	  break;
      }

      write_instr_name();
      WRITE_FORMAT_x(A);
      WRITE_FORMAT_COMMA_x(B);
      WRITE_FORMAT_COMMA_x(C);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldA, fieldB, fieldC);
      break;

    case 1:

      /* For ARCtangent 32-bit instructions with 2 operands */

      /* field C is either a register or limm (different!) */
      CHECK_FIELD_C();
      FIELD_B();
      CHECK_FLAG();

      if (BITS(state->words[0],22,23) == 1 )
	fieldCisReg = 0;
      if (fieldCisReg) state->ea_reg1 = fieldC;
      /* field C is either a shimm (same as fieldC) or limm (different!) */
      /* Say ea is not present, so only one of us will do the name lookup. */
      else state->_offset += fieldB, state->_ea_present = 0;

      write_instr_name();
      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(C);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
      break;

    case 2:

      /* For BTST, CMP, MUL64, MULU64 instruction */

      /* field C is either a register or limm (different!) */
      subopcode =  BITS(state->words[0],22,23);
      if (subopcode == 0 || ((subopcode == 3) && (!BIT(state->words[0],5))))
      {
      	CHECK_FIELD_C();
	if (is_limm)
	{
	  FIELD_B();
	  if (!fieldBisReg)
	    fieldB = fieldC;
	}
	else
	{
      	  CHECK_FIELD_B();
	}
      }
      else if (subopcode == 1 || ((subopcode == 3) && (BIT(state->words[0],5))))
      {
	FIELD_C();
	fieldCisReg = 0;
      	CHECK_FIELD_B();
      }
      else if (subopcode == 2)
      {
	FIELD_B();
	fieldC = FIELDS(state->words[0]);
	fieldCisReg = 0;
      }
      if (subopcode == 3)
	CHECK_COND();

      if (fieldCisReg) state->ea_reg1 = fieldC;
      /* field C is either a shimm (same as fieldC) or limm (different!) */
      /* Say ea is not present, so only one of us will do the name lookup. */
      else state->_offset += fieldB, state->_ea_present = 0;

      write_instr_name();
      if (mul)
      {
	/* For Multiply instructions, the first operand is 0 */
	WRITE_FORMAT_x(A);
	WRITE_FORMAT_COMMA_x(B);
        WRITE_FORMAT_COMMA_x(C);
        WRITE_NOP_COMMENT();
        my_sprintf(state, state->operandBuffer, formatString, 0, fieldB, fieldC);
      }
      else
      {
	WRITE_FORMAT_x(B);
        WRITE_FORMAT_COMMA_x(C);
        WRITE_NOP_COMMENT();
        my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
      }
      break;

    case 3:
      /*
       * For FLAG instruction
       */
      subopcode =  BITS(state->words[0],22,23);

      if (subopcode == 0 || ((subopcode == 3) && (!BIT(state->words[0],5))))
      {
        CHECK_FIELD_C();
      }
      else if (subopcode == 1 || ((subopcode == 3) && (BIT(state->words[0],5))))
      {
        FIELD_C();
	fieldCisReg = 0;
      }
      else if (subopcode == 2)
      {
	fieldC = FIELDS(state->words[0]);
	fieldCisReg = 0;
      }
      if (subopcode == 3)
        CHECK_COND();
      flag = 0;  /* this is the FLAG instruction -- it's redundant */

      write_instr_name();
      WRITE_FORMAT_x(C);
      my_sprintf(state, state->operandBuffer, formatString, fieldC);
      break;

    case 4:
      /*
       * For op_JC -- jump to address specified.
       *     Also covers jump and link--bit 9 of the instr. word
       *     selects whether linked, thus "is_linked" is set above.
       */
      subopcode =  BITS(state->words[0],22,23);
      if (subopcode == 0 || ((subopcode == 3) && (!BIT(state->words[0],5))))
      {
        CHECK_FIELD_C();
	/* ilink registers */
	if (fieldC == 29 || fieldC == 31)
      	  CHECK_FLAG();
      }
      else if (subopcode == 1 || ((subopcode == 3) && (BIT(state->words[0],5))))
      {
        FIELD_C();
	fieldCisReg = 0;
      }
      else if (subopcode == 2)
      {
	fieldC = FIELDS(state->words[0]);
	fieldCisReg = 0;
      }

      if (subopcode == 3)
        CHECK_COND();

      state->nullifyMode = BITS(state->words[0],16,16);

      if (!fieldCisReg)
	{
	  state->flow = is_linked ? direct_call : direct_jump;
	  add_target(fieldC);
	}
      else
	{
	  state->flow = is_linked ? indirect_call : indirect_jump;
	  /*
	   * We should also treat this as indirect call if NOT linked
	   * but the preceding instruction was a "lr blink,[status]"
	   * and we have a delay slot with "add blink,blink,2".
	   * For now we can't detect such.
	   */
	  state->register_for_indirect_jump = fieldC;
	}

      write_instr_name();
      strcat(formatString,
	     IS_REG(C)?"[%r]":"%s"); /* address/label name */

      if (IS_REG(C))
	my_sprintf(state, state->operandBuffer, formatString, fieldC);
      else
	my_sprintf(state, state->operandBuffer, formatString,
		   post_address(state, fieldC));
      break;

    case 5:
      /* LD instruction.  B and C can be regs, or one or both can be limm. */

      CHECK_FIELD_A();
      CHECK_FIELD_B();

      if(FIELDA(state->words[0]) == 62)
	{
	  instrName = "prefetch";
	}



      if (is_limm)
      {
        FIELD_C();
        if (!fieldCisReg)
          fieldC = fieldB;
      }
      else
      {
        CHECK_FIELD_C();
      }
      if (dbg) printf("5:b reg %d %d c reg %d %d  \n",
		      fieldBisReg,fieldB,fieldCisReg,fieldC);
      state->_offset = 0;
      state->_ea_present = 1;
      if (fieldBisReg) state->ea_reg1 = fieldB; else state->_offset += fieldB;
      if (fieldCisReg) state->ea_reg2 = fieldC; else state->_offset += fieldC;
      state->_mem_load = 1;

      directMem     = BIT(state->words[0],15);
      /* - We should display the instruction as decoded, not some censored
	   version of it
         - Scaled index is encoded as 'addrWriteBack', even though it isn't
	   actually doing a write back;  it is legitimate with a LIMM.  */
#if 0
      /* Check if address writeback is allowed before decoding the
	 address writeback field of a load instruction.*/
      if (fieldBisReg && (fieldB != 62))
#endif
        addrWriteBack = BITS(state->words[0],22,23);
      signExtend    = BIT(state->words[0],16);

      write_instr_name();

      /* Check for prefetch or ld 0,...*/
      if(IS_REG(A))
	WRITE_FORMAT_x_COMMA_LB(A);
      else
	{
	  strcat(formatString,"%*");
	  WRITE_FORMAT_LB();
	}


      if (fieldBisReg || fieldB != 0)
	WRITE_FORMAT_x(B);
      else
	fieldB = fieldC;

      WRITE_FORMAT_COMMA_x_RB(C);
      my_sprintf(state, state->operandBuffer, formatString, fieldA, fieldB, fieldC);
      break;

    case 6:
      /* LD instruction. */
      CHECK_FIELD_B();
      CHECK_FIELD_A();
      /* Support for Prefetch */
      /* Fixme :: Check for A700 within this function */

      if(FIELDA(state->words[0]) == 62)
	{
	  instrName = "prefetch";
	}

      fieldC = FIELDD9(state->words[0]);
      fieldCisReg = 0;

      if (dbg) printf_unfiltered("6:b reg %d %d c 0x%x  \n",
				 fieldBisReg,fieldB,fieldC);
      state->_ea_present = 1;
      state->_offset = fieldC;
      state->_mem_load = 1;
      if (fieldBisReg) state->ea_reg1 = fieldB;
      /* field B is either a shimm (same as fieldC) or limm (different!) */
      /* Say ea is not present, so only one of us will do the name lookup. */
      else state->_offset += fieldB, state->_ea_present = 0;

      directMem     = BIT(state->words[0],11);
      /* Check if address writeback is allowed before decoding the
	 address writeback field of a load instruction.*/
      if (fieldBisReg && (fieldB != 62))
        addrWriteBack = BITS(state->words[0],9,10);
      signExtend    = BIT(state->words[0],6);

      write_instr_name();
      if(IS_REG(A))
	WRITE_FORMAT_x_COMMA_LB(A);
      else
	{
	  strcat(formatString,"%*");
	  WRITE_FORMAT_LB();
	}
      if (!fieldBisReg)
	{
	  fieldB = state->_offset;
	  WRITE_FORMAT_x_RB(B);
	}
      else
	{
	  WRITE_FORMAT_x(B);
	  WRITE_FORMAT_COMMA_x_RB(C);
	}
      my_sprintf(state, state->operandBuffer, formatString, fieldA, fieldB, fieldC);
      break;

    case 7:
      /* ST instruction. */
      CHECK_FIELD_B();
      CHECK_FIELD_C();
      state->source_operand.registerNum = fieldC;
      state->sourceType = fieldCisReg ? ARC_REGISTER : ARC_LIMM ;
      fieldA  = FIELDD9(state->words[0]); /* shimm */
      fieldAisReg=0;

      /* [B,A offset] */
      if (dbg) printf_unfiltered("7:b reg %d %x off %x\n",
				 fieldBisReg,fieldB,fieldA);
      state->_ea_present = 1;
      state->_offset = fieldA;
      if (fieldBisReg) state->ea_reg1 = fieldB;
      /*
       * field B is either a shimm (same as fieldA) or limm (different!)
       * Say ea is not present, so only one of us will do the name lookup.
       * (for is_limm we do the name translation here).
       */
      else
	state->_offset += fieldB, state->_ea_present = 0;

      directMem     = BIT(state->words[0],5);
      addrWriteBack = BITS(state->words[0],3,4);

      write_instr_name();
      WRITE_FORMAT_x_COMMA_LB(C);
      if (fieldA == 0)
      {
        WRITE_FORMAT_x_RB(B);
      }
      else
      {
	WRITE_FORMAT_x(B);
        fieldAisReg = 0;
        WRITE_FORMAT_COMMA_x_RB(A);
      }
      my_sprintf(state, state->operandBuffer, formatString, fieldC, fieldB, fieldA);
      break;

    case 8:
      /* SR instruction */
      CHECK_FIELD_B();
      switch (BITS(state->words[0],22,23))
      {
 	case 0:
          if (is_limm)
          {
       	    FIELD_C();
      	    if (!fieldCisReg)
	      fieldC = fieldB;
      	  }
      	  else
	  {
	    CHECK_FIELD_C();
	  }
	  break;
	case 1:
	  FIELD_C();
	  fieldCisReg = 0;
	  break;
	case 2:
	  fieldC = FIELDS(state->words[0]);
	  fieldCisReg = 0;
	  break;
      }

      write_instr_name();
      WRITE_FORMAT_x_COMMA_LB(B);
      /* Try to print B as an aux reg if it is not a core reg. */
      usesAuxReg = 1;
      WRITE_FORMAT_x(C);
      WRITE_FORMAT_RB();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
      break;

    case 9:
      /* BBIT0/BBIT1 Instruction */

      CHECK_FIELD_C();
      if (is_limm || BIT(state->words[0],4))
      {
	fieldCisReg = 0;
        FIELD_B();
      }
      else
      {
        CHECK_FIELD_B();
      }
      fieldAisReg = fieldA = 0;
      fieldA = FIELDS9(state->words[0]);
      fieldA += (addr & ~0x3);
      CHECK_NULLIFY();

      write_instr_name();

      add_target(fieldA);
      state->flow = state->_opcode == op_BLC ? direct_call : direct_jump;
      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(C);
      strcat(formatString, ",%s"); /* address/label name */
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC, post_address(state, fieldA));
      break;

    case 10:
      /* LR instruction */
      CHECK_FIELD_B();
      switch (BITS(state->words[0],22,23))
      {
 	case 0:
	  CHECK_FIELD_C(); break;
	case 1:
	  FIELD_C();
	  fieldCisReg = 0;
	  break;
	case 2:
	  fieldC = FIELDS(state->words[0]);
	  fieldCisReg = 0;
	  break;
      }

      write_instr_name();
      WRITE_FORMAT_x_COMMA_LB(B);
      /* Try to print B as an aux reg if it is not a core reg. */
      usesAuxReg = 1;
      WRITE_FORMAT_x(C);
      WRITE_FORMAT_RB();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
      break;

    case 11:
      /* lp instruction */

      if (BITS(state->words[0],22,23) == 3)
      {
        FIELD_C();
        CHECK_COND();
      }
      else
      {
	fieldC = FIELDS(state->words[0]);
      }

      fieldC = fieldC << 1;
      fieldC += (addr & ~0x3);

      write_instr_name();

      /* This address could be a label we know.  Convert it. */
      add_target(fieldC);
      state->flow = state->_opcode == op_BLC ? direct_call : direct_jump;

      fieldCisReg = 0;
      strcat(formatString, "%s"); /* address/label name */
      my_sprintf(state, state->operandBuffer, formatString, post_address(state, fieldC));
      break;

    case 12:
      /* MOV instruction */
      FIELD_B();
      subopcode = BITS(state->words[0],22,23);
      if (subopcode == 0 || ((subopcode == 3) && (!BIT(state->words[0],5))))
      {
      	CHECK_FIELD_C();
      }
      else if (subopcode == 1 || ((subopcode == 3) && (BIT(state->words[0],5))))
      {
      	FIELD_C();
	fieldCisReg = 0;
      }
      else if (subopcode == 2)
      {
	fieldC = FIELDS(state->words[0]);
	fieldCisReg = 0;
      }
      if (subopcode == 3)
      {
        CHECK_FLAG_COND();
      }
      else
      {
        CHECK_FLAG();
      }

     write_instr_name();
     WRITE_FORMAT_x(B);
     WRITE_FORMAT_COMMA_x(C);
     WRITE_NOP_COMMENT();
     my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
     break;

    case 13:
    /* "B", "BL" instruction */

      fieldA = 0;
      if ((state->_opcode == op_BC  && (BIT(state->words[0],16))) ||
 	  (state->_opcode == op_BLC && (BIT(state->words[0],17))))
      {
	/* unconditional branch s25 or branch and link d25 */
        fieldA = (BITS(state->words[0],0,4)) << 10;
      }
      fieldA |= BITS(state->words[0],6,15);

      if (state->_opcode == op_BLC)
      {
	  /* Fix for Bug #553.  A bl unconditional has only 9 bits in the
	   * least order bits. */
	fieldA = fieldA << 9;
        fieldA |= BITS(state->words[0],18,26);
	fieldA = fieldA << 2;
      }
      else
      {
	fieldA = fieldA << 10;
        fieldA |= BITS(state->words[0],17,26);
	fieldA = fieldA << 1;
      }

      if ((state->_opcode == op_BC  && (BIT(state->words[0],16))) ||
 	  (state->_opcode == op_BLC && (BIT(state->words[0],17))))
	/* unconditional branch s25 or branch and link d25 */
        fieldA = sign_extend(fieldA, 25);
      else
	/* conditional branch s21 or branch and link d21 */
        fieldA = sign_extend(fieldA, 21);

      fieldA += (addr & ~0x3);

      if (BIT(state->words[0],16) && state->_opcode == op_BC)
        CHECK_NULLIFY();
      else
	/* Checking for bl unconditionally FIX For Bug #553 */
	if((state->_opcode == op_BLC && BITS(state->words[0],16,17) == 2 )
	   ||(state->_opcode == op_BC && (BIT(state->words[0],16))))
	    CHECK_NULLIFY();
	  else
	    CHECK_COND_NULLIFY();



      write_instr_name();
      /* This address could be a label we know.  Convert it. */
      add_target(fieldA); /* For debugger. */
      state->flow = state->_opcode == op_BLC /* BL */
          ? direct_call
          : direct_jump;
        /* indirect calls are achieved by "lr blink,[status]; */
        /*      lr dest<- func addr; j [dest]" */

      strcat(formatString, "%s"); /* address/label name */
      my_sprintf(state, state->operandBuffer, formatString, post_address(state, fieldA));
      break;

    case 14:

      /* Extension Instructions */

      FIELD_C_AC();
      FIELD_B_AC();

      write_instr_name();
      if (mul)
      {
        fieldA = fieldAisReg = 0;
	WRITE_FORMAT_x(A);
        WRITE_FORMAT_COMMA_x(B);
      }
      else
        WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(C);
      WRITE_NOP_COMMENT();
      if (mul)
        my_sprintf(state, state->operandBuffer, formatString, 0, fieldB, fieldC);
      else
        my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
      break;

    case 15:

      /* ARCompact 16-bit Load/Add resister-register */

      FIELD_C_AC();
      FIELD_B_AC();
      FIELD_A_AC();

      write_instr_name();

      if (BITS(state->words[0],3,4) != 3)
      {
        WRITE_FORMAT_x_COMMA_LB(A);
	WRITE_FORMAT_x(B);
	WRITE_FORMAT_COMMA_x_RB(C);
      }
      else
      {
        WRITE_FORMAT_x(A);
        WRITE_FORMAT_COMMA_x(B);
        WRITE_FORMAT_COMMA_x(C);
      }
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldA, fieldB, fieldC);
      break;

    case 16:

    /* ARCompact 16-bit Add/Sub/Shift instructions */

      FIELD_C_AC();
      FIELD_B_AC();
      fieldA = FIELDA_AC(state->words[0]);
      fieldAisReg = 0;

      write_instr_name();
      WRITE_FORMAT_x(C);
      WRITE_FORMAT_COMMA_x(B);
      WRITE_FORMAT_COMMA_x(A);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldC, fieldB, fieldA);
      break;

    case 17:

      /* add_s instruction, one Dest/Source can be any of r0 - r63 */

      CHECK_FIELD_H_AC();
      FIELD_B_AC();

      write_instr_name();
      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(B);
      WRITE_FORMAT_COMMA_x(C);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldB, fieldC);
      break;

    case 18:

      /* mov_s/cmp_s instruction, one Dest/Source can be any of r0 - r63 */

      if ((BITS(state->words[0],3,4) == 1) || (BITS(state->words[0],3,4) == 2))
      {
      	CHECK_FIELD_H_AC();
      }
      else if (BITS(state->words[0],3,4) == 3)
      {
	FIELD_H_AC();
      }
      FIELD_B_AC();

      write_instr_name();
      if (BITS(state->words[0],3,4) == 3)
      {
        WRITE_FORMAT_x(C);
        WRITE_FORMAT_COMMA_x(B);
        WRITE_NOP_COMMENT();
        my_sprintf(state, state->operandBuffer, formatString, fieldC, fieldB);
      }
      else
      {
        WRITE_FORMAT_x(B);
        WRITE_FORMAT_COMMA_x(C);
        WRITE_NOP_COMMENT();
        my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
      }
      break;

    case 19:

      /* Stack pointer-based instructions [major opcode 0x18] */

      if (BITS(state->words[0],5,7) == 5)
        fieldA = 28;
      else
      {
        FIELD_B_AC();
	fieldA = fieldB;
      }
      fieldB = 28; /* Field B is the stack pointer register */
      fieldC = (FIELDU_AC(state->words[0])) << 2;
      fieldCisReg = 0;

      write_instr_name();

      switch (BITS(state->words[0],5,7))
      {
	case 0:
	case 1:
	case 2:
	case 3:
          WRITE_FORMAT_x_COMMA_LB(A);
	  WRITE_FORMAT_x(B);
	  WRITE_FORMAT_COMMA_x_RB(C);
	  break;
	case 4:
	case 5:
          WRITE_FORMAT_x(A);
          WRITE_FORMAT_COMMA_x(B);
          WRITE_FORMAT_COMMA_x(C);
	  break;
      }
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldA, fieldB, fieldC);
      break;

    case 20:

      /* gp-relative instructions [major opcode 0x19] */

      fieldA = 0;
      fieldB = 26; /* Field B is the gp register */
      fieldC = FIELDS_AC(state->words[0]);
      switch (BITS(state->words[0],9,10))
      {
	case 0:
	case 3:
	  fieldC = fieldC << 2; break;
	case 2:
	  fieldC = fieldC << 1; break;
      }
      fieldCisReg = 0;

      write_instr_name();

      if (BITS(state->words[0],9,10) != 3)
      {
        WRITE_FORMAT_x_COMMA_LB(A);
	WRITE_FORMAT_x(B);
	WRITE_FORMAT_COMMA_x_RB(C);
      }
      else
      {
        WRITE_FORMAT_x(A);
        WRITE_FORMAT_COMMA_x(B);
        WRITE_FORMAT_COMMA_x(C);
      }
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldA, fieldB, fieldC);
      break;

    case 21:

      /* add/cmp/btst instructions [major opcode 28] */

      FIELD_B_AC();
      if (state->_opcode == op_Su5)
        fieldC = (BITS(state->words[0],0,4));
      else
        fieldC = (BITS(state->words[0],0,6));
      fieldCisReg = 0;
      write_instr_name();

      if (!BIT(state->words[0],7))
      {
        WRITE_FORMAT_x(B);
        WRITE_FORMAT_COMMA_x(B);
        WRITE_FORMAT_COMMA_x(C);
        WRITE_NOP_COMMENT();
        my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldB, fieldC);
      }
      else
      {
        WRITE_FORMAT_x(B);
        WRITE_FORMAT_COMMA_x(C);
        WRITE_NOP_COMMENT();
        my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
      }
      break;

    case 22:

      /* ARCompact 16-bit instructions, General ops/ single ops */

      FIELD_C_AC();
      FIELD_B_AC();

      write_instr_name();

      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(B);
      WRITE_FORMAT_COMMA_x(C);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldB, fieldC);
      break;

    case 23:

      /* Shift/subtract/bit immediate instructions [major opcode 23] */

      FIELD_B_AC();
      fieldC = FIELDU_AC(state->words[0]);
      fieldCisReg = 0;
      write_instr_name();
      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(B);
      WRITE_FORMAT_COMMA_x(C);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldB, fieldC);
      break;

    case 24:

      /* ARCompact 16-bit Branch conditionally */

      if (state->_opcode == op_BL_S)
      {
        fieldA = (BITS(state->words[0],0,10)) << 2;
	fieldA = sign_extend(fieldA, 13);
      }
      else if (BITS(state->words[0],9,10) != 3)
      {
        fieldA = (BITS(state->words[0],0,8)) << 1;
	fieldA = sign_extend(fieldA, 10);
      }
      else
      {
        fieldA = (BITS(state->words[0],0,5)) << 1;
	fieldA = sign_extend(fieldA, 7);
      }
      fieldA += (addr & ~0x3);

      write_instr_name();
      /* This address could be a label we know.  Convert it. */
      add_target(fieldA); /* For debugger. */
      state->flow = state->_opcode == op_BL_S /* BL */
          ? direct_call
          : direct_jump;
        /* indirect calls are achieved by "lr blink,[status]; */
        /*      lr dest<- func addr; j [dest]" */

      strcat(formatString, "%s"); /* address/label name */
      my_sprintf(state, state->operandBuffer, formatString, post_address(state, fieldA));
      break;

    case 25:

      /* ARCompact 16-bit Branch conditionally on reg z/nz */

      FIELD_B_AC();
      fieldC = (BITS(state->words[0],0,6)) << 1;
      fieldC = sign_extend (fieldC, 8);

      fieldC += (addr & ~0x3);
      fieldA = fieldAisReg = fieldCisReg = 0;

      write_instr_name();
      /* This address could be a label we know.  Convert it. */
      add_target(fieldC); /* For debugger. */
      state->flow = direct_jump;

      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(A);
      strcat(formatString, ",%s"); /* address/label name */
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldA, post_address(state, fieldC));
      break;

    case 26:

      /* Zero operand Instructions */

      write_instr_name();
      state->operandBuffer[0] = '\0';
      break;

    case 27:

      /* j_s instruction */

      FIELD_B_AC();
      write_instr_name();
      strcat(formatString,"[%r]");
      my_sprintf(state, state->operandBuffer, formatString, fieldB);
      break;

    case 28:

      /* Load/Store with offset */

      FIELD_C_AC();
      FIELD_B_AC();
      switch (state->_opcode)
      {
	case op_LD_S :
	case op_ST_S :
      	  fieldA = (FIELDU_AC(state->words[0])) << 2;
	  break;
	case op_LDB_S :
	case op_STB_S :
      	  fieldA = (FIELDU_AC(state->words[0]));
	  break;
	case op_LDW_S :
	case op_LDWX_S :
	case op_STW_S :
      	  fieldA = (FIELDU_AC(state->words[0])) << 1;
	  break;
      }
      fieldAisReg = 0;

      write_instr_name();

      WRITE_FORMAT_x_COMMA_LB(C);
      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(A);
      WRITE_FORMAT_RB();
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldC, fieldB, fieldA);
      break;

    case 29:

      /* Load pc-relative */

      FIELD_B_AC();
      fieldC = 63;
      fieldA = (BITS(state->words[0],0,7)) << 2;
      fieldAisReg = 0;

      write_instr_name();

      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(C);
      WRITE_FORMAT_COMMA_x(A);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC, fieldA);
      break;

    case 30:

      /* mov immediate */

      FIELD_B_AC();
      fieldC = (BITS(state->words[0],0,7));
      fieldCisReg = 0;

      write_instr_name();

      WRITE_FORMAT_x(B);
      WRITE_FORMAT_COMMA_x(C);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
      break;

    case 31:

      /* push/pop instructions */

      if (BITS(state->words[0],0,4) == 1)
      {
        FIELD_B_AC();
      }
      else if (BITS(state->words[0],0,4) == 17)
	fieldB = 31;

      write_instr_name();

      WRITE_FORMAT_x(B);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldB);
      break;

    case 32:

      /* Single operand instruction */

      if (!BITS(state->words[0],22,23))
      {
        CHECK_FIELD_C();
      }
      else
      {
	FIELD_C();
	fieldCisReg = 0;
      }

      write_instr_name();

      if (!fieldC)
        state->operandBuffer[0] = '\0';
      else
      {
        WRITE_FORMAT_x(C);
        WRITE_NOP_COMMENT();
        my_sprintf(state, state->operandBuffer, formatString, fieldC);
      }
      break;

  case 33:
    /* For trap_s and the class of instructions that have
       unsigned 6 bits in the fields B and C in A700 16 bit
       instructions */
    fieldC = FIELDC_AC(state->words[0]);
    fieldB = FIELDB_AC(state->words[0]);
    fieldCisReg = 0;
    fieldBisReg = 0;
    write_instr_name();
    strcat(formatString,"%d");
    my_sprintf(state,state->operandBuffer,formatString, ((fieldB << 3) | fieldC));
    break;

  case 34:
    /* For ex.di and its class of instructions within op_major_4
       This class is different from the normal set of instructions
       in op_major_4 because this uses bit 15 as .di and the second
       operand is actually a memory operand.
       This is of the class
       <op>.<di> b,[c] and <op>.<di> b,[limm]
    */


    /* field C is either a register or limm (different!) */

    CHECK_FIELD_C();
    FIELD_B();
    directMem = BIT(state->words[0],15);


    if (BITS(state->words[0],22,23) == 1 )
      fieldCisReg = 0;
    if (fieldCisReg)
      state->ea_reg1 = fieldC;

    write_instr_name();
    WRITE_FORMAT_x_COMMA_LB(B);

    WRITE_FORMAT_x_RB(C);

    WRITE_NOP_COMMENT();
    my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
    break;

  case 35:

    /* sub_s.ne instruction */

    FIELD_B_AC();
    write_instr_name();
    strcat(formatString,"%r,%r,%r");
    my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldB, fieldB);
    break;

  case 36:

    FIELD_B_AC();

    write_instr_name();

    WRITE_FORMAT_x(B);
    WRITE_NOP_COMMENT();
    my_sprintf(state, state->operandBuffer, formatString, fieldB);

    break;
    
  /* START ARC LOCAL */
  case 44:
      /* rtsc instruction */
      /* The source operand has no use.  */
      fieldB = fieldBisReg = 0;

      write_instr_name();
      WRITE_FORMAT_x(A);
      WRITE_FORMAT_COMMA_x(B);
      WRITE_NOP_COMMENT();
      my_sprintf(state, state->operandBuffer, formatString, fieldA,
		 fieldB);
      break;
  /* END ARC LOCAL */

    /*******SIMD instructions decoding follows*************/
  case 37:
  case 39:
  case 41:
    /*fieldA is vr register
      fieldB is I register
      fieldC is a constant
      %*,[%(,%<]
      or
      %*,%(,%<
      or
      %*,%(,%u
    */

    CHECK_FIELD_A();

    CHECK_FIELD_B();
    if (decodingClass == 41)
       {
	 FIELD_C();
       }
    else
      {
	FIELD_U8();

	if (simd_scale_u8>0)
	  fieldC = fieldC << simd_scale_u8;
      }

    fieldCisReg = 0;

    write_instr_name();
    (decodingClass == 37 ? WRITE_FORMAT_x_COMMA_LB(A) :
                           WRITE_FORMAT_x_COMMA(A));
    WRITE_FORMAT_x_COMMA(B);
    (decodingClass == 37 ?  WRITE_FORMAT_x_RB(C):
                            WRITE_FORMAT_x(C));
    WRITE_NOP_COMMENT();
    my_sprintf(state,state->operandBuffer, formatString, fieldA, fieldB, fieldC);


    break;
  case 38:
    /* fieldA is a vr register
       fieldB is a ARC700 basecase register.
       %*,[%b]
    */
    CHECK_FIELD_A();
    CHECK_FIELD_B();

    write_instr_name();
    WRITE_FORMAT_x_COMMA_LB(A);
    WRITE_FORMAT_x_RB(B);
    WRITE_NOP_COMMENT();
    my_sprintf(state,state->operandBuffer, formatString, fieldA, fieldB);

    break;
  case 40:
    /* fieldB & fieldC are vr registers
       %(,%)
       or
       %B,%C
       or
       %(,%C
    */
    CHECK_FIELD_B();
    CHECK_FIELD_C();

    write_instr_name();
    WRITE_FORMAT_x(B);
    WRITE_FORMAT_COMMA_x(C);
    my_sprintf(state, state->operandBuffer, formatString, fieldB, fieldC);
    break;

  case 42:
    /* fieldA, fieldB, fieldC are all vr registers
       %*, %(, %) */
    CHECK_FIELD_A();
    CHECK_FIELD_B();
    FIELD_C();

    write_instr_name();
    WRITE_FORMAT_x(A);
    WRITE_FORMAT_COMMA_x(B);
    WRITE_FORMAT_COMMA_x(C);
    my_sprintf(state, state->operandBuffer, formatString, fieldA, fieldB, fieldC);
    break;

  case 43:
    /* Only fieldC is a register
     %C*/
    CHECK_FIELD_C();

    if (BITS(state->words[0], 17, 23) == 55)
      fieldCisReg = 0;

    write_instr_name();
    WRITE_FORMAT_x(C);
    my_sprintf(state, state->operandBuffer, formatString, fieldC);
    break;

    /***************SIMD decoding ends*********************/
  default:
    mwerror(state, "Bad decoding class in ARC disassembler");
    break;
  }

  state->_cond = cond;
  return state->instructionLen = offset;
}


/*
 * _coreRegName - Returns the name the user specified core extension
 *                register.
 */
static const char *
_coreRegName
(
 void *_this ATTRIBUTE_UNUSED, /* C++ this pointer */
 int v                         /* Register value */
 )
{
  return arcExtMap_coreRegName(v);
}

/*
 * _auxRegName - Returns the name the user specified AUX extension
 *               register.
 */
static const char *
_auxRegName
( void *_this ATTRIBUTE_UNUSED, /* C++ this pointer */
  int v                         /* Register value */
  )
{
  return arcExtMap_auxRegName(v);
}


/*
 * _condCodeName - Returns the name the user specified condition code
 *                 name.
 */
static const char *
_condCodeName
(
 void *_this ATTRIBUTE_UNUSED, /* C++ this pointer */
 int v                         /* Register value */
 )
{
  return arcExtMap_condCodeName(v);
}


/*
 * _instName - Returns the name the user specified extension instruction.
 */
static const char *
_instName
(
 void *_this ATTRIBUTE_UNUSED, /* C++ this pointer */
 int op1,                      /* major opcode value */
 int op2,                      /* minor opcode value */
 int *flags                    /* instruction flags */
 )
{
  return arcExtMap_instName(op1, op2, flags);
}

static void
parse_disassembler_options (char *options)
{
  const char *p; 
  for (p = options; p != NULL; )
    {
	  if (CONST_STRNEQ (p, "simd"))
	    {
	      enable_simd = 1;
	    }
	  if (CONST_STRNEQ (p, "insn-stream"))
	    {
		  enable_insn_stream = 1;
	    }
	  
	  p = strchr (p, ',');
	  
	  if (p != NULL)
		p++;
	  
    }
	
}

/* ARCompact_decodeInstr - Decode an ARCompact instruction returning the
   size of the instruction in bytes or zero if unrecognized.  */
int
ARCompact_decodeInstr (bfd_vma           address,    /* Address of this instruction.  */
                       disassemble_info* info)
{
  int status;
  bfd_byte buffer[4];
  struct arcDisState s;	/* ARC Disassembler state */
  void *stream = info->stream; /* output stream */
  fprintf_ftype func = info->fprintf_func;
  int bytes;
  int lowbyte, highbyte;
  char buf[256];

  if (info->disassembler_options)
    {
      parse_disassembler_options (info->disassembler_options);

      /* To avoid repeated parsing of these options, we remove them here.  */
      info->disassembler_options = NULL;
    }

  lowbyte = ((info->endian == BFD_ENDIAN_LITTLE) ? 1 : 0);
  highbyte = ((info->endian == BFD_ENDIAN_LITTLE) ? 0 : 1);

  memset(&s, 0, sizeof(struct arcDisState));

  /* read first instruction */
  status = (*info->read_memory_func) (address, buffer, 2, info);

  if (status != 0)
    {
      (*info->memory_error_func) (status, address, info);
      return -1;
    }

  if (((buffer[lowbyte] & 0xf8) > 0x38) && ((buffer[lowbyte] & 0xf8) != 0x48))
  {
    s.instructionLen = 2;
    s.words[0] = (buffer[lowbyte] << 8) | buffer[highbyte];
    status = (*info->read_memory_func) (address + 2, buffer, 4, info);
    if (info->endian == BFD_ENDIAN_LITTLE)
      s.words[1] = bfd_getl32(buffer);
    else
      s.words[1] = bfd_getb32(buffer);
  }
  else
  {
    s.instructionLen = 4;
    status = (*info->read_memory_func) (address + 2, &buffer[2], 2, info);
    if (status != 0)
    {
      (*info->memory_error_func) (status, address + 2, info);
      return -1;
    }
    if (info->endian == BFD_ENDIAN_LITTLE)
      s.words[0] = bfd_getl32(buffer);
    else
      s.words[0] = bfd_getb32(buffer);

    /* always read second word in case of limm */
    /* we ignore the result since last insn may not have a limm */
    status = (*info->read_memory_func) (address + 4, buffer, 4, info);
    if (info->endian == BFD_ENDIAN_LITTLE)
      s.words[1] = bfd_getl32(buffer);
    else
      s.words[1] = bfd_getb32(buffer);
  }

  s._this = &s;
  s.coreRegName = _coreRegName;
  s.auxRegName = _auxRegName;
  s.condCodeName = _condCodeName;
  s.instName = _instName;

  /* disassemble */
  bytes = dsmOneArcInst(address, (void *)&s, info);

  /* display the disassembled instruction */
  {
    char* instr   = s.instrBuffer;
    char* operand = s.operandBuffer;
    char* space   = strchr(instr, ' ');

    if (enable_insn_stream)
      {
        /* Show instruction stream from MSB to LSB*/

        if (s.instructionLen == 2)
          (*func) (stream, "    %04x ", (unsigned int) s.words[0]);
        else
          (*func) (stream, "%08x ",     (unsigned int) s.words[0]);

        (*func) (stream, "    ");
      }

    /* if the operand is actually in the instruction buffer */
    if ((space != NULL) && (operand[0] == '\0'))
      {
          *space  = '\0';
          operand = space + 1;
      }

    (*func) (stream, "%s ", instr);

    if (__TRANSLATION_REQUIRED(s))
      {
        bfd_vma addr;
        char *tmpBuffer;
        int i = 1;

        if (operand[0] != '@')
        {
          /* Branch instruction with 3 operands, Translation is required
             only for the third operand. Print the first 2 operands */
          strncpy(buf, operand, sizeof (buf) - 1);
          tmpBuffer = strtok(buf,"@");
          (*func) (stream, "%s", tmpBuffer);
          i = strlen(tmpBuffer) + 1;
        }

        addr = s.addresses[operand[i] - '0'];
        (*info->print_address_func) ((bfd_vma) addr, info);
        //(*func) (stream, "\n");
      }
    else
      (*func) (stream, "%s", operand);
  }

  /* We print max bytes for instruction */
  info->bytes_per_line = 8;
  
  return bytes; //s.instructionLen;
}

/*
 * This function is the same as decodeInstr except that this function
 * returns a struct arcDisState instead of the instruction length.
 *
 * This struct contains information useful to the debugger.
 */
struct arcDisState
arcAnalyzeInstr
(
 bfd_vma           address,		/* Address of this instruction */
 disassemble_info* info
 )
{
  int status;
  bfd_byte buffer[4];
  struct arcDisState s;	/* ARC Disassembler state */
  int bytes;
  int lowbyte, highbyte;

  lowbyte = ((info->endian == BFD_ENDIAN_LITTLE) ? 1 : 0);
  highbyte = ((info->endian == BFD_ENDIAN_LITTLE) ? 0 : 1);

  memset(&s, 0, sizeof(struct arcDisState));

  /* read first instruction */
  status = (*info->read_memory_func) (address, buffer, 2, info);

  if (status != 0)
    {
      (*info->memory_error_func) (status, address, info);
      s.instructionLen = -1;
      return s;
    }

  if (((buffer[lowbyte] & 0xf8) > 0x38) && ((buffer[lowbyte] & 0xf8) != 0x48))
  {
    s.instructionLen = 2;
    s.words[0] = (buffer[lowbyte] << 8) | buffer[highbyte];
    status = (*info->read_memory_func) (address + 2, buffer, 4, info);
    if (info->endian == BFD_ENDIAN_LITTLE)
      s.words[1] = bfd_getl32(buffer);
    else
      s.words[1] = bfd_getb32(buffer);
  }
  else
  {
    s.instructionLen = 4;
    status = (*info->read_memory_func) (address + 2, &buffer[2], 2, info);
    if (status != 0)
    {
      (*info->memory_error_func) (status, address + 2, info);
      s.instructionLen = -1;
      return s;
    }
    if (info->endian == BFD_ENDIAN_LITTLE)
      s.words[0] = bfd_getl32(buffer);
    else
      s.words[0] = bfd_getb32(buffer);

    /* always read second word in case of limm */
    /* we ignore the result since last insn may not have a limm */
    status = (*info->read_memory_func) (address + 4, buffer, 4, info);
    if (info->endian == BFD_ENDIAN_LITTLE)
      s.words[1] = bfd_getl32(buffer);
    else
      s.words[1] = bfd_getb32(buffer);
  }

  s._this = &s;
  s.coreRegName = _coreRegName;
  s.auxRegName = _auxRegName;
  s.condCodeName = _condCodeName;
  s.instName = _instName;

  /* disassemble */
  bytes = dsmOneArcInst(address, (void *)&s, info);
  /* We print max bytes for instruction */
  info->bytes_per_line = bytes;
  return s;
}


void
arc_print_disassembler_options (FILE *stream)
{
  fprintf (stream, "\n\
 ARC-specific disassembler options:\n\
 use with the -M switch, with options separated by commas\n\n");

  fprintf (stream, "  insn-stream    Show the instruction byte stream from most\n");
  fprintf (stream, "                 significant byte to least significant byte (excluding LIMM).\n");
  fprintf (stream, "                 This option is useful for viewing the actual encoding of instructions.\n");
  
  fprintf (stream, "  simd           Enable SIMD instructions disassembly.\n\n");
}
