/* $VER: m68k_disasm.c V0.4 (13.04.2002)
 *
 * Disassembler module for the M680x0 microprocessor family
 * Copyright (c) 1999-2002  Frank Wille
 * Based on NetBSD's m68k/m68k/db_disasm.c by Christian E. Hopps.
 *
 * Copyright (c) 1994 Christian E. Hopps
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Christian E. Hopps.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * v0.4  (19.04.2002) phx
 *       Fixed size extension for CAS.
 *       S/D-rounding precision 040FPU-instructions have to be recognized
 *       on bit 6 of the extension word, not bit 7! Fixed some other
 *       bugs with FDxxx/FSxxx handling.
 *       FETOXM1 was missing.
 *       Fixed displaying of destination address for word-branches.
 *       Wrong k-factor for FMOVE.P FPn,<ea>{#k}.
 * v0.3  (07.03.2001) phx
 *       Replaced "UNKNOWN COPROC INSTR" by "linef", because opcodes should
 *       be limited to 15 characters.
 *       Little-endian support.
 * v0.2  (27.06.2000) phx
 *       PC-relative displacements are printed as destination address (like
 *       branch destinations). Extended instructions, like FPU-
 *       instructions had wrong PC-relative dest. address - fixed.
 *       CMPA has to be checked before CMPM, to be correctly recognized.
 *       Missing instructions implemented: PVALID, CINV, CPUSH.
 *       Fixed size-extension for FPU instructions.
 *       Dest. register of FMOVECR wasn't printed.
 *       MMU FC-field: sfc and dfc were exchanged, print '#' before an
 *       immediate FC (I'm not sure if this is the right way).
 *       EA-field of PLOAD wasn't printed.
 *       Disassembler printed FPU condition codes intead of MMU condition
 *       codes for PDBcc, PScc and PTRAPcc.
 * v0.1  (26.06.2000) phx
 *       Made the interface compatible to PPC disassembler module.
 *       Branch destinations are printed as real address.
 *       Fixed a lot of bugs, e.g. in ADDA/SUBA, ABCD, SBCD recognition,
 *       SWAP, PACK, CMPM, SUBX, CALLM were missing.
 *       Included missing Motorola addressing mode syntax for UNPK, PACK,
 *       ABCD, SBCD, MOVE16, MOVEP, CAS2, ADDX.
 *       Most instructions are (hopefully) printed in Motorola syntax
 *       now, which means "move.b" instead of "movb".
 * v0.0  (06.03.1999) phx
 *       File created, based on NetBSD's m68k/m68k/db_disasm.c by
 *       Christian E. Hopps.
 */

#ifndef R_IPI
#define R_IPI
#endif

#define M68K_DISASM_C
#include <stdio.h>
#include <string.h>
#include "m68k_disasm.h"

static void get_modregstr (dis_buffer_t *, int, int, int, int);
static void get_immed (dis_buffer_t *, int);
static void get_fpustdGEN (dis_buffer_t *, u_short, const char *);
static void addstr (dis_buffer_t *, const char *s);
static void prints (dis_buffer_t *, int, int);
static void printu (dis_buffer_t *, u_int, int);
static void prints_wb (dis_buffer_t *, int, int, int);
static void printu_wb (dis_buffer_t *, u_int, int, int);
static void prints_bf (dis_buffer_t *, int, int, int);
static void printu_bf (dis_buffer_t *, u_int, int, int);
static void iaddstr (dis_buffer_t *, const char *s);
//static void iprints (dis_buffer_t *, int, int);
static void iprintu (dis_buffer_t *, u_int, int);
//static void iprints_wb (dis_buffer_t *, int, int, int);
static void iprintu_wb (dis_buffer_t *, u_int, int, int);
static void make_cond (dis_buffer_t *, int , char *);
static void print_fcond (dis_buffer_t *, char);
static void print_mcond (dis_buffer_t *, char);
static void print_disp (dis_buffer_t *, int, int, int, int);
static void print_addr (dis_buffer_t *, u_long);
static void print_reglist (dis_buffer_t *, int, u_short);
static void print_freglist (dis_buffer_t *, int, u_short, int);
static void print_fcode (dis_buffer_t *, u_short);
static void print_AxAyPredec(dis_buffer_t *, u_short);
static void print_DxDy(dis_buffer_t *, u_short);
static void print_RnPlus(dis_buffer_t *, u_short, int, int, int);

/* groups */
static void opcode_bitmanip (dis_buffer_t *, u_short);
static void opcode_move (dis_buffer_t *, u_short);
static void opcode_misc (dis_buffer_t *, u_short);
static void opcode_branch (dis_buffer_t *, u_short);
static void opcode_coproc (dis_buffer_t *, u_short);
static void opcode_0101 (dis_buffer_t *, u_short);
static void opcode_1000 (dis_buffer_t *, u_short);
static void opcode_addsub (dis_buffer_t *, u_short);
static void opcode_1010 (dis_buffer_t *, u_short);
static void opcode_1011 (dis_buffer_t *, u_short);
static void opcode_1100 (dis_buffer_t *, u_short);
static void opcode_1110 (dis_buffer_t *, u_short);
static void opcode_fpu (dis_buffer_t *, u_short);
static void opcode_mmu (dis_buffer_t *, u_short);
static void opcode_mmu040 (dis_buffer_t *, u_short);
static void opcode_move16 (dis_buffer_t *, u_short);

/* subs of groups */
static void opcode_movec (dis_buffer_t *, u_short);
static void opcode_divmul (dis_buffer_t *, u_short);
static void opcode_movem (dis_buffer_t *, u_short);
static void opcode_fmove_ext (dis_buffer_t *, u_short, u_short);
static void opcode_pmove (dis_buffer_t *, u_short, u_short);
static void opcode_pflush (dis_buffer_t *, u_short, u_short);

#define addchar(ch) (*dbuf->casm++ = ch)
#define iaddchar(ch) (*dbuf->cinfo++ = ch)

typedef void dis_func_t (dis_buffer_t *, u_short);

static dis_func_t *const opcode_map[16] = {
  opcode_bitmanip, opcode_move, opcode_move, opcode_move,
  opcode_misc, opcode_0101, opcode_branch, opcode_move,
  opcode_1000, opcode_addsub, opcode_1010, opcode_1011,
  opcode_1100, opcode_addsub, opcode_1110, opcode_coproc
};

static const char *const cc_table[16] = {
  "t", "f", "hi", "ls",
  "cc", "cs", "ne", "eq",
  "vc", "vs", "pl", "mi",
  "ge", "lt", "gt", "le"
};

static const char *const fpcc_table[32] = {
  "f", "eq", "ogt", "oge", "olt", "ole", "ogl", "or",
  "un", "ueq", "ugt", "uge", "ult", "ule", "ne", "t",
  "sf", "seq", "gt", "ge", "lt", "le", "gl", "gle",
  "ngle", "ngl", "nle", "nlt", "nge", "ngt", "sne", "st"
};

static const char *const mmcc_table[16] = {
  "bs", "bc", "ls", "lc", "ss", "sc", "as", "ac",
  "ws", "wc", "is", "ic", "gs", "gc", "cs", "cc"
};

static const char *const aregs[8] = {
  "a0","a1","a2","a3","a4","a5","a6","sp"
};
static const char *const dregs[8] = {
  "d0","d1","d2","d3","d4","d5","d6","d7"
};
static const char *const fpregs[8] = {
  "fp0","fp1","fp2","fp3","fp4","fp5","fp6","fp7"
};
static const char *const fpcregs[3] = {
  "fpiar", "fpsr", "fpcr"
};

static char asm_buffer[256];
static char info_buffer[256];
static int db_radix = 16;

static inline u_short read16(short *p) {
  return ((u_short)*(u_char *)p)<<8 | (u_short)*((u_char *)p+1);
}


static inline u_long read32(short *p) {
  return ((u_long)*(u_char *)p)<<24 | ((u_long)*((u_char *)p+1))<<16 |
         ((u_long)*((u_char *)p+2))<<8 | (u_long)*((u_char *)p+3);
}


R_IPI m68k_word *M68k_Disassemble(struct DisasmPara_68k *dp)
/* Disassemble M68k instruction and return a pointer to the next */
/* instruction, or NULL if an error occurred. */
{
  u_short opc;
  dis_func_t *func;
  dis_buffer_t dbuf;
  char *s;

  if (dp->opcode==NULL || dp->operands==NULL)
    return (NULL);  /* no buffers */

  dbuf.dp = dp;
  dbuf.casm = dbuf.dasm = asm_buffer;
  dbuf.cinfo = dbuf.info = info_buffer;
  dbuf.used = 0;
  dbuf.val = (short *)dp->instr;
  dbuf.sval = (short *)dp->iaddr;
  dbuf.mit = 0;
  dbuf.dasm[0] = 0;
  dbuf.info[0] = 0;
  dp->type = dp->flags = 0;
  dp->displacement = 0;
  db_radix = dp->radix;

  opc = read16(dbuf.val);
  dbuf.used++;
  
  func = opcode_map[OPCODE_MAP(opc)];
  func(&dbuf, opc);

  if ((s = strchr(asm_buffer,'\t'))) {
    *s++ = '\0';
    strcpy(dp->operands,s);
  }
  else {
    *dp->operands = '\0';
  }
  strcpy(dp->opcode,asm_buffer);

#if 0  /* Symbol information ? */
  printf("\t%s",asm_buffer);
  if (info_buffer[0]) 
    printf("\t[%s]\n",info_buffer);
  else
    printf("\n");
#endif

  return (dp->instr + dbuf.used);
}


/*
 * Bit manipulation/MOVEP/Immediate.
 */
static void opcode_bitmanip(dis_buffer_t *dbuf, u_short opc)
{
  char *tmp;
  u_short ext;
  int sz;

  tmp = NULL;
  
  switch (opc) {
  case ANDITOCCR_INST:
    tmp = "andi.b\t";
    break;
  case ANDIROSR_INST:
    tmp = "andi.w\t";
    break;
  case EORITOCCR_INST:
    tmp = "eori.b\t";
    break;
  case EORITOSR_INST:
    tmp = "eori.w\t";
    break;
  case ORITOCCR_INST:
    tmp = "ori.b\t";
    break;
  case ORITOSR_INST:
    tmp = "ori.w\t";
    break;
  }
  if (tmp) {
    addstr(dbuf, tmp);
    if (ISBITSET(opc,6)) {
      get_immed(dbuf, SIZE_WORD);
      addstr(dbuf, ",sr");
    } else {
      get_immed(dbuf, SIZE_BYTE);
      addstr(dbuf, ",ccr");
    }
    return;
  }

  if (IS_INST(RTM,opc)) {
    addstr(dbuf, "rtm\t");
    if (ISBITSET(opc,3))
      PRINT_AREG(dbuf, BITFIELD(opc,2,0));
    else
      PRINT_DREG(dbuf, BITFIELD(opc,2,0));
    return;
  }

  if (IS_INST(MOVEP,opc)) {
    addstr(dbuf, "movep.");
    if (ISBITSET(opc,6)) 
      addchar('l');
    else
      addchar('w');
    addchar('\t');
    if (ISBITSET(opc,7)) {
      PRINT_DREG(dbuf, BITFIELD(opc, 11, 9));
      addchar(',');
    }
    if (dbuf->mit) {  /*phx*/
      PRINT_AREG(dbuf, BITFIELD(opc, 2, 0));
      addchar('@');
      addchar('(');
      print_disp(dbuf, read16(dbuf->val + 1), SIZE_WORD, BITFIELD(opc, 2, 0),0);
      addchar(')');
    } else {
      print_disp(dbuf, read16(dbuf->val + 1), SIZE_WORD, BITFIELD(opc, 2, 0),0);
      addchar('(');
      PRINT_AREG(dbuf, BITFIELD(opc, 2, 0));
      addchar(')');
    }
    dbuf->used++;
    if (!ISBITSET(opc,7)) {
      addchar(',');
      PRINT_DREG(dbuf, BITFIELD(opc, 11, 9));
    }
    *dbuf->casm = 0;
    return;
  }

  switch (opc & BCHGD_MASK) {
  case BCHGD_INST:
    tmp = "bchg\t";
    break;
  case BCLRD_INST:
    tmp = "bclr\t";
    break;
  case BSETD_INST:
    tmp = "bset\t";
    break;
  case BTSTD_INST:
    tmp = "btst\t";
    break;
  }
  if (tmp) {
    addstr(dbuf, tmp);
    PRINT_DREG(dbuf, BITFIELD(opc,11,9));
    addchar(',');
    get_modregstr(dbuf,5,GETMOD_BEFORE,0,0);
    return;
  }

  switch (opc & BCHGS_MASK) {
  case BCHGS_INST:
    tmp = "bchg\t";
    break;
  case BCLRS_INST:
    tmp = "bclr\t";
    break;
  case BSETS_INST:
    tmp = "bset\t";
    break;
  case BTSTS_INST:
    tmp = "btst\t";
    break;
  }
  if (tmp) {
    addstr(dbuf, tmp);
    get_immed(dbuf, SIZE_BYTE);
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 1);
    return;
  }

  if (IS_INST(CALLM,opc)) {  /*phx*/
    addstr(dbuf, "callm\t");
    get_immed(dbuf, SIZE_BYTE);
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 1);
    return;
  }

  if (IS_INST(CAS2,opc)) {
    u_short ext2;

    ext = read16(dbuf->val + 1);
    ext2 = read16(dbuf->val + 2);
    dbuf->used += 2;
    
    if (ISBITSET(opc,9))
      addstr(dbuf, "cas2.l\t");
    else
      addstr(dbuf, "cas2.w\t");

    PRINT_DREG(dbuf, BITFIELD(ext,2,0));
    addchar(':');
    PRINT_DREG(dbuf, BITFIELD(ext2,2,0));
    addchar(',');
    
    PRINT_DREG(dbuf, BITFIELD(ext,8,6));
    addchar(':');
    PRINT_DREG(dbuf, BITFIELD(ext2,8,6));
    addchar(',');
    
    print_RnPlus(dbuf,ext,ISBITSET(ext,15),14,0);
    addchar(':');
    print_RnPlus(dbuf,ext2,ISBITSET(ext2,15),14,0);
    return;
  }

  switch (opc & CAS_MASK) {
  case CAS_INST:
    ext = read16(dbuf->val + 1);
    dbuf->used++;

    addstr(dbuf,"cas.");
    sz = BITFIELD(opc,10,9);
    if (sz == 1) {
      sz = SIZE_BYTE;
      addchar('b');
    } else if (sz == 2) {
      sz = SIZE_WORD;
      addchar('w');
    } else {
      sz = SIZE_LONG;
      addchar('l');
    }
    addchar('\t');
    PRINT_DREG(dbuf, BITFIELD(ext, 2, 0));
    addchar(',');
    PRINT_DREG(dbuf, BITFIELD(ext, 8, 6));
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 1);
    return;
  case CHK2_INST:
  /* case CMP2_INST: */
    ext = read16(dbuf->val + 1);
    dbuf->used++;

    if (ISBITSET(ext,11)) 
      addstr(dbuf,"chk2.");
    else 
      addstr(dbuf,"cmp2.");
      
    sz = BITFIELD(opc,10,9);
    if (sz == 0) {
      sz = SIZE_BYTE;
      addchar('b');
    } else if (sz == 1) {
      sz = SIZE_WORD;
      addchar('w');
    } else {
      sz = SIZE_LONG;
      addchar('l');
    }
    addchar('\t');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 1);

    addchar(',');
    if(ISBITSET(ext,15))
      PRINT_AREG(dbuf, BITFIELD(ext, 14, 12));
    else
      PRINT_DREG(dbuf, BITFIELD(ext, 14, 12));
    return;
  }
  
  switch (ADDI_MASK & opc) {
  case MOVES_INST:
    addstr(dbuf, "moves.");
    sz = BITFIELD(opc,7,6);
    if (sz == 0) {
      addchar('b');
      sz = SIZE_BYTE;
    } else if (sz == 1) {
      addchar('w');
      sz = SIZE_WORD;
    } else {
      addchar ('l');
      sz = SIZE_LONG;
    }
    addchar('\t');
    
    ext = read16(dbuf->val + 1);
    dbuf->used++;
    
    if (ISBITSET(ext,11)) {
      if (ISBITSET(ext,15)) 
        PRINT_AREG(dbuf,BITFIELD(ext,14,12));
      else
        PRINT_DREG(dbuf,BITFIELD(ext,14,12));
      addchar(',');
      get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 1);
    } else {
      get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 1);
      addchar(',');
      if (ISBITSET(ext,15)) 
        PRINT_AREG(dbuf,BITFIELD(ext,14,12));
      else
        PRINT_DREG(dbuf,BITFIELD(ext,14,12));
    }     
    return;
  case ADDI_INST:
    tmp = "addi";
    break;
  case ANDI_INST:
    tmp = "andi";
    break;
  case CMPI_INST:
    tmp = "cmpi";
    break;
  case EORI_INST:
    tmp = "eori";
    break;
  case ORI_INST:
    tmp = "ori";
    break;
  case SUBI_INST:
    tmp = "subi";
    break;
  }
  if (tmp) {
    addstr(dbuf, tmp);
    addchar('.');
    sz = BITFIELD(opc,7,6);
    switch (sz) {
    case 0:
      addchar('b');
      addchar('\t');
      sz = SIZE_BYTE;
      break;
    case 1:
      addchar('w');
      addchar('\t');
      sz = SIZE_WORD;
      break;
    case 2:
      addchar ('l');
      addchar('\t');
      get_immed(dbuf,SIZE_LONG);
      addchar(',');
      get_modregstr(dbuf,5,GETMOD_BEFORE,SIZE_LONG,2);
      return;
    }
    get_immed(dbuf,sz);
    addchar(',');
    get_modregstr(dbuf,5,GETMOD_BEFORE,sz,1);
    return;
  }
}


/*
 * move byte/word/long and q
 * 00xx (01==.b 10==.l 11==.w) and 0111(Q)
 */
static void opcode_move(dis_buffer_t *dbuf, u_short opc)
{
  int sz, lused;

  sz = 0;
  switch (OPCODE_MAP(opc)) {
  case 0x1:   /* move.b */
    sz = SIZE_BYTE;
    break;
  case 0x3:   /* move.w */
    sz = SIZE_WORD;
    break;
  case 0x2:   /* move.l */
    sz = SIZE_LONG;
    break;
  case 0x7:   /* moveq */
    addstr(dbuf, "moveq\t#");
    prints_bf(dbuf, opc, 7, 0);
    addchar(',');
    PRINT_DREG(dbuf,BITFIELD(opc,11,9));
    return; 
  }
  addstr(dbuf, "move");

  if (BITFIELD(opc,8,6) == AR_DIR) 
    addchar('a');

  addchar('.');
  if (sz == SIZE_BYTE)
    addchar('b');
  else if (sz == SIZE_WORD)
    addchar('w');
  else
    addchar('l');

  addchar('\t');
  lused = dbuf->used;
  get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 0);
  addchar(',');
  get_modregstr(dbuf, 11, GETMOD_AFTER, sz, dbuf->used - lused);
}


/*
 * misc opcodes.
 */
static void opcode_misc(dis_buffer_t *dbuf, u_short opc)
{
  char *tmp;
  int sz;

  tmp = NULL;
      
  /* Check against no option instructions */
  switch (opc) {
  case BGND_INST:
    tmp = "bgnd";
    break;
  case ILLEGAL_INST:
    tmp = "illegal";
    break;
  case MOVEFRC_INST:
  case MOVETOC_INST:
    opcode_movec(dbuf, opc);
    return;
  case NOP_INST:
    tmp = "nop";
    break;
  case RESET_INST:
    tmp = "reset";
    break;
  case RTD_INST:
    addstr(dbuf, "rtd\t");
    get_immed(dbuf, SIZE_WORD);
    return;
  case RTE_INST:
    tmp = "rte";
    break;
  case RTR_INST:
    tmp = "rtr";
    break;
  case RTS_INST:
    tmp = "rts";
    break;
  case STOP_INST:
    addstr(dbuf, "stop\t");
    get_immed(dbuf, SIZE_WORD);
    return;
  case TRAPV_INST:
    tmp = "trapv";
    break;
  default:
    break;
  }
  if (tmp) {
    addstr(dbuf, tmp);
    return;
  }

  switch (opc & BKPT_MASK) {
  case BKPT_INST:
    addstr(dbuf, "bkpt\t#");
    printu_bf(dbuf, opc, 2, 0);
    return;
  case EXTBW_INST:
    addstr(dbuf, "ext.w\t");
    get_modregstr(dbuf,2,DR_DIR,0,0);
    return;
  case EXTWL_INST:
    addstr(dbuf, "ext.l\t");
    get_modregstr(dbuf,2,DR_DIR,0,0);
    return;
  case EXTBL_INST:
    addstr(dbuf, "extb.l\t");
    get_modregstr(dbuf,2,DR_DIR,0,0);
    return;
  case LINKW_INST:
  case LINKL_INST:
    if ((LINKW_MASK & opc) == LINKW_INST) {
      addstr(dbuf, "link.w\t");
      get_modregstr(dbuf, 2, AR_DIR, 0, 1);
    } else {
      addstr(dbuf, "link.l\t");
      get_modregstr(dbuf, 2, AR_DIR, 0, 2);
    }
    addchar(',');
    if ((LINKW_MASK & opc) == LINKW_INST)
      get_immed(dbuf, SIZE_WORD);
    else 
      get_immed(dbuf,SIZE_LONG);
    return;
  case MOVETOUSP_INST:
  case MOVEFRUSP_INST:
    addstr(dbuf, "move.l\t");
    if (!ISBITSET(opc,3)) {
      get_modregstr(dbuf, 2, AR_DIR, 0, 0);
      addchar(',');
    }
    addstr(dbuf, "usp");
    if (ISBITSET(opc,3)) {
      addchar(',');
      get_modregstr(dbuf, 2, AR_DIR, 0, 0);
    }
    return;
  case SWAP_INST:  /*phx - swap was missing */
    addstr(dbuf, "swap\t");
    get_modregstr(dbuf,2,DR_DIR,0,0);
    return;
  case UNLK_INST:
    addstr(dbuf, "unlk\t");
    get_modregstr(dbuf, 2, AR_DIR, 0, 0);
    return;
  }
  
  if ((opc & TRAP_MASK) == TRAP_INST) {
    addstr(dbuf, "trap\t#");
    printu_bf(dbuf, opc, 3, 0);
    return;
  }

  sz = 0;
  switch (DIVSL_MASK & opc) {
  case DIVSL_INST:
  case MULSL_INST:
    opcode_divmul(dbuf, opc);
    return;
  case JMP_INST:
    tmp = "jmp\t";
    break;
  case JSR_INST:
    tmp = "jsr\t";
    break;
  case MOVEFRCCR_INST:
    tmp = "move\tccr,";
    break;
  case MOVEFRSR_INST:
    tmp = "move\tsr,";
    break;
  case NBCD_INST:
    tmp = "nbcd\t";
    break;
  case PEA_INST:
    tmp = "pea\t";
    break;
  case TAS_INST:
    tmp = "tas\t";
    break;
  case MOVETOCCR_INST:
  case MOVETOSR_INST:
    tmp = "move\t";
    sz = SIZE_WORD;
    break;
  }
  if (tmp) {
    addstr(dbuf, tmp);
    get_modregstr(dbuf,5, GETMOD_BEFORE, sz, 0);
    if(IS_INST(MOVETOSR,opc))
      addstr(dbuf, ",sr");
    else if(IS_INST(MOVETOCCR,opc))
      addstr(dbuf, ",ccr");
    return;
  }

  if ((opc & MOVEM_MASK) == MOVEM_INST) {
    opcode_movem(dbuf, opc);
    return;
  }

  switch (opc & CLR_MASK) {
  case CLR_INST:
    tmp = "clr";
    break;
  case NEG_INST:
    tmp = "neg";
    break;
  case NEGX_INST:
    tmp = "negx";
    break;
  case NOT_INST:
    tmp = "not";
    break;
  case TST_INST:
    tmp = "tst";
    break;
  }
  if (tmp) {
    int sz, msz;
    
    addstr(dbuf, tmp);

    msz = BITFIELD(opc,7,6);
    if (msz == 0) {
      tmp = ".b\t";
      sz = SIZE_BYTE;
    } else if (msz == 1) {
      tmp = ".w\t";
      sz = SIZE_WORD;
    } else {
      tmp = ".l\t";
      sz = SIZE_LONG;
    }
    addstr(dbuf, tmp);
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 0);
    return;
  }
  
  if ((opc & LEA_MASK) == LEA_INST) {
    addstr(dbuf, "lea\t");
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_LONG, 0);
    addchar(',');
    get_modregstr(dbuf, 11, AR_DIR, 0, 0);
    return;
  } else if ((opc & CHK_MASK) == CHK_INST) {
    if (BITFIELD(opc,8,7) == 0x3) {
      addstr(dbuf, "chk.w\t");
      get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_WORD, 0);
    } else {
      addstr(dbuf, "chk.l\t");
      get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_LONG, 0);
    }
    addchar(',');
    get_modregstr(dbuf, 11, DR_DIR, 0, 0);
    return;
  } 
}


/*
 * ADDQ/SUBQ/Scc/DBcc/TRAPcc
 */
static void opcode_0101(dis_buffer_t *dbuf, u_short opc)
{
  int data;

  if (IS_INST(TRAPcc, opc) && BITFIELD(opc,2,0) > 1) {
    int opmode;

    opmode = BITFIELD(opc,2,0);
    make_cond(dbuf,11,"trap");

    addchar('.');
    if (opmode == 0x2) {
      addchar('w');
      addchar('\t');
      get_immed(dbuf, SIZE_WORD);
    } else if (opmode == 0x3) {
      addchar('l');
      addchar('\t');
      get_immed(dbuf, SIZE_LONG);
    }
    return;
  } else if (IS_INST(DBcc, opc)) {
    make_cond(dbuf,11,"db");
    addchar('\t');
    PRINT_DREG(dbuf, BITFIELD(opc,2,0));
    addchar(',');
    print_disp(dbuf, read16(dbuf->val + 1), SIZE_WORD, -1, 0);
    dbuf->used++;
    return;
  } else if (IS_INST(Scc,opc)) {
    make_cond(dbuf,11,"s");
    addchar('\t');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_BYTE, 0);
    return;
  } else if (IS_INST(ADDQ, opc) || IS_INST(SUBQ, opc)) {
    int size = BITFIELD(opc,7,6);

    if (IS_INST(SUBQ, opc)) 
      addstr(dbuf, "subq.");
    else
      addstr(dbuf, "addq.");
    
    if (size == 0x1) 
      addchar('w');
    else if (size == 0x2)
      addchar('l');
    else
      addchar('b');
    
    addchar('\t');
    addchar('#');
    data = BITFIELD(opc,11,9);
    if (data == 0)
      data = 8;
    printu(dbuf, data, SIZE_BYTE);
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 0);
    
    return;
  }
}


/*
 * Bcc/BSR/BRA
 */
static void opcode_branch(dis_buffer_t *dbuf, u_short opc)
{
  int disp;

  if (IS_INST(BRA,opc))
      addstr(dbuf, "bra");      
  else if (IS_INST(BSR,opc))
      addstr(dbuf, "bsr");      
  else 
      make_cond(dbuf,11,"b");

  addchar('.');
  disp = BITFIELD(opc,7,0);
  if (disp == 0) {
    /* 16-bit signed displacement */
    disp = read16(dbuf->val + 1);
    dbuf->used++;
    addchar('w');
  } else if (disp == 0xff) {
    /* 32-bit signed displacement */
    disp = read32(dbuf->val + 1);
    dbuf->used += 2;
    addchar('l');
  } else {
    /* 8-bit signed displacement in opcode. */
    /* Needs to be sign-extended... */
    if (ISBITSET(disp,7))
      disp -= 256;
    addchar('b');
  }
  addchar('\t');
  print_addr(dbuf, disp + (u_long)dbuf->sval + 2);  /*phx - use sval */
}


/*
 * ADD/ADDA/ADDX/SUB/SUBA/SUBX
 */
static void opcode_addsub(dis_buffer_t *dbuf, u_short opc)
{
  int sz, ch, amode;
  
  sz = BITFIELD(opc,7,6);
  amode = 0;
  
  if (sz == 0) {
    ch = 'b';
    sz = SIZE_BYTE;
  } else if (sz == 1) {
    ch = 'w';
    sz = SIZE_WORD;
  } else if (sz == 2) {
    ch = 'l';
    sz = SIZE_LONG;
  } else {
    amode = 1;
    if (!ISBITSET(opc,8))  {
      sz = SIZE_WORD;
      ch = 'w';
    } else {
      sz = SIZE_LONG;
      ch = 'l';
    }
  }
  
  if ((IS_INST(ADDX,opc) || IS_INST(SUBX,opc)) && !amode) {  /*phx FIXED*/
    if (IS_INST(ADDX,opc))
      addstr(dbuf,"addx.");
    else
      addstr(dbuf,"subx.");

    addchar(ch);
    addchar('\t');
    
    if (ISBITSET(opc,3))
      print_AxAyPredec(dbuf,opc);
    else
      print_DxDy(dbuf,opc);
  } else {
    if (IS_INST(ADD,opc))
      addstr(dbuf, "add");
    else
      addstr(dbuf, "sub");

    if (amode)
      addchar('a');
    addchar('.');
    addchar(ch);
    addchar('\t');

    if (ISBITSET(opc,8) && amode == 0) {
      PRINT_DREG(dbuf,BITFIELD(opc,11,9));
      addchar(',');
      get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 0);
    } else {
      get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 0);
      addchar(',');
      if (amode)
        PRINT_AREG(dbuf,BITFIELD(opc,11,9));
      else
        PRINT_DREG(dbuf,BITFIELD(opc,11,9));
    }
  }
  return;
}


/*
 * Shift/Rotate/Bit Field
 */
static void opcode_1110(dis_buffer_t *dbuf, u_short opc)
{
  char *tmp;
  u_short ext;
  int type, sz;

  tmp = NULL;
  
  switch (opc & BFCHG_MASK) {
  case BFCHG_INST:
    tmp = "bfchg";
    break;
  case BFCLR_INST:
    tmp = "bfclr";
    break;
  case BFEXTS_INST:
    tmp = "bfexts";
    break;
  case BFEXTU_INST:
    tmp = "bfextu";
    break;
  case BFFFO_INST:
    tmp = "bfffo";
    break;
  case BFINS_INST:
    tmp = "bfins";
    break;
  case BFSET_INST:
    tmp = "bfset";
    break;
  case BFTST_INST:
    tmp = "bftst";
    break;
  }
  if (tmp) {
    short bf;
    
    addstr(dbuf, tmp);
    addchar('\t');
    
    ext = read16(dbuf->val + 1);
    dbuf->used++;
    
    if (IS_INST(BFINS,opc)) {
      PRINT_DREG(dbuf, BITFIELD(ext,14,12));
      addchar(',');
    }
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 1);
    addchar('{');

    bf = BITFIELD(ext,10,6);
    if (ISBITSET(ext, 11)) {
      PRINT_DREG(dbuf, bf);
    } else
      printu_wb(dbuf, bf, SIZE_BYTE, 10);
    
    addchar(':');

    bf = BITFIELD(ext, 4, 0);
    if (ISBITSET(ext, 5))
      PRINT_DREG(dbuf, bf);
    else {
      if (bf == 0)
        bf = 32;
      printu_wb(dbuf, bf, SIZE_BYTE, 10);
    }
    addchar('}');
    if (ISBITSET(opc,8) && !IS_INST(BFINS,opc)) {
      addchar(',');
      PRINT_DREG(dbuf, BITFIELD(ext,14,12));
    } else
      *dbuf->casm = 0;
    return;
  }
  sz = BITFIELD(opc,7,6);
  if (sz == 0x3)
    type = BITFIELD(opc, 10, 9);
  else
    type = BITFIELD(opc, 4, 3);

  switch (type) {
  case AS_TYPE:
    addchar('a');
    addchar('s');
    break;
  case LS_TYPE:
    addchar('l');
    addchar('s');
    break;
  case RO_TYPE:
    addchar('r');
    addchar('o');
    break;
  case ROX_TYPE:
    addchar('r');
    addchar('o');
    addchar('x');
    break;
  }

  if (ISBITSET(opc,8))
    addchar('l');
  else
    addchar('r');
  
  addchar('.');
  switch (sz) {
  case 0:
    sz = SIZE_BYTE;
    addchar('b');
    break;
  case 3:
  case 1:
    sz = SIZE_WORD;
    addchar('w');
    break;
  case 2:
    sz = SIZE_LONG;
    addchar('l');
    break;
    
  }
  addchar('\t');
  if(BITFIELD(opc,7,6) == 0x3) {
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 0);
    return;
  } else if (ISBITSET(opc,5)) 
    PRINT_DREG(dbuf, BITFIELD(opc,11,9));
  else {
    addchar('#');
    sz = BITFIELD(opc,11,9);
    if (sz == 0)
      sz = 8;
    printu_wb(dbuf, sz, SIZE_BYTE, 10);
  }
  addchar(',');
  PRINT_DREG(dbuf, BITFIELD(opc,2,0));
  return;
}


/*
 * CMP/CMPA/EOR
 */
static void opcode_1011(dis_buffer_t *dbuf, u_short opc)
{
  int sz;
  
  if (IS_INST(CMPA,opc)) {
    addstr(dbuf, "cmpa.");
    
    if (ISBITSET(opc, 8)) {
      addchar('l');
      sz = SIZE_LONG;
    } else {
      addchar('w');
      sz = SIZE_WORD;
    }
    addchar('\t');
  }
  else if (IS_INST(CMPM,opc)) {  /*phx - CMPM was missing! */
    addstr(dbuf, "cmpm.");
    switch (BITFIELD(opc,7,6)) {
    case 0:
      addchar('b');
      break;
    case 1:
      addchar('w');
      break;
    case 2:
      addchar('l');
      break;
    }
    addchar('\t');
    print_RnPlus(dbuf,opc,1,2,1);
    addchar(',');
    print_RnPlus(dbuf,opc,1,11,1);
    return;
  } else {
    if (IS_INST(CMP, opc))
      addstr(dbuf, "cmp.");
    else
      addstr(dbuf, "eor.");

    sz = BITFIELD(opc,7,6);
    switch (sz) {
    case 0:
      addchar('b');
      sz = SIZE_BYTE;
      break;
    case 1:
      addchar('w');
      sz = SIZE_WORD;
      break;
    case 2:
      addchar('l');
      sz = SIZE_LONG;
      break;
    }
    addchar('\t');
    if (IS_INST(EOR,opc)) {
      PRINT_DREG(dbuf, BITFIELD(opc,11,9));
      addchar(',');
    }
  }
  get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 0);

  if (IS_INST(CMPA,opc)) {
    addchar(',');
    PRINT_AREG(dbuf, BITFIELD(opc,11,9));
  } else if (IS_INST(CMP,opc)) {
    addchar(',');
    PRINT_DREG(dbuf, BITFIELD(opc,11,9));
  }
  return;
}


/*
 * OR/DIV/SBCD
 */
static void opcode_1000(dis_buffer_t *dbuf, u_short opc)
{
  int sz;
  
  if (IS_INST(UNPKA,opc)) {
    addstr(dbuf, "unpk\t");
    print_AxAyPredec(dbuf,opc);
    addchar(',');
    get_immed(dbuf,SIZE_WORD);
  } else if (IS_INST(UNPKD,opc)) {
    addstr(dbuf, "unpk\t");
    print_DxDy(dbuf,opc);
    addchar(',');
    get_immed(dbuf,SIZE_WORD);
  } else if (IS_INST(PACKA,opc)) {  /*phx - PACK was missing */
    addstr(dbuf, "pack\t");
    print_AxAyPredec(dbuf,opc);
    addchar(',');
    get_immed(dbuf,SIZE_WORD);
  } else if (IS_INST(PACKD,opc)) {
    addstr(dbuf, "pack\t");
    print_DxDy(dbuf,opc);
    addchar(',');
    get_immed(dbuf,SIZE_WORD);
  } else if (IS_INST(SBCDA,opc)) {
    addstr(dbuf, "sbcd\t");
    print_AxAyPredec(dbuf,opc);
  } else if (IS_INST(SBCDD,opc)) {
    addstr(dbuf, "sbcd\t");
    print_DxDy(dbuf,opc);
  } else if (IS_INST(DIVSW,opc) || IS_INST(DIVUW,opc)) {
    if (IS_INST(DIVSW,opc))
      addstr(dbuf, "divs.w\t");
    else
      addstr(dbuf, "divu.w\t");
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_WORD, 0);
    addchar(',');
    PRINT_DREG(dbuf, BITFIELD(opc,11,9));
  } else {
    addstr(dbuf, "or.");

    sz = BITFIELD(opc,7,6);
    switch (sz) {
    case 0:
      addchar('b');
      sz = SIZE_BYTE;
      break;
    case 1:
      addchar('w');
      sz = SIZE_WORD;
      break;
    case 2:
      addchar('l');
      sz = SIZE_LONG;
      break;
    }
    addchar('\t');
    if (ISBITSET(opc,8)) {
      PRINT_DREG(dbuf, BITFIELD(opc,11,9));
      addchar(',');
    }
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 0);
    if (!ISBITSET(opc,8)) {
      addchar(',');
      PRINT_DREG(dbuf, BITFIELD(opc,11,9));
    }
  }
}


/*
 * AND/MUL/ABCD/EXG (1100)
 */
static void opcode_1100(dis_buffer_t *dbuf, u_short opc)
{
  int sz;
  
  if (IS_INST(ABCDA,opc)) {
    addstr(dbuf, "abcd\t");
    print_AxAyPredec(dbuf,opc);
  } else if (IS_INST(ABCDD,opc)) {
    addstr(dbuf, "abcd\t");
    print_DxDy(dbuf,opc);
  } else if (IS_INST(MULSW,opc) || IS_INST(MULUW,opc)) {
    if (IS_INST(MULSW,opc))
      addstr(dbuf, "muls.w\t");
    else
      addstr(dbuf, "mulu.w\t");
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_WORD, 0);
    addchar(',');
    PRINT_DREG(dbuf, BITFIELD(opc,11,9));
  } else if (IS_INST(EXG,opc)) {
    addstr(dbuf, "exg\t");
    if (ISBITSET(opc,7)) {
      PRINT_DREG(dbuf,BITFIELD(opc,11,9));
      addchar(',');
      PRINT_AREG(dbuf,BITFIELD(opc,2,0));
    } else if (ISBITSET(opc,3)) {
      PRINT_AREG(dbuf,BITFIELD(opc,11,9));
      addchar(',');
      PRINT_AREG(dbuf,BITFIELD(opc,2,0));
    } else {
      PRINT_DREG(dbuf,BITFIELD(opc,11,9));
      addchar(',');
      PRINT_DREG(dbuf,BITFIELD(opc,2,0));
    }
  } else {
    addstr(dbuf, "and.");

    sz = BITFIELD(opc,7,6);
    switch (sz) {
    case 0:
      addchar('b');
      sz = SIZE_BYTE;
      break;
    case 1:
      addchar('w');
      sz = SIZE_WORD;
      break;
    case 2:
      addchar('l');
      sz = SIZE_LONG;
      break;
    }
    addchar('\t');
    
    if (ISBITSET(opc,8)) {
      PRINT_DREG(dbuf, BITFIELD(opc,11,9));
      addchar(',');
    }
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 0);
    if (!ISBITSET(opc,8)) {
      addchar(',');
      PRINT_DREG(dbuf, BITFIELD(opc,11,9));
    }
  }
}


/*
 * Coprocessor instruction
 */
static void opcode_coproc(dis_buffer_t *dbuf, u_short opc)
{
  switch (BITFIELD(read16(dbuf->val),11,9)) {
  case 1:
    opcode_fpu(dbuf, opc);
    return;
  case 0:
    opcode_mmu(dbuf, opc);
    return;
  case 2:
    opcode_mmu040(dbuf, opc);
    return;
  case 3:
    opcode_move16(dbuf, opc);
    return;
  }
  switch (BITFIELD(opc,8,6)) {
  case 0:
    dbuf->used++;
    break;
  case 3:
    dbuf->used++;
    /*FALLTHROUGH*/
  case 2:
    dbuf->used++;
    break;
  case 1:
    dbuf->used++;
  case 4:
  case 5:
  default:
    break;
  }
  addstr(dbuf, "linef");
  return;
}


/*
 * Resvd
 */
static void opcode_1010(dis_buffer_t *dbuf, u_short opc)
{
  addstr(dbuf, "linea");
  dbuf->used++;
}


static void opcode_fpu(dis_buffer_t *dbuf, u_short opc)
{
  u_short ext;
  int type, opmode;

  type = BITFIELD(opc,8,6);
  switch (type) {
  /* cpGEN */
  case 0:
    ext = read16(dbuf->val + 1);
    dbuf->used++;
    opmode = BITFIELD(ext,5,0);
    if (ISBITSET(ext,6))
      opmode &= ~4;

    if (BITFIELD(opc,5,0) == 0 && BITFIELD(ext,15,10) == 0x17) {
      addstr(dbuf,"fmovecr.x\t#");
      printu(dbuf,BITFIELD(ext,6,0),SIZE_BYTE);
      addchar(',');
      PRINT_FPREG(dbuf, BITFIELD(ext,9,7));
      return;
    }
    if (ISBITSET(ext,15) || ISBITSET(ext,13)) {
      opcode_fmove_ext(dbuf, opc, ext);
      return;
    }

    switch(opmode) {
    case FMOVE:
      get_fpustdGEN(dbuf,ext,"fmove");
      return;
    case FABS:
      get_fpustdGEN(dbuf,ext,"fabs");
      return;
    case FACOS:
      get_fpustdGEN(dbuf,ext,"facos");
      return;
    case FADD:
      get_fpustdGEN(dbuf,ext,"fadd");
      return;
    case FASIN:
      get_fpustdGEN(dbuf,ext,"fasin");
      return;
    case FATAN:
      get_fpustdGEN(dbuf,ext,"fatan");
      return;
    case FATANH:
      get_fpustdGEN(dbuf,ext,"fatanh");
      return;
    case FCMP:
      get_fpustdGEN(dbuf,ext,"fcmp");
      return;
    case FCOS:
      get_fpustdGEN(dbuf,ext,"fcos");
      return;
    case FCOSH:
      get_fpustdGEN(dbuf,ext,"fcosh");
      return;
    case FDIV:
      get_fpustdGEN(dbuf,ext,"fdiv");
      return;
    case FETOX:
      get_fpustdGEN(dbuf,ext,"fetox");
      return;
    case FETOXM1:
      get_fpustdGEN(dbuf,ext,"fetoxm1");
      return;
    case FGETEXP:
      get_fpustdGEN(dbuf,ext,"fgetexp");
      return;
    case FGETMAN:
      get_fpustdGEN(dbuf,ext,"fgetman");
      return;
    case FINT:
      get_fpustdGEN(dbuf,ext,"fint");
      return;
    case FINTRZ:
      get_fpustdGEN(dbuf,ext,"fintrz");
      return;
    case FLOG10:
      get_fpustdGEN(dbuf,ext,"flog10");
      return;
    case FLOG2:
      get_fpustdGEN(dbuf,ext,"flog2");
      return;
    case FLOGN:
      get_fpustdGEN(dbuf,ext,"flogn");
      return;
    case FLOGNP1:
      get_fpustdGEN(dbuf,ext,"flognp1");
      return;
    case FMOD:
      get_fpustdGEN(dbuf,ext,"fmod");
      return;
    case FMUL:
      get_fpustdGEN(dbuf,ext,"fmul");
      return;
    case FNEG:
      get_fpustdGEN(dbuf,ext,"fneg");
      return;
    case FREM:
      get_fpustdGEN(dbuf,ext,"frem");
      return;
    case FSCALE:
      get_fpustdGEN(dbuf,ext,"fscale");
      return;
    case FSGLDIV:
      get_fpustdGEN(dbuf,ext,"fsgldiv");
      return;
    case FSGLMUL:
      get_fpustdGEN(dbuf,ext,"fsglmul");
      return;
    case FSIN:
      get_fpustdGEN(dbuf,ext,"fsin");
      return;
    case FSINH:
      get_fpustdGEN(dbuf,ext,"fsinh");
      return;
    case FSQRT:
      get_fpustdGEN(dbuf,ext,"fsqrt");
      return;
    case FSUB:
      get_fpustdGEN(dbuf,ext,"fsub");
      return;
    case FTAN:
      get_fpustdGEN(dbuf,ext,"ftan");
      return;
    case FTANH:
      get_fpustdGEN(dbuf,ext,"ftanh");
      return;
    case FTENTOX:
      get_fpustdGEN(dbuf,ext,"ftentox");
      return;
    case FTST:
      get_fpustdGEN(dbuf,ext,"ftst");
      return;
    case FTWOTOX:
      get_fpustdGEN(dbuf,ext,"ftwotox");
      return;
      
    }
  /* cpBcc */
  case 2:
    if (BITFIELD(opc,5,0) == 0 && read16(dbuf->val + 1) == 0) {
      dbuf->used++;
      addstr (dbuf, "fnop");
      return;
    }     
  case 3:
    addstr(dbuf, "fb");
    print_fcond(dbuf, BITFIELD(opc,5,0));
    addchar('.');
    if (type == 2) {
      addchar('w');
      addchar('\t');
      print_disp(dbuf,read16(dbuf->val + 1), SIZE_WORD, -1, 0);
      dbuf->used++;
    } else {
      addchar('l');
      addchar('\t');
      print_disp(dbuf,read32(dbuf->val + 1), SIZE_LONG, -1, 0);
      dbuf->used += 2;
    }
    return;
  /* cpDBcc/cpScc/cpTrap */
  case 1:
    ext = read16(dbuf->val + 1);
    dbuf->used++;

    if (BITFIELD(opc,5,3) == 0x1) {
      /* fdbcc */
      addstr(dbuf,"fdb");
      print_fcond(dbuf,BITFIELD(ext,5,0));
      addchar('\t');
      PRINT_DREG(dbuf, BITFIELD(opc,2,0));
      addchar(',');
      print_disp(dbuf, read16(dbuf->val + 2), SIZE_WORD, -1, 1);
      dbuf->used++;
    } else if (BITFIELD(opc,5,3) == 0x7 &&
        BITFIELD(opc,2,0) > 1) {
      addstr(dbuf,"ftrap");
      print_fcond(dbuf,BITFIELD(ext,5,0));

      addchar('.');
      if (BITFIELD(opc,2,0) == 0x2) {
        addchar('w');
        addchar('\t');
        dbuf->val++;
        get_immed(dbuf, SIZE_WORD);
        dbuf->val--;
      } else if (BITFIELD(opc,2,0) == 0x3) {
        addchar('l');
        addchar('\t');
        dbuf->val++;
        get_immed(dbuf, SIZE_LONG);
        dbuf->val--;
      }
    } else {
      addstr(dbuf,"fs");
      print_fcond(dbuf,BITFIELD(ext,5,0));
      addchar('\t');
      get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_BYTE, 1);
    }
    return;
  case 4:
    addstr(dbuf,"fsave\t");
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 0);
    return;
  case 5:
    addstr(dbuf,"frestore\t");
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 0);
    return;
  }
}


/*
 * XXX - This screws up on:  fmovem  a0@(312),fpcr/fpsr/fpi
 */
static void opcode_fmove_ext(dis_buffer_t *dbuf, u_short opc, u_short ext)
{
  int sz;

  sz = 0;
  if (BITFIELD(ext,15,13) == 3) {
    /* fmove r ==> m */
    addstr(dbuf, "fmove.");
    switch (BITFIELD(ext,12,10)) {
    case 0:
      addchar('l');
      sz = SIZE_LONG;
      break;
    case 1:
      addchar('s');
      sz = SIZE_SINGLE;
      break;
    case 2:
      addchar('x');
      sz = SIZE_EXTENDED;
      break;
    case 7:
    case 3:
      addchar('p');
      sz = SIZE_PACKED;
      break;
    case 4:
      addchar('w');
      sz = SIZE_WORD;
      break;
    case 5:
      addchar('d');
      sz = SIZE_DOUBLE;
      break;
    case 6:
      addchar('b');
      sz = SIZE_BYTE;
      break;
    }
    addchar('\t');
    PRINT_FPREG(dbuf, BITFIELD(ext,9,7));
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 1);
    if (sz == SIZE_PACKED) {
      addchar('{');
      if (ISBITSET(ext,12)) {
        PRINT_DREG(dbuf,BITFIELD(ext,6,4));
      } else {
        addchar('#');
        prints_bf(dbuf, ext, 6, 0);
      }
      addchar('}');
    }
    return;
  }
  addstr(dbuf,"fmovem.");

  if (!ISBITSET(ext,14)) {
    /* fmove[m] control reg */
    addchar('l');
    addchar('\t');

    if (ISBITSET(ext,13)) {
      print_freglist(dbuf, AR_DEC, BITFIELD(ext,12,10), 1);
      addchar(',');
    }
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_LONG, 1);
    if (!ISBITSET(ext,13)) {
      addchar(',');
      print_freglist(dbuf, AR_DEC, BITFIELD(ext,12,10), 1);
    }
    return;
  }
  addchar('x');
  addchar('\t');

  if (ISBITSET(ext,11)) {
    if (ISBITSET(ext,13)) {
      PRINT_DREG(dbuf,BITFIELD(ext,6,4));
      addchar(',');
    }
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_EXTENDED, 1);
    if (!ISBITSET(ext,13)) {
      addchar(',');
      PRINT_DREG(dbuf,BITFIELD(ext,6,4));
    }   
  } else {
    if (ISBITSET(ext,13)) {
      print_freglist(dbuf, BITFIELD(opc,5,3),
               BITFIELD(ext,7,0), 0);
      addchar(',');
    }
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_EXTENDED, 1);
    if (!ISBITSET(ext,13)) {
      addchar(',');
      print_freglist(dbuf, BITFIELD(opc,5,3),
               BITFIELD(ext,7,0), 0);
    }   
  }
}


static void opcode_mmu(dis_buffer_t *dbuf, u_short opc)
{
  u_short ext;
  int type;

  type = BITFIELD(opc,8,6);
  switch (type) {
  /* cpGEN? */
  case 0:
    ext = read16(dbuf->val + 1);
    dbuf->used++;
    
    switch(BITFIELD(ext,15,13)) {
    case 5:
    case 1:
      opcode_pflush(dbuf, opc, ext);
      return;
    case 0:
    case 3:
    case 2:
      opcode_pmove(dbuf, opc, ext);
      return;
    case 4:
      addstr(dbuf, "ptest");
      if (ISBITSET(ext,9))
        addchar('r');
      else
        addchar('w');
      addchar('\t');
      print_fcode(dbuf, BITFIELD(ext, 5, 0));
      addchar(',');
      get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 1);
      addchar(',');
      addchar('#');
      printu_bf(dbuf, ext, 12, 10);
      if (ISBITSET(ext, 8)) {
        addchar(',');
        PRINT_AREG(dbuf, BITFIELD(ext, 7, 5));
      }
    }
    return;
  case 2:
  case 3:
    addstr(dbuf, "pb");
    print_mcond(dbuf, BITFIELD(opc,5,0));
    addchar('.');
    if (type == 2) {
      addchar('w');
      addchar('\t');
      print_disp(dbuf,read16(dbuf->val + 1), SIZE_WORD, -1, 0);
      dbuf->used++;
    } else {
      addchar('l');
      addchar('\t');
      print_disp(dbuf,read32(dbuf->val + 1), SIZE_LONG, -1, 0);
      dbuf->used += 2;
    }
    return;
  case 1:
    ext = read16(dbuf->val + 1);
    dbuf->used++;

    if (BITFIELD(opc,5,3) == 0x1) {
      /* pdbcc */
      addstr(dbuf,"pdb");
      print_mcond(dbuf,BITFIELD(ext,5,0));
      addchar('\t');
      PRINT_DREG(dbuf, BITFIELD(opc,2,0));
      addchar(',');
      print_disp(dbuf, read16(dbuf->val + 2), SIZE_WORD, -1, 1);
      dbuf->used++;
    } else if (BITFIELD(opc,5,3) == 0x7 &&
        BITFIELD(opc,2,0) > 1) {
      addstr(dbuf,"ptrap");
      print_mcond(dbuf,BITFIELD(ext,5,0));
      addchar('.');

      if (BITFIELD(opc,2,0) == 0x2) {
        addchar('w');
        addchar('\t');
        dbuf->val++;
        get_immed(dbuf, SIZE_WORD);
        dbuf->val--;
      } else if (BITFIELD(opc,2,0) == 0x3) {
        addchar('l');
        addchar('\t');
        dbuf->val++;
        get_immed(dbuf, SIZE_LONG);
        dbuf->val--;
      }
    } else {
      addstr(dbuf,"ps");
      print_mcond(dbuf,BITFIELD(ext,5,0));
      addchar('\t');
      get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_BYTE, 1);
    }
    return;
  case 4:
    addstr(dbuf,"psave\t");
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 0);
    return;
  case 5:
    addstr(dbuf,"prestore\t");
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 0);
    return;
  }
}


static void opcode_pflush(dis_buffer_t *dbuf, u_short opc, u_short ext)
{
  u_short mode, mask, fc;
  
  mode = BITFIELD(ext,12,10);
  mask = BITFIELD(ext,8,5);
  fc = BITFIELD(ext, 5, 0);
  
  if (ext == 0xa000) {
    addstr(dbuf,"pflushr\t");
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_LONG, 1);
    return;
  }
  
  if (mode == 0) {
    addstr(dbuf,"pload");
    if (ISBITSET(ext,9))
      addchar('r');
    else
      addchar('w');
    addchar('\t');
    print_fcode(dbuf, fc);
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_LONG, 1);  /*phx*/
    return;
  }
  else if ((mode&6) == 2) {  /*phx - PVALID was missing */
    addstr(dbuf,"pvalid\t");
    if (mode == 2)
      addstr(dbuf,"val");
    else
      PRINT_AREG(dbuf, BITFIELD(ext,2,0));
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_LONG, 1);
    return;
  }

  addstr(dbuf,"pflush");
  switch (mode) {
  case 1:
    addchar('a');
    *dbuf->casm = 0;
    break;
  case 7:
  case 5:
    addchar('s');
    /*FALLTHROUGH*/
  case 6:
  case 4:
    addchar('\t');
    print_fcode(dbuf, fc);
    addchar(',');
    addchar('#');
    printu(dbuf, mask, SIZE_BYTE);
    if (!ISBITSET(mode,1)) 
      break;
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, SIZE_LONG, 1);
  }
}


static void opcode_pmove(dis_buffer_t *dbuf, u_short opc, u_short ext)
{
  const char *reg;
  int rtom, sz, preg;

  reg  = "???";
  sz   = 0;
  rtom = ISBITSET(ext, 9);
  preg = BITFIELD(ext, 12, 10);
  
  addstr(dbuf,"pmove");
  if (ISBITSET(ext,8)) {
    addchar('f');
    addchar('d');
  }
  switch (BITFIELD(ext, 15, 13)) {
  case 0: /* tt regs 030o */
    switch (preg) {
    case 2:
      reg = "tt0";
      break;
    case 3:
      reg = "tt1";
      break;
    }
    sz = SIZE_LONG;
    break;
  case 2:
    switch (preg) {
    case 0:
      reg = "tc";
      sz = SIZE_LONG;
      break;
    case 1:
      reg = "drp";
      sz = SIZE_QUAD;
      break;
    case 2:
      reg = "srp";
      sz = SIZE_QUAD;
      break;
    case 3:
      reg = "crp";
      sz = SIZE_QUAD;
      break;
    case 4:
      reg = "cal";
      sz = SIZE_BYTE;
      break;
    case 5:
      reg = "val";
      sz = SIZE_BYTE;
      break;
    case 6:
      reg = "scc";
      sz = SIZE_BYTE;
      break;
    case 7:
      reg = "ac";
      sz = SIZE_WORD;
    }
    break;
  case 3:
    switch (preg) {
    case 0:
      reg = "mmusr";
      break;
    case 1:
      reg = "pcsr";
      break;
    case 4:
      reg = "bad";
      break;
    case 5:
      reg = "bac";
      break;
    }
    sz = SIZE_WORD;
    break;
  }
  if (sz) addchar('.');
  switch (sz) {
  case SIZE_BYTE:
    addchar ('b');
    break;
  case SIZE_WORD:
    addchar ('w');
    break;
  case SIZE_LONG:
    addchar ('l');
    break;
  case SIZE_QUAD:
    addchar ('d');
    break;
  }   
  addchar('\t');
  
  if (!rtom) {
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 1);
    addchar(',');
  }
  addstr(dbuf, reg);
  if (BITFIELD(ext, 15, 13) == 3 && preg > 1) 
    printu_bf(dbuf, ext, 4, 2);
  if (rtom) {
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 1);
  }
  return;
}


static void print_fcode(dis_buffer_t *dbuf, u_short fc)
{
  if (ISBITSET(fc, 4)) {
    addchar('#');   /* ??? */
    printu_bf(dbuf, fc, 3, 0);
  }
  else if (ISBITSET(fc, 3))
    PRINT_DREG(dbuf, BITFIELD(fc, 2, 0));
  else if (fc == 1)
    addstr(dbuf, "dfc");
  else
    addstr(dbuf, "sfc");
}


static void opcode_mmu040(dis_buffer_t *dbuf, u_short opc)
{
  if (ISBITSET(opc, 8)) {
    if (ISBITSET(opc, 6)) {
      addstr(dbuf, "ptest");
      if (ISBITSET(opc, 5))
        addchar('r');
      else
        addchar('w');
      addchar('\t');
      print_RnPlus(dbuf,opc,1,2,0);
    } else {
      addstr(dbuf, "pflush");
      switch (BITFIELD(opc, 4, 3)) {
      case 3:
        addchar('a');
        *dbuf->casm = 0;
        break;
      case 2:
        addchar('a');
        addchar('n');
        *dbuf->casm = 0;
        break;
      case 0:
        addchar('n');
        /*FALLTHROUGH*/
      case 1:
        addchar('\t');
        print_RnPlus(dbuf,opc,1,2,0);
        break;
      }
    }
  }

  else {  /*phx - CINV and CPUSH were missing */
    if (ISBITSET(opc, 5))
      addstr(dbuf, "cpush");
    else
      addstr(dbuf, "cinv");
    switch (BITFIELD(opc, 4, 3)) {  /* scope */
    case 1:
      addchar('l');
      break;
    case 2:
      addchar('p');
      break;
    case 3:
      addchar('a');
      break;
    }
    switch (BITFIELD(opc, 7, 6)) {  /* caches */
    case 0:
      addstr(dbuf,"\tnc");
      break;
    case 1:
      addstr(dbuf,"\tdc");
      break;
    case 2:
      addstr(dbuf,"\tic");
      break;
    case 3:
      addstr(dbuf,"\tbc");
      break;
    }
    if (BITFIELD(opc,4,3) != 3) {
      addchar(',');
      print_RnPlus(dbuf,opc,1,2,0);
    }
  }
}


/*
 * disassemble long format (64b) divs/muls divu/mulu opcode.
 * Note: opcode's dbuf->used already accounted for.
 */
static void opcode_divmul(dis_buffer_t *dbuf, u_short opc)
{
  u_short ext;
  int iq, hr;
  
  ext = read16(dbuf->val + 1);
  dbuf->used++;

  iq = BITFIELD(ext,14,12);
  hr = BITFIELD(ext,2,0);
  
  if (IS_INST(DIVSL,opc)) 
    addstr(dbuf, "div");
  else
    addstr(dbuf, "mul");
  if (ISBITSET(ext,11))
    addchar('s');
  else
    addchar('u');
  if (IS_INST(DIVSL,opc) && !ISBITSET(ext,10) && iq != hr) {
    addchar('l');
  }
  addchar('.');
  addchar('l');
  addchar('\t');

  get_modregstr(dbuf,5,GETMOD_BEFORE,SIZE_LONG,1);
  addchar(',');

  if (ISBITSET(ext,10) ||
      (iq != hr && IS_INST(DIVSL,opc))) {
    /* 64 bit version */
    PRINT_DREG(dbuf, hr);
    if (dbuf->mit) 
      addchar(',');
    else
      addchar(':');
  }
  PRINT_DREG(dbuf, iq);
}


static void print_reglist(dis_buffer_t *dbuf, int mod, u_short rl)
{
  const char *const regs[16] = {
    "d0","d1","d2","d3","d4","d5","d6","d7",
    "a0","a1","a2","a3","a4","a5","a6","a7" };
  int bit, list;

  if (mod == AR_DEC) {
    list = rl;
    rl = 0;
    /* I am sure there is some trick... */
    for (bit = 0; bit < 16; bit++)
      if (list & (1 << bit)) 
        rl |= (0x8000 >> bit);
  } 
  for (bit = 0, list = 0; bit < 16; bit++) {
    if (ISBITSET(rl,bit) && bit != 8) {
      if (list == 0) {
        list = 1;
        addstr(dbuf, regs[bit]);
      } else if (list == 1) {
        list++;
        addchar('-');
      }
    } else {
      if (list) {
        if (list > 1)
          addstr(dbuf, regs[bit-1]);
        addchar('/');
        list = 0;
      }
      if (ISBITSET(rl,bit)) {
        addstr(dbuf, regs[bit]);
        list = 1;
      }
    }
  }
  if (dbuf->casm[-1] == '/' || dbuf->casm[-1] == '-')
    dbuf->casm--;
  *dbuf->casm = 0;
}


static void print_freglist(dis_buffer_t *dbuf, int mod, u_short rl, int cntl)
{
  const char *const * regs;
  int bit, list, upper;

  regs = cntl ? fpcregs : fpregs;
  upper = cntl ? 3 : 8;

  if (!cntl && mod != AR_DEC) {
    list = rl;
    rl = 0;
    /* I am sure there is some trick... */
    for (bit = 0; bit < upper; bit++)
      if (list & (1 << bit)) 
        rl |= (0x80 >> bit);
  } 
  for (bit = 0, list = 0; bit < upper; bit++) {
    if (ISBITSET(rl,bit)) {
      if (list == 0) {
        addstr(dbuf, regs[bit]);
        if (cntl)
          addchar('/');
        else
          list = 1;
      } else if (list == 1) {
        list++;
        addchar('-');
      }
    } else {
      if (list) {
        if (list > 1)
          addstr(dbuf, regs[bit-1]);
        addchar('/');
        list = 0;
      }
    }
  }
  if (list > 1)
    addstr(dbuf, regs[upper-1]);

  if (dbuf->casm[-1] == '/' || dbuf->casm[-1] == '-')
    dbuf->casm--;
  *dbuf->casm = 0;
}


/*
 * disassemble movem opcode.
 */
static void opcode_movem(dis_buffer_t *dbuf, u_short opc)
{
  u_short rl;
  
  rl = read16(dbuf->val + 1);
  dbuf->used++;
  
  if (ISBITSET(opc,6))
    addstr(dbuf, "movem.l\t");
  else
    addstr(dbuf, "movem.w\t");
  if (ISBITSET(opc,10)) {
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 1);
    addchar(',');
    print_reglist(dbuf, BITFIELD(opc,5,3), rl);
  } else {
    print_reglist(dbuf, BITFIELD(opc,5,3), rl);
    addchar(',');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, 0, 1);
  }
}


/*
 * disassemble movec opcode.
 */
static void opcode_movec(dis_buffer_t *dbuf, u_short opc)
{
  char *tmp;
  u_short ext;

  ext = read16(dbuf->val + 1);
  dbuf->used++;

  addstr(dbuf, "movec\t");
  if (ISBITSET(opc,0)) {
    dbuf->val++;
    if (ISBITSET(ext,15)) 
      get_modregstr(dbuf,14,AR_DIR,0,0);
    else
      get_modregstr(dbuf,14,DR_DIR,0,0);
    dbuf->val--;
    addchar(',');
  }
  switch (BITFIELD(ext,11,0)) {
    /* 010/020/030/040/CPU32/060 */
  case 0x000:
    tmp = "sfc";
    break;
  case 0x001:
    tmp = "dfc";
    break;
  case 0x800:
    tmp = "usp";
    break;
  case 0x801:
    tmp = "vbr";
    break;
    /* 020/030 */
  case 0x802:
    tmp = "caar";
    break;
    /* 020/030/040/060 */
  case 0x002:
    tmp = "cacr";
    break;
    /* 020/030/040 */
  case 0x803:
    tmp = "msp";
    break;
  case 0x804:
    tmp = "isp";
    break;
    /* 040/060 */
  case 0x003:
    tmp = "tc";
    break;
  case 0x004:
    tmp = "itt0";
    break;
  case 0x005:
    tmp = "itt1";
    break;
  case 0x006:
    tmp = "dtt0";
    break;
  case 0x007:
    tmp = "dtt1";
    break;
    /* 040 */
  case 0x805:
    tmp = "mmusr";
    break;
    /* 040/060 */
  case 0x806:
    tmp = "urp";
    break;
  case 0x807:
    tmp = "srp";
    break;
    /* 060 */
  case 0x008:
    tmp = "buscr";
    break;
  case 0x808:
    tmp = "pcr";
    break;
  default:
    tmp = "INVALID";
    break;
  }
  addstr(dbuf, tmp);
  if (!ISBITSET(opc,0)) {
    dbuf->val++;
    addchar(',');
    if (ISBITSET(ext,15)) 
      get_modregstr(dbuf,14,AR_DIR,0,0);
    else
      get_modregstr(dbuf,14,DR_DIR,0,0);
    dbuf->val--;
  }
}


/*
 * disassemble move16 opcode.
 */
static void opcode_move16(dis_buffer_t *dbuf, u_short opc)
{
  addstr(dbuf, "move16\t");

  if (ISBITSET(opc, 5)) {
    print_RnPlus(dbuf,opc,1,2,1);
    addchar(',');
    print_RnPlus(dbuf,read16(dbuf->val + 1),1,14,1);
    dbuf->used++;
  } else {
    switch (BITFIELD(opc,4,3)) {
    case 0:
      print_RnPlus(dbuf,opc,1,2,1);
      addchar(',');
      get_immed(dbuf, SIZE_LONG);
      break;
    case 1:
      get_immed(dbuf, SIZE_LONG);
      addchar(',');
      print_RnPlus(dbuf,opc,1,2,1);
      break;
    case 2:
      print_RnPlus(dbuf,opc,1,2,0);
      addchar(',');
      get_immed(dbuf, SIZE_LONG);
      break;
    case 3:
      get_immed(dbuf, SIZE_LONG);
      addchar(',');
      print_RnPlus(dbuf,opc,1,2,0);
      break;
    }
  }
}


/*
 * copy const string 's' into ``dbuf''->casm
 */
static void addstr(dis_buffer_t *dbuf, const char *s)
{
  if (s)
  while ((*dbuf->casm++ = *s++))
    ;
  dbuf->casm--;
}


/*
 * copy const string 's' into ``dbuf''->cinfo
 */
static void iaddstr(dis_buffer_t *dbuf, const char *s)
{
  while ((*dbuf->cinfo++ = *s++))
    ;
  dbuf->cinfo--;
}


static void get_modregstr_moto(dis_buffer_t *dbuf, int bit, int mod, int sz, int dd)
{
  u_char scale, idx;
  const short *nval;
  u_short ext;
  int disp, odisp, bd, od, reg;
  
  odisp = 0;

  /* check to see if we have been given the mod */
  if (mod != GETMOD_BEFORE && mod != GETMOD_AFTER)
    reg = BITFIELD(read16(dbuf->val), bit, bit-2);
  else if (mod == GETMOD_BEFORE) {
    mod = BITFIELD(read16(dbuf->val), bit, bit-2);
    reg = BITFIELD(read16(dbuf->val), bit-3, bit-5);
  } else {
    reg = BITFIELD(read16(dbuf->val), bit, bit-2);
    mod = BITFIELD(read16(dbuf->val), bit-3, bit-5);
  }
  switch (mod) {
  case DR_DIR:
  case AR_DIR:
    if (mod == DR_DIR)
      PRINT_DREG(dbuf, reg);
    else
      PRINT_AREG(dbuf, reg);
    break;
  case AR_DIS:
    print_disp(dbuf, read16(dbuf->val + 1 + dd), SIZE_WORD, reg, dd);
    dbuf->used++;
    /*FALLTHROUGH*/
  case AR_IND:
  case AR_INC:
  case AR_DEC:
    if (mod == AR_DEC)
      addchar('-');
    addchar('(');
    PRINT_AREG(dbuf, reg);
    addchar(')');
    if (mod == AR_INC)
      addchar('+');
    break;
  /* mod 6 & 7 are the biggies. */
  case MOD_SPECIAL:
    if (reg == 0) {
      /* abs short addr */
      print_addr(dbuf, read16(dbuf->val + 1 + dd));
      dbuf->used++;
      addchar('.');
      addchar('w');
      break;
    } else if (reg == 1) {
      /* abs long addr */
      print_addr(dbuf, read32(dbuf->val + 1 + dd));
      dbuf->used += 2;
      addchar('.');
      addchar('l');
      break;
    } else if (reg == 2) {
      /* pc ind displ. xxx(PC) */
      dbuf->used++;
      print_disp(dbuf, read16(dbuf->val + 1 + dd), SIZE_WORD, -1, dd);
      addstr(dbuf,"(pc)");
      break;
    } else if (reg == 4) {
      /* uses ``sz'' to figure imediate data. */
      if (sz == SIZE_BYTE) {
        addchar('#');
        prints(dbuf,
            *((char *)dbuf->val + 3+ (dd * 2)), sz);
        dbuf->used++;
      } else if (sz == SIZE_WORD) {
        addchar('#');
        prints(dbuf, read16(dbuf->val + 1 + dd), sz);
        dbuf->used++;
      } else if (sz == SIZE_LONG) {
        addchar('#');
        prints(dbuf, read32(dbuf->val + 1 + dd),
            sz);
        dbuf->used += 2;
      } else if (sz == SIZE_QUAD) {
        dbuf->used += 4;
        addstr(dbuf,"#<quad>");
      } else if (sz == SIZE_SINGLE) {
        dbuf->used += 2;
        addstr(dbuf,"#<single>");
      } else if (sz == SIZE_DOUBLE) {
        dbuf->used += 4;
        addstr(dbuf,"#<double>");
      } else if (sz == SIZE_PACKED) {
        dbuf->used += 6;
        addstr(dbuf,"#<packed>");
      } else if (sz == SIZE_EXTENDED) {
        dbuf->used += 6;
        addstr(dbuf,"#<extended>");
      }
      break;
    }
    /* standrd PC stuff. */
    /*FALLTHROUGH*/
  case AR_IDX: 
    ext = read16(dbuf->val + 1 + dd);
    dbuf->used++;
    nval = dbuf->val + 2 + dd; /* set to possible displacements */
    scale = BITFIELD(ext,10,9);
    idx = BITFIELD(ext,14,12);
    
    if (ISBITSET(ext,8)) {
      /* either base disp, or memory indirect */
      bd = BITFIELD(ext,5,4);
      od = BITFIELD(ext,1,0);
      if (bd == 1)
        disp = 0;
      else if (bd == 2) {
        dbuf->used++;
        disp = *nval++;
      } else {
        dbuf->used += 2;
        disp = *(long *)nval;
        nval += 2;
      }

      if (od == 1) 
        odisp = 0;
      else if (od == 2) {
        dbuf->used++;
        odisp = *nval++;
      } else if (od == 3) {
        dbuf->used += 2;
        odisp = *(long *)nval;
        nval += 2;
      }
    } else {
      /*
       * We set od and bd to zero, these values are
       * not allowed in opcodes that use base and
       * outer displacement, e.g. we can tell if we
       * are using on of those modes by checking
       * `bd' and `od'.
       */
      od = 0; 
      bd = 0;
      disp = (char)BITFIELD(ext,7,0);
    }
    /*
     * write everything into buf
     */
    addchar('(');
    if (od)
      addchar('['); /* begin memory indirect xxx-indexed */
    prints(dbuf, disp,
        bd == 2 ? SIZE_WORD :
        bd == 3 ? SIZE_LONG :
        SIZE_BYTE);
    addchar(',');
    if (bd && ISBITSET(ext,7)) {
      addchar('z');
      if (mod != MOD_SPECIAL) 
        PRINT_AREG(dbuf,reg);
      else {
        addchar('p');
        addchar('c');
      } 
    } else if (mod == AR_IDX) 
      PRINT_AREG(dbuf, reg);
    else {
      addchar('p');
      addchar('c');
    }
    
    if (od && ISBITSET(ext,2)) 
      addchar(']'); /* post-indexed. */
    addchar(',');
    if (bd && ISBITSET(ext,6)) 
      addchar('0');
    else {
      if (0x8000 & ext)
        PRINT_AREG(dbuf, idx);
      else
        PRINT_DREG(dbuf, idx);
      addchar('.');
      addchar(0x800 & ext ? 'l' : 'w');
      if (scale) {
        addchar('*');
        addchar('0' + (1 << scale));
      }
    }
    if (od) {
      if (!ISBITSET(ext,2)) 
        addchar(']'); /* pre-indexed */
      addchar(',');
      prints(dbuf, odisp,
          od == 2 ? SIZE_WORD :
          od == 3 ? SIZE_LONG :
          SIZE_BYTE);
    }
    addchar(')');
    break;
  }
  *dbuf->casm = 0;
}     

  
/* mit syntax makes for spaghetti parses */
static void get_modregstr_mit(dis_buffer_t *dbuf,int bit, int mod, int sz, int dd)
{
  u_char scale, idx;
  const short *nval;
  u_short ext;
  int disp, odisp, bd, od, reg;
  
  disp = odisp = 0;
  /* check to see if we have been given the mod */
  if (mod != GETMOD_BEFORE && mod != GETMOD_AFTER)
    reg = BITFIELD(read16(dbuf->val), bit, bit-2);
  else if (mod == GETMOD_BEFORE) {
    mod = BITFIELD(read16(dbuf->val), bit, bit-2);
    reg = BITFIELD(read16(dbuf->val), bit-3, bit-5);
  } else {
    reg = BITFIELD(read16(dbuf->val), bit, bit-2);
    mod = BITFIELD(read16(dbuf->val), bit-3, bit-5);
  }
  switch (mod) {
  case DR_DIR:
  case AR_DIR:
    if (mod == DR_DIR)
      PRINT_DREG(dbuf, reg);
    else
      PRINT_AREG(dbuf, reg);
    break;
  case AR_DIS:
    dbuf->used++; /* tell caller we used an ext word. */
    disp = read16(dbuf->val + 1 + dd);
    /*FALLTHROUGH*/
  case AR_IND:
  case AR_INC:
  case AR_DEC:
    PRINT_AREG(dbuf, reg);
    addchar('@' );
    if (mod == AR_DEC)
      addchar('-');
    else if (mod == AR_INC)
      addchar('+');
    else if (mod == AR_DIS) {
      addchar('(');
      print_disp(dbuf, disp, SIZE_WORD, reg, dd);
      addchar(')');
    }
    break;
  /* mod 6 & 7 are the biggies. */
  case MOD_SPECIAL:
    if (reg == 0) {
      /* abs short addr */
      print_addr(dbuf, read16(dbuf->val + 1 + dd));
      dbuf->used++;
      break;
    } else if (reg == 1) {
      /* abs long addr */
      print_addr(dbuf, read32(dbuf->val + 1 + dd));
      dbuf->used += 2;
      break;
    } else if (reg == 2) {
      /* pc ind displ. pc@(xxx) */
      addstr(dbuf,"pc@(");
      print_disp(dbuf, read16(dbuf->val + 1 + dd), SIZE_WORD, -1, dd);
      dbuf->used++;
      addchar(')');
      break;
    } else if (reg == 4) {
      /* uses ``sz'' to figure imediate data. */
      if (sz == SIZE_BYTE) {
        addchar('#');
        prints(dbuf,
            *((char *)dbuf->val + 3 + (dd * 2)), sz);
        dbuf->used++;
      } else if (sz == SIZE_WORD) {
        addchar('#');
        prints(dbuf, read16(dbuf->val + 1 + dd), sz);
        dbuf->used++;
      } else if (sz == SIZE_LONG) {
        addchar('#');
        prints(dbuf, read32(dbuf->val + 1 + dd),
            sz);
        dbuf->used += 2;
      } else if (sz == SIZE_QUAD) {
        dbuf->used += 4;
        addstr(dbuf,"#<quad>");
      } else if (sz == SIZE_SINGLE) {
        dbuf->used += 2;
        addstr(dbuf,"#<single>");
      } else if (sz == SIZE_DOUBLE) {
        dbuf->used += 4;
        addstr(dbuf,"#<double>");
      } else if (sz == SIZE_PACKED) {
        dbuf->used += 6;
        addstr(dbuf,"#<packed>");
      } else if (sz == SIZE_EXTENDED) {
        dbuf->used += 6;
        addstr(dbuf,"#<extended>");
      }
      break;
    }
    /* standrd PC stuff. */
    /*FALLTHROUGH*/
  case AR_IDX: 
    dbuf->used++; /* indicate use of ext word. */
    ext = read16(dbuf->val + 1 + dd);
    nval = dbuf->val + 2 + dd; /* set to possible displacements */
    scale = BITFIELD(ext,10,9);
    idx = BITFIELD(ext,14,12);
    
    if (ISBITSET(ext,8)) {
      /* either base disp, or memory indirect */
      bd = BITFIELD(ext,5,4);
      od = BITFIELD(ext,1,0);
      if (bd == 1)
        disp = 0;
      else if (bd == 2) {
        dbuf->used++;
        disp = *nval++;
      } else {
        dbuf->used += 2;
        disp = *(long *)nval;
        nval += 2;
      }

      if (od == 1) 
        odisp = 0;
      else if (od == 2) {
        dbuf->used++;
        odisp = *nval++;
      } else if (od == 3) {
        dbuf->used += 2;
        odisp = *(long *)nval;
        nval += 2;
      }
    } else {
      /*
       * We set od and bd to zero, these values are
       * not allowed in opcodes that use base and
       * outer displacement, e.g. we can tell if we
       * are using on of those modes by checking
       * `bd' and `od'.
       */
      od = 0; 
      bd = 0;
      disp = (char)BITFIELD(ext,7,0);
    }
    /*
     * write everything into buf
     */
    /* if base register not suppresed */
    if (mod == AR_IDX && (!bd || !ISBITSET(ext,7)))
      PRINT_AREG(dbuf, reg);
    else if (mod == MOD_SPECIAL && ISBITSET(ext,7)) {
      addchar('z');
      addchar('p');
      addchar('c');
    } else if (mod == MOD_SPECIAL) {
      addchar('p');
      addchar('c');
    }
    addchar('@');
    addchar('(');
    
    if (bd && bd != 1) {
      prints(dbuf, disp,
          bd == 2 ? SIZE_WORD :
          bd == 3 ? SIZE_LONG :
          SIZE_BYTE);
      if (od && !ISBITSET(ext,6) && !ISBITSET(ext,2)) 
        /* Pre-indexed and not suppressing index */
        addchar(',');
      else if (od && ISBITSET(ext,2)) {
        /* Post-indexed */
        addchar(')');
        addchar('@');
        addchar('(');
      } else if (!od)
        addchar(',');
    } else if (!bd) {
            /* don't forget simple 8 bit displacement. */
      prints(dbuf, disp,
          bd == 2 ? SIZE_WORD :
          bd == 3 ? SIZE_LONG :
          SIZE_BYTE);
      addchar(',');
    }
    
    /* Post-indexed? */
    if (od && ISBITSET(ext,2)) {
      /* have displacement? */
      if (od != 1) {
        prints(dbuf, odisp,
            od == 2 ? SIZE_WORD :
            od == 3 ? SIZE_LONG :
            SIZE_BYTE);
        addchar(',');
      }
    } 
      
    if (!bd || !ISBITSET(ext,6)) {
      if (ISBITSET(ext,15))
        PRINT_AREG(dbuf,idx);
      else
        PRINT_DREG(dbuf,idx);
      addchar(':');
      addchar(ISBITSET(ext,11) ? 'l' : 'w');
      if (scale) {
        addchar(':');
        addchar('0' + (1 << scale));
      }
    }
    /* pre-indexed? */
    if (od && !ISBITSET(ext,2)) {
      if (od != 1) {
        addchar(')');
        addchar('@');
        addchar('(');
        prints(dbuf, odisp,
            od == 2 ? SIZE_WORD :
            od == 3 ? SIZE_LONG :
            SIZE_BYTE);
      }
    }
    addchar(')');
    break;
  }
  *dbuf->casm = 0;
}   


/*
 * Given a disassembly buffer ``dbuf'' and a starting bit of the
 * mod|reg field ``bit'' (or just a reg field if ``mod'' is not
 * GETMOD_BEFORE or GETMOD_AFTER), disassemble and write into ``dbuf''
 * the mod|reg pair.
 */
static void get_modregstr(dis_buffer_t *dbuf, int bit, int mod, int sz, int dispdisp)
{
  if (dbuf->mit) 
    get_modregstr_mit(dbuf,bit,mod,sz,dispdisp);
  else 
    get_modregstr_moto(dbuf,bit,mod,sz,dispdisp);
}


/*
 * given a bit position ``bit'' in the current ``dbuf''->val
 * and the ``base'' string of the opcode, append the full
 * opcode name including condition found at ``bit''.
 */
static void make_cond(dis_buffer_t *dbuf, int bit, char *base)
{
  int cc;
  const char *ccs;

  cc = BITFIELD(read16(dbuf->val),bit,bit-3);
  ccs = cc_table[cc&15];

  addstr(dbuf, base);
  addstr(dbuf, ccs);
}


static void print_fcond(dis_buffer_t *dbuf, char cp)
{
  addstr(dbuf,fpcc_table[cp&31]);   /* XXX - not 63 ?*/
}


static void print_mcond(dis_buffer_t *dbuf, char cp)
{
  addstr(dbuf,mmcc_table[cp&15]);
}


/*
 * given dis_buffer_t ``dbuf'' get the immediate value from the
 * extension words following current instruction, output a
 * hash (``#'') sign and the value.  Increment the ``dbuf''->used
 * field accordingly.
 */
static void get_immed(dis_buffer_t *dbuf, int sz)
{
  addchar('#');
  switch (sz) {
  case SIZE_BYTE:
    prints(dbuf, BITFIELD(read16(dbuf->val + 1),7,0), SIZE_BYTE);
    dbuf->used++;
    break;
  case SIZE_WORD:
    prints(dbuf, read16(dbuf->val + 1), SIZE_WORD);
    dbuf->used++;
    break;
  case SIZE_LONG:
    prints(dbuf, read32(dbuf->val + 1), SIZE_LONG);
    dbuf->used += 2;
    break;
  }
  return;
}


static void get_fpustdGEN(dis_buffer_t *dbuf, u_short ext, const char *name)
{
  int sz;
  
  /*
   * If bit six is set, its a 040 s/d opcode, then if bit 2 is
   * set its "d".  This is not documented, however thats the way
   * it is.
   */

  sz = 0;
  addchar(*name++);
  if (ISBITSET(ext,6)) {
    if(ISBITSET(ext,2))
      addchar('d');
    else
      addchar('s');
  }
  addstr(dbuf,name);
  addchar('.');

  if (ISBITSET(ext,14)) {
    switch (BITFIELD(ext,12,10)) {
    case 0:
      addchar('l');
      sz = SIZE_LONG;
      break;
    case 1:
      addchar('s');
      sz = SIZE_SINGLE;
      break;
    case 2:
      addchar('x');
      sz = SIZE_EXTENDED;
      break;
    case 3:
      addchar('p');
      sz = SIZE_PACKED;
      break;
    case 4:
      addchar('w');
      sz = SIZE_WORD;
      break;
    case 5:
      addchar('d');
      sz = SIZE_DOUBLE;
      break;
    case 6:
      addchar('b');
      sz = SIZE_BYTE;
      break;
    }
    addchar('\t');
    get_modregstr(dbuf, 5, GETMOD_BEFORE, sz, 1);
    if (BITFIELD(ext,6,3) == 6) {
      addchar(',');
      PRINT_FPREG(dbuf, BITFIELD(ext,2,0));
      addchar(':');
      PRINT_FPREG(dbuf, BITFIELD(ext,9,7));
    } else if (BITFIELD(ext,5,0) != FTST) {
      addchar(',');
      PRINT_FPREG(dbuf, BITFIELD(ext,9,7));
    }
  } else {
    addchar('x');
    addchar('\t');
    PRINT_FPREG(dbuf, BITFIELD(ext,12,10));
    if (BITFIELD(ext,6,3) == 6) {
      addchar(',');
      PRINT_FPREG(dbuf, BITFIELD(ext,2,0));
      addchar(':');
      PRINT_FPREG(dbuf, BITFIELD(ext,9,7));
    } else if (BITFIELD(ext,5,0) != FTST) {
      addchar(',');
      PRINT_FPREG(dbuf, BITFIELD(ext,9,7));
    }
  }
}


/*
 * given value ``disp'' print it to ``dbuf''->buf. ``rel'' is a
 * register number 0-7 (a0-a7), or -1 (pc). Thus possible extra info
 * could be output to the ``dbuf''->info buffer.
 */
static void print_disp(dis_buffer_t *dbuf, int disp, int sz, int rel, int dd)
{
  char *symname;
  u_long nv = 0;
  u_long diff;

  if (dbuf == NULL)
    return;
    
  if (sz == SIZE_WORD)
    disp = (int)((short)disp);
  if (rel == -1) {
    /*phx - use sval to print real destination address */
    nv = disp + (u_long)dbuf->sval + 2*(dd+1);
    printu(dbuf, nv, SIZE_LONG);
  }
  else {
    if (dbuf->dp->get_areg)
      nv = disp + dbuf->dp->get_areg(rel);
    prints(dbuf, disp, sz);
  }
    
  diff = INT_MAX;
  symname = NULL;

  if (dbuf && dbuf->dp && dbuf->dp->find_symbol) {
    if ((symname = dbuf->dp->find_symbol(nv,&diff))!= NULL) {
      iaddstr(dbuf, "disp:");
      iaddstr(dbuf, symname);
      iaddchar('+');
      iprintu(dbuf, diff, SIZE_LONG);
      iaddchar(' ');
      *dbuf->cinfo = 0;
    }
  }
}

static void print_addr(dis_buffer_t *dbuf, u_long addr)
{
  u_long diff = INT_MAX;
  char *symname = NULL;
        
#if 0
  diff = INT_MAX;
  symname = NULL;
#endif
  if (dbuf->dp->find_symbol) {
    if (symname == dbuf->dp->find_symbol(addr,&diff)) {
      if (diff == 0)
        addstr(dbuf,symname);
      else {
        addchar('<');
        addstr(dbuf,symname);
        addchar('+');
        printu(dbuf, diff, SIZE_LONG);
        addchar('>');
        *dbuf->casm = 0;
      }
      iaddstr(dbuf,"addr:");
      iprintu(dbuf, addr, SIZE_LONG);
      iaddchar(' ');
      *dbuf->cinfo = 0;
      return;
    } 
  }
  printu(dbuf, addr, SIZE_LONG);
}


static void prints(dis_buffer_t *dbuf, int val, int sz)
{
  if (val == 0) {
    dbuf->casm[0] = '0';
    dbuf->casm[1] = 0;
  } else if (sz == SIZE_BYTE) 
    prints_wb(dbuf, (char)val, sz, db_radix);
  else if (sz == SIZE_WORD) 
    prints_wb(dbuf, (short)val, sz, db_radix);
  else 
    prints_wb(dbuf, (long)val, sz, db_radix);
  
  dbuf->casm = &dbuf->casm[strlen(dbuf->casm)];
}


#if 0
static void iprints(dis_buffer_t *dbuf, int val, int sz)
{
  if (val == 0) {
    dbuf->cinfo[0] = '0';
    dbuf->cinfo[1] = 0;
  } else if (sz == SIZE_BYTE) 
    iprints_wb(dbuf, (char)val, sz, db_radix);
  else if (sz == SIZE_WORD) 
    iprints_wb(dbuf, (short)val, sz, db_radix);
  else 
    iprints_wb(dbuf, (long)val, sz, db_radix);
  
  dbuf->cinfo = &dbuf->cinfo[strlen(dbuf->cinfo)];
}
#endif


static void printu(dis_buffer_t *dbuf, u_int val, int sz)
{
  if (val == 0) {
    dbuf->casm[0] = '0';
    dbuf->casm[1] = 0;
  } else if (sz == SIZE_BYTE) 
    printu_wb(dbuf, (u_char)val, sz, db_radix);
  else if (sz == SIZE_WORD) 
    printu_wb(dbuf, (u_short)val, sz, db_radix);
  else 
    printu_wb(dbuf, (u_long)val, sz, db_radix);
  dbuf->casm = &dbuf->casm[strlen(dbuf->casm)];
}


static void iprintu(dis_buffer_t *dbuf, u_int val, int sz)
{
  if (val == 0) {
    dbuf->cinfo[0] = '0';
    dbuf->cinfo[1] = 0;
  } else if (sz == SIZE_BYTE) 
    iprintu_wb(dbuf, (u_char)val, sz, db_radix);
  else if (sz == SIZE_WORD) 
    iprintu_wb(dbuf, (u_short)val, sz, db_radix);
  else 
    iprintu_wb(dbuf, (u_long)val, sz, db_radix);
  dbuf->cinfo = &dbuf->cinfo[strlen(dbuf->cinfo)];
}


static void printu_wb(dis_buffer_t *dbuf, u_int val, int sz, int base)
{
  static char buf[sizeof(long) * NBBY / 3 + 2];
  char *p, ch;

  if (base != 10) {
    addchar('0');
    if (base != 8) {
      base = 16;
      addchar('x');
    }
  }

  p = buf;
  do {
    *++p = "0123456789abcdef"[val % base];
  } while (val /= base);

  while ((ch = *p--))
    addchar(ch);
  
  *dbuf->casm = 0;
}


static void prints_wb(dis_buffer_t *dbuf, int val, int sz, int base)
{
  if (val < 0) {
    addchar('-');
    val = -val;
  }
  printu_wb(dbuf, val, sz, base);
}


static void iprintu_wb(dis_buffer_t *dbuf, u_int val, int sz, int base)
{
  static char buf[sizeof(long) * NBBY / 3 + 2];
  char *p, ch;

  if (base != 10) {
    iaddchar('0');
    if (base != 8) {
      base = 16;
      iaddchar('x');
    }
  }

  p = buf;
  do {
    *++p = "0123456789abcdef"[val % base];
  } while (val /= base);

  while ((ch = *p--))
    iaddchar(ch);
  
  *dbuf->cinfo = 0;
}


#if 0
static void iprints_wb(dis_buffer_t *dbuf, int val, int sz, int base)
{
  if (val < 0) {
    iaddchar('-');
    val = -val;
  }
  iprintu_wb(dbuf, val, sz, base);
}
#endif


static void prints_bf(dis_buffer_t *dbuf, int val, int sb, int eb)
{
  if (ISBITSET(val,sb)) 
    val = (~0 & ~BITFIELD(~0, sb, eb)) | BITFIELD(val, sb, eb);
  else
    val = BITFIELD(val,sb,eb);
  
  prints(dbuf, val, SIZE_LONG);
}


static void printu_bf(dis_buffer_t *dbuf, u_int val, int sb, int eb)
{
  printu(dbuf,BITFIELD(val,sb,eb),SIZE_LONG);
} 


/* prints -(Ax),-(Ay) (phx)*/
static void print_AxAyPredec(dis_buffer_t *dbuf, u_short opc)
{
  if (dbuf->mit) {
    PRINT_AREG(dbuf,BITFIELD(opc,2,0));
    addstr(dbuf, "@-,");
    PRINT_AREG(dbuf,BITFIELD(opc,11,9));
    addstr(dbuf, "@-");
  } else {
    addstr(dbuf, "-(");
    PRINT_AREG(dbuf,BITFIELD(opc,2,0));
    addstr(dbuf, "),-(");
    PRINT_AREG(dbuf,BITFIELD(opc,11,9));
    addchar(')');
  }
  *dbuf->casm = 0;
}


/* prints Dx,Dy (phx)*/
static void print_DxDy(dis_buffer_t *dbuf, u_short opc)
{
  PRINT_DREG(dbuf,BITFIELD(opc,2,0));
  addchar(',');
  PRINT_DREG(dbuf,BITFIELD(opc,11,9));
}


/* prints (Rn) or (Rn)+  (phx)*/
static void print_RnPlus(dis_buffer_t *dbuf, u_short opc, int An, int sb, int inc)
{
  if (dbuf->mit) {
    if (An)
      PRINT_AREG(dbuf, BITFIELD(opc,sb,sb-2));
    else
      PRINT_DREG(dbuf, BITFIELD(opc,sb,sb-2));
    addchar('@');
    if (inc)
      addchar('+');
  } else {
    addchar('(');
    if (An)
      PRINT_AREG(dbuf, BITFIELD(opc,sb,sb-2));
    else
      PRINT_DREG(dbuf, BITFIELD(opc,sb,sb-2));
    addchar(')');
    if (inc)
      addchar('+');
  }
  *dbuf->casm = 0;
}
