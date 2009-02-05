/* $VER: ppc_disasm.c V1.4 (29.08.2001)
 *
 * Disassembler module for the PowerPC microprocessor family
 * Copyright (c) 1998-2001  Frank Wille
 *
 * ppc_disasm.c is freeware and may be freely redistributed as long as
 * no modifications are made and nothing is charged for it.
 * Non-commercial usage is allowed without any restrictions.
 * EVERY PRODUCT OR PROGRAM DERIVED DIRECTLY FROM MY SOURCE MAY NOT BE
 * SOLD COMMERCIALLY WITHOUT PERMISSION FROM THE AUTHOR.
 *
 *
 * v1.4  (29.08.2001) phx
 *       AltiVec support.
 * v1.3  (09.03.2001) phx
 *       Last two operands in 4-operand float instructions were swapped.
 * v1.2  (09.11.2000) phx
 *       Fixed syntax of mffs, mtfsf and mtfsfi.
 * v1.1  (19.02.2000) phx
 *       fabs wasn't recognized.
 * v1.0  (30.01.2000) phx
 *       stfsx, stfdx, lfsx, lfdx, stfsux, stfdux, lfsux, lfdux, etc.
 *       printed "rd,ra,rb" as operands instead "fd,ra,rb".
 * v0.4  (01.06.1999) phx
 *       'stwm' shoud have been 'stmw'.
 * v0.3  (17.11.1998) phx
 *       The OE-types (e.g. addo, subfeo, etc.) didn't work for all
 *       instructions.
 *       AA-form branches have an absolute destination.
 *       addze and subfze must not have a third operand.
 *       sc was not recognized.
 * v0.2  (29.05.1998) phx
 *       Sign error. SUBI got negative immediate values.
 * v0.1  (23.05.1998) phx
 *       First version, which implements all PowerPC instructions.
 * v0.0  (09.05.1998) phx
 *       File created.
 */

#define PPC_DISASM_C
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "ppc_disasm.h"


static char *trap_condition[32] = {
  NULL,"lgt","llt",NULL,"eq","lge","lle",NULL,
  "gt",NULL,NULL,NULL,"ge",NULL,NULL,NULL,
  "lt",NULL,NULL,NULL,"le",NULL,NULL,NULL,
  "ne",NULL,NULL,NULL,NULL,NULL,NULL,NULL
};

static char *cmpname[4] = {
  "cmpw","cmpd","cmplw","cmpld"
};

static char *b_ext[4] = {
  "","l","a","la"
};

static char *b_condition[8] = {
  "ge","le","ne","ns","lt","gt","eq","so"
};

static char *b_decr[16] = {
  "nzf","zf",NULL,NULL,"nzt","zt",NULL,NULL,
  "nz","z",NULL,NULL,"nz","z",NULL,NULL
};

static char *regsel[2] = {
  "","r"
};

static char *oesel[2] = {
  "","o"
};

static char *rcsel[2] = {
  "","."
};

static char *ldstnames[] = {
  "lwz","lwzu","lbz","lbzu","stw","stwu","stb","stbu","lhz","lhzu",
  "lha","lhau","sth","sthu","lmw","stmw","lfs","lfsu","lfd","lfdu",
  "stfs","stfsu","stfd","stfdu"
};

static char *vmnames[] = {
  "mhaddshs","mhraddshs","mladduhm",NULL,"msumubm","msummbm",
  "msumuhm","msumuhs","msumshm","msumshs","sel","perm",
  "sldoi",NULL,"maddfp","nmsubfp"
};



static void ierror(char *errtxt,...)
/* display internal error and quit program */
{
  va_list vl;

  fprintf(stderr,"\nINTERNAL ERROR (PPC disassembler): ");
  va_start(vl,errtxt);
  vfprintf(stderr,errtxt,vl);
  va_end(vl);
  fprintf(stderr,".\nAborting.\n");
  exit(EXIT_FAILURE);
}


static ppc_word swapda(ppc_word w)
{
  return ((w&0xfc00ffff)|((w&PPCAMASK)<<5)|((w&PPCDMASK)>>5));
}


static ppc_word swapab(ppc_word w)
{
  return ((w&0xffe007ff)|((w&PPCBMASK)<<5)|((w&PPCAMASK)>>5));
}


static void ill(struct DisasmPara_PPC *dp,ppc_word in)
{
  strcpy(dp->opcode,".word");
  sprintf(dp->operands,"0x%08lx",(unsigned long)in);
  dp->flags |= PPCF_ILLEGAL;
}


static void imm(struct DisasmPara_PPC *dp,ppc_word in,int uimm,int type)
/* Generate immediate instruction operand. */
/* type 0: D-mode, D,A,imm */
/* type 1: S-mode, A,S,imm */
/* type 2: S/D register is ignored (trap,cmpi) */
/* type 3: A register is ignored (li) */
{
  int i = (int)(in & 0xffff);

  dp->type = PPCINSTR_IMM;
  if (!uimm) {
    if (i > 0x7fff)
      i -= 0x10000;
  }
  else
    dp->flags |= PPCF_UNSIGNED;
  dp->displacement = i;

  switch (type) {
    case 0:
      sprintf(dp->operands,"r%d,r%d,%d",(int)PPCGETD(in),(int)PPCGETA(in),i);
      break;
    case 1:
      sprintf(dp->operands,"r%d,r%d,%d",(int)PPCGETA(in),(int)PPCGETD(in),i);
      break;
    case 2:
      sprintf(dp->operands,"r%d,%d",(int)PPCGETA(in),i);
      break;
    case 3:
      sprintf(dp->operands,"r%d,%d",(int)PPCGETD(in),i);
      break;
    default:
      ierror("imm(): Wrong type");
      break;
  }
}


static void ra_rb(char *s,ppc_word in)
{
  sprintf(s,"r%d,r%d",(int)PPCGETA(in),(int)PPCGETB(in));
}


static char *rd_ra_rb(char *s,ppc_word in,int mask)
{
  static const char *fmt = "r%d,";

  if (mask) {
    if (mask & 4)
      s += sprintf(s,fmt,(int)PPCGETD(in));
    if (mask & 2)
      s += sprintf(s,fmt,(int)PPCGETA(in));
    if (mask & 1)
      s += sprintf(s,fmt,(int)PPCGETB(in));
    *--s = '\0';
  }
  else
    *s = '\0';
  return (s);
}


static char *fd_ra_rb(char *s,ppc_word in,int mask)
{
  static const char *ffmt = "f%d,";
  static const char *rfmt = "r%d,";

  if (mask) {
    if (mask & 4)
      s += sprintf(s,ffmt,(int)PPCGETD(in));
    if (mask & 2)
      s += sprintf(s,rfmt,(int)PPCGETA(in));
    if (mask & 1)
      s += sprintf(s,rfmt,(int)PPCGETB(in));
    *--s = '\0';
  }
  else
    *s = '\0';
  return (s);
}


static char *vd_va_vb(char *s,ppc_word in,int mask)
{
  static const char *fmt = "v%d,";

  if (mask) {
    if (mask & 4)
      s += sprintf(s,fmt,(int)PPCGETD(in));

    if (mask & 2) {
      if (mask & 16) {  /* A = SIMM */
        int a = PPCGETA(in);
        s += sprintf(s,fmt+1,(a>15)?(a-32):a);
      }
      else if (mask & 8)  /* A = UIMM */
        s += sprintf(s,fmt+1,(int)PPCGETA(in));
      else
        s += sprintf(s,fmt,(int)PPCGETA(in));
    }

    if (mask & 1)
      s += sprintf(s,fmt,(int)PPCGETB(in));
    *--s = '\0';
  }
  else
    *s = '\0';
  return (s);
}


static void trapi(struct DisasmPara_PPC *dp,ppc_word in,unsigned char dmode)
{
  char *cnd;

  if ((cnd = trap_condition[PPCGETD(in)])) {
    dp->flags |= dmode;
    sprintf(dp->opcode,"t%c%s",dmode?'d':'w',cnd);
    imm(dp,in,0,2);
  }
  else
    ill(dp,in);
}


static void cmpi(struct DisasmPara_PPC *dp,ppc_word in,int uimm)
{
  char *oper = dp->operands;
  int i = (int)PPCGETL(in);

  if (i < 2) {
    if (i)
      dp->flags |= PPCF_64;
    sprintf(dp->opcode,"%si",cmpname[uimm*2+i]);
    if ((i = (int)PPCGETCRD(in))) {
      sprintf(oper,"cr%c,",'0'+i);
      dp->operands += 4;
    }
    imm(dp,in,uimm,2);
    dp->operands = oper;
  }
  else
    ill(dp,in);
}


static void addi(struct DisasmPara_PPC *dp,ppc_word in,char *ext)
{
  if ((in&0x08000000) && !PPCGETA(in)) {
    sprintf(dp->opcode,"l%s",ext);  /* li, lis */
    imm(dp,in,0,3);
  }
  else {
    sprintf(dp->opcode,"%s%s",(in&0x8000)?"sub":"add",ext);
    if (in & 0x8000)
      in = (in^0xffff) + 1;
    imm(dp,in,1,0);
  }
}


static int branch(struct DisasmPara_PPC *dp,ppc_word in,
                    char *bname,int aform,int bdisp)
/* build a branch instr. and return number of chars written to operand */
{
  int bo = (int)PPCGETD(in);
  int bi = (int)PPCGETA(in);
  char y = (char)(bo & 1);
  int opercnt = 0;
  char *ext = b_ext[aform*2+(int)(in&1)];

  if (bdisp < 0)
    y ^= 1;
  y = y ? '+':'-';

  if (bo & 4) {
    /* standard case - no decrement */
    if (bo & 16) {
      /* branch always */
      if (PPCGETIDX(in) != 16) {
        sprintf(dp->opcode,"b%s%s",bname,ext);
      }
      else {
        sprintf(dp->opcode,"bc%s",ext);
        opercnt = sprintf(dp->operands,"%d,%d",bo,bi);
      }
    }
    else {
      /* branch conditional */
      sprintf(dp->opcode,"b%s%s%s%c",b_condition[((bo&8)>>1)+(bi&3)],
              bname,ext,y);
      if (bi >= 4)
        opercnt = sprintf(dp->operands,"cr%d",bi>>2);
    }
  }

  else {
    /* CTR is decremented and checked */
    sprintf(dp->opcode,"bd%s%s%s%c",b_decr[bo>>1],bname,ext,y);
    if (!(bo & 16))
      opercnt = sprintf(dp->operands,"%d",bi);
  }

  return (opercnt);
}


static void bc(struct DisasmPara_PPC *dp,ppc_word in)
{
  int d = (int)(in & 0xfffc);
  int offs;
  char *oper = dp->operands;

  if (d >= 0x8000)
    d -= 0x10000;
  if ((offs = branch(dp,in,"",(in&2)?1:0,d))) {
    oper += offs;
    *oper++ = ',';
  }
  if (in & 2)  /* AA ? */
    sprintf(dp->operands,"0x%lx",(unsigned long)d);
  else
    sprintf(oper,"0x%lx",(unsigned long)((char *)dp->iaddr + d));
  dp->type = PPCINSTR_BRANCH;
  dp->displacement = (ppc_word)d;
}


static void bli(struct DisasmPara_PPC *dp,ppc_word in)
{
  int d = (int)(in & 0x3fffffc);

  if (d >= 0x2000000)
    d -= 0x4000000;
  sprintf(dp->opcode,"b%s",b_ext[in&3]);
  if (in & 2)  /* AA ? */
    sprintf(dp->operands,"0x%lx",(unsigned long)d);
  else
    sprintf(dp->operands,"0x%lx",(unsigned long)((char *)dp->iaddr + d));
  dp->type = PPCINSTR_BRANCH;
  dp->displacement = (ppc_word)d;
}


static void mcrf(struct DisasmPara_PPC *dp,ppc_word in,char c)
{
  if (!(in & 0x0063f801)) {
    sprintf(dp->opcode,"mcrf%c",c);
    sprintf(dp->operands,"cr%d,cr%d",(int)PPCGETCRD(in),(int)PPCGETCRA(in));
  }
  else
    ill(dp,in);
}


static void crop(struct DisasmPara_PPC *dp,ppc_word in,char *n1,char *n2)
{
  int crd = (int)PPCGETD(in);
  int cra = (int)PPCGETA(in);
  int crb = (int)PPCGETB(in);

  if (!(in & 1)) {
    sprintf(dp->opcode,"cr%s",(cra==crb && n2)?n2:n1);
    if (cra == crb && n2)
      sprintf(dp->operands,"%d,%d",crd,cra);
    else
      sprintf(dp->operands,"%d,%d,%d",crd,cra,crb);
  }
  else
    ill(dp,in);
}


static void nooper(struct DisasmPara_PPC *dp,ppc_word in,char *name,
                   unsigned char dmode)
{
  if (in & (PPCDMASK|PPCAMASK|PPCBMASK|1)) {
    ill(dp,in);
  }
  else {
    dp->flags |= dmode;
    strcpy(dp->opcode,name);
  }
}


static void rlw(struct DisasmPara_PPC *dp,ppc_word in,char *name,int i)
{
  int s = (int)PPCGETD(in);
  int a = (int)PPCGETA(in);
  int bsh = (int)PPCGETB(in);
  int mb = (int)PPCGETC(in);
  int me = (int)PPCGETM(in);

  sprintf(dp->opcode,"rlw%s%c",name,in&1?'.':'\0');
  sprintf(dp->operands,"r%d,r%d,%s%d,%d,%d",a,s,regsel[i],bsh,mb,me);
}


static void ori(struct DisasmPara_PPC *dp,ppc_word in,char *name)
{
  strcpy(dp->opcode,name);
  imm(dp,in,1,1);
}


static void rld(struct DisasmPara_PPC *dp,ppc_word in,char *name,int i)
{
  int s = (int)PPCGETD(in);
  int a = (int)PPCGETA(in);
  int bsh = i ? (int)PPCGETB(in) : (int)(((in&2)<<4)+PPCGETB(in));
  int m = (int)(in&0x7e0)>>5;

  dp->flags |= PPCF_64;
  sprintf(dp->opcode,"rld%s%c",name,in&1?'.':'\0');
  sprintf(dp->operands,"r%d,r%d,%s%d,%d",a,s,regsel[i],bsh,m);
}


static void cmp(struct DisasmPara_PPC *dp,ppc_word in)
{
  char *oper = dp->operands;
  int i = (int)PPCGETL(in);

  if (i < 2) {
    if (i)
      dp->flags |= PPCF_64;
    strcpy(dp->opcode,cmpname[((in&PPCIDX2MASK)?2:0)+i]);
    if ((i = (int)PPCGETCRD(in)))
      oper += sprintf(oper,"cr%c,",'0'+i);
    ra_rb(oper,in);
  }
  else
    ill(dp,in);
}


static void trap(struct DisasmPara_PPC *dp,ppc_word in,unsigned char dmode)
{
  char *cnd;
  int to = (int)PPCGETD(in);

  if ((cnd = trap_condition[to])) {
    dp->flags |= dmode;
    sprintf(dp->opcode,"t%c%s",dmode?'d':'w',cnd);
    ra_rb(dp->operands,in);
  }
  else {
    if (to == 31) {
      if (dmode) {
        dp->flags |= dmode;
        strcpy(dp->opcode,"td");
        strcpy(dp->operands,"31,0,0");
      }
      else
        strcpy(dp->opcode,"trap");
    }
    else
      ill(dp,in);
  }
}


static void dab(struct DisasmPara_PPC *dp,ppc_word in,char *name,int mask,
                int smode,int chkoe,int chkrc,unsigned char dmode)
/* standard instruction: xxxx rD,rA,rB */
{
  if (chkrc>=0 && (in&1)!=chkrc) {
    ill(dp,in);
  }
  else {
    dp->flags |= dmode;
    if (smode)
      in = swapda(in);  /* rA,rS,rB */
    sprintf(dp->opcode,"%s%s%s",name,
            oesel[chkoe&&(in&PPCOE)],rcsel[(chkrc<0)&&(in&1)]);
    rd_ra_rb(dp->operands,in,mask);
  }
}


static void rrn(struct DisasmPara_PPC *dp,ppc_word in,char *name,
                int smode,int chkoe,int chkrc,unsigned char dmode)
/* Last operand is no register: xxxx rD,rA,NB */
{
  char *s;

  if (chkrc>=0 && (in&1)!=chkrc) {
    ill(dp,in);
  }
  else {
    dp->flags |= dmode;
    if (smode)
      in = swapda(in);  /* rA,rS,NB */
    sprintf(dp->opcode,"%s%s%s",name,
            oesel[chkoe&&(in&PPCOE)],rcsel[(chkrc<0)&&(in&1)]);
    s = rd_ra_rb(dp->operands,in,6);
    sprintf(s,",%d",(int)PPCGETB(in));
  }
}


static void mtcr(struct DisasmPara_PPC *dp,ppc_word in)
{
  int s = (int)PPCGETD(in);
  int crm = (int)(in&0x000ff000)>>12;
  char *oper = dp->operands;

  if (in & 0x00100801) {
    ill(dp,in);
  }
  else {
    sprintf(dp->opcode,"mtcr%c",crm==0xff?'\0':'f');
    if (crm != 0xff)
      oper += sprintf(oper,"0x%02x,",crm);
    sprintf(oper,"r%d",s);
  }
}


static void msr(struct DisasmPara_PPC *dp,ppc_word in,int smode)
{
  int s = (int)PPCGETD(in);
  int sr = (int)(in&0x000f0000)>>16;

  if (in & 0x0010f801) {
    ill(dp,in);
  }
  else {
    dp->flags |= PPCF_SUPER;
    sprintf(dp->opcode,"m%csr",smode?'t':'f');
    if (smode)
      sprintf(dp->operands,"%d,r%d",sr,s);
    else
      sprintf(dp->operands,"r%d,%d",s,sr);
  }
}


static void mspr(struct DisasmPara_PPC *dp,ppc_word in,int smode)
{
  int d = (int)PPCGETD(in);
  int spr = (int)((PPCGETB(in)<<5)+PPCGETA(in));
  int fmt = 0;
  char *x;

  if (in & 1) {
    ill(dp,in);
  }

  else {
    if (spr!=1 && spr!=8 && spr!=9)
      dp->flags |= PPCF_SUPER;
    switch (spr) {
      case 1:
        x = "xer";
        break;
      case 8:
        x = "lr";
        break;
      case 9:
        x = "ctr";
        break;
      case 18:
        x = "dsisr";
        break;
      case 19:
        x = "dar";
        break;
      case 22:
        x = "dec";
        break;
      case 25:
        x = "sdr1";
        break;
      case 26:
        x = "srr0";
        break;
      case 27:
        x = "srr1";
        break;
      case 272:
      case 273:
      case 274:
      case 275:
        x = "sprg";
        spr -= 272;
        fmt = 1;
        break;
      case 280:
        x = "asr";
        break;
      case 282:
        x = "ear";
        break;
      case 284:
        x = "tbl";
        break;
      case 285:
        x = "tbu";
        break;
      case 528:
      case 530:
      case 532:
      case 534:
        x = "ibatu";
        spr = (spr-528)>>1;
        fmt = 1;
        break;
      case 529:
      case 531:
      case 533:
      case 535:
        x = "ibatl";
        spr = (spr-529)>>1;
        fmt = 1;
        break;
      case 536:
      case 538:
      case 540:
      case 542:
        x = "dbatu";
        spr = (spr-536)>>1;
        fmt = 1;
        break;
      case 537:
      case 539:
      case 541:
      case 543:
        x = "dbatl";
        spr = (spr-537)>>1;
        fmt = 1;
        break;
      case 1013:
        x = "dabr";
        break;
      default:
        x = "spr";
        fmt = 1;
        break;
    }

    sprintf(dp->opcode,"m%c%s",smode?'t':'f',x);
    if (fmt) {
      if (smode)
        sprintf(dp->operands,"%d,r%d",spr,d);
      else
        sprintf(dp->operands,"r%d,%d",d,spr);
    }
    else
      sprintf(dp->operands,"r%d",d);
  }
}


static void mtb(struct DisasmPara_PPC *dp,ppc_word in)
{
  int d = (int)PPCGETD(in);
  int tbr = (int)((PPCGETB(in)<<5)+PPCGETA(in));
  char *s = dp->operands;
  char x;

  if (in & 1) {
    ill(dp,in);
  }

  else {
    s += sprintf(s,"r%d",d);
    switch (tbr) {
      case 268:
        x = 'l';
        break;
      case 269:
        x = 'u';
        break;
      default:
        x = '\0';
        dp->flags |= PPCF_SUPER;
        sprintf(s,",%d",tbr);
        break;
    }
    sprintf(dp->opcode,"mftb%c",x);
  }
}


static void sradi(struct DisasmPara_PPC *dp,ppc_word in)
{
  int s = (int)PPCGETD(in);
  int a = (int)PPCGETA(in);
  int bsh = (int)(((in&2)<<4)+PPCGETB(in));

  dp->flags |= PPCF_64;
  sprintf(dp->opcode,"sradi%c",in&1?'.':'\0');
  sprintf(dp->operands,"r%d,r%d,%d",a,s,bsh);
}


static void ldst(struct DisasmPara_PPC *dp,ppc_word in,char *name,
                 char reg,unsigned char dmode)
{
  int s = (int)PPCGETD(in);
  int a = (int)PPCGETA(in);
  int d = (ppc_word)(in & 0xffff);

  dp->type = PPCINSTR_LDST;
  dp->flags |= dmode;
  dp->sreg = (short)a;
  if (d >= 0x8000)
    d -= 0x10000;
  dp->displacement = (ppc_word)d;
  strcpy(dp->opcode,name);
  sprintf(dp->operands,"%c%d,%d(r%d)",reg,s,d,a);
}


static void fdabc(struct DisasmPara_PPC *dp,ppc_word in,char *name,
                  int mask,unsigned char dmode)
/* standard floating point instruction: xxxx fD,fA,fC,fB */
{
  static const char *fmt = "f%d,";
  char *s = dp->operands;
  int err = 0;

  dp->flags |= dmode;
  sprintf(dp->opcode,"f%s%s",name,rcsel[in&1]);
  s += sprintf(s,fmt,(int)PPCGETD(in));
  if (mask & 4)
    s += sprintf(s,fmt,(int)PPCGETA(in));
  else
    err |= (int)PPCGETA(in);
  if (mask & 1)
    s += sprintf(s,fmt,(int)PPCGETC(in));
  else if (!(mask&8))
    err |= (int)PPCGETC(in);
  if (mask & 2)
    s += sprintf(s,fmt,(int)PPCGETB(in));
  else if (PPCGETB(in))
    err |= (int)PPCGETB(in);
  *(s-1) = '\0';
  if (err)
    ill(dp,in);
}


static void fdab(struct DisasmPara_PPC *dp,ppc_word in,char *name,int mask)
/* indexed float instruction: xxxx fD,rA,rB */
{
  strcpy(dp->opcode,name);
  fd_ra_rb(dp->operands,in,mask);
}


static void fcmp(struct DisasmPara_PPC *dp,ppc_word in,char c)
{
  if (in & 0x00600001) {
    ill(dp,in);
  }
  else {
    sprintf(dp->opcode,"fcmp%c",c);
    sprintf(dp->operands,"cr%d,f%d,f%d",(int)PPCGETCRD(in),
            (int)PPCGETA(in),(int)PPCGETB(in));
  }
}


static void mtfsb(struct DisasmPara_PPC *dp,ppc_word in,int n)
{
  if (in & (PPCAMASK|PPCBMASK)) {
    ill(dp,in);
  }
  else {
    sprintf(dp->opcode,"mtfsb%d%s",n,rcsel[in&1]);
    sprintf(dp->operands,"%d",(int)PPCGETD(in));
  }
}


static void vdab(struct DisasmPara_PPC *dp,ppc_word in,char *name,
                 int mask,int chkrc)
/* standard AltiVec instruction: vxxx vD,vA,vB */
{
  sprintf(dp->opcode,"%s%s",name,rcsel[chkrc&&(in&PPCVRC)]);
  vd_va_vb(dp->operands,in,mask);
}


static void vdabc(struct DisasmPara_PPC *dp,ppc_word in)
/* four operands AltiVec instruction: vxxx vD,vA,vB,vC */
{
  int nameidx = (in & 0x3f) - 32;

  if (vmnames[nameidx]) {
    sprintf(dp->opcode,"v%s",vmnames[nameidx]);
    sprintf(vd_va_vb(dp->operands,in,7),
            (nameidx==12) ? ",%d" : ",v%d", (int)PPCGETC(in));
  }
  else
    ill(dp,in);
}


static void vldst(struct DisasmPara_PPC *dp,ppc_word in,char *name)
{
  if (in & 1) {
    ill(dp,in);
  }
  else {
    dp->flags |= PPCF_ALTIVEC;
    strcpy(dp->opcode,name);
    sprintf(dp->operands,"v%d,r%d,r%d",(int)PPCGETD(in),
            (int)PPCGETA(in),(int)PPCGETB(in));
  }
}


static void dstrm(struct DisasmPara_PPC *dp,ppc_word in,char *name)
{
  if (in & 0x01800001) {
    ill(dp,in);
  }
  else {
    char *s = dp->operands;;

    if (PPCGETIDX2(in) == 822) {  /* dss, dssall */
      if (PPCGETA(in) || PPCGETB(in)) {
        ill(dp,in);
        return;
      }
      sprintf(dp->opcode,"d%s%s",name,(in&PPCDST) ? "all" : "");
    }
    else {
      sprintf(dp->opcode,"d%s%c",name,(in&PPCDST) ? 't' : '\0');
      s += sprintf(s,"r%d,r%d,",(int)PPCGETA(in),(int)PPCGETB(in));
    }
    sprintf(s,"%d",(int)PPCGETSTRM(in));
    dp->flags |= PPCF_ALTIVEC;
  }
}



ppc_word *PPC_Disassemble(struct DisasmPara_PPC *dp, int endian)
/* Disassemble PPC instruction and return a pointer to the next */
/* instruction, or NULL if an error occured. */
{
  ppc_word in = *(dp->instr);

  if (dp->opcode==NULL || dp->operands==NULL)
    return (NULL);  /* no buffers */

//XXX
#if LIL_ENDIAN
if (!endian) {
  in = (in & 0xff)<<24 | (in & 0xff00)<<8 | (in & 0xff0000)>>8 |
       (in & 0xff000000)>>24;
}
#endif
  dp->type = PPCINSTR_OTHER;
  dp->flags = 0;
  *(dp->operands) = 0;

  switch (PPCGETIDX(in)) {
    case 2:
      trapi(dp,in,PPCF_64);  /* tdi */
      break;

    case 3:
      trapi(dp,in,0);  /* twi */
      break;

    case 4:
      dp->flags |= PPCF_ALTIVEC;

      if ((in & 0x30) == 0x20) {
        /* vxxx vA,vB,vC,vD  - four operands instructions */
        vdabc(dp,in);
        break;
      }
      if (in & 1) {
        ill(dp,in);
        break;
      }

      switch (PPCGETIDX2(in)<<1) {
        case 0:
          vdab(dp,in,"vaddubm",7,0);
          break;

        case 2:
          vdab(dp,in,"vmaxub",7,0);
          break;

        case 4:
          vdab(dp,in,"vrlb",7,0);
          break;

        case 6:
        case 6+PPCVRC:
          vdab(dp,in,"vcmpequb",7,1);
          break;

        case 8:
          vdab(dp,in,"vmuloub",7,0);
          break;

        case 10:
          vdab(dp,in,"vaddfp",7,0);
          break;

        case 12:
          vdab(dp,in,"vmrghb",7,0);
          break;

        case 14:
          vdab(dp,in,"vpkuhum",7,0);
          break;

        case 64:
          vdab(dp,in,"vadduhm",7,0);
          break;

        case 66:
          vdab(dp,in,"vmaxuh",7,0);
          break;

        case 68:
          vdab(dp,in,"vrlh",7,0);
          break;

        case 70:
        case 70+PPCVRC:
          vdab(dp,in,"vcmpequh",7,1);
          break;

        case 72:
          vdab(dp,in,"vmulouh",7,0);
          break;

        case 74:
          vdab(dp,in,"vsubfp",7,0);
          break;

        case 76:
          vdab(dp,in,"vmrghh",7,0);
          break;

        case 78:
          vdab(dp,in,"vpkuwum",7,0);
          break;

        case 128:
          vdab(dp,in,"vadduwm",7,0);
          break;

        case 130:
          vdab(dp,in,"vmaxuw",7,0);
          break;

        case 132:
          vdab(dp,in,"vrlw",7,0);
          break;

        case 134:
        case 134+PPCVRC:
          vdab(dp,in,"vcmpequw",7,1);
          break;

        case 140:
          vdab(dp,in,"vmrghw",7,0);
          break;

        case 142:
          vdab(dp,in,"vpkuhus",7,0);
          break;

        case 198:
        case 198+PPCVRC:
          vdab(dp,in,"vcmpeqfp",7,1);
          break;

        case 206:
          vdab(dp,in,"vpkuwus",7,0);
          break;

        case 258:
          vdab(dp,in,"vmaxsb",7,0);
          break;

        case 260:
          vdab(dp,in,"vslb",7,0);
          break;

        case 264:
          vdab(dp,in,"vmulosb",7,0);
          break;

        case 266:
          vdab(dp,in,"vrefp",5,0);
          break;

        case 268:
          vdab(dp,in,"vmrglb",7,0);
          break;

        case 270:
          vdab(dp,in,"vpkshus",7,0);
          break;

        case 322:
          vdab(dp,in,"vmaxsh",7,0);
          break;

        case 324:
          vdab(dp,in,"vslh",7,0);
          break;

        case 328:
          vdab(dp,in,"vmulosh",7,0);
          break;

        case 330:
          vdab(dp,in,"vrsqrtefp",5,0);
          break;

        case 332:
          vdab(dp,in,"vmrglh",7,0);
          break;

        case 334:
          vdab(dp,in,"vpkswus",7,0);
          break;

        case 384:
          vdab(dp,in,"vaddcuw",7,0);
          break;

        case 386:
          vdab(dp,in,"vmaxsw",7,0);
          break;

        case 388:
          vdab(dp,in,"vslw",7,0);
          break;

        case 394:
          vdab(dp,in,"vexptefp",5,0);
          break;

        case 396:
          vdab(dp,in,"vmrglw",7,0);
          break;

        case 398:
          vdab(dp,in,"vpkshss",7,0);
          break;

        case 452:
          vdab(dp,in,"vsl",7,0);
          break;

        case 454:
        case 454+PPCVRC:
          vdab(dp,in,"vcmpgefp",7,1);
          break;

        case 458:
          vdab(dp,in,"vlogefp",5,0);
          break;

        case 462:
          vdab(dp,in,"vpkswss",7,0);
          break;

        case 512:
          vdab(dp,in,"vaddubs",7,0);
          break;

        case 514:
          vdab(dp,in,"vminub",7,0);
          break;

        case 516:
          vdab(dp,in,"vsrb",7,0);
          break;

        case 518:
        case 518+PPCVRC:
          vdab(dp,in,"vcmpgtub",7,1);
          break;

        case 520:
          vdab(dp,in,"vmuleub",7,0);
          break;

        case 522:
          vdab(dp,in,"vrfin",5,0);
          break;

        case 524:
          vdab(dp,in,"vspltb",15,0);
          break;

        case 526:
          vdab(dp,in,"vupkhsb",5,0);
          break;

        case 576:
          vdab(dp,in,"vadduhs",7,0);
          break;

        case 578:
          vdab(dp,in,"vminuh",7,0);
          break;

        case 580:
          vdab(dp,in,"vsrh",7,0);
          break;

        case 582:
        case 582+PPCVRC:
          vdab(dp,in,"vcmpgtuh",7,1);
          break;

        case 584:
          vdab(dp,in,"vmuleuh",7,0);
          break;

        case 586:
          vdab(dp,in,"vrfiz",5,0);
          break;

        case 588:
          vdab(dp,in,"vsplth",15,0);
          break;

        case 590:
          vdab(dp,in,"vupkhsh",5,0);
          break;

        case 640:
          vdab(dp,in,"vadduws",7,0);
          break;

        case 642:
          vdab(dp,in,"vminuw",7,0);
          break;

        case 644:
          vdab(dp,in,"vsrw",7,0);
          break;

        case 646:
        case 646+PPCVRC:
          vdab(dp,in,"vcmpgtuw",7,1);
          break;

        case 650:
          vdab(dp,in,"vrfip",5,0);
          break;

        case 652:
          vdab(dp,in,"vspltw",15,0);
          break;

        case 654:
          vdab(dp,in,"vupklsb",5,0);
          break;

        case 708:
          vdab(dp,in,"vsr",7,0);
          break;

        case 710:
        case 710+PPCVRC:
          vdab(dp,in,"vcmpgtfp",7,1);
          break;

        case 714:
          vdab(dp,in,"vrfim",5,0);
          break;

        case 718:
          vdab(dp,in,"vupklsh",5,0);
          break;

        case 768:
          vdab(dp,in,"vaddsbs",7,0);
          break;

        case 770:
          vdab(dp,in,"vminsb",7,0);
          break;

        case 772:
          vdab(dp,in,"vsrab",7,0);
          break;

        case 774:
        case 774+PPCVRC:
          vdab(dp,in,"vcmpgtsb",7,1);
          break;

        case 776:
          vdab(dp,in,"vmulesb",7,0);
          break;

        case 778:
          vdab(dp,in,"vcfux",15,0);
          break;

        case 780:
          vdab(dp,in,"vspltisb",22,0);
          break;

        case 782:
          vdab(dp,in,"vpkpx",7,0);
          break;

        case 832:
          vdab(dp,in,"vaddshs",7,0);
          break;

        case 834:
          vdab(dp,in,"vminsh",7,0);
          break;

        case 836:
          vdab(dp,in,"vsrah",7,0);
          break;

        case 838:
        case 838+PPCVRC:
          vdab(dp,in,"vcmpgtsh",7,1);
          break;

        case 840:
          vdab(dp,in,"vmulesh",7,0);
          break;

        case 842:
          vdab(dp,in,"vcfsx",15,0);
          break;

        case 844:
          vdab(dp,in,"vspltish",22,0);
          break;

        case 846:
          vdab(dp,in,"vupkhpx",5,0);
          break;

        case 896:
          vdab(dp,in,"vaddsws",7,0);
          break;

        case 898:
          vdab(dp,in,"vminsw",7,0);
          break;

        case 900:
          vdab(dp,in,"vsraw",7,0);
          break;

        case 902:
        case 902+PPCVRC:
          vdab(dp,in,"vcmpgtsw",7,1);
          break;

        case 906:
          vdab(dp,in,"vctuxs",15,0);
          break;

        case 908:
          vdab(dp,in,"vspltisw",22,0);
          break;

        case 966:
        case 966+PPCVRC:
          vdab(dp,in,"vcmpbfp",7,1);
          break;

        case 970:
          vdab(dp,in,"vctsxs",15,0);
          break;

        case 974:
          vdab(dp,in,"vupklpx",5,0);
          break;

        case 1024:
          vdab(dp,in,"vsububm",7,0);
          break;

        case 1026:
          vdab(dp,in,"vavgub",7,0);
          break;

        case 1028:
          vdab(dp,in,"vand",7,0);
          break;

        case 1034:
          vdab(dp,in,"vmaxfp",7,0);
          break;

        case 1036:
          vdab(dp,in,"vslo",7,0);
          break;

        case 1088:
          vdab(dp,in,"vsubuhm",7,0);
          break;

        case 1090:
          vdab(dp,in,"vavguh",7,0);
          break;

        case 1092:
          vdab(dp,in,"vandc",7,0);
          break;

        case 1098:
          vdab(dp,in,"vminfp",7,0);
          break;

        case 1100:
          vdab(dp,in,"vsro",7,0);
          break;

        case 1152:
          vdab(dp,in,"vsubuwm",7,0);
          break;

        case 1154:
          vdab(dp,in,"vavguw",7,0);
          break;

        case 1156:
          vdab(dp,in,"vor",7,0);
          break;

        case 1220:
          vdab(dp,in,"vxor",7,0);
          break;

        case 1282:
          vdab(dp,in,"vavgsb",7,0);
          break;

        case 1284:
          vdab(dp,in,"vnor",7,0);
          break;

        case 1346:
          vdab(dp,in,"vavgsh",7,0);
          break;

        case 1408:
          vdab(dp,in,"vsubcuw",7,0);
          break;

        case 1410:
          vdab(dp,in,"vavgsw",7,0);
          break;

        case 1536:
          vdab(dp,in,"vsububs",7,0);
          break;

        case 1540:
          vdab(dp,in,"mfvscr",4,0);
          break;

        case 1544:
          vdab(dp,in,"vsum4ubs",7,0);
          break;

        case 1600:
          vdab(dp,in,"vsubuhs",7,0);
          break;

        case 1604:
          vdab(dp,in,"mtvscr",1,0);
          break;

        case 1608:
          vdab(dp,in,"vsum4shs",7,0);
          break;

        case 1664:
          vdab(dp,in,"vsubuws",7,0);
          break;

        case 1672:
          vdab(dp,in,"vsum2sws",7,0);
          break;

        case 1792:
          vdab(dp,in,"vsubsbs",7,0);
          break;

        case 1800:
          vdab(dp,in,"vsum4sbs",7,0);
          break;

        case 1856:
          vdab(dp,in,"vsubshs",7,0);
          break;

        case 1920:
          vdab(dp,in,"vsubsws",7,0);
          break;

        case 1928:
          vdab(dp,in,"vsumsws",7,0);
          break;

        default:
          ill(dp,in);
          break;
      }
      break;

    case 7: 
      strcpy(dp->opcode,"mulli");
      imm(dp,in,0,0);
      break;

    case 8:
      strcpy(dp->opcode,"subfic");
      imm(dp,in,0,0);
      break;

    case 10:
      cmpi(dp,in,1);  /* cmpli */
      break;

    case 11:
      cmpi(dp,in,0);  /* cmpi */
      break;

    case 12:
      addi(dp,in,"ic");  /* addic */
      break;

    case 13:
      addi(dp,in,"ic.");  /* addic. */
      break;

    case 14:
      addi(dp,in,"i");  /* addi */
      break;

    case 15:
      addi(dp,in,"is");  /* addis */
      break;

    case 16:
      bc(dp,in);
      break;

    case 17:
      if ((in & ~PPCIDXMASK) == 2)
        strcpy(dp->opcode,"sc");
      else
        ill(dp,in);
      break;

    case 18:
      bli(dp,in);
      break;

    case 19:
      switch (PPCGETIDX2(in)) {
        case 0:
          mcrf(dp,in,'\0');  /* mcrf */
          break;

        case 16:
          branch(dp,in,"lr",0,0);  /* bclr */
          break;

        case 33:
          crop(dp,in,"nor","not");  /* crnor */
          break;

        case 50:
          nooper(dp,in,"rfi",PPCF_SUPER);
          break;

        case 129:
          crop(dp,in,"andc",NULL);  /* crandc */
          break;

        case 150:
          nooper(dp,in,"isync",0);
          break;

        case 193:
          crop(dp,in,"xor","clr");  /* crxor */
          break;

        case 225:
          crop(dp,in,"nand",NULL);  /* crnand */
          break;

        case 257:
          crop(dp,in,"and",NULL);  /* crand */
          break;

        case 289:
          crop(dp,in,"eqv","set");  /* creqv */
          break;

        case 417:
          crop(dp,in,"orc",NULL);  /* crorc */
          break;

        case 449:
          crop(dp,in,"or","move");  /* cror */
          break;

        case 528:
          branch(dp,in,"ctr",0,0);  /* bcctr */
          break;

        default:
          ill(dp,in);
          break;
      }
      break;

    case 20:
      rlw(dp,in,"imi",0);  /* rlwimi */
      break;

    case 21:
      rlw(dp,in,"inm",0);  /* rlwinm */
      break;

    case 23:
      rlw(dp,in,"nm",1);  /* rlwnm */
      break;

    case 24:
      if (in & ~PPCIDXMASK)
        ori(dp,in,"ori");
      else
        strcpy(dp->opcode,"nop");
      break;

    case 25:
      ori(dp,in,"oris");
      break;

    case 26:
      ori(dp,in,"xori");
      break;

    case 27:
      ori(dp,in,"xoris");
      break;

    case 28:
      ori(dp,in,"andi.");
      break;

    case 29:
      ori(dp,in,"andis.");
      break;

    case 30:
      switch (in & 0x1c) {
        case 0:
          rld(dp,in,"icl",0);  /* rldicl */
          break;
        case 1:
          rld(dp,in,"icr",0);  /* rldicr */
          break;
        case 2:
          rld(dp,in,"ic",0);   /* rldic */
          break;
        case 3:
          rld(dp,in,"imi",0);  /* rldimi */
          break;
        case 4:
          rld(dp,in,in&2?"cl":"cr",1);  /* rldcl, rldcr */
          break;
        default:
          ill(dp,in);
          break;
      }
      break;

    case 31:
      switch (PPCGETIDX2(in)) {
        case 0:
        case 32:
          if (in & 1)
            ill(dp,in);
          else
            cmp(dp,in);  /* cmp, cmpl */
          break;

        case 4:
          if (in & 1)
            ill(dp,in);
          else
            trap(dp,in,0);  /* tw */
          break;

        case 6:
          vldst(dp,in,"lvsl");  /* AltiVec */
          break;

        case 7:
          vldst(dp,in,"lvebx");  /* AltiVec */
          break;

        case 8:
        case (PPCOE>>1)+8:
          dab(dp,swapab(in),"subc",7,0,1,-1,0);
          break;

        case 9:
          dab(dp,in,"mulhdu",7,0,0,-1,PPCF_64);
          break;

        case 10:
        case (PPCOE>>1)+10:
          dab(dp,in,"addc",7,0,1,-1,0);
          break;

        case 11:
          dab(dp,in,"mulhwu",7,0,0,-1,0);
          break;

        case 19:
          if (in & (PPCAMASK|PPCBMASK))
            ill(dp,in);
          else
            dab(dp,in,"mfcr",4,0,0,0,0);
          break;

        case 20:
          dab(dp,in,"lwarx",7,0,0,0,0);
          break;

        case 21:
          dab(dp,in,"ldx",7,0,0,0,PPCF_64);
          break;

        case 23:
          dab(dp,in,"lwzx",7,0,0,0,0);
          break;

        case 24:
          dab(dp,in,"slw",7,1,0,-1,0);
          break;

        case 26:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"cntlzw",6,1,0,-1,0);
          break;

        case 27:
          dab(dp,in,"sld",7,1,0,-1,PPCF_64);
          break;

        case 28:
          dab(dp,in,"and",7,1,0,-1,0);
          break;

        case 38:
          vldst(dp,in,"lvsr");  /* AltiVec */
          break;

        case 39:
          vldst(dp,in,"lvehx");  /* AltiVec */
          break;

        case 40:
        case (PPCOE>>1)+40:
          dab(dp,swapab(in),"sub",7,0,1,-1,0);
          break;

        case 53:
          dab(dp,in,"ldux",7,0,0,0,PPCF_64);
          break;

        case 54:
          if (in & PPCDMASK)
            ill(dp,in);
          else
            dab(dp,in,"dcbst",3,0,0,0,0);
          break;

        case 55:
          dab(dp,in,"lwzux",7,0,0,0,0);
          break;

        case 58:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"cntlzd",6,1,0,-1,PPCF_64);
          break;

        case 60:
          dab(dp,in,"andc",7,1,0,-1,0);
          break;

        case 68:
          trap(dp,in,PPCF_64);  /* td */
          break;

        case 71:
          vldst(dp,in,"lvewx");  /* AltiVec */
          break;

        case 73:
          dab(dp,in,"mulhd",7,0,0,-1,PPCF_64);
          break;

        case 75:
          dab(dp,in,"mulhw",7,0,0,-1,0);
          break;

        case 83:
          if (in & (PPCAMASK|PPCBMASK))
            ill(dp,in);
          else
            dab(dp,in,"mfmsr",4,0,0,0,PPCF_SUPER);
          break;

        case 84:
          dab(dp,in,"ldarx",7,0,0,0,PPCF_64);
          break;

        case 86:
          if (in & PPCDMASK)
            ill(dp,in);
          else
            dab(dp,in,"dcbf",3,0,0,0,0);
          break;

        case 87:
          dab(dp,in,"lbzx",7,0,0,0,0);
          break;

        case 103:
          vldst(dp,in,"lvx");  /* AltiVec */
          break;

        case 104:
        case (PPCOE>>1)+104:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"neg",6,0,1,-1,0);
          break;

        case 119:
          dab(dp,in,"lbzux",7,0,0,0,0);
          break;

        case 124:
          if (PPCGETD(in) == PPCGETB(in))
            dab(dp,in,"not",6,1,0,-1,0);
          else
            dab(dp,in,"nor",7,1,0,-1,0);
          break;

        case 135:
          vldst(dp,in,"stvebx");  /* AltiVec */
          break;

        case 136:
        case (PPCOE>>1)+136:
          dab(dp,in,"subfe",7,0,1,-1,0);
          break;

        case 138:
        case (PPCOE>>1)+138:
          dab(dp,in,"adde",7,0,1,-1,0);
          break;

        case 144:
          mtcr(dp,in);
          break;

        case 146:
          if (in & (PPCAMASK|PPCBMASK))
            ill(dp,in);
          else
            dab(dp,in,"mtmsr",4,0,0,0,PPCF_SUPER);
          break;

        case 149:
          dab(dp,in,"stdx",7,0,0,0,PPCF_64);
          break;

        case 150:
          dab(dp,in,"stwcx.",7,0,0,1,0);
          break;

        case 151:
          dab(dp,in,"stwx",7,0,0,0,0);
          break;

        case 167:
          vldst(dp,in,"stvehx");  /* AltiVec */
          break;

        case 181:
          dab(dp,in,"stdux",7,0,0,0,PPCF_64);
          break;

        case 183:
          dab(dp,in,"stwux",7,0,0,0,0);
          break;

        case 199:
          vldst(dp,in,"stvewx");  /* AltiVec */
          break;

        case 200:
        case (PPCOE>>1)+200:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"subfze",6,0,1,-1,0);
          break;

        case 202:
        case (PPCOE>>1)+202:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"addze",6,0,1,-1,0);
          break;

        case 210:
          msr(dp,in,1);  /* mfsr */
          break;

        case 214:
          dab(dp,in,"stdcx.",7,0,0,1,PPCF_64);
          break;

        case 215:
          dab(dp,in,"stbx",7,0,0,0,0);
          break;

        case 231:
          vldst(dp,in,"stvx");  /* AltiVec */
          break;

        case 232:
        case (PPCOE>>1)+232:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"subfme",6,0,1,-1,0);
          break;

        case 233:
        case (PPCOE>>1)+233:
          dab(dp,in,"mulld",7,0,1,-1,PPCF_64);
          break;

        case 234:
        case (PPCOE>>1)+234:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"addme",6,0,1,-1,0);
          break;

        case 235:
        case (PPCOE>>1)+235:
          dab(dp,in,"mullw",7,0,1,-1,0);
          break;

        case 242:
          if (in & PPCAMASK)
            ill(dp,in);
          else
            dab(dp,in,"mtsrin",5,0,0,0,PPCF_SUPER);
          break;

        case 246:
          if (in & PPCDMASK)
            ill(dp,in);
          else
            dab(dp,in,"dcbtst",3,0,0,0,0);
          break;

        case 247:
          dab(dp,in,"stbux",7,0,0,0,0);
          break;

        case 266:
        case (PPCOE>>1)+266:
          dab(dp,in,"add",7,0,1,-1,0);
          break;

        case 278:
          if (in & PPCDMASK)
            ill(dp,in);
          else
            dab(dp,in,"dcbt",3,0,0,0,0);
          break;

        case 279:
          dab(dp,in,"lhzx",7,0,0,0,0);
          break;

        case 284:
          dab(dp,in,"eqv",7,1,0,-1,0);
          break;

        case 306:
          if (in & (PPCDMASK|PPCAMASK))
            ill(dp,in);
          else
            dab(dp,in,"tlbie",1,0,0,0,PPCF_SUPER);
          break;

        case 310:
          dab(dp,in,"eciwx",7,0,0,0,0);
          break;

        case 311:
          dab(dp,in,"lhzux",7,0,0,0,0);
          break;

        case 316:
          dab(dp,in,"xor",7,1,0,-1,0);
          break;

        case 339:
          mspr(dp,in,0);  /* mfspr */
          break;

        case 341:
          dab(dp,in,"lwax",7,0,0,0,PPCF_64);
          break;

        case 342:
          dstrm(dp,in,"st");  /* AltiVec Stream */
          break;

        case 343:
          dab(dp,in,"lhax",7,0,0,0,0);
          break;

        case 359:
          vldst(dp,in,"lvxl");  /* AltiVec */
          break;

        case 370:
          nooper(dp,in,"tlbia",PPCF_SUPER);
          break;

        case 371:
          mtb(dp,in);  /* mftb */
          break;

        case 373:
          dab(dp,in,"lwaux",7,0,0,0,PPCF_64);
          break;

        case 374:
          dstrm(dp,in,"stst");  /* AltiVec Stream */
          break;

        case 375:
          dab(dp,in,"lhaux",7,0,0,0,0);
          break;

        case 407:
          dab(dp,in,"sthx",7,0,0,0,0);
          break;

        case 412:
          dab(dp,in,"orc",7,1,0,-1,0);
          break;

        case 413:
          sradi(dp,in);  /* sradi */
          break;

        case 434:
          if (in & (PPCDMASK|PPCAMASK))
            ill(dp,in);
          else
            dab(dp,in,"slbie",1,0,0,0,PPCF_SUPER|PPCF_64);
          break;

        case 438:
          dab(dp,in,"ecowx",7,0,0,0,0);
          break;

        case 439:
          dab(dp,in,"sthux",7,0,0,0,0);
          break;

        case 444:
          if (PPCGETD(in) == PPCGETB(in))
            dab(dp,in,"mr",6,1,0,-1,0);
          else
            dab(dp,in,"or",7,1,0,-1,0);
          break;

        case 457:
        case (PPCOE>>1)+457:
          dab(dp,in,"divdu",7,0,1,-1,PPCF_64);
          break;

        case 459:
        case (PPCOE>>1)+459:
          dab(dp,in,"divwu",7,0,1,-1,0);
          break;

        case 467:
          mspr(dp,in,1);  /* mtspr */
          break;

        case 470:
          if (in & PPCDMASK)
            ill(dp,in);
          else
            dab(dp,in,"dcbi",3,0,0,0,0);
          break;

        case 476:
          dab(dp,in,"nand",7,1,0,-1,0);
          break;

        case 487:
          vldst(dp,in,"stvxl");  /* AltiVec */
          break;

        case 489:
        case (PPCOE>>1)+489:
          dab(dp,in,"divd",7,0,1,-1,PPCF_64);
          break;

        case 491:
        case (PPCOE>>1)+491:
          dab(dp,in,"divw",7,0,1,-1,0);
          break;

        case 498:
          nooper(dp,in,"slbia",PPCF_SUPER|PPCF_64);
          break;

        case 512:
          if (in & 0x007ff801)
            ill(dp,in);
          else {
            strcpy(dp->opcode,"mcrxr");
            sprintf(dp->operands,"cr%d",(int)PPCGETCRD(in));
          }
          break;

        case 533:
          dab(dp,in,"lswx",7,0,0,0,0);
          break;

        case 534:
          dab(dp,in,"lwbrx",7,0,0,0,0);
          break;

        case 535:
          fdab(dp,in,"lfsx",7);
          break;

        case 536:
          dab(dp,in,"srw",7,1,0,-1,0);
          break;

        case 539:
          dab(dp,in,"srd",7,1,0,-1,PPCF_64);
          break;

        case 566:
          nooper(dp,in,"tlbsync",PPCF_SUPER);
          break;

        case 567:
          fdab(dp,in,"lfsux",7);
          break;

        case 595:
          msr(dp,in,0);  /* mfsr */
          break;

        case 597:
          rrn(dp,in,"lswi",0,0,0,0);
          break;

        case 598:
          nooper(dp,in,"sync",PPCF_SUPER);
          break;

        case 599:
          fdab(dp,in,"lfdx",7);
          break;

        case 631:
          fdab(dp,in,"lfdux",7);
          break;

        case 659:
          if (in & PPCAMASK)
            ill(dp,in);
          else
            dab(dp,in,"mfsrin",5,0,0,0,PPCF_SUPER);
          break;

        case 661:
          dab(dp,in,"stswx",7,0,0,0,0);
          break;

        case 662:
          dab(dp,in,"stwbrx",7,0,0,0,0);
          break;

        case 663:
          fdab(dp,in,"stfsx",7);
          break;

        case 695:
          fdab(dp,in,"stfsux",7);
          break;

        case 725:
          rrn(dp,in,"stswi",0,0,0,0);
          break;

        case 727:
          fdab(dp,in,"stfdx",7);
          break;

        case 759:
          fdab(dp,in,"stfdux",7);
          break;

        case 790:
          dab(dp,in,"lhbrx",7,0,0,0,0);
          break;

        case 792:
          dab(dp,in,"sraw",7,1,0,-1,0);
          break;

        case 794:
          dab(dp,in,"srad",7,1,0,-1,PPCF_64);
          break;

        case 822:
          dstrm(dp,in,"ss");  /* AltiVec Stream */
          break;

        case 824:
          rrn(dp,in,"srawi",1,0,-1,0);
          break;

        case 854:
          nooper(dp,in,"eieio",PPCF_SUPER);
          break;

        case 918:
          dab(dp,in,"sthbrx",7,0,0,0,0);
          break;

        case 922:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"extsh",6,1,0,-1,0);
          break;

        case 954:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"extsb",6,1,0,-1,0);
          break;

        case 982:
          if (in & PPCDMASK)
            ill(dp,in);
          else
            dab(dp,in,"icbi",3,0,0,0,0);
          break;

        case 983:
          fdab(dp,in,"stfiwx",7);
          break;

        case 986:
          if (in & PPCBMASK)
            ill(dp,in);
          else
            dab(dp,in,"extsw",6,1,0,-1,PPCF_64);
          break;

        case 1014:
          if (in & PPCDMASK)
            ill(dp,in);
          else
            dab(dp,in,"dcbz",3,0,0,0,0);
          break;

        default:
          ill(dp,in);
          break;
      }
      break;

    case 32:
    case 33:
    case 34:
    case 35:
    case 36:
    case 37:
    case 38:
    case 39:
    case 40:
    case 41:
    case 42:
    case 43:
    case 44:
    case 45:
    case 46:
    case 47:
      ldst(dp,in,ldstnames[PPCGETIDX(in)-32],'r',0);
      break;

    case 48:
    case 49:
    case 50:
    case 51:
    case 52:
    case 53:
    case 54:
    case 55:
      ldst(dp,in,ldstnames[PPCGETIDX(in)-32],'f',0);
      break;

    case 58:
      switch (in & 3) {
        case 0:
          ldst(dp,in&~3,"ld",'r',PPCF_64);
          break;
        case 1:
          ldst(dp,in&~3,"ldu",'r',PPCF_64);
          break;
        case 2:
          ldst(dp,in&~3,"lwa",'r',PPCF_64);
          break;
        default:
          ill(dp,in);
          break;
      }
      break;

    case 59:
      switch (in & 0x3e) {
        case 36:
          fdabc(dp,in,"divs",6,0);
          break;

        case 40:
          fdabc(dp,in,"subs",6,0);
          break;

        case 42:
          fdabc(dp,in,"adds",6,0);
          break;

        case 44:
          fdabc(dp,in,"sqrts",2,0);
          break;

        case 48:
          fdabc(dp,in,"res",2,0);
          break;

        case 50:
          fdabc(dp,in,"muls",5,0);
          break;

        case 56:
          fdabc(dp,in,"msubs",7,0);
          break;

        case 58:
          fdabc(dp,in,"madds",7,0);
          break;

        case 60:
          fdabc(dp,in,"nmsubs",7,0);
          break;

        case 62:
          fdabc(dp,in,"nmadds",7,0);
          break;

        default:
          ill(dp,in);
          break;
      }
      break;

    case 62:
      switch (in & 3) {
        case 0:
          ldst(dp,in&~3,"std",'r',PPCF_64);
          break;
        case 1:
          ldst(dp,in&~3,"stdu",'r',PPCF_64);
          break;
        default:
          ill(dp,in);
          break;
      }
      break;

    case 63:
      if (in & 32) {
        switch (in & 0x1e) {
          case 4:
            fdabc(dp,in,"div",6,0);
            break;

          case 8:
            fdabc(dp,in,"sub",6,0);
            break;

          case 10:
            fdabc(dp,in,"add",6,0);
            break;

          case 12:
            fdabc(dp,in,"sqrt",2,0);
            break;

          case 14:
            fdabc(dp,in,"sel",7,0);
            break;

          case 18:
            fdabc(dp,in,"mul",5,0);
            break;

          case 20:
            fdabc(dp,in,"sqrte",2,0);
            break;

          case 24:
            fdabc(dp,in,"msub",7,0);
            break;

          case 26:
            fdabc(dp,in,"madd",7,0);
            break;

          case 28:
            fdabc(dp,in,"nmsub",7,0);
            break;

          case 30:
            fdabc(dp,in,"nmadd",7,0);
            break;

          default:
            ill(dp,in);
            break;
        }
      }

      else {
        switch (PPCGETIDX2(in)) {
          case 0:
            fcmp(dp,in,'u');
            break;

          case 12:
            fdabc(dp,in,"rsp",10,0);
            break;

          case 14:
            fdabc(dp,in,"ctiw",10,0);
            break;

          case 15:
            fdabc(dp,in,"ctiwz",10,0);
            break;

          case 32:
            fcmp(dp,in,'o');
            break;

          case 38:
            mtfsb(dp,in,1);
            break;

          case 40:
            fdabc(dp,in,"neg",10,0);
            break;

          case 64:
            mcrf(dp,in,'s');  /* mcrfs */
            break;

          case 70:
            mtfsb(dp,in,0);
            break;

          case 72:
            fdabc(dp,in,"mr",10,0);
            break;

          case 134:
            if (!(in & 0x006f0800)) {
              sprintf(dp->opcode,"mtfsfi%s",rcsel[in&1]);
              sprintf(dp->operands,"%d,%d",(int)PPCGETCRD(in),
                      (int)(in & 0xf000)>>12);
            }
            else
              ill(dp,in);
            break;

          case 136:
            fdabc(dp,in,"nabs",10,0);
            break;

          case 264:
            fdabc(dp,in,"abs",10,0);
            break;

          case 583:
            if (!(in & (PPCAMASK|PPCBMASK))) {
              sprintf(dp->opcode,"mffs%s",rcsel[in&1]);
              sprintf(dp->operands,"f%d",(int)PPCGETD(in));
            }
            else
              ill(dp,in);
            break;

          case 711:
            if (!(in & 0x02010000)) {
              sprintf(dp->opcode,"mtfsf%s",rcsel[in&1]);
              sprintf(dp->operands,"%d,f%d",
                      (int)(in & 0x01fe0000)>>17,(int)PPCGETB(in));
            }
            else
              ill(dp,in);
            break;

          case 814:
            fdabc(dp,in,"fctid",10,PPCF_64);
            break;

          case 815:
            fdabc(dp,in,"fctidz",10,PPCF_64);
            break;

          case 846:
            fdabc(dp,in,"fcfid",10,PPCF_64);
            break;

          default:
            ill(dp,in);
            break;
        }
      }
      break;

    default:
      ill(dp,in);
      break;
  }
  return (dp->instr + 1);
}
