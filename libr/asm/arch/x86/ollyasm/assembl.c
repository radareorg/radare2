// Free Disassembler and Assembler -- Assembler
//
// Copyright (C) 2001 Oleh Yuschuk
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

// 16.01.2002 - corrected error in processing of immediate constants.


#define STRICT

//#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
//#include <dir.h>
#include <math.h>
#include <float.h>
//#pragma hdrstop

#include "disasm.h"

static int       ideal=0;                // Force IDEAL decoding mode
static int       sizesens=0;             // How to decode size-sensitive mnemonics

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// ASSEMBLER FUNCTIONS //////////////////////////////

// Scanner modes.
#define SA_NAME        0x0001          // Don't try to decode labels
#define SA_IMPORT      0x0002          // Allow import pseudolabel

// Types of input tokens reported by scanner.
#define SCAN_EOL       0               // End of line
#define SCAN_REG8      1               // 8-bit register
#define SCAN_REG16     2               // 16-bit register
#define SCAN_REG32     3               // 32-bit register
#define SCAN_SEG       4               // Segment register
#define SCAN_FPU       5               // FPU register
#define SCAN_MMX       6               // MMX register
#define SCAN_CR        7               // Control register
#define SCAN_DR        8               // Debug register
#define SCAN_OPSIZE    9               // Operand size modifier
#define SCAN_JMPSIZE   10              // Jump size modifier
#define SCAN_LOCAL     11              // Address on stack in form LOCAL.decimal
#define SCAN_ARG       12              // Address on stack in form ARG.decimal
#define SCAN_PTR       20              // PTR in MASM addressing statements
#define SCAN_REP       21              // REP prefix
#define SCAN_REPE      22              // REPE prefix
#define SCAN_REPNE     23              // REPNE prefix
#define SCAN_LOCK      24              // LOCK prefix
#define SCAN_NAME      25              // Command or label
#define SCAN_ICONST    26              // Hexadecimal constant
#define SCAN_DCONST    27              // Decimal constant
#define SCAN_OFS       28              // Undefined constant
#define SCAN_FCONST    29              // Floating-point constant
#define SCAN_EIP       30              // Register EIP
#define SCAN_SIGNED    31              // Keyword "SIGNED" (in expressions)
#define SCAN_UNSIGNED  32              // Keyword "UNSIGNED" (in expressions)
#define SCAN_CHAR      33              // Keyword "CHAR" (in expressions)
#define SCAN_FLOAT     34              // Keyword "FLOAT" (in expressions)
#define SCAN_DOUBLE    35              // Keyword "DOUBLE" (in expressions)
#define SCAN_FLOAT10   36              // Keyword "FLOAT10" (in expressions)
#define SCAN_STRING    37              // Keyword "STRING" (in expressions)
#define SCAN_UNICODE   38              // Keyword "UNICODE" (in expressions)
#define SCAN_MSG       39              // Pseudovariable MSG (in expressions)

#define SCAN_SYMB      64              // Any other character
#define SCAN_IMPORT    65              // Import pseudolabel
#define SCAN_ERR       255             // Definitely bad item

// Definition used by Assembler to report command matching errors.
#define MA_JMP         0x0001          // Invalid jump size modifier
#define MA_NOP         0x0002          // Wrong number of operands
#define MA_TYP         0x0004          // Bad operand type
#define MA_NOS         0x0008          // Explicit operand size expected
#define MA_SIZ         0x0010          // Bad operand size
#define MA_DIF         0x0020          // Different operand sizes
#define MA_SEG         0x0040          // Invalid segment register
#define MA_RNG         0x0080          // Constant out of expected range

typedef struct t_asmoperand {
  int            type;                 // Operand type, see beginning of file
  int            size;                 // Operand size or 0 if yet unknown
  int            index;                // Index or other register
  int            scale;                // Scale
  int            base;                 // Base register if present
  long           offset;               // Immediate value or offset
  int            anyoffset;            // Offset is present but undefined
  int            segment;              // Segment in address if present
  int            jmpmode;              // Specified jump size
} t_asmoperand;

static char      *asmcmd;              // Pointer to 0-terminated source line
static int       scan;                 // Type of last scanned element
static int       prio;                 // Priority of operation (0: highest)
static char      sdata[TEXTLEN];       // Last scanned name (depends on type)
static long      idata;                // Last scanned value
static long      double fdata;         // Floating-point number
static char      *asmerror;            // Explanation of last error, or NULL

// Simple and slightly recursive scanner shared by Assemble(). The scanner is
// straightforward and ineffective, but high speed is not a must here. As
// input, it uses global pointer to source line asmcmd. On exit, it fills in
// global variables scan, prio, sdata, idata and/or fdata. If some error is
// detected, asmerror points to error message, otherwise asmerror remains
// unchanged.
static void Scanasm(int mode) {
  int i,j,base,maxdigit;
  long decimal,hex;
  long double floating,divisor;
  char s[TEXTLEN],*pcmd;
  sdata[0]='\0';
  idata=0;
  if (asmcmd==NULL) {
    asmerror="NULL input line"; scan=SCAN_ERR; return; };
  while (*asmcmd==' ' || *asmcmd=='\t')
    asmcmd++;                          // Skip leading spaces
  if (*asmcmd=='\0' || *asmcmd==';') {
    scan=SCAN_EOL; return; };          // Empty line
  if (isalpha((unsigned char)*asmcmd) || *asmcmd=='_' || *asmcmd=='@') {
    sdata[0]=*asmcmd++; i=1;           // Some keyword or identifier
    while ((isalnum((unsigned char)*asmcmd) || *asmcmd=='_' || *asmcmd=='@') &&
      i<sizeof(sdata))
      sdata[i++]=*asmcmd++;
    if (i>=sizeof(sdata)) {
      asmerror="Too long identifier"; scan=SCAN_ERR; return; };
    sdata[i]='\0';
    while (*asmcmd==' ' || *asmcmd=='\t')
      asmcmd++;                        // Skip trailing spaces
    strcpy(s,sdata); strupr(s);
    for (j=0; j<=8; j++) {             // j==8 means "any register"
      if (strcmp(s,regname[0][j])!=0) continue;
      idata=j; scan=SCAN_REG8;         // 8-bit register
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,regname[1][j])!=0) continue;
      idata=j; scan=SCAN_REG16;        // 16-bit register
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,regname[2][j])!=0) continue;
      idata=j; scan=SCAN_REG32;        // 32-bit register
      return; };
    for (j=0; j<6; j++) {
      if (strcmp(s,segname[j])!=0) continue;
      idata=j; scan=SCAN_SEG;          // Segment register
      while (*asmcmd==' ' || *asmcmd=='\t')
        asmcmd++;                      // Skip trailing spaces
      return; };
    if (strcmp(s,"ST")==0) {
      pcmd=asmcmd; Scanasm(SA_NAME);   // FPU register
      if (scan!=SCAN_SYMB || idata!='(') {
        asmcmd=pcmd;                   // Undo last scan
        idata=0; scan=SCAN_FPU; return; };
      Scanasm(SA_NAME); j=idata;
      if ((scan!=SCAN_ICONST && scan!=SCAN_DCONST) || idata<0 || idata>7) {
        asmerror="FPU registers have indexes 0 to 7";
        scan=SCAN_ERR; return; };
      Scanasm(SA_NAME);
      if (scan!=SCAN_SYMB || idata!=')') {
        asmerror="Closing parenthesis expected";
        scan=SCAN_ERR; return; };
      idata=j; scan=SCAN_FPU; return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,fpuname[j])!=0) continue;
      idata=j; scan=SCAN_FPU;          // FPU register (alternative coding)
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,mmxname[j])!=0) continue;
      idata=j; scan=SCAN_MMX;          // MMX register
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,crname[j])!=0) continue;
      idata=j; scan=SCAN_CR;           // Control register
      return; };
    for (j=0; j<=8; j++) {
      if (strcmp(s,drname[j])!=0) continue;
      idata=j; scan=SCAN_DR;           // Debug register
      return; };
    for (j=0; j<sizeof(sizename)/sizeof(sizename[0]); j++) {
      if (strcmp(s,sizename[j])!=0) continue;
      pcmd=asmcmd; Scanasm(SA_NAME);
      if (scan!=SCAN_PTR)              // Fetch non-functional "PTR"
        asmcmd=pcmd;
      idata=j; scan=SCAN_OPSIZE;       // Operand (data) size in bytes
      return; };
    if (strcmp(s,"EIP")==0) {          // Register EIP
      scan=SCAN_EIP; idata=0; return; };
    if (strcmp(s,"SHORT")==0) {        // Relative jump has 1-byte offset
      scan=SCAN_JMPSIZE; idata=1; return; };
    if (strcmp(s,"LONG")==0) {         // Relative jump has 4-byte offset
      scan=SCAN_JMPSIZE; idata=2; return; };
    if (strcmp(s,"NEAR")==0) {         // Jump within same code segment
      scan=SCAN_JMPSIZE; idata=4; return; };
    if (strcmp(s,"FAR")==0) {          // Jump to different code segment
      scan=SCAN_JMPSIZE; idata=8; return; };
    if (strcmp(s,"LOCAL")==0 && *asmcmd=='.') {
      asmcmd++;
      while (*asmcmd==' ' || *asmcmd=='\t')
        asmcmd++;                      // Skip trailing spaces
      if (!isdigit((unsigned char)*asmcmd)) {
        asmerror="Integer number expected";
        scan=SCAN_ERR; return; };
      while (isdigit((unsigned char)*asmcmd))         // LOCAL index is decimal number!
        idata=idata*10+(*asmcmd++)-'0';
      scan=SCAN_LOCAL; return; };
    if (strcmp(s,"ARG")==0 && *asmcmd=='.') {
      asmcmd++;
      while (*asmcmd==' ' || *asmcmd=='\t')
        asmcmd++;                      // Skip trailing spaces
      if (!isdigit((unsigned char)*asmcmd)) {
        asmerror="Integer number expected";
        scan=SCAN_ERR; return; };
      while (isdigit((unsigned char)*asmcmd))         // ARG index is decimal number!
        idata=idata*10+(*asmcmd++)-'0';
      scan=SCAN_ARG; return; };
    if (strcmp(s,"REP")==0) {
      scan=SCAN_REP; return; };        // REP prefix
    if (strcmp(s,"REPE")==0 || strcmp(s,"REPZ")==0) {
      scan=SCAN_REPE; return; };       // REPE prefix
    if (strcmp(s,"REPNE")==0 || strcmp(s,"REPNZ")==0) {
      scan=SCAN_REPNE; return; };      // REPNE prefix
    if (strcmp(s,"LOCK")==0) {
      scan=SCAN_LOCK; return; };       // LOCK prefix
    if (strcmp(s,"PTR")==0) {
      scan=SCAN_PTR; return; };        // PTR in MASM addressing statements
    if (strcmp(s,"CONST")==0 || strcmp(s,"OFFSET")==0) {
      scan=SCAN_OFS; return; };        // Present but undefined offset/constant
    if (strcmp(s,"SIGNED")==0) {
      scan=SCAN_SIGNED; return; };     // Keyword "SIGNED" (in expressions)
    if (strcmp(s,"UNSIGNED")==0) {
      scan=SCAN_UNSIGNED; return; };   // Keyword "UNSIGNED" (in expressions)
    if (strcmp(s,"CHAR")==0) {
      scan=SCAN_CHAR; return; };       // Keyword "CHAR" (in expressions)
    if (strcmp(s,"FLOAT")==0) {
      scan=SCAN_FLOAT; return; };      // Keyword "FLOAT" (in expressions)
    if (strcmp(s,"DOUBLE")==0) {
      scan=SCAN_DOUBLE; return; };     // Keyword "DOUBLE" (in expressions)
    if (strcmp(s,"FLOAT10")==0) {
      scan=SCAN_FLOAT10; return; };    // Keyword "FLOAT10" (in expressions)
    if (strcmp(s,"STRING")==0) {
      scan=SCAN_STRING; return; };     // Keyword "STRING" (in expressions)
    if (strcmp(s,"UNICODE")==0) {
      scan=SCAN_UNICODE; return; };    // Keyword "UNICODE" (in expressions)
    if (strcmp(s,"MSG")==0) {
      scan=SCAN_MSG; return; };        // Pseudovariable MSG (in expressions)
    if (mode & SA_NAME) {
      idata=i; scan=SCAN_NAME;         // Don't try to decode symbolic label
      return; }
    asmerror="Unknown identifier";
    scan=SCAN_ERR; return; }
  else if (isdigit((unsigned char)*asmcmd)) {         // Constant
    base=10; maxdigit=0; decimal=hex=0L; floating=0.0;
    if (asmcmd[0]=='0' && toupper((unsigned char)asmcmd[1])=='X') {
      base=16; asmcmd+=2; };           // Force hexadecimal number
//printf("DIGIT (%s) %d\n", asmcmd, base);
    while (1) {
      if (isdigit((unsigned char)*asmcmd)) {
        decimal=decimal*10+(*asmcmd)-'0';
        floating=floating*10.0+(*asmcmd)-'0';
        //hex=hex*16+(*asmcmd)-'0';
        hex=hex*base+(*asmcmd)-'0';
        if (maxdigit==0) maxdigit=9;
        asmcmd++; }
      else if (isxdigit((unsigned char)*asmcmd)) {
        hex=hex*16+toupper((unsigned char)*asmcmd++)-'A'+10;
        maxdigit=15; }
      else break; };
    if (maxdigit==0) {
      asmerror="Hexadecimal digits after 0x... expected";
      scan=SCAN_ERR; return; };
    if (toupper((unsigned char)*asmcmd)=='H') {       // Force hexadecimal number
      if (base==16) {
        asmerror="Please don't mix 0xXXXX and XXXXh forms";
        scan=SCAN_ERR; return; };
      asmcmd++;
      idata=hex; scan=SCAN_ICONST;
      while (*asmcmd==' ' || *asmcmd=='\t') asmcmd++;
      return; };

    // XXX We must force base 10 by default
    if (*asmcmd=='.') {                // Force decimal number
      if (base==16 || maxdigit>9) {
        asmerror="Not a decimal number"; scan=SCAN_ERR; return; };
      asmcmd++;
      if (isdigit((unsigned char)*asmcmd) || toupper((unsigned char)*asmcmd)=='E') {
        divisor=1.0;
        while (isdigit((unsigned char)*asmcmd)) {     // Floating-point number
          divisor/=10.0;
          floating+=divisor*(*asmcmd-'0');
          asmcmd++; };
        if (toupper((unsigned char)*asmcmd)=='E') {
          asmcmd++;
          if (*asmcmd=='-') { base=-1; asmcmd++; }
          else base=1;
          if (!isdigit((unsigned char)*asmcmd)) {
            asmerror="Invalid exponent"; scan=SCAN_ERR; return; };
          decimal=0;
          while (isdigit((unsigned char)*asmcmd)) {
            if (decimal<65536L) decimal=decimal*10+(*asmcmd++)-'0'; };
          floating*=pow10l(decimal*base); };
        fdata=floating;
        scan=SCAN_FCONST; return; }
      else {
        idata=decimal; scan=SCAN_DCONST;
        while (*asmcmd==' ' || *asmcmd=='\t') asmcmd++;
        return;
      };
    };
    idata=hex; scan=SCAN_ICONST;       // Default is hexadecimal
    while (*asmcmd==' ' || *asmcmd=='\t') asmcmd++;
    return; }
  else if (*asmcmd=='\'') {            // Character constant
    asmcmd++;
    if (*asmcmd=='\0' || (*asmcmd=='\\' && asmcmd[1]=='\0'))  {
      asmerror="Unterminated character constant"; scan=SCAN_ERR; return; };
    if (*asmcmd=='\'') {
      asmerror="Empty character constant"; scan=SCAN_ERR; return; };
    if (*asmcmd=='\\') asmcmd++;
    idata=*asmcmd++;
    if (*asmcmd!='\'')  {
      asmerror="Unterminated character constant"; scan=SCAN_ERR; return; };
    asmcmd++;
    while (*asmcmd==' ' || *asmcmd=='\t') asmcmd++;
    scan=SCAN_ICONST; return; }
  else {                               // Any other character or combination
    idata=sdata[0]=*asmcmd++; sdata[1]=sdata[2]='\0';
    if (idata=='|' && *asmcmd=='|') {
      //idata='||'; prio=10;             // '||'
      idata=(('|'<<8)|'|'); prio=10;     // '||'
      sdata[1]=*asmcmd++; }
    else if (idata=='&' && *asmcmd=='&') {
      //idata='&&'; prio=9;              // '&&'
      idata=(('&'<<8)|'&'); prio=9;      // '&&'
      sdata[1]=*asmcmd++; }
    else if (idata=='=' && *asmcmd=='=') {
      //idata='=='; prio=5;              // '=='
      idata=(('='<<8)|'='); prio=5;      // '=='
      sdata[1]=*asmcmd++; }
    else if (idata=='!' && *asmcmd=='=') {
      //idata='!='; prio=5;              // '!='
      idata=(('!'<<8)|'='); prio=5;      // '!='
      sdata[1]=*asmcmd++; }
    else if (idata=='<' && *asmcmd=='=') {
      //idata='<='; prio=4;              // '<='
      idata=(('<'<<8)|'='); prio=4;      // '<='
      sdata[1]=*asmcmd++; }
    else if (idata=='>' && *asmcmd=='=') {
      //idata='>='; prio=4;              // '>='
      idata=(('>'<<8)|'='); prio=4;      // '>='
      sdata[1]=*asmcmd++; }
    else if (idata=='<' && *asmcmd=='<') {
      //idata='<<'; prio=3;              // '<<'
      idata=(('<'<<8)|'<'); prio=3;      // '<<'
      sdata[1]=*asmcmd++; }
    else if (idata=='>' && *asmcmd=='>') {
      //idata='>>'; prio=3;              // '>>'
      idata=(('>'<<8)|'>'); prio=3;      // '>>'
      sdata[1]=*asmcmd++; }
    else if (idata=='|') prio=8;       // '|'
    else if (idata=='^') prio=7;       // '^'
    else if (idata=='&') prio=6;       // '&'
    else if (idata=='<') {
      if (*asmcmd=='&') {              // Import pseudolabel (for internal use)
        if ((mode & SA_IMPORT)==0) {
          asmerror="Syntax error"; scan=SCAN_ERR; return; };
        asmcmd++; i=0;
        while (*asmcmd!='\0' && *asmcmd!='>') {
          sdata[i++]=*asmcmd++;
          if (i>=sizeof(sdata)) {
            asmerror="Too long import name"; scan=SCAN_ERR; return;
          };
        };
        if (*asmcmd!='>') {
          asmerror="Unterminated import name"; scan=SCAN_ERR; return; };
        asmcmd++; sdata[i]='\0';
        scan=SCAN_IMPORT; return; }
      else prio=4; }                   // '<'
    else if (idata=='>') prio=4;       // '>'
    else if (idata=='+') prio=2;       // '+'
    else if (idata=='-') prio=2;       // '-'
    else if (idata=='*') prio=1;       // '*'
    else if (idata=='/') prio=1;       // '/'
    else if (idata=='%') prio=1;       // '%'
    else if (idata==']') {
      pcmd=asmcmd; Scanasm(SA_NAME);
      if (scan!=SCAN_SYMB || idata!='[') {
        idata=']'; asmcmd=pcmd; prio=0; }
      else {
        idata='+'; prio=2;             // Translate '][' to '+'
      };
    }
    else prio=0;                       // Any other character
    scan=SCAN_SYMB;
    return;
  };
};

// Fetches one complete operand from the input line and fills in structure op
// with operand's data. Expects that first token of the operand is already
// scanned. Supports operands in generalized form (for example, R32 means any
// of general-purpose 32-bit integer registers).
static void Parseasmoperand(t_asmoperand *op) {
  int i,j,bracket,sign,xlataddr;
  int reg,r[9];
  long offset;
  if (scan==SCAN_EOL || scan==SCAN_ERR)
    return;                            // No or bad operand
  // Jump or call address may begin with address size modifier(s) SHORT, LONG,
  // NEAR and/or FAR. Not all combinations are allowed. After operand is
  // completely parsed, this function roughly checks whether modifier is
  // allowed. Exact check is done in Assemble().
  if (scan==SCAN_JMPSIZE) {
    j=0;
    while (scan==SCAN_JMPSIZE) {
      j|=idata;                        // Fetch all size modifiers
      Scanasm(0); };
    if (
      ((j & 0x03)==0x03) ||            // Mixed SHORT and LONG
      ((j & 0x0C)==0x0C) ||            // Mixed NEAR and FAR
      ((j & 0x09)==0x09)               // Mixed FAR and SHORT
    ) {
      asmerror="Invalid combination of jump address modifiers";
      scan=SCAN_ERR; return; };
    if ((j & 0x08)==0) j|=0x04;        // Force NEAR if not FAR
    op->jmpmode=j; };
  // Simple operands are either register or constant, their processing is
  // obvious and straightforward.
  if (scan==SCAN_REG8 || scan==SCAN_REG16 || scan==SCAN_REG32) {
    op->type=REG; op->index=idata;     // Integer general-purpose register
    if (scan==SCAN_REG8) op->size=1;
    else if (scan==SCAN_REG16) op->size=2;
    else op->size=4; }
  else if (scan==SCAN_FPU) {           // FPU register
    op->type=RST; op->index=idata; }
  else if (scan==SCAN_MMX) {           // MMX or 3DNow! register
    op->type=RMX; op->index=idata; }
  else if (scan==SCAN_CR) {            // Control register
    op->type=CRX; op->index=idata; }
  else if (scan==SCAN_DR) {            // Debug register
    op->type=DRX; op->index=idata; }
  else if (scan==SCAN_SYMB && idata=='-') {
    Scanasm(0);                        // Negative constant
    if (scan!=SCAN_ICONST && scan!=SCAN_DCONST && scan!=SCAN_OFS) {
      asmerror="Integer number expected";
      scan=SCAN_ERR; return; };
    op->type=IMM; op->offset=-idata;
    if (scan==SCAN_OFS) op->anyoffset=1; }
  else if (scan==SCAN_SYMB && idata=='+') {
    Scanasm(0);                        // Positive constant
    if (scan!=SCAN_ICONST && scan!=SCAN_DCONST && scan!=SCAN_OFS) {
      asmerror="Integer number expected";
      scan=SCAN_ERR; return; };
    op->type=IMM; op->offset=idata;
    if (scan==SCAN_OFS) op->anyoffset=1; }
  else if (scan==SCAN_ICONST || scan==SCAN_DCONST || scan==SCAN_OFS) {
    j=idata;
    if (scan==SCAN_OFS) op->anyoffset=1;
    Scanasm(0);
    if (scan==SCAN_SYMB && idata==':') {
      Scanasm(0);                      // Absolute long address (seg:offset)
      if (scan!=SCAN_ICONST && scan!=SCAN_DCONST && scan!=SCAN_OFS) {
        asmerror="Integer address expected";
        scan=SCAN_ERR; return; };
      op->type=JMF; op->offset=idata; op->segment=j;
      if (scan==SCAN_OFS) op->anyoffset=1; }
    else {
      op->type=IMM; op->offset=j;      // Constant without sign
      return;                          // Next token already scanned
    }; }
  else if (scan==SCAN_FCONST) {
    asmerror="Floating-point numbers are not allowed in command";
    scan=SCAN_ERR; return; }
  // Segment register or address.
  else if (scan==SCAN_SEG || scan==SCAN_OPSIZE ||
    (scan==SCAN_SYMB && idata=='[')
  ) {                                  // Segment register or address
    bracket=0;
    if (scan==SCAN_SEG) {
      j=idata; Scanasm(0);
      if (scan!=SCAN_SYMB || idata!=':') {
        op->type=SGM; op->index=j;     // Segment register as operand
        return; };                     // Next token already scanned
      op->segment=j; Scanasm(0); };
    // Scan 32-bit address. This parser does not support 16-bit addresses.
    // First of all, get size of operand (optional), segment register (optional)
    // and opening bracket (required).
    while (1) {
      if (scan==SCAN_SYMB && idata=='[') {
        if (bracket) {                 // Bracket
          asmerror="Only one opening bracket allowed";
          scan=SCAN_ERR; return; };
        bracket=1; }
      else if (scan==SCAN_OPSIZE) {
        if (op->size!=0) {             // Size of operand
          asmerror="Duplicated size modifier";
          scan=SCAN_ERR; return; };
        op->size=idata; }
      else if (scan==SCAN_SEG) {
        if (op->segment!=SEG_UNDEF) {  // Segment register
          asmerror="Duplicated segment register";
          scan=SCAN_ERR; return; };
        op->segment=idata; Scanasm(0);
        if (scan!=SCAN_SYMB || idata!=':') {
          asmerror="Semicolon expected";
          scan=SCAN_ERR; return;
        }; }
      else if (scan==SCAN_ERR)
        return;
      else break;                      // None of expected address elements
      Scanasm(0); };
    if (bracket==0) {
      asmerror="Address expression requires brackets";
      scan=SCAN_ERR; return; };
    // Assembling a 32-bit address may be a kind of nigthmare, due to a large
    // number of allowed forms. Parser collects immediate offset in op->offset
    // and count for each register in array r[]. Then it decides whether this
    // combination is valid and determines scale, index and base. Assemble()
    // will use these numbers to select address form (with or without SIB byte,
    // 8- or 32-bit offset, use segment prefix or not). As a useful side effect
    // of this technique, one may specify, for example, [EAX*5] which will
    // correctly assemble to [EAX*4+EAX].
    for (i=0; i<=8; i++) r[i]=0;
    sign='+';                          // Default sign for the first operand
    xlataddr=0;
    while (1) {                        // Get SIB and offset
      if (scan==SCAN_SYMB && (idata=='+' || idata=='-')) {
        sign=idata; Scanasm(0); };
      if (scan==SCAN_ERR) return;
      if (sign=='?') {
        asmerror="Syntax error"; scan=SCAN_ERR; return; };
      // Register AL appears as part of operand of (seldom used) command XLAT.
      if (scan==SCAN_REG8 && idata==GREG_EAX) {
        if (sign=='-') {
          asmerror="Unable to subtract register"; scan=SCAN_ERR; return; };
        if (xlataddr!=0) {
          asmerror="Too many registers"; scan=SCAN_ERR; return; };
        xlataddr=1;
        Scanasm(0); }
      else if (scan==SCAN_REG16) {
        asmerror="Sorry, 16-bit addressing is not supported";
        scan=SCAN_ERR; return; }
      else if (scan==SCAN_REG32) {
        if (sign=='-') {
          asmerror="Unable to subtract register"; scan=SCAN_ERR; return; };
        reg=idata; Scanasm(0);
        if (scan==SCAN_SYMB && idata=='*') {
          Scanasm(0);                  // Try index*scale
          if (scan==SCAN_ERR) return;
          if (scan==SCAN_OFS) {
            asmerror="Undefined scale is not allowed"; scan=SCAN_ERR; return; };
          if (scan!=SCAN_ICONST && scan!=SCAN_DCONST) {
            asmerror="Syntax error"; scan=SCAN_ERR; return; };
          if (idata==6 || idata==7 || idata>9) {
            asmerror="Invalid scale"; scan=SCAN_ERR; return; };
          r[reg]+=idata;
          Scanasm(0); }
        else r[reg]++; }               // Simple register
      else if (scan==SCAN_LOCAL) {
        r[GREG_EBP]++;
        op->offset-=idata*4;
        Scanasm(0); }
      else if (scan==SCAN_ARG) {
        r[GREG_EBP]++;
        op->offset+=(idata+1)*4;
        Scanasm(0); }
      else if (scan==SCAN_ICONST || scan==SCAN_DCONST) {
        offset=idata; Scanasm(0);
        if (scan==SCAN_SYMB && idata=='*') {
          Scanasm(0);                  // Try scale*index
          if (scan==SCAN_ERR) return;
          if (sign=='-') {
            asmerror="Unable to subtract register"; scan=SCAN_ERR; return; };
          if (scan==SCAN_REG16) {
            asmerror="Sorry, 16-bit addressing is not supported";
            scan=SCAN_ERR; return; };
          if (scan!=SCAN_REG32) {
            asmerror="Syntax error"; scan=SCAN_ERR; return; };
          if (offset==6 || offset==7 || offset>9) {
            asmerror="Invalid scale"; scan=SCAN_ERR; return; };
          r[idata]+=offset;
          Scanasm(0); }
        else {
          if (sign=='-') op->offset-=offset;
          else op->offset+=offset;
        }; }
      else if (scan==SCAN_OFS) {
        Scanasm(0);
        if (scan==SCAN_SYMB && idata=='*') {
          asmerror="Undefined scale is not allowed"; scan=SCAN_ERR; return; }
        else {
          op->anyoffset=1;
        }; }
      else break;                      // None of expected address elements
      if (scan==SCAN_SYMB && idata==']') break;
      sign='?';
    };
    if (scan==SCAN_ERR) return;
    if (scan!=SCAN_SYMB || idata!=']') {
      asmerror="Syntax error";
      scan=SCAN_ERR; return; };
    // Process XLAT address separately.
    if (xlataddr!=0) {                 // XLAT address in form [EBX+AX]
      for (i=0; i<=8; i++) {           // Check which registers used
        if (i==GREG_EBX) continue;
        if (r[i]!=0) break; };
      if (i<=8 || r[GREG_EBX]!=1 || op->offset!=0 || op->anyoffset!=0) {
        asmerror="Invalid address"; scan=SCAN_ERR; return; };
      op->type=MXL; }
    // Determine scale, index and base.
    else {
      j=0;                             // Number of used registers
      for (i=0; i<=8; i++) {
        if (r[i]==0)
          continue;                    // Unused register
        if (r[i]==3 || r[i]==5 || r[i]==9) {
          if (op->index>=0 || op->base>=0) {
            if (j==0) asmerror="Invalid scale";
            else asmerror="Too many registers";
            scan=SCAN_ERR; return; };
          op->index=op->base=i;
          op->scale=r[i]-1; }
        else if (r[i]==2 || r[i]==4 || r[i]==8) {
          if (op->index>=0) {
            if (j<=1) asmerror="Only one register may be scaled";
            else asmerror="Too many registers";
            scan=SCAN_ERR; return; };
          op->index=i; op->scale=r[i]; }
        else if (r[i]==1) {
          if (op->base<0)
            op->base=i;
          else if (op->index<0) {
            op->index=i; op->scale=1; }
          else {
            asmerror="Too many registers";
            scan=SCAN_ERR; return;
          }; }
        else {
          asmerror="Invalid scale"; scan=SCAN_ERR; return; };
        j++;
      };
      op->type=MRG;
    }; }
  else {
    asmerror="Unrecognized operand"; scan=SCAN_ERR; return; };
  // In general, address modifier is allowed only with address expression which
  // is a constant, a far address or a memory expression. More precise check
  // will be done later in Assemble().
  if (op->jmpmode!=0 && op->type!=IMM && op->type!=JMF && op->type!=MRG) {
    asmerror="Jump address modifier is not allowed";
    scan=SCAN_ERR; return; };
  Scanasm(0);                          // Fetch next token from input line
};

// Function assembles text into 32-bit 80x86 machine code. It supports imprecise
// operands (for example, R32 stays for any general-purpose 32-bit register).
// This allows to search for incomplete commands. Command is precise when all
// significant bytes in model.mask are 0xFF. Some commands have more than one
// decoding. By calling Assemble() with attempt=0,1... and constsize=0,1,2,3 one
// gets also alternative variants (bit 0x1 of constsize is responsible for size
// of address constant and bit 0x2 - for immediate data). However, only one
// address form is generated ([EAX*2], but not [EAX+EAX]; [EBX+EAX] but not
// [EAX+EBX]; [EAX] will not use SIB byte; no DS: prefix and so on). Returns
// number of bytes in assembled code or non-positive number in case of detected
// error. This number is the negation of the offset in the input text where the
// error encountered. Unfortunately, BC 4.52 is unable to compile the switch
// (arg) in this code when any common subexpression optimization is on. The
// next #pragma statement disables all optimizations.

//#pragma option -Od                     // No optimizations, or BC 4.52 crashes

int Assemble(char *cmd,ulong ip,t_asmmodel *model,int attempt,
  int constsize,char *errtext) {
  int i,j,k,namelen,nameok,arg,match = 0,datasize,addrsize,bytesize,minop,maxop;
  int rep,lock,segment,jmpsize,jmpmode,longjump;
  int hasrm,hassib,dispsize,immsize;
  int anydisp,anyimm,anyjmp;
  long l,displacement,immediate,jmpoffset = 0;
  char name[32],*nameend;
  char tcode[MAXCMDSIZE],tmask[MAXCMDSIZE];
  t_asmoperand aop[3],*op;             // Up to 3 operands allowed
  const t_cmddata *pd;
  if (model!=NULL) model->length=0;
  if (cmd==NULL || model==NULL || errtext==NULL) {
    if (errtext!=NULL) strcpy(errtext,"Internal OLLYDBG error");
    return 0; };                       // Error in parameters
  asmcmd=cmd;
  rep=lock=0; errtext[0]='\0';
  Scanasm(SA_NAME);
  if (scan==SCAN_EOL)                  // End of line, nothing to assemble
    return 0;
  while (1) {                          // Fetch all REPxx and LOCK prefixes
    if (scan==SCAN_REP || scan==SCAN_REPE || scan==SCAN_REPNE) {
      if (rep!=0) {
        strcpy(errtext,"Duplicated REP prefix"); goto error; };
      rep=scan; }
    else if (scan==SCAN_LOCK) {
      if (lock!=0) {
        strcpy(errtext,"Duplicated LOCK prefix"); goto error; };
      lock=scan; }
    else break;                        // No more prefixes
    Scanasm(SA_NAME); };
  if (scan!=SCAN_NAME || idata>16) {
    strcpy(errtext,"Command mnemonic expected"); goto error; };
  nameend=asmcmd;
  strupr(sdata);
  // Prepare full mnemonic (including repeat prefix, if any).
  if (rep==SCAN_REP) snprintf(name,sizeof(name)-1,"REP %s",sdata);
  else if (rep==SCAN_REPE) snprintf(name,sizeof(name)-1,"REPE %s",sdata);
  else if (rep==SCAN_REPNE) snprintf(name,sizeof(name)-1,"REPNE %s",sdata);
  else strncpy(name,sdata, sizeof(name)-1);
  Scanasm(0);
  // Parse command operands (up to 3). Note: jump address is always the first
  // (and only) operand in actual command set.
  for (i=0; i<3; i++) {
    aop[i].type=NNN;                   // No operand
    aop[i].size=0;                     // Undefined size
    aop[i].index=-1;                   // No index
    aop[i].scale=0;                    // No scale
    aop[i].base=-1;                    // No base
    aop[i].offset=0;                   // No offset
    aop[i].anyoffset=0;                // No offset
    aop[i].segment=SEG_UNDEF;          // No segment
    aop[i].jmpmode=0; };               // No jump size modifier
  Parseasmoperand(aop+0);
  jmpmode=aop[0].jmpmode;
  if (jmpmode!=0) jmpmode|=0x80;
  if (scan==SCAN_SYMB && idata==',') {
    Scanasm(0);
    Parseasmoperand(aop+1);
    if (scan==SCAN_SYMB && idata==',') {
      Scanasm(0);
      Parseasmoperand(aop+2);
    };
  };
  if (scan==SCAN_ERR) {
    strcpy(errtext,asmerror); goto error; };
  if (scan!=SCAN_EOL) {
    strcpy(errtext,"Extra input after operand"); goto error; };
  // If jump size is not specified, function tries to use short jump. If
  // attempt fails, it retries with long form.
  longjump=0;                          // Try short jump on the first pass
retrylongjump:
  nameok=0;
  // Some commands allow different number of operands. Variables minop and
  // maxop accumulate their minimal and maximal counts. The numbers are not
  // used in assembly process but allow for better error diagnostics.
  minop=3; maxop=0;
  // Main assembly loop: try to find the command which matches all operands,
  // but do not process operands yet.
  namelen=strlen(name);
  for (pd=cmddata; pd->mask!=0; pd++) {
    if (pd->name[0]=='&') {            // Mnemonic depends on operand size
      j=1;
      datasize=2;
      addrsize=4;
      while (1) {                      // Try all mnemonics (separated by ':')
        for (i=0; pd->name[j]!='\0' && pd->name[j]!=':'; j++) {
          if (pd->name[j]=='*') {
            if (name[i]=='W') { datasize=2; i++; }
            else if (name[i]=='D') { datasize=4; i++; }
            else if (sizesens==0) datasize=2;
            else datasize=4; }
          else if (pd->name[j]==name[i]) i++;
          else break;
        };
        if (name[i]=='\0' && (pd->name[j]=='\0' || pd->name[j]==':'))
          break;                       // Bingo!
        while (pd->name[j]!='\0' && pd->name[j]!=':')
          j++;
        if (pd->name[j]==':') {
          j++; datasize=4; }           // Retry with 32-bit mnenonic
        else {
          i=0; break;                  // Comparison failed
        };
      };
      if (i==0) continue; }
    else if (pd->name[0]=='$') {       // Mnemonic depends on address size
      j=1;
      datasize=0;
      addrsize=2;
      while (1) {                      // Try all mnemonics (separated by ':')
        for (i=0; pd->name[j]!='\0' && pd->name[j]!=':'; j++) {
          if (pd->name[j]=='*') {
            if (name[i]=='W') { addrsize=2; i++; }
            else if (name[i]=='D') { addrsize=4; i++; }
            else if (sizesens==0) addrsize=2;
            else addrsize=4; }
          else if (pd->name[j]==name[i]) i++;
          else break;
        };
        if (name[i]=='\0' && (pd->name[j]=='\0' || pd->name[j]==':'))
          break;                       // Bingo!
        while (pd->name[j]!='\0' && pd->name[j]!=':')
          j++;
        if (pd->name[j]==':') {
          j++; addrsize=4; }           // Retry with 32-bit mnenonic
        else {
          i=0; break;                  // Comparison failed
        };
      };
      if (i==0) continue; }
    else {                             // Compare with all synonimes
      j=k=0;
      datasize=0;                      // Default settings
      addrsize=4;
      while (1) {
        while (pd->name[j]!=',' && pd->name[j]!='\0') j++;
        if (j-k==namelen && strnicmp(name,pd->name+k,namelen)==0) break;
        k=j+1; if (pd->name[j]=='\0') break;
        j=k; };
      if (k>j) continue;
    };
    // For error diagnostics it is important to know whether mnemonic exists.
    nameok++;
    if (pd->arg1==NNN || pd->arg1>=PSEUDOOP)
       minop=0;
    else if (pd->arg2==NNN || pd->arg2>=PSEUDOOP) {
       if (minop>1) minop=1;
       if (maxop<1) maxop=1; }
    else if (pd->arg3==NNN || pd->arg3>=PSEUDOOP) {
       if (minop>2) minop=2;
       if (maxop<2) maxop=2; }
    else
      maxop=3;
    // Determine default and allowed operand size(s).
    if (pd->bits==FF) datasize=2;      // Forced 16-bit size
    if (pd->bits==WW || pd->bits==WS || pd->bits==W3 || pd->bits==WP)
      bytesize=1;                      // 1-byte size allowed
    else
      bytesize=0;                      // Word/dword size only
    // Check whether command operands match specified. If so, variable match
    // remains zero, otherwise it contains kind of mismatch. This allows for
    // better error diagnostics.
    match=0;
    for (j=0; j<3; j++) {              // Up to 3 operands
      op=aop+j;
      if (j==0) arg=pd->arg1;
      else if (j==1) arg=pd->arg2;
      else arg=pd->arg3;
      if (arg==NNN || arg>=PSEUDOOP) {
        if (op->type!=NNN)             // No more arguments
          match|=MA_NOP;
        break; };
      if (op->type==NNN) {
        match|=MA_NOP; break; };       // No corresponding operand
      switch (arg) {
        case REG:                      // Integer register in Reg field
        case RCM:                      // Integer register in command byte
        case RAC:                      // Accumulator (AL/AX/EAX, implicit)
          if (op->type!=REG) match|=MA_TYP;
          if (arg==RAC && op->index!=GREG_EAX && op->index!=8) match|=MA_TYP;
          if (bytesize==0 && op->size==1) match|=MA_SIZ;
          if (datasize==0) datasize=op->size;
          if (datasize!=op->size) match|=MA_DIF;
          break;
        case RG4:                      // Integer 4-byte register in Reg field
          if (op->type!=REG) match|=MA_TYP;
          if (op->size!=4) match|=MA_SIZ;
          if (datasize==0) datasize=op->size;
          if (datasize!=op->size) match|=MA_DIF;
          break;
        case RAX:                      // AX (2-byte, implicit)
          if (op->type!=REG || (op->index!=GREG_EAX && op->index!=8))
            match|=MA_TYP;
          if (op->size!=2) match|=MA_SIZ;
          if (datasize==0) datasize=op->size;
          if (datasize!=op->size) match|=MA_DIF;
          break;
        case RDX:                      // DX (16-bit implicit port address)
          if (op->type!=REG || (op->index!=GREG_EDX && op->index!=8))
            match|=MA_TYP;
          if (op->size!=2) match|=MA_SIZ; break;
        case RCL:                      // Implicit CL register (for shifts)
          if (op->type!=REG || (op->index!=GREG_ECX && op->index!=8))
            match|=MA_TYP;
          if (op->size!=1) match|=MA_SIZ;
          break;
        case RS0:                      // Top of FPU stack (ST(0))
          if (op->type!=RST || (op->index!=0 && op->index!=8))
            match|=MA_TYP;
          break;
        case RST:                      // FPU register (ST(i)) in command byte
          if (op->type!=RST) match|=MA_TYP; break;
        case RMX:                      // MMX register MMx
        case R3D:                      // 3DNow! register MMx
          if (op->type!=RMX) match|=MA_TYP; break;
        case MRG:                      // Memory/register in ModRM byte
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (bytesize==0 && op->size==1) match|=MA_SIZ;
          if (datasize==0) datasize=op->size;
          if (op->size!=0 && op->size!=datasize) match|=MA_DIF;
          break;
        case MR1:                      // 1-byte memory/register in ModRM byte
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=1) match|=MA_SIZ;
          break;
        case MR2:                      // 2-byte memory/register in ModRM byte
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=2) match|=MA_SIZ;
          break;
        case MR4:                      // 4-byte memory/register in ModRM byte
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=4) match|=MA_SIZ;
          break;
        case RR4:                      // 4-byte memory/register (register only)
          if (op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=4) match|=MA_SIZ;
          break;
        case MRJ:                      // Memory/reg in ModRM as JUMP target
          if (op->type!=MRG && op->type!=REG) match|=MA_TYP;
          if (op->size!=0 && op->size!=4) match|=MA_SIZ;
          if ((jmpmode & 0x09)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case MR8:                      // 8-byte memory/MMX register in ModRM
        case MRD:                      // 8-byte memory/3DNow! register in ModRM
          if (op->type!=MRG && op->type!=RMX) match|=MA_TYP;
          if (op->size!=0 && op->size!=8) match|=MA_SIZ;
          break;
        case RR8:                      // 8-byte MMX register only in ModRM
        case RRD:                      // 8-byte memory/3DNow! (register only)
          if (op->type!=RMX) match|=MA_TYP;
          if (op->size!=0 && op->size!=8) match|=MA_SIZ;
          break;
        case MMA:                      // Memory address in ModRM byte for LEA
          if (op->type!=MRG) match|=MA_TYP; break;
        case MML:                      // Memory in ModRM byte (for LES)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=6) match|=MA_SIZ;
          if (datasize==0) datasize=4; else if (datasize!=4) match|=MA_DIF;
          break;
        case MMS:                      // Memory in ModRM byte (as SEG:OFFS)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=6) match|=MA_SIZ;
          if ((jmpmode & 0x07)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case MM6:                      // Memory in ModRm (6-byte descriptor)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=6) match|=MA_SIZ;
          break;
        case MMB:                      // Two adjacent memory locations (BOUND)
          if (op->type!=MRG) match|=MA_TYP;
          k=op->size; if (ideal==0 && k>1) k/=2;
          if (k!=0 && k!=datasize) match|=MA_DIF;
          break;
        case MD2:                      // Memory in ModRM byte (16-bit integer)
        case MB2:                      // Memory in ModRM byte (16-bit binary)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=2) match|=MA_SIZ;
          break;
        case MD4:                      // Memory in ModRM byte (32-bit integer)
        case MF4:                      // Memory in ModRM byte (32-bit float)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=4) match|=MA_SIZ;
          break;
        case MD8:                      // Memory in ModRM byte (64-bit integer)
        case MF8:                      // Memory in ModRM byte (64-bit float)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=8) match|=MA_SIZ;
          break;
        case MDA:                      // Memory in ModRM byte (80-bit BCD)
        case MFA:                      // Memory in ModRM byte (80-bit float)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0 && op->size!=10) match|=MA_SIZ;
          break;
        case MFE:                      // Memory in ModRM byte (FPU environment)
        case MFS:                      // Memory in ModRM byte (FPU state)
        case MFX:                      // Memory in ModRM byte (ext. FPU state)
          if (op->type!=MRG) match|=MA_TYP;
          if (op->size!=0) match|=MA_SIZ;
          break;
        case MSO:                      // Source in string operands ([ESI])
          if (op->type!=MRG || op->base!=GREG_ESI ||
            op->index!=-1 || op->offset!=0 || op->anyoffset!=0) match|=MA_TYP;
          if (datasize==0) datasize=op->size;
          if (op->size!=0 && op->size!=datasize) match|=MA_DIF;
          break;
        case MDE:                      // Destination in string operands ([EDI])
          if (op->type!=MRG || op->base!=GREG_EDI ||
            op->index!=-1 || op->offset!=0 || op->anyoffset!=0) match|=MA_TYP;
          if (op->segment!=SEG_UNDEF && op->segment!=SEG_ES) match|=MA_SEG;
          if (datasize==0) datasize=op->size;
          if (op->size!=0 && op->size!=datasize) match|=MA_DIF;
          break;
        case MXL:                      // XLAT operand ([EBX+AL])
          if (op->type!=MXL) match|=MA_TYP; break;
        case IMM:                      // Immediate data (8 or 16/32)
        case IMU:                      // Immediate unsigned data (8 or 16/32)
          if (op->type!=IMM) match|=MA_TYP;
          break;
        case VXD:                      // VxD service (32-bit only)
          if (op->type!=IMM) match|=MA_TYP;
          if (datasize==0) datasize=4;
          if (datasize!=4) match|=MA_SIZ;
          break;
        case JMF:                      // Immediate absolute far jump/call addr
          if (op->type!=JMF) match|=MA_TYP;
          if ((jmpmode & 0x05)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case JOB:                      // Immediate byte offset (for jumps)
          if (op->type!=IMM || longjump) match|=MA_TYP;
          if ((jmpmode & 0x0A)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case JOW:                      // Immediate full offset (for jumps)
          if (op->type!=IMM) match|=MA_TYP;
          if ((jmpmode & 0x09)!=0) match|=MA_JMP;
          jmpmode&=0x7F; break;
        case IMA:                      // Immediate absolute near data address
          if (op->type!=MRG || op->base>=0 || op->index>=0) match|=MA_TYP;
          break;
        case IMX:                      // Immediate sign-extendable byte
          if (op->type!=IMM) match|=MA_TYP;
          if (op->offset<-128 || op->offset>127) match|=MA_RNG;
          break;
        case C01:                      // Implicit constant 1 (for shifts)
          if (op->type!=IMM || (op->offset!=1 && op->anyoffset==0))
            match|=MA_TYP;
          break;
        case IMS:                      // Immediate byte (for shifts)
        case IM1:                      // Immediate byte
          if (op->type!=IMM) match|=MA_TYP;
          if (op->offset<-128 || op->offset>255) match|=MA_RNG;
          break;
        case IM2:                      // Immediate word (ENTER/RET)
          if (op->type!=IMM) match|=MA_TYP;
          if (op->offset<0 || op->offset>65535) match|=MA_RNG;
          break;
        case SGM:                      // Segment register in ModRM byte
          if (op->type!=SGM) match|=MA_TYP;
          if (datasize==0) datasize=2;
          if (datasize!=2) match|=MA_DIF;
          break;
        case SCM:                      // Segment register in command byte
          if (op->type!=SGM) match|=MA_TYP;
          break;
        case CRX:                      // Control register CRx
        case DRX:                      // Debug register DRx
          if (op->type!=arg) match|=MA_TYP;
          if (datasize==0) datasize=4;
          if (datasize!=4) match|=MA_DIF;
          break;
        case PRN:                      // Near return address (pseudooperand)
        case PRF:                      // Far return address (pseudooperand)
        case PAC:                      // Accumulator (AL/AX/EAX, pseudooperand)
        case PAH:                      // AH (in LAHF/SAHF, pseudooperand)
        case PFL:                      // Lower byte of flags (pseudooperand)
        case PS0:                      // Top of FPU stack (pseudooperand)
        case PS1:                      // ST(1) (pseudooperand)
        case PCX:                      // CX/ECX (pseudooperand)
        case PDI:                      // EDI (pseudooperand in MMX extensions)
          break;
        default:                       // Undefined type of operand
          strcpy(errtext,"Internal Assembler error");
        goto error;
      };                               // End of switch (arg)
      if ((jmpmode & 0x80)!=0) match|=MA_JMP;
      if (match!=0) break;             // Some of the operands doesn't match
    };                                 // End of operand matching loop
    if (match==0) {                    // Exact match found
      if (attempt>0) {
        --attempt; nameok=0; }         // Well, try to find yet another match
      else break;
    };
  };                                   // End of command search loop
  // Check whether some error was detected. If several errors were found
  // similtaneously, report one (roughly in order of significance).
  if (nameok==0) {                     // Mnemonic unavailable
    strcpy(errtext,"Unrecognized command");
    asmcmd=nameend; goto error; };
  if (match!=0) {                      // Command not found
    if (minop>0 && aop[minop-1].type==NNN)
      strcpy(errtext,"Too few operands");
    else if (maxop<3 && aop[maxop].type!=NNN)
      strcpy(errtext,"Too many operands");
    else if (nameok>1)                 // More that 1 command
      strcpy(errtext,"Command does not support given operands");
    else if (match & MA_JMP)
      strcpy(errtext,"Invalid jump size modifier");
    else if (match & MA_NOP)
      strcpy(errtext,"Wrong number of operands");
    else if (match & MA_TYP)
      strcpy(errtext,"Command does not support given operands");
    else if (match & MA_NOS)
      strcpy(errtext,"Please specify operand size");
    else if (match & MA_SIZ)
      strcpy(errtext,"Bad operand size");
    else if (match & MA_DIF)
      strcpy(errtext,"Different size of operands");
    else if (match & MA_SEG)
      strcpy(errtext,"Invalid segment register");
    else if (match & MA_RNG)
      strcpy(errtext,"Constant out of expected range");
    else
      strcpy(errtext,"Erroneous command");
    goto error;
  };
  // Exact match found. Now construct the code.
  hasrm=0;                             // Whether command has ModR/M byte
  hassib=0;                            // Whether command has SIB byte
  dispsize=0;                          // Size of displacement (if any)
  immsize=0;                           // Size of immediate data (if any)
  segment=SEG_UNDEF;                   // Necessary segment prefix
  jmpsize=0;                           // No relative jumps
  memset(tcode,0,sizeof(tcode));
  *(ulong *)tcode=pd->code & pd->mask;
  memset(tmask,0,sizeof(tmask));
  *(ulong *)tmask=pd->mask;
  i=pd->len-1;                         // Last byte of command itself
  if (rep) i++;                        // REPxx prefixes count as extra byte
  // In some cases at least one operand must have explicit size declaration (as
  // in MOV [EAX],1). This preliminary check does not include all cases.
  if (pd->bits==WW || pd->bits==WS || pd->bits==WP) {
    if (datasize==0) {
      strcpy(errtext,"Please specify operand size"); goto error; }
    else if (datasize>1)
      tcode[i]|=0x01;                  // WORD or DWORD size of operands
    tmask[i]|=0x01; }
  else if (pd->bits==W3) {
    if (datasize==0) {
      strcpy(errtext,"Please specify operand size"); goto error; }
    else if (datasize>1)
      tcode[i]|=0x08;                  // WORD or DWORD size of operands
    tmask[i]|=0x08; };
  // Present suffix of 3DNow! command as immediate byte operand.
  if ((pd->type & C_TYPEMASK)==C_NOW) {
    immsize=1;
    immediate=(pd->code>>16) & 0xFF; };
  // Process operands again, this time constructing the code.
  anydisp=anyimm=anyjmp=0;
  for (j=0; j<3; j++) {                // Up to 3 operands
    op=aop+j;
    if (j==0) arg=pd->arg1;
    else if (j==1) arg=pd->arg2;
    else arg=pd->arg3;
    if (arg==NNN) break;               // All operands processed
    switch (arg) {
      case REG:                        // Integer register in Reg field
      case RG4:                        // Integer 4-byte register in Reg field
      case RMX:                        // MMX register MMx
      case R3D:                        // 3DNow! register MMx
      case CRX:                        // Control register CRx
      case DRX:                        // Debug register DRx
        hasrm=1;
        if (op->index<8) {
          tcode[i+1]|=(char)(op->index<<3); tmask[i+1]|=0x38; };
        break;
      case RCM:                        // Integer register in command byte
      case RST:                        // FPU register (ST(i)) in command byte
        if (op->index<8) {
          tcode[i]|=(char)op->index; tmask[i]|=0x07; };
        break;
      case RAC:                        // Accumulator (AL/AX/EAX, implicit)
      case RAX:                        // AX (2-byte, implicit)
      case RDX:                        // DX (16-bit implicit port address)
      case RCL:                        // Implicit CL register (for shifts)
      case RS0:                        // Top of FPU stack (ST(0))
      case MDE:                        // Destination in string op's ([EDI])
      case C01:                        // Implicit constant 1 (for shifts)
        break;                         // Simply skip implicit operands
      case MSO:                        // Source in string op's ([ESI])
      case MXL:                        // XLAT operand ([EBX+AL])
        if (op->segment!=SEG_UNDEF && op->segment!=SEG_DS)
          segment=op->segment;
        break;
      case MRG:                        // Memory/register in ModRM byte
      case MRJ:                        // Memory/reg in ModRM as JUMP target
      case MR1:                        // 1-byte memory/register in ModRM byte
      case MR2:                        // 2-byte memory/register in ModRM byte
      case MR4:                        // 4-byte memory/register in ModRM byte
      case RR4:                        // 4-byte memory/register (register only)
      case MR8:                        // 8-byte memory/MMX register in ModRM
      case RR8:                        // 8-byte MMX register only in ModRM
      case MRD:                        // 8-byte memory/3DNow! register in ModRM
      case RRD:                        // 8-byte memory/3DNow! (register only)
        hasrm=1;
        if (op->type!=MRG) {           // Register in ModRM byte
          tcode[i+1]|=0xC0; tmask[i+1]|=0xC0;
          if (op->index<8) {
            tcode[i+1]|=(char)op->index; tmask[i+1]|=0x07; };
          break;
        };                             // Note: NO BREAK, continue with address
      case MMA:                        // Memory address in ModRM byte for LEA
      case MML:                        // Memory in ModRM byte (for LES)
      case MMS:                        // Memory in ModRM byte (as SEG:OFFS)
      case MM6:                        // Memory in ModRm (6-byte descriptor)
      case MMB:                        // Two adjacent memory locations (BOUND)
      case MD2:                        // Memory in ModRM byte (16-bit integer)
      case MB2:                        // Memory in ModRM byte (16-bit binary)
      case MD4:                        // Memory in ModRM byte (32-bit integer)
      case MD8:                        // Memory in ModRM byte (64-bit integer)
      case MDA:                        // Memory in ModRM byte (80-bit BCD)
      case MF4:                        // Memory in ModRM byte (32-bit float)
      case MF8:                        // Memory in ModRM byte (64-bit float)
      case MFA:                        // Memory in ModRM byte (80-bit float)
      case MFE:                        // Memory in ModRM byte (FPU environment)
      case MFS:                        // Memory in ModRM byte (FPU state)
      case MFX:                        // Memory in ModRM byte (ext. FPU state)
        hasrm=1; displacement=op->offset; anydisp=op->anyoffset;
        if (op->base<0 && op->index<0) {
          dispsize=4;                  // Special case of immediate address
          if (op->segment!=SEG_UNDEF && op->segment!=SEG_DS)
            segment=op->segment;
          tcode[i+1]|=0x05;
          tmask[i+1]|=0xC7; }
        else if (op->index<0 && op->base!=GREG_ESP) {
          tmask[i+1]|=0xC0;            // SIB byte unnecessary
          if (op->offset==0 && op->anyoffset==0 && op->base!=GREG_EBP)
            ;                          // [EBP] always requires offset
          else if ((constsize & 1)!=0 &&
            ((op->offset>=-128 && op->offset<128) || op->anyoffset!=0)
          ) {
            tcode[i+1]|=0x40;          // Disp8
            dispsize=1; }
          else {
            tcode[i+1]|=0x80;          // Disp32
            dispsize=4; };
          if (op->base<8) {
            if (op->segment!=SEG_UNDEF && op->segment!=addr32[op->base].defseg)
              segment=op->segment;
            tcode[i+1]|=
              (char)op->base;          // Note that case [ESP] has base<0.
            tmask[i+1]|=0x07; }
          else segment=op->segment; }
        else {                         // SIB byte necessary
          hassib=1;
          if (op->base==GREG_EBP &&     // EBP as base requires offset, optimize
            op->index>=0 && op->scale==1 && op->offset==0 && op->anyoffset==0) {
            op->base=op->index; op->index=GREG_EBP; };
          if (op->index==GREG_ESP &&    // ESP cannot be an index, reorder
            op->scale<=1) {
            op->index=op->base; op->base=GREG_ESP; op->scale=1; };
          if (op->base<0 &&            // No base means 4-byte offset, optimize
            op->index>=0 && op->scale==2 &&
            op->offset>=-128 && op->offset<128 && op->anyoffset==0) {
            op->base=op->index; op->scale=1; };
          if (op->index==GREG_ESP) {    // Reordering was unsuccessful
            strcpy(errtext,"Invalid indexing mode");
            goto error; };
          if (op->base<0) {
            tcode[i+1]|=0x04;
            dispsize=4; }
          else if (op->offset==0 && op->anyoffset==0 && op->base!=GREG_EBP)
            tcode[i+1]|=0x04;          // No displacement
          else if ((constsize & 1)!=0 &&
            ((op->offset>=-128 && op->offset<128) || op->anyoffset!=0)
          ) {
            tcode[i+1]|=0x44;          // Disp8
            dispsize=1; }
          else {
            tcode[i+1]|=0x84;          // Disp32
            dispsize=4; };
          tmask[i+1]|=0xC7;            // ModRM completed, proceed with SIB
          if (op->scale==2) tcode[i+2]|=0x40;
          else if (op->scale==4) tcode[i+2]|=0x80;
          else if (op->scale==8) tcode[i+2]|=0xC0;
          tmask[i+2]|=0xC0;
          if (op->index<8) {
            if (op->index<0) op->index=0x04;
            tcode[i+2]|=(char)(op->index<<3);
            tmask[i+2]|=0x38; };
          if (op->base<8) {
            if (op->base<0) op->base=0x05;
            if (op->segment!=SEG_UNDEF && op->segment!=addr32[op->base].defseg)
              segment=op->segment;
            tcode[i+2]|=(char)op->base;
            tmask[i+2]|=0x07; }
          else segment=op->segment; };
        break;
      case IMM:                        // Immediate data (8 or 16/32)
      case IMU:                        // Immediate unsigned data (8 or 16/32)
      case VXD:                        // VxD service (32-bit only)
        if (datasize==0 && pd->arg2==NNN && (pd->bits==SS || pd->bits==WS))
          datasize=4;
        if (datasize==0) {
          strcpy(errtext,"Please specify operand size");
          goto error; };
        immediate=op->offset; anyimm=op->anyoffset;
        if (pd->bits==SS || pd->bits==WS) {
          if (datasize>1 && (constsize & 2)!=0 &&
            ((immediate>=-128 && immediate<128) || op->anyoffset!=0)) {
            immsize=1; tcode[i]|=0x02; }
          else immsize=datasize;
          tmask[i]|=0x02; }
        else immsize=datasize;
        break;
      case IMX:                        // Immediate sign-extendable byte
      case IMS:                        // Immediate byte (for shifts)
      case IM1:                        // Immediate byte
        if (immsize==2)                // To accommodate ENTER instruction
          immediate=(immediate & 0xFFFF) | (op->offset<<16);
        else immediate=op->offset;
        anyimm|=op->anyoffset;
        immsize++; break;
      case IM2:                        // Immediate word (ENTER/RET)
        immediate=op->offset; anyimm=op->anyoffset;
        immsize=2; break;
      case IMA:                        // Immediate absolute near data address
        if (op->segment!=SEG_UNDEF && op->segment!=SEG_DS)
          segment=op->segment;
        displacement=op->offset; anydisp=op->anyoffset;
        dispsize=4; break;
      case JOB:                        // Immediate byte offset (for jumps)
        jmpoffset=op->offset; anyjmp=op->anyoffset;
        jmpsize=1; break;
      case JOW:                        // Immediate full offset (for jumps)
        jmpoffset=op->offset; anyjmp=op->anyoffset;
        jmpsize=4; break;
      case JMF:                        // Immediate absolute far jump/call addr
        displacement=op->offset; anydisp=op->anyoffset; dispsize=4;
        immediate=op->segment; anyimm=op->anyoffset; immsize=2;
        break;
      case SGM:                        // Segment register in ModRM byte
        hasrm=1;
        if (op->index<6) {
          tcode[i+1]|=(char)(op->index<<3); tmask[i+1]|=0x38; };
        break;
      case SCM:                        // Segment register in command byte
        if (op->index==SEG_FS || op->index==SEG_GS) {
          tcode[0]=0x0F; tmask[0]=0xFF;
          i=1;
          if (strcmp(name,"PUSH")==0)
            tcode[i]=(char)((op->index<<3) | 0x80);
          else
            tcode[i]=(char)((op->index<<3) | 0x81);
          tmask[i]=0xFF; }
        else if (op->index<6) {
          if (op->index==SEG_CS && strcmp(name,"POP")==0) {
            strcpy(errtext,"Unable to POP CS");
            goto error; };
          tcode[i]=(char)((tcode[i] & 0xC7) | (op->index<<3)); }
        else {
          tcode[i]&=0xC7;
          tmask[i]&=0xC7; };
        break;
      case PRN:                        // Near return address (pseudooperand)
      case PRF:                        // Far return address (pseudooperand)
      case PAC:                        // Accumulator (AL/AX/EAX, pseudooperand)
      case PAH:                        // AH (in LAHF/SAHF, pseudooperand)
      case PFL:                        // Lower byte of flags (pseudooperand)
      case PS0:                        // Top of FPU stack (pseudooperand)
      case PS1:                        // ST(1) (pseudooperand)
      case PCX:                        // CX/ECX (pseudooperand)
      case PDI:                        // EDI (pseudooperand in MMX extensions)
        break;                         // Simply skip preudooperands
      default:                         // Undefined type of operand
        strcpy(errtext,"Internal Assembler error");
      goto error;
    };
  };
  // Gather parts of command together in the complete command.
  j=0;
  if (lock!=0) {                       // Lock prefix specified
    model->code[j]=0xF0;
    model->mask[j]=0xFF; j++; };
  if (datasize==2 && pd->bits!=FF) {   // Data size prefix necessary
    model->code[j]=0x66;
    model->mask[j]=0xFF; j++; };
  if (addrsize==2) {                   // Address size prefix necessary
    model->code[j]=0x67;
    model->mask[j]=0xFF; j++; };
  if (segment!=SEG_UNDEF) {            // Segment prefix necessary
    if (segment==SEG_ES) model->code[j]=0x26;
    else if (segment==SEG_CS) model->code[j]=0x2E;
    else if (segment==SEG_SS) model->code[j]=0x36;
    else if (segment==SEG_DS) model->code[j]=0x3E;
    else if (segment==SEG_FS) model->code[j]=0x64;
    else if (segment==SEG_GS) model->code[j]=0x65;
    else { strcpy(errtext,"Internal Assembler error"); goto error; };
    model->mask[j]=0xFF; j++; };
  if (dispsize>0) {
    memcpy(tcode+i+1+hasrm+hassib,&displacement,dispsize);
    if (anydisp==0) memset(tmask+i+1+hasrm+hassib,0xFF,dispsize); };
  if (immsize>0) {
    if (immsize==1) l=0xFFFFFF00L;
    else if (immsize==2) l=0xFFFF0000L;
    else l=0L;
    if ((immediate & l)!=0 && (immediate & l)!=l) {
      strcpy(errtext,"Constant does not fit into operand");
      goto error; };
    memcpy(tcode+i+1+hasrm+hassib+dispsize,&immediate,immsize);
    if (anyimm==0) memset(tmask+i+1+hasrm+hassib+dispsize,0xFF,immsize); };
  i=i+1+hasrm+hassib+dispsize+immsize;
  jmpoffset -= (i+j+jmpsize);
  model->jmpsize=jmpsize;
  model->jmpoffset=jmpoffset;
  model->jmppos=i+j;
  if (jmpsize!=0) {
    if (ip!=0) {
      jmpoffset=jmpoffset-ip;
      if (jmpsize==1 && anyjmp==0 && (jmpoffset<-128 || jmpoffset>=128)) {
        if (longjump==0 && (jmpmode & 0x03)==0) {
          longjump=1;
          goto retrylongjump; };
        sprintf(errtext,
          "Relative jump out of range, use %s LONG form",name);
        goto error; };
      memcpy(tcode+i,&jmpoffset,jmpsize);
    };
    if (anyjmp==0) memset(tmask+i,0xFF,jmpsize);
    i+=jmpsize; };
  memcpy(model->code+j,tcode,i);
  memcpy(model->mask+j,tmask,i);
  i+=j;
  model->length=i;
  return i;                            // Positive value: length of code
error:
  model->length=0;
  return cmd-asmcmd;                   // Negative value: position of error
};

//#pragma option -O.                     // Restore old optimization options
