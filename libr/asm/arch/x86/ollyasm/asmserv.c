// Free Disassembler and Assembler -- Command data and service routines
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
//
// 05.03.2002: Corrected error, FSTSW AX assembled with data size prefix

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

const char *regname[3][9] = {
  { "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH", "R8"  },
  { "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R16" },
  { "EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI","R32" } };

const char *segname[8] = {
  "ES","CS","SS","DS","FS","GS","SEG?","SEG?" };

const char *sizename[11] = {
  "(0-BYTE)", "BYTE", "WORD", "(3-BYTE)",
  "DWORD", "(5-BYTE)", "FWORD", "(7-BYTE)",
  "QWORD", "(9-BYTE)", "TBYTE" };

const t_addrdec addr16[8] = {
  { SEG_DS,"BX+SI" }, { SEG_DS,"BX+DI" },
  { SEG_SS,"BP+SI" }, { SEG_SS,"BP+DI" },
  { SEG_DS,"SI" },    { SEG_DS,"DI" },
  { SEG_SS,"BP" },    { SEG_DS,"BX" } };

const t_addrdec addr32[8] = {
  { SEG_DS,"EAX" }, { SEG_DS,"ECX" },
  { SEG_DS,"EDX" }, { SEG_DS,"EBX" },
  { SEG_SS,"" },    { SEG_SS,"EBP" },
  { SEG_DS,"ESI" }, { SEG_DS,"EDI" } };

const char *fpuname[9] = {
  "ST0","ST1","ST2","ST3","ST4","ST5","ST6","ST7","FPU" };

const char *mmxname[9] = {
  "MM0","MM1","MM2","MM3","MM4","MM5","MM6","MM7","MMX" };

const char *crname[9] = {
  "CR0","CR1","CR2","CR3","CR4","CR5","CR6","CR7","CRX" };

const char *drname[9] = {
  "DR0","DR1","DR2","DR3","DR4","DR5","DR6","DR7","DRX" };

// List of available processor commands with decoding, types of parameters and
// other useful information. Last element has field mask=0. If mnemonic begins
// with ampersand ('&'), its mnemonic decodes differently depending on operand
// size (16 or 32 bits). If mnemonic begins with dollar ('$'), this mnemonic
// depends on address size. Semicolon (':') separates 16-bit form from 32-bit,
// asterisk ('*') will be substituted by either W (16), D (32) or none (16/32)
// character. If command is of type C_MMX or C_NOW, or if type contains C_EXPL
// (=0x01), Disassembler must specify explicit size of memory operand.
const t_cmddata cmddata[] = {
  { 0x0000FF, 0x000090, 1,00,  NNN,NNN,NNN, C_CMD+0,        "NOP" },
  { 0x0000FE, 0x00008A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "MOV" },
  { 0x0000F8, 0x000050, 1,00,  RCM,NNN,NNN, C_PSH+0,        "PUSH" },
  { 0x0000FE, 0x000088, 1,WW,  MRG,REG,NNN, C_CMD+0,        "MOV" },
  { 0x0000FF, 0x0000E8, 1,00,  JOW,NNN,NNN, C_CAL+0,        "CALL" },
  { 0x0000FD, 0x000068, 1,SS,  IMM,NNN,NNN, C_PSH+0,        "PUSH" },
  { 0x0000FF, 0x00008D, 1,00,  REG,MMA,NNN, C_CMD+0,        "LEA" },
  { 0x0000FF, 0x000074, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JE,JZ" },
  { 0x0000F8, 0x000058, 1,00,  RCM,NNN,NNN, C_POP+0,        "POP" },
  { 0x0038FC, 0x000080, 1,WS,  MRG,IMM,NNN, C_CMD+1,        "ADD" },
  { 0x0000FF, 0x000075, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JNZ,JNE" },
  { 0x0000FF, 0x0000EB, 1,00,  JOB,NNN,NNN, C_JMP+0,        "JMP" },
  { 0x0000FF, 0x0000E9, 1,00,  JOW,NNN,NNN, C_JMP+0,        "JMP" },
  { 0x0000FE, 0x000084, 1,WW,  MRG,REG,NNN, C_CMD+0,        "TEST" },
  { 0x0038FE, 0x0000C6, 1,WW,  MRG,IMM,NNN, C_CMD+1,        "MOV" },
  { 0x0000FE, 0x000032, 1,WW,  REG,MRG,NNN, C_CMD+0,        "XOR" },
  { 0x0000FE, 0x00003A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "CMP" },
  { 0x0038FC, 0x003880, 1,WS,  MRG,IMM,NNN, C_CMD+1,        "CMP" },
  { 0x0038FF, 0x0010FF, 1,00,  MRJ,NNN,NNN, C_CAL+0,        "CALL" },
  { 0x0000FF, 0x0000C3, 1,00,  NNN,NNN,NNN, C_RET+0,        "RETN,RET" },
  { 0x0000F0, 0x0000B0, 1,W3,  RCM,IMM,NNN, C_CMD+0,        "MOV" },
  { 0x0000FE, 0x0000A0, 1,WW,  RAC,IMA,NNN, C_CMD+0,        "MOV" },
  { 0x00FFFF, 0x00840F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JE,JZ" },
  { 0x0000F8, 0x000040, 1,00,  RCM,NNN,NNN, C_CMD+0,        "INC" },
  { 0x0038FE, 0x0000F6, 1,WW,  MRG,IMU,NNN, C_CMD+1,        "TEST" },
  { 0x0000FE, 0x0000A2, 1,WW,  IMA,RAC,NNN, C_CMD+0,        "MOV" },
  { 0x0000FE, 0x00002A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "SUB" },
  { 0x0000FF, 0x00007E, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JLE,JNG" },
  { 0x00FFFF, 0x00850F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JNZ,JNE" },
  { 0x0000FF, 0x0000C2, 1,00,  IM2,PRN,NNN, C_RET+0,        "RETN" },
  { 0x0038FF, 0x0030FF, 1,00,  MRG,NNN,NNN, C_PSH+1,        "PUSH" },
  { 0x0038FC, 0x000880, 1,WS,  MRG,IMU,NNN, C_CMD+1,        "OR" },
  { 0x0038FC, 0x002880, 1,WS,  MRG,IMM,NNN, C_CMD+1,        "SUB" },
  { 0x0000F8, 0x000048, 1,00,  RCM,NNN,NNN, C_CMD+0,        "DEC" },
  { 0x00FFFF, 0x00BF0F, 2,00,  REG,MR2,NNN, C_CMD+1,        "MOVSX" },
  { 0x0000FF, 0x00007C, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JL,JNGE" },
  { 0x0000FE, 0x000002, 1,WW,  REG,MRG,NNN, C_CMD+0,        "ADD" },
  { 0x0038FC, 0x002080, 1,WS,  MRG,IMU,NNN, C_CMD+1,        "AND" },
  { 0x0000FE, 0x00003C, 1,WW,  RAC,IMM,NNN, C_CMD+0,        "CMP" },
  { 0x0038FF, 0x0020FF, 1,00,  MRJ,NNN,NNN, C_JMP+0,        "JMP" },
  { 0x0038FE, 0x0010F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "NOT" },
  { 0x0038FE, 0x0028C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "SHR" },
  { 0x0000FE, 0x000038, 1,WW,  MRG,REG,NNN, C_CMD+0,        "CMP" },
  { 0x0000FF, 0x00007D, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JGE,JNL" },
  { 0x0000FF, 0x00007F, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JG,JNLE" },
  { 0x0038FE, 0x0020C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "SHL" },
  { 0x0000FE, 0x00001A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "SBB" },
  { 0x0038FE, 0x0018F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "NEG" },
  { 0x0000FF, 0x0000C9, 1,00,  NNN,NNN,NNN, C_CMD+0,        "LEAVE" },
  { 0x0000FF, 0x000060, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "&PUSHA*" },
  { 0x0038FF, 0x00008F, 1,00,  MRG,NNN,NNN, C_POP+1,        "POP" },
  { 0x0000FF, 0x000061, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "&POPA*" },
  { 0x0000F8, 0x000090, 1,00,  RAC,RCM,NNN, C_CMD+0,        "XCHG" },
  { 0x0000FE, 0x000086, 1,WW,  MRG,REG,NNN, C_CMD+0,        "XCHG" },
  { 0x0000FE, 0x000000, 1,WW,  MRG,REG,NNN, C_CMD+0,        "ADD" },
  { 0x0000FE, 0x000010, 1,WW,  MRG,REG,NNN, C_CMD+C_RARE+0, "ADC" },
  { 0x0000FE, 0x000012, 1,WW,  REG,MRG,NNN, C_CMD+C_RARE+0, "ADC" },
  { 0x0000FE, 0x000020, 1,WW,  MRG,REG,NNN, C_CMD+0,        "AND" },
  { 0x0000FE, 0x000022, 1,WW,  REG,MRG,NNN, C_CMD+0,        "AND" },
  { 0x0000FE, 0x000008, 1,WW,  MRG,REG,NNN, C_CMD+0,        "OR" },
  { 0x0000FE, 0x00000A, 1,WW,  REG,MRG,NNN, C_CMD+0,        "OR" },
  { 0x0000FE, 0x000028, 1,WW,  MRG,REG,NNN, C_CMD+0,        "SUB" },
  { 0x0000FE, 0x000018, 1,WW,  MRG,REG,NNN, C_CMD+C_RARE+0, "SBB" },
  { 0x0000FE, 0x000030, 1,WW,  MRG,REG,NNN, C_CMD+0,        "XOR" },
  { 0x0038FC, 0x001080, 1,WS,  MRG,IMM,NNN, C_CMD+C_RARE+1, "ADC" },
  { 0x0038FC, 0x001880, 1,WS,  MRG,IMM,NNN, C_CMD+C_RARE+1, "SBB" },
  { 0x0038FC, 0x003080, 1,WS,  MRG,IMU,NNN, C_CMD+1,        "XOR" },
  { 0x0000FE, 0x000004, 1,WW,  RAC,IMM,NNN, C_CMD+0,        "ADD" },
  { 0x0000FE, 0x000014, 1,WW,  RAC,IMM,NNN, C_CMD+C_RARE+0, "ADC" },
  { 0x0000FE, 0x000024, 1,WW,  RAC,IMU,NNN, C_CMD+0,        "AND" },
  { 0x0000FE, 0x00000C, 1,WW,  RAC,IMU,NNN, C_CMD+0,        "OR" },
  { 0x0000FE, 0x00002C, 1,WW,  RAC,IMM,NNN, C_CMD+0,        "SUB" },
  { 0x0000FE, 0x00001C, 1,WW,  RAC,IMM,NNN, C_CMD+C_RARE+0, "SBB" },
  { 0x0000FE, 0x000034, 1,WW,  RAC,IMU,NNN, C_CMD+0,        "XOR" },
  { 0x0038FE, 0x0000FE, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "INC" },
  { 0x0038FE, 0x0008FE, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "DEC" },
  { 0x0000FE, 0x0000A8, 1,WW,  RAC,IMU,NNN, C_CMD+0,        "TEST" },
  { 0x0038FE, 0x0020F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "MUL" },
  { 0x0038FE, 0x0028F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "IMUL" },
  { 0x00FFFF, 0x00AF0F, 2,00,  REG,MRG,NNN, C_CMD+0,        "IMUL" },
  { 0x0000FF, 0x00006B, 1,00,  REG,MRG,IMX, C_CMD+C_RARE+0, "IMUL" },
  { 0x0000FF, 0x000069, 1,00,  REG,MRG,IMM, C_CMD+C_RARE+0, "IMUL" },
  { 0x0038FE, 0x0030F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "DIV" },
  { 0x0038FE, 0x0038F6, 1,WW,  MRG,NNN,NNN, C_CMD+1,        "IDIV" },
  { 0x0000FF, 0x000098, 1,00,  NNN,NNN,NNN, C_CMD+0,        "&CBW:CWDE" },
  { 0x0000FF, 0x000099, 1,00,  NNN,NNN,NNN, C_CMD+0,        "&CWD:CDQ" },
  { 0x0038FE, 0x0000D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "ROL" },
  { 0x0038FE, 0x0008D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "ROR" },
  { 0x0038FE, 0x0010D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "RCL" },
  { 0x0038FE, 0x0018D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "RCR" },
  { 0x0038FE, 0x0020D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "SHL" },
  { 0x0038FE, 0x0028D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "SHR" },
  { 0x0038FE, 0x0038D0, 1,WW,  MRG,C01,NNN, C_CMD+1,        "SAR" },
  { 0x0038FE, 0x0000D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "ROL" },
  { 0x0038FE, 0x0008D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "ROR" },
  { 0x0038FE, 0x0010D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "RCL" },
  { 0x0038FE, 0x0018D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "RCR" },
  { 0x0038FE, 0x0020D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "SHL" },
  { 0x0038FE, 0x0028D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "SHR" },
  { 0x0038FE, 0x0038D2, 1,WW,  MRG,RCL,NNN, C_CMD+1,        "SAR" },
  { 0x0038FE, 0x0000C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "ROL" },
  { 0x0038FE, 0x0008C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "ROR" },
  { 0x0038FE, 0x0010C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "RCL" },
  { 0x0038FE, 0x0018C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "RCR" },
  { 0x0038FE, 0x0038C0, 1,WW,  MRG,IMS,NNN, C_CMD+1,        "SAR" },
  { 0x0000FF, 0x000070, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JO" },
  { 0x0000FF, 0x000071, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JNO" },
  { 0x0000FF, 0x000072, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JB,JC" },
  { 0x0000FF, 0x000073, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JNB,JNC" },
  { 0x0000FF, 0x000076, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JBE,JNA" },
  { 0x0000FF, 0x000077, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JA,JNBE" },
  { 0x0000FF, 0x000078, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JS" },
  { 0x0000FF, 0x000079, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JNS" },
  { 0x0000FF, 0x00007A, 1,CC,  JOB,NNN,NNN, C_JMC+C_RARE+0, "JPE,JP" },
  { 0x0000FF, 0x00007B, 1,CC,  JOB,NNN,NNN, C_JMC+C_RARE+0, "JPO,JNP" },
  { 0x0000FF, 0x0000E3, 1,00,  JOB,NNN,NNN, C_JMC+C_RARE+0, "$JCXZ:JECXZ" },
  { 0x00FFFF, 0x00800F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JO" },
  { 0x00FFFF, 0x00810F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JNO" },
  { 0x00FFFF, 0x00820F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JB,JC" },
  { 0x00FFFF, 0x00830F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JNB,JNC" },
  { 0x00FFFF, 0x00860F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JBE,JNA" },
  { 0x00FFFF, 0x00870F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JA,JNBE" },
  { 0x00FFFF, 0x00880F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JS" },
  { 0x00FFFF, 0x00890F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JNS" },
  { 0x00FFFF, 0x008A0F, 2,CC,  JOW,NNN,NNN, C_JMC+C_RARE+0, "JPE,JP" },
  { 0x00FFFF, 0x008B0F, 2,CC,  JOW,NNN,NNN, C_JMC+C_RARE+0, "JPO,JNP" },
  { 0x00FFFF, 0x008C0F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JL,JNGE" },
  { 0x00FFFF, 0x008D0F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JGE,JNL" },
  { 0x00FFFF, 0x008E0F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JLE,JNG" },
  { 0x00FFFF, 0x008F0F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JG,JNLE" },
  { 0x0000FF, 0x0000F8, 1,00,  NNN,NNN,NNN, C_CMD+0,        "CLC" },
  { 0x0000FF, 0x0000F9, 1,00,  NNN,NNN,NNN, C_CMD+0,        "STC" },
  { 0x0000FF, 0x0000F5, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "CMC" },
  { 0x0000FF, 0x0000FC, 1,00,  NNN,NNN,NNN, C_CMD+0,        "CLD" },
  { 0x0000FF, 0x0000FD, 1,00,  NNN,NNN,NNN, C_CMD+0,        "STD" },
  { 0x0000FF, 0x0000FA, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "CLI" },
  { 0x0000FF, 0x0000FB, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "STI" },
  { 0x0000FF, 0x00008C, 1,FF,  MRG,SGM,NNN, C_CMD+C_RARE+0, "MOV" },
  { 0x0000FF, 0x00008E, 1,FF,  SGM,MRG,NNN, C_CMD+C_RARE+0, "MOV" },
  { 0x0000FE, 0x0000A6, 1,WW,  MSO,MDE,NNN, C_CMD+1,        "CMPS" },
  { 0x0000FE, 0x0000AC, 1,WW,  MSO,NNN,NNN, C_CMD+1,        "LODS" },
  { 0x0000FE, 0x0000A4, 1,WW,  MDE,MSO,NNN, C_CMD+1,        "MOVS" },
  { 0x0000FE, 0x0000AE, 1,WW,  MDE,PAC,NNN, C_CMD+1,        "SCAS" },
  { 0x0000FE, 0x0000AA, 1,WW,  MDE,PAC,NNN, C_CMD+1,        "STOS" },
  { 0x00FEFF, 0x00A4F3, 1,WW,  MDE,MSO,PCX, C_REP+1,        "REP MOVS" },
  { 0x00FEFF, 0x00ACF3, 1,WW,  MSO,PAC,PCX, C_REP+C_RARE+1, "REP LODS" },
  { 0x00FEFF, 0x00AAF3, 1,WW,  MDE,PAC,PCX, C_REP+1,        "REP STOS" },
  { 0x00FEFF, 0x00A6F3, 1,WW,  MDE,MSO,PCX, C_REP+1,        "REPE CMPS" },
  { 0x00FEFF, 0x00AEF3, 1,WW,  MDE,PAC,PCX, C_REP+1,        "REPE SCAS" },
  { 0x00FEFF, 0x00A6F2, 1,WW,  MDE,MSO,PCX, C_REP+1,        "REPNE CMPS" },
  { 0x00FEFF, 0x00AEF2, 1,WW,  MDE,PAC,PCX, C_REP+1,        "REPNE SCAS" },
  { 0x0000FF, 0x0000EA, 1,00,  JMF,NNN,NNN, C_JMP+C_RARE+0, "JMP" },
  { 0x0038FF, 0x0028FF, 1,00,  MMS,NNN,NNN, C_JMP+C_RARE+1, "JMP" },
  { 0x0000FF, 0x00009A, 1,00,  JMF,NNN,NNN, C_CAL+C_RARE+0, "CALL" },
  { 0x0038FF, 0x0018FF, 1,00,  MMS,NNN,NNN, C_CAL+C_RARE+1, "CALL" },
  { 0x0000FF, 0x0000CB, 1,00,  PRF,NNN,NNN, C_RET+C_RARE+0, "RETF" },
  { 0x0000FF, 0x0000CA, 1,00,  IM2,PRF,NNN, C_RET+C_RARE+0, "RETF" },
  { 0x00FFFF, 0x00A40F, 2,00,  MRG,REG,IMS, C_CMD+0,        "SHLD" },
  { 0x00FFFF, 0x00AC0F, 2,00,  MRG,REG,IMS, C_CMD+0,        "SHRD" },
  { 0x00FFFF, 0x00A50F, 2,00,  MRG,REG,RCL, C_CMD+0,        "SHLD" },
  { 0x00FFFF, 0x00AD0F, 2,00,  MRG,REG,RCL, C_CMD+0,        "SHRD" },
  { 0x00F8FF, 0x00C80F, 2,00,  RCM,NNN,NNN, C_CMD+C_RARE+0, "BSWAP" },
  { 0x00FEFF, 0x00C00F, 2,WW,  MRG,REG,NNN, C_CMD+C_RARE+0, "XADD" },
  { 0x0000FF, 0x0000E2, 1,LL,  JOB,PCX,NNN, C_JMC+0,        "$LOOP*" },
  { 0x0000FF, 0x0000E1, 1,LL,  JOB,PCX,NNN, C_JMC+0,        "$LOOP*E" },
  { 0x0000FF, 0x0000E0, 1,LL,  JOB,PCX,NNN, C_JMC+0,        "$LOOP*NE" },
  { 0x0000FF, 0x0000C8, 1,00,  IM2,IM1,NNN, C_CMD+0,        "ENTER" },
  { 0x0000FE, 0x0000E4, 1,WP,  RAC,IM1,NNN, C_CMD+C_RARE+0, "IN" },
  { 0x0000FE, 0x0000EC, 1,WP,  RAC,RDX,NNN, C_CMD+C_RARE+0, "IN" },
  { 0x0000FE, 0x0000E6, 1,WP,  IM1,RAC,NNN, C_CMD+C_RARE+0, "OUT" },
  { 0x0000FE, 0x0000EE, 1,WP,  RDX,RAC,NNN, C_CMD+C_RARE+0, "OUT" },
  { 0x0000FE, 0x00006C, 1,WP,  MDE,RDX,NNN, C_CMD+C_RARE+1, "INS" },
  { 0x0000FE, 0x00006E, 1,WP,  RDX,MDE,NNN, C_CMD+C_RARE+1, "OUTS" },
  { 0x00FEFF, 0x006CF3, 1,WP,  MDE,RDX,PCX, C_REP+C_RARE+1, "REP INS" },
  { 0x00FEFF, 0x006EF3, 1,WP,  RDX,MDE,PCX, C_REP+C_RARE+1, "REP OUTS" },
  { 0x0000FF, 0x000037, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "AAA" },
  { 0x0000FF, 0x00003F, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "AAS" },
  { 0x00FFFF, 0x000AD4, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "AAM" },
  { 0x0000FF, 0x0000D4, 1,00,  IM1,NNN,NNN, C_CMD+C_RARE+0, "AAM" },
  { 0x00FFFF, 0x000AD5, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "AAD" },
  { 0x0000FF, 0x0000D5, 1,00,  IM1,NNN,NNN, C_CMD+C_RARE+0, "AAD" },
  { 0x0000FF, 0x000027, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "DAA" },
  { 0x0000FF, 0x00002F, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "DAS" },
  { 0x0000FF, 0x0000F4, 1,PR,  NNN,NNN,NNN, C_PRI+C_RARE+0, "HLT" },
  { 0x0000FF, 0x00000E, 1,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" },
  { 0x0000FF, 0x000016, 1,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" },
  { 0x0000FF, 0x00001E, 1,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" },
  { 0x0000FF, 0x000006, 1,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" },
  { 0x00FFFF, 0x00A00F, 2,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" },
  { 0x00FFFF, 0x00A80F, 2,00,  SCM,NNN,NNN, C_PSH+C_RARE+0, "PUSH" },
  { 0x0000FF, 0x00001F, 1,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" },
  { 0x0000FF, 0x000007, 1,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" },
  { 0x0000FF, 0x000017, 1,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" },
  { 0x00FFFF, 0x00A10F, 2,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" },
  { 0x00FFFF, 0x00A90F, 2,00,  SCM,NNN,NNN, C_POP+C_RARE+0, "POP" },
  { 0x0000FF, 0x0000D7, 1,00,  MXL,NNN,NNN, C_CMD+C_RARE+1, "XLAT" },
  { 0x00FFFF, 0x00BE0F, 2,00,  REG,MR1,NNN, C_CMD+1,        "MOVSX" },
  { 0x00FFFF, 0x00B60F, 2,00,  REG,MR1,NNN, C_CMD+1,        "MOVZX" },
  { 0x00FFFF, 0x00B70F, 2,00,  REG,MR2,NNN, C_CMD+1,        "MOVZX" },
  { 0x0000FF, 0x00009B, 1,00,  NNN,NNN,NNN, C_CMD+0,        "WAIT" },
  { 0x0000FF, 0x00009F, 1,00,  PAH,PFL,NNN, C_CMD+C_RARE+0, "LAHF" },
  { 0x0000FF, 0x00009E, 1,00,  PFL,PAH,NNN, C_CMD+C_RARE+0, "SAHF" },
  { 0x0000FF, 0x00009C, 1,00,  NNN,NNN,NNN, C_PSH+0,        "&PUSHF*" },
  { 0x0000FF, 0x00009D, 1,00,  NNN,NNN,NNN, C_FLG+0,        "&POPF*" },
  { 0x0000FF, 0x0000CD, 1,00,  IM1,NNN,NNN, C_CAL+C_RARE+0, "INT" },
  { 0x0000FF, 0x0000CC, 1,00,  NNN,NNN,NNN, C_CAL+C_RARE+0, "INT3" },
  { 0x0000FF, 0x0000CE, 1,00,  NNN,NNN,NNN, C_CAL+C_RARE+0, "INTO" },
  { 0x0000FF, 0x0000CF, 1,00,  NNN,NNN,NNN, C_RTF+C_RARE+0, "&IRET*" },
  { 0x00FFFF, 0x00900F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETO" },
  { 0x00FFFF, 0x00910F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETNO" },
  { 0x00FFFF, 0x00920F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETB,SETC" },
  { 0x00FFFF, 0x00930F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETNB,SETNC" },
  { 0x00FFFF, 0x00940F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETE,SETZ" },
  { 0x00FFFF, 0x00950F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETNE,SETNZ" },
  { 0x00FFFF, 0x00960F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETBE,SETNA" },
  { 0x00FFFF, 0x00970F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETA,SETNBE" },
  { 0x00FFFF, 0x00980F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETS" },
  { 0x00FFFF, 0x00990F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETNS" },
  { 0x00FFFF, 0x009A0F, 2,CC,  MR1,NNN,NNN, C_CMD+C_RARE+0, "SETPE,SETP" },
  { 0x00FFFF, 0x009B0F, 2,CC,  MR1,NNN,NNN, C_CMD+C_RARE+0, "SETPO,SETNP" },
  { 0x00FFFF, 0x009C0F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETL,SETNGE" },
  { 0x00FFFF, 0x009D0F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETGE,SETNL" },
  { 0x00FFFF, 0x009E0F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETLE,SETNG" },
  { 0x00FFFF, 0x009F0F, 2,CC,  MR1,NNN,NNN, C_CMD+0,        "SETG,SETNLE" },
  { 0x38FFFF, 0x20BA0F, 2,00,  MRG,IM1,NNN, C_CMD+C_RARE+1, "BT" },
  { 0x38FFFF, 0x28BA0F, 2,00,  MRG,IM1,NNN, C_CMD+C_RARE+1, "BTS" },
  { 0x38FFFF, 0x30BA0F, 2,00,  MRG,IM1,NNN, C_CMD+C_RARE+1, "BTR" },
  { 0x38FFFF, 0x38BA0F, 2,00,  MRG,IM1,NNN, C_CMD+C_RARE+1, "BTC" },
  { 0x00FFFF, 0x00A30F, 2,00,  MRG,REG,NNN, C_CMD+C_RARE+1, "BT" },
  { 0x00FFFF, 0x00AB0F, 2,00,  MRG,REG,NNN, C_CMD+C_RARE+1, "BTS" },
  { 0x00FFFF, 0x00B30F, 2,00,  MRG,REG,NNN, C_CMD+C_RARE+1, "BTR" },
  { 0x00FFFF, 0x00BB0F, 2,00,  MRG,REG,NNN, C_CMD+C_RARE+1, "BTC" },
  { 0x0000FF, 0x0000C5, 1,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LDS" },
  { 0x0000FF, 0x0000C4, 1,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LES" },
  { 0x00FFFF, 0x00B40F, 2,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LFS" },
  { 0x00FFFF, 0x00B50F, 2,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LGS" },
  { 0x00FFFF, 0x00B20F, 2,00,  REG,MML,NNN, C_CMD+C_RARE+0, "LSS" },
  { 0x0000FF, 0x000063, 1,00,  MRG,REG,NNN, C_CMD+C_RARE+0, "ARPL" },
  { 0x0000FF, 0x000062, 1,00,  REG,MMB,NNN, C_CMD+C_RARE+0, "BOUND" },
  { 0x00FFFF, 0x00BC0F, 2,00,  REG,MRG,NNN, C_CMD+C_RARE+0, "BSF" },
  { 0x00FFFF, 0x00BD0F, 2,00,  REG,MRG,NNN, C_CMD+C_RARE+0, "BSR" },
  { 0x00FFFF, 0x00060F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "CLTS" },
  { 0x00FFFF, 0x00400F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVO" },
  { 0x00FFFF, 0x00410F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVNO" },
  { 0x00FFFF, 0x00420F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVB,CMOVC" },
  { 0x00FFFF, 0x00430F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVNB,CMOVNC" },
  { 0x00FFFF, 0x00440F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVE,CMOVZ" },
  { 0x00FFFF, 0x00450F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVNE,CMOVNZ" },
  { 0x00FFFF, 0x00460F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVBE,CMOVNA" },
  { 0x00FFFF, 0x00470F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVA,CMOVNBE" },
  { 0x00FFFF, 0x00480F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVS" },
  { 0x00FFFF, 0x00490F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVNS" },
  { 0x00FFFF, 0x004A0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVPE,CMOVP" },
  { 0x00FFFF, 0x004B0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVPO,CMOVNP" },
  { 0x00FFFF, 0x004C0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVL,CMOVNGE" },
  { 0x00FFFF, 0x004D0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVGE,CMOVNL" },
  { 0x00FFFF, 0x004E0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVLE,CMOVNG" },
  { 0x00FFFF, 0x004F0F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVG,CMOVNLE" },
  { 0x00FEFF, 0x00B00F, 2,WW,  MRG,REG,NNN, C_CMD+C_RARE+0, "CMPXCHG" },
  { 0x38FFFF, 0x08C70F, 2,00,  MD8,NNN,NNN, C_CMD+C_RARE+1, "CMPXCHG8B" },
  { 0x00FFFF, 0x00A20F, 2,00,  NNN,NNN,NNN, C_CMD+0,        "CPUID" },
  { 0x00FFFF, 0x00080F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "INVD" },
  { 0x00FFFF, 0x00020F, 2,00,  REG,MRG,NNN, C_CMD+C_RARE+0, "LAR" },
  { 0x00FFFF, 0x00030F, 2,00,  REG,MRG,NNN, C_CMD+C_RARE+0, "LSL" },
  { 0x38FFFF, 0x38010F, 2,PR,  MR1,NNN,NNN, C_CMD+C_RARE+0, "INVLPG" },
  { 0x00FFFF, 0x00090F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "WBINVD" },
  { 0x38FFFF, 0x10010F, 2,PR,  MM6,NNN,NNN, C_CMD+C_RARE+0, "LGDT" },
  { 0x38FFFF, 0x00010F, 2,00,  MM6,NNN,NNN, C_CMD+C_RARE+0, "SGDT" },
  { 0x38FFFF, 0x18010F, 2,PR,  MM6,NNN,NNN, C_CMD+C_RARE+0, "LIDT" },
  { 0x38FFFF, 0x08010F, 2,00,  MM6,NNN,NNN, C_CMD+C_RARE+0, "SIDT" },
  { 0x38FFFF, 0x10000F, 2,PR,  MR2,NNN,NNN, C_CMD+C_RARE+0, "LLDT" },
  { 0x38FFFF, 0x00000F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "SLDT" },
  { 0x38FFFF, 0x18000F, 2,PR,  MR2,NNN,NNN, C_CMD+C_RARE+0, "LTR" },
  { 0x38FFFF, 0x08000F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "STR" },
  { 0x38FFFF, 0x30010F, 2,PR,  MR2,NNN,NNN, C_CMD+C_RARE+0, "LMSW" },
  { 0x38FFFF, 0x20010F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "SMSW" },
  { 0x38FFFF, 0x20000F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "VERR" },
  { 0x38FFFF, 0x28000F, 2,00,  MR2,NNN,NNN, C_CMD+C_RARE+0, "VERW" },
  { 0xC0FFFF, 0xC0220F, 2,PR,  CRX,RR4,NNN, C_CMD+C_RARE+0, "MOV" },
  { 0xC0FFFF, 0xC0200F, 2,00,  RR4,CRX,NNN, C_CMD+C_RARE+0, "MOV" },
  { 0xC0FFFF, 0xC0230F, 2,PR,  DRX,RR4,NNN, C_CMD+C_RARE+0, "MOV" },
  { 0xC0FFFF, 0xC0210F, 2,PR,  RR4,DRX,NNN, C_CMD+C_RARE+0, "MOV" },
  { 0x00FFFF, 0x00310F, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "RDTSC" },
  { 0x00FFFF, 0x00320F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "RDMSR" },
  { 0x00FFFF, 0x00300F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "WRMSR" },
  { 0x00FFFF, 0x00330F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "RDPMC" },
  { 0x00FFFF, 0x00AA0F, 2,PR,  NNN,NNN,NNN, C_RTF+C_RARE+0, "RSM" },
  { 0x00FFFF, 0x000B0F, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "UD2" },
  { 0x00FFFF, 0x00340F, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "SYSENTER" },
  { 0x00FFFF, 0x00350F, 2,PR,  NNN,NNN,NNN, C_CMD+C_RARE+0, "SYSEXIT" },
  { 0x0000FF, 0x0000D6, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "SALC" },
  // FPU instructions. Never change the order of instructions!
  { 0x00FFFF, 0x00F0D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "F2XM1" },
  { 0x00FFFF, 0x00E0D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FCHS" },
  { 0x00FFFF, 0x00E1D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FABS" },
  { 0x00FFFF, 0x00E2DB, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FCLEX" },
  { 0x00FFFF, 0x00E3DB, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FINIT" },
  { 0x00FFFF, 0x00F6D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FDECSTP" },
  { 0x00FFFF, 0x00F7D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FINCSTP" },
  { 0x00FFFF, 0x00E4D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FTST" },
  { 0x00FFFF, 0x00FAD9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FSQRT" },
  { 0x00FFFF, 0x00FED9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FSIN" },
  { 0x00FFFF, 0x00FFD9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FCOS" },
  { 0x00FFFF, 0x00FBD9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FSINCOS" },
  { 0x00FFFF, 0x00F2D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FPTAN" },
  { 0x00FFFF, 0x00F3D9, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FPATAN" },
  { 0x00FFFF, 0x00F8D9, 2,00,  PS1,PS0,NNN, C_FLT+0,        "FPREM" },
  { 0x00FFFF, 0x00F5D9, 2,00,  PS1,PS0,NNN, C_FLT+0,        "FPREM1" },
  { 0x00FFFF, 0x00F1D9, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FYL2X" },
  { 0x00FFFF, 0x00F9D9, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FYL2XP1" },
  { 0x00FFFF, 0x00FCD9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FRNDINT" },
  { 0x00FFFF, 0x00E8D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLD1" },
  { 0x00FFFF, 0x00E9D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDL2T" },
  { 0x00FFFF, 0x00EAD9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDL2E" },
  { 0x00FFFF, 0x00EBD9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDPI" },
  { 0x00FFFF, 0x00ECD9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDLG2" },
  { 0x00FFFF, 0x00EDD9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDLN2" },
  { 0x00FFFF, 0x00EED9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FLDZ" },
  { 0x00FFFF, 0x00FDD9, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FSCALE" },
  { 0x00FFFF, 0x00D0D9, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FNOP" },
  { 0x00FFFF, 0x00E0DF, 2,FF,  RAX,NNN,NNN, C_FLT+0,        "FSTSW" },
  { 0x00FFFF, 0x00E5D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FXAM" },
  { 0x00FFFF, 0x00F4D9, 2,00,  PS0,NNN,NNN, C_FLT+0,        "FXTRACT" },
  { 0x00FFFF, 0x00D9DE, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FCOMPP" },
  { 0x00FFFF, 0x00E9DA, 2,00,  PS0,PS1,NNN, C_FLT+0,        "FUCOMPP" },
  { 0x00F8FF, 0x00C0DD, 2,00,  RST,NNN,NNN, C_FLT+0,        "FFREE" },
  { 0x00F8FF, 0x00C0DA, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVB" },
  { 0x00F8FF, 0x00C8DA, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVE" },
  { 0x00F8FF, 0x00D0DA, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVBE" },
  { 0x00F8FF, 0x00D8DA, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVU" },
  { 0x00F8FF, 0x00C0DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVNB" },
  { 0x00F8FF, 0x00C8DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVNE" },
  { 0x00F8FF, 0x00D0DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVNBE" },
  { 0x00F8FF, 0x00D8DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCMOVNU" },
  { 0x00F8FF, 0x00F0DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCOMI" },
  { 0x00F8FF, 0x00F0DF, 2,00,  RS0,RST,NNN, C_FLT+0,        "FCOMIP" },
  { 0x00F8FF, 0x00E8DB, 2,00,  RS0,RST,NNN, C_FLT+0,        "FUCOMI" },
  { 0x00F8FF, 0x00E8DF, 2,00,  RS0,RST,NNN, C_FLT+0,        "FUCOMIP" },
  { 0x00F8FF, 0x00C0D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FADD" },
  { 0x00F8FF, 0x00C0DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FADD" },
  { 0x00F8FF, 0x00C0DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FADDP" },
  { 0x00F8FF, 0x00E0D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FSUB" },
  { 0x00F8FF, 0x00E8DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FSUB" },
  { 0x00F8FF, 0x00E8DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FSUBP" },
  { 0x00F8FF, 0x00E8D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FSUBR" },
  { 0x00F8FF, 0x00E0DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FSUBR" },
  { 0x00F8FF, 0x00E0DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FSUBRP" },
  { 0x00F8FF, 0x00C8D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FMUL" },
  { 0x00F8FF, 0x00C8DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FMUL" },
  { 0x00F8FF, 0x00C8DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FMULP" },
  { 0x00F8FF, 0x00D0D8, 2,00,  RST,PS0,NNN, C_FLT+0,        "FCOM" },
  { 0x00F8FF, 0x00D8D8, 2,00,  RST,PS0,NNN, C_FLT+0,        "FCOMP" },
  { 0x00F8FF, 0x00E0DD, 2,00,  RST,PS0,NNN, C_FLT+0,        "FUCOM" },
  { 0x00F8FF, 0x00E8DD, 2,00,  RST,PS0,NNN, C_FLT+0,        "FUCOMP" },
  { 0x00F8FF, 0x00F0D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FDIV" },
  { 0x00F8FF, 0x00F8DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FDIV" },
  { 0x00F8FF, 0x00F8DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FDIVP" },
  { 0x00F8FF, 0x00F8D8, 2,00,  RS0,RST,NNN, C_FLT+0,        "FDIVR" },
  { 0x00F8FF, 0x00F0DC, 2,00,  RST,RS0,NNN, C_FLT+0,        "FDIVR" },
  { 0x00F8FF, 0x00F0DE, 2,00,  RST,RS0,NNN, C_FLT+0,        "FDIVRP" },
  { 0x00F8FF, 0x00C0D9, 2,00,  RST,NNN,NNN, C_FLT+0,        "FLD" },
  { 0x00F8FF, 0x00D0DD, 2,00,  RST,PS0,NNN, C_FLT+0,        "FST" },
  { 0x00F8FF, 0x00D8DD, 2,00,  RST,PS0,NNN, C_FLT+0,        "FSTP" },
  { 0x00F8FF, 0x00C8D9, 2,00,  RST,PS0,NNN, C_FLT+0,        "FXCH" },
  { 0x0038FF, 0x0000D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FADD" },
  { 0x0038FF, 0x0000DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FADD" },
  { 0x0038FF, 0x0000DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIADD" },
  { 0x0038FF, 0x0000DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIADD" },
  { 0x0038FF, 0x0020D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FSUB" },
  { 0x0038FF, 0x0020DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FSUB" },
  { 0x0038FF, 0x0020DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FISUB" },
  { 0x0038FF, 0x0020DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FISUB" },
  { 0x0038FF, 0x0028D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FSUBR" },
  { 0x0038FF, 0x0028DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FSUBR" },
  { 0x0038FF, 0x0028DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FISUBR" },
  { 0x0038FF, 0x0028DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FISUBR" },
  { 0x0038FF, 0x0008D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FMUL" },
  { 0x0038FF, 0x0008DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FMUL" },
  { 0x0038FF, 0x0008DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIMUL" },
  { 0x0038FF, 0x0008DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIMUL" },
  { 0x0038FF, 0x0010D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FCOM" },
  { 0x0038FF, 0x0010DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FCOM" },
  { 0x0038FF, 0x0018D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FCOMP" },
  { 0x0038FF, 0x0018DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FCOMP" },
  { 0x0038FF, 0x0030D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FDIV" },
  { 0x0038FF, 0x0030DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FDIV" },
  { 0x0038FF, 0x0030DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIDIV" },
  { 0x0038FF, 0x0030DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIDIV" },
  { 0x0038FF, 0x0038D8, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FDIVR" },
  { 0x0038FF, 0x0038DC, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FDIVR" },
  { 0x0038FF, 0x0038DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIDIVR" },
  { 0x0038FF, 0x0038DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIDIVR" },
  { 0x0038FF, 0x0020DF, 1,00,  MDA,NNN,NNN, C_FLT+C_RARE+1, "FBLD" },
  { 0x0038FF, 0x0030DF, 1,00,  MDA,PS0,NNN, C_FLT+C_RARE+1, "FBSTP" },
  { 0x0038FF, 0x0010DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FICOM" },
  { 0x0038FF, 0x0010DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FICOM" },
  { 0x0038FF, 0x0018DE, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FICOMP" },
  { 0x0038FF, 0x0018DA, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FICOMP" },
  { 0x0038FF, 0x0000DF, 1,00,  MD2,NNN,NNN, C_FLT+1,        "FILD" },
  { 0x0038FF, 0x0000DB, 1,00,  MD4,NNN,NNN, C_FLT+1,        "FILD" },
  { 0x0038FF, 0x0028DF, 1,00,  MD8,NNN,NNN, C_FLT+1,        "FILD" },
  { 0x0038FF, 0x0010DF, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FIST" },
  { 0x0038FF, 0x0010DB, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FIST" },
  { 0x0038FF, 0x0018DF, 1,00,  MD2,PS0,NNN, C_FLT+1,        "FISTP" },
  { 0x0038FF, 0x0018DB, 1,00,  MD4,PS0,NNN, C_FLT+1,        "FISTP" },
  { 0x0038FF, 0x0038DF, 1,00,  MD8,PS0,NNN, C_FLT+1,        "FISTP" },
  { 0x0038FF, 0x0000D9, 1,00,  MF4,NNN,NNN, C_FLT+1,        "FLD" },
  { 0x0038FF, 0x0000DD, 1,00,  MF8,NNN,NNN, C_FLT+1,        "FLD" },
  { 0x0038FF, 0x0028DB, 1,00,  MFA,NNN,NNN, C_FLT+1,        "FLD" },
  { 0x0038FF, 0x0010D9, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FST" },
  { 0x0038FF, 0x0010DD, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FST" },
  { 0x0038FF, 0x0018D9, 1,00,  MF4,PS0,NNN, C_FLT+1,        "FSTP" },
  { 0x0038FF, 0x0018DD, 1,00,  MF8,PS0,NNN, C_FLT+1,        "FSTP" },
  { 0x0038FF, 0x0038DB, 1,00,  MFA,PS0,NNN, C_FLT+1,        "FSTP" },
  { 0x0038FF, 0x0028D9, 1,00,  MB2,NNN,NNN, C_FLT+0,        "FLDCW" },
  { 0x0038FF, 0x0038D9, 1,00,  MB2,NNN,NNN, C_FLT+0,        "FSTCW" },
  { 0x0038FF, 0x0020D9, 1,00,  MFE,NNN,NNN, C_FLT+0,        "FLDENV" },
  { 0x0038FF, 0x0030D9, 1,00,  MFE,NNN,NNN, C_FLT+0,        "FSTENV" },
  { 0x0038FF, 0x0020DD, 1,00,  MFS,NNN,NNN, C_FLT+0,        "FRSTOR" },
  { 0x0038FF, 0x0030DD, 1,00,  MFS,NNN,NNN, C_FLT+0,        "FSAVE" },
  { 0x0038FF, 0x0038DD, 1,00,  MB2,NNN,NNN, C_FLT+0,        "FSTSW" },
  { 0x38FFFF, 0x08AE0F, 2,00,  MFX,NNN,NNN, C_FLT+0,        "FXRSTOR" },
  { 0x38FFFF, 0x00AE0F, 2,00,  MFX,NNN,NNN, C_FLT+0,        "FXSAVE" },
  { 0x00FFFF, 0x00E0DB, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FENI" },
  { 0x00FFFF, 0x00E1DB, 2,00,  NNN,NNN,NNN, C_FLT+0,        "FDISI" },
  // MMX instructions. Length of MMX operand fields (in bytes) is added to the
  // type, length of 0 means 8-byte MMX operand.
  { 0x00FFFF, 0x00770F, 2,00,  NNN,NNN,NNN, C_MMX+0,        "EMMS" },
  { 0x00FFFF, 0x006E0F, 2,00,  RMX,MR4,NNN, C_MMX+0,        "MOVD" },
  { 0x00FFFF, 0x007E0F, 2,00,  MR4,RMX,NNN, C_MMX+0,        "MOVD" },
  { 0x00FFFF, 0x006F0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "MOVQ" },
  { 0x00FFFF, 0x007F0F, 2,00,  MR8,RMX,NNN, C_MMX+0,        "MOVQ" },
  { 0x00FFFF, 0x00630F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PACKSSWB" },
  { 0x00FFFF, 0x006B0F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PACKSSDW" },
  { 0x00FFFF, 0x00670F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PACKUSWB" },
  { 0x00FFFF, 0x00FC0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PADDB" },
  { 0x00FFFF, 0x00FD0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PADDW" },
  { 0x00FFFF, 0x00FE0F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PADDD" },
  { 0x00FFFF, 0x00F80F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PSUBB" },
  { 0x00FFFF, 0x00F90F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSUBW" },
  { 0x00FFFF, 0x00FA0F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PSUBD" },
  { 0x00FFFF, 0x00EC0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PADDSB" },
  { 0x00FFFF, 0x00ED0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PADDSW" },
  { 0x00FFFF, 0x00E80F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PSUBSB" },
  { 0x00FFFF, 0x00E90F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSUBSW" },
  { 0x00FFFF, 0x00DC0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PADDUSB" },
  { 0x00FFFF, 0x00DD0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PADDUSW" },
  { 0x00FFFF, 0x00D80F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PSUBUSB" },
  { 0x00FFFF, 0x00D90F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSUBUSW" },
  { 0x00FFFF, 0x00DB0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PAND" },
  { 0x00FFFF, 0x00DF0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PANDN" },
  { 0x00FFFF, 0x00740F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PCMPEQB" },
  { 0x00FFFF, 0x00750F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PCMPEQW" },
  { 0x00FFFF, 0x00760F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PCMPEQD" },
  { 0x00FFFF, 0x00640F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PCMPGTB" },
  { 0x00FFFF, 0x00650F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PCMPGTW" },
  { 0x00FFFF, 0x00660F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PCMPGTD" },
  { 0x00FFFF, 0x00F50F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMADDWD" },
  { 0x00FFFF, 0x00E50F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMULHW" },
  { 0x00FFFF, 0x00D50F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMULLW" },
  { 0x00FFFF, 0x00EB0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "POR" },
  { 0x00FFFF, 0x00F10F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSLLW" },
  { 0x38FFFF, 0x30710F, 2,00,  MR8,IM1,NNN, C_MMX+2,        "PSLLW" },
  { 0x00FFFF, 0x00F20F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PSLLD" },
  { 0x38FFFF, 0x30720F, 2,00,  MR8,IM1,NNN, C_MMX+4,        "PSLLD" },
  { 0x00FFFF, 0x00F30F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PSLLQ" },
  { 0x38FFFF, 0x30730F, 2,00,  MR8,IM1,NNN, C_MMX+0,        "PSLLQ" },
  { 0x00FFFF, 0x00E10F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSRAW" },
  { 0x38FFFF, 0x20710F, 2,00,  MR8,IM1,NNN, C_MMX+2,        "PSRAW" },
  { 0x00FFFF, 0x00E20F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PSRAD" },
  { 0x38FFFF, 0x20720F, 2,00,  MR8,IM1,NNN, C_MMX+4,        "PSRAD" },
  { 0x00FFFF, 0x00D10F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PSRLW" },
  { 0x38FFFF, 0x10710F, 2,00,  MR8,IM1,NNN, C_MMX+2,        "PSRLW" },
  { 0x00FFFF, 0x00D20F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PSRLD" },
  { 0x38FFFF, 0x10720F, 2,00,  MR8,IM1,NNN, C_MMX+4,        "PSRLD" },
  { 0x00FFFF, 0x00D30F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PSRLQ" },
  { 0x38FFFF, 0x10730F, 2,00,  MR8,IM1,NNN, C_MMX+0,        "PSRLQ" },
  { 0x00FFFF, 0x00680F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PUNPCKHBW" },
  { 0x00FFFF, 0x00690F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PUNPCKHWD" },
  { 0x00FFFF, 0x006A0F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PUNPCKHDQ" },
  { 0x00FFFF, 0x00600F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PUNPCKLBW" },
  { 0x00FFFF, 0x00610F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PUNPCKLWD" },
  { 0x00FFFF, 0x00620F, 2,00,  RMX,MR8,NNN, C_MMX+4,        "PUNPCKLDQ" },
  { 0x00FFFF, 0x00EF0F, 2,00,  RMX,MR8,NNN, C_MMX+0,        "PXOR" },
  // AMD extensions to MMX command set (including Athlon/PIII extensions).
  { 0x00FFFF, 0x000E0F, 2,00,  NNN,NNN,NNN, C_MMX+0,        "FEMMS" },
  { 0x38FFFF, 0x000D0F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCH" },
  { 0x38FFFF, 0x080D0F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHW" },
  { 0x00FFFF, 0x00F70F, 2,00,  RMX,RR8,PDI, C_MMX+1,        "MASKMOVQ" },
  { 0x00FFFF, 0x00E70F, 2,00,  MD8,RMX,NNN, C_MMX+0,        "MOVNTQ" },
  { 0x00FFFF, 0x00E00F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PAVGB" },
  { 0x00FFFF, 0x00E30F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PAVGW" },
  { 0x00FFFF, 0x00C50F, 2,00,  RR4,RMX,IM1, C_MMX+2,        "PEXTRW" },
  { 0x00FFFF, 0x00C40F, 2,00,  RMX,MR2,IM1, C_MMX+2,        "PINSRW" },
  { 0x00FFFF, 0x00EE0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMAXSW" },
  { 0x00FFFF, 0x00DE0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PMAXUB" },
  { 0x00FFFF, 0x00EA0F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMINSW" },
  { 0x00FFFF, 0x00DA0F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PMINUB" },
  { 0x00FFFF, 0x00D70F, 2,00,  RG4,RR8,NNN, C_MMX+1,        "PMOVMSKB" },
  { 0x00FFFF, 0x00E40F, 2,00,  RMX,MR8,NNN, C_MMX+2,        "PMULHUW" },
  { 0x38FFFF, 0x00180F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHNTA" },
  { 0x38FFFF, 0x08180F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHT0" },
  { 0x38FFFF, 0x10180F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHT1" },
  { 0x38FFFF, 0x18180F, 2,00,  MD8,NNN,NNN, C_MMX+0,        "PREFETCHT2" },
  { 0x00FFFF, 0x00F60F, 2,00,  RMX,MR8,NNN, C_MMX+1,        "PSADBW" },
  { 0x00FFFF, 0x00700F, 2,00,  RMX,MR8,IM1, C_MMX+2,        "PSHUFW" },
  { 0xFFFFFF, 0xF8AE0F, 2,00,  NNN,NNN,NNN, C_MMX+0,        "SFENCE" },
  // AMD 3DNow! instructions (including Athlon extensions).
  { 0x00FFFF, 0xBF0F0F, 2,00,  RMX,MR8,NNN, C_NOW+1,        "PAVGUSB" },
  { 0x00FFFF, 0x9E0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFADD" },
  { 0x00FFFF, 0x9A0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFSUB" },
  { 0x00FFFF, 0xAA0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFSUBR" },
  { 0x00FFFF, 0xAE0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFACC" },
  { 0x00FFFF, 0x900F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PFCMPGE" },
  { 0x00FFFF, 0xA00F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PFCMPGT" },
  { 0x00FFFF, 0xB00F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PFCMPEQ" },
  { 0x00FFFF, 0x940F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFMIN" },
  { 0x00FFFF, 0xA40F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFMAX" },
  { 0x00FFFF, 0x0D0F0F, 2,00,  R3D,MR8,NNN, C_NOW+4,        "PI2FD" },
  { 0x00FFFF, 0x1D0F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PF2ID" },
  { 0x00FFFF, 0x960F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRCP" },
  { 0x00FFFF, 0x970F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRSQRT" },
  { 0x00FFFF, 0xB40F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFMUL" },
  { 0x00FFFF, 0xA60F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRCPIT1" },
  { 0x00FFFF, 0xA70F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRSQIT1" },
  { 0x00FFFF, 0xB60F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFRCPIT2" },
  { 0x00FFFF, 0xB70F0F, 2,00,  RMX,MR8,NNN, C_NOW+2,        "PMULHRW" },
  { 0x00FFFF, 0x1C0F0F, 2,00,  RMX,MRD,NNN, C_NOW+4,        "PF2IW" },
  { 0x00FFFF, 0x8A0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFNACC" },
  { 0x00FFFF, 0x8E0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PFPNACC" },
  { 0x00FFFF, 0x0C0F0F, 2,00,  R3D,MR8,NNN, C_NOW+4,        "PI2FW" },
  { 0x00FFFF, 0xBB0F0F, 2,00,  R3D,MRD,NNN, C_NOW+4,        "PSWAPD" },
  // Some alternative mnemonics for Assembler, not used by Disassembler (so
  // implicit pseudooperands are not marked).
  { 0x0000FF, 0x0000A6, 1,00,  NNN,NNN,NNN, C_CMD+0,        "CMPSB" },
  { 0x00FFFF, 0x00A766, 2,00,  NNN,NNN,NNN, C_CMD+0,        "CMPSW" },
  { 0x0000FF, 0x0000A7, 1,00,  NNN,NNN,NNN, C_CMD+0,        "CMPSD" },
  { 0x0000FF, 0x0000AC, 1,00,  NNN,NNN,NNN, C_CMD+0,        "LODSB" },
  { 0x00FFFF, 0x00AD66, 2,00,  NNN,NNN,NNN, C_CMD+0,        "LODSW" },
  { 0x0000FF, 0x0000AD, 1,00,  NNN,NNN,NNN, C_CMD+0,        "LODSD" },
  { 0x0000FF, 0x0000A4, 1,00,  NNN,NNN,NNN, C_CMD+0,        "MOVSB" },
  { 0x00FFFF, 0x00A566, 2,00,  NNN,NNN,NNN, C_CMD+0,        "MOVSW" },
  { 0x0000FF, 0x0000A5, 1,00,  NNN,NNN,NNN, C_CMD+0,        "MOVSD" },
  { 0x0000FF, 0x0000AE, 1,00,  NNN,NNN,NNN, C_CMD+0,        "SCASB" },
  { 0x00FFFF, 0x00AF66, 1,00,  NNN,NNN,NNN, C_CMD+0,        "SCASW" },
  { 0x0000FF, 0x0000AF, 1,00,  NNN,NNN,NNN, C_CMD+0,        "SCASD" },
  { 0x0000FF, 0x0000AA, 1,00,  NNN,NNN,NNN, C_CMD+0,        "STOSB" },
  { 0x00FFFF, 0x00AB66, 2,00,  NNN,NNN,NNN, C_CMD+0,        "STOSW" },
  { 0x0000FF, 0x0000AB, 1,00,  NNN,NNN,NNN, C_CMD+0,        "STOSD" },
  { 0x00FFFF, 0x00A4F3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP MOVSB" },
  { 0xFFFFFF, 0xA5F366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP MOVSW" },
  { 0x00FFFF, 0x00A5F3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP MOVSD" },
  { 0x00FFFF, 0x00ACF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP LODSB" },
  { 0xFFFFFF, 0xADF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP LODSW" },
  { 0x00FFFF, 0x00ADF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP LODSD" },
  { 0x00FFFF, 0x00AAF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP STOSB" },
  { 0xFFFFFF, 0xABF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP STOSW" },
  { 0x00FFFF, 0x00ABF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP STOSD" },
  { 0x00FFFF, 0x00A6F3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPE CMPSB" },
  { 0xFFFFFF, 0xA7F366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REPE CMPSW" },
  { 0x00FFFF, 0x00A7F3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPE CMPSD" },
  { 0x00FFFF, 0x00AEF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPE SCASB" },
  { 0xFFFFFF, 0xAFF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REPE SCASW" },
  { 0x00FFFF, 0x00AFF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPE SCASD" },
  { 0x00FFFF, 0x00A6F2, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPNE CMPSB" },
  { 0xFFFFFF, 0xA7F266, 2,00,  NNN,NNN,NNN, C_REP+0,        "REPNE CMPSW" },
  { 0x00FFFF, 0x00A7F2, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPNE CMPSD" },
  { 0x00FFFF, 0x00AEF2, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPNE SCASB" },
  { 0xFFFFFF, 0xAFF266, 2,00,  NNN,NNN,NNN, C_REP+0,        "REPNE SCASW" },
  { 0x00FFFF, 0x00AFF2, 1,00,  NNN,NNN,NNN, C_REP+0,        "REPNE SCASD" },
  { 0x0000FF, 0x00006C, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "INSB" },
  { 0x00FFFF, 0x006D66, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "INSW" },
  { 0x0000FF, 0x00006D, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "INSD" },
  { 0x0000FF, 0x00006E, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "OUTSB" },
  { 0x00FFFF, 0x006F66, 2,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "OUTSW" },
  { 0x0000FF, 0x00006F, 1,00,  NNN,NNN,NNN, C_CMD+C_RARE+0, "OUTSD" },
  { 0x00FFFF, 0x006CF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP INSB" },
  { 0xFFFFFF, 0x6DF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP INSW" },
  { 0x00FFFF, 0x006DF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP INSD" },
  { 0x00FFFF, 0x006EF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP OUTSB" },
  { 0xFFFFFF, 0x6FF366, 2,00,  NNN,NNN,NNN, C_REP+0,        "REP OUTSW" },
  { 0x00FFFF, 0x006FF3, 1,00,  NNN,NNN,NNN, C_REP+0,        "REP OUTSD" },
  { 0x0000FF, 0x0000E1, 1,00,  JOB,NNN,NNN, C_JMC+0,        "$LOOP*Z" },
  { 0x0000FF, 0x0000E0, 1,00,  JOB,NNN,NNN, C_JMC+0,        "$LOOP*NZ" },
  { 0x0000FF, 0x00009B, 1,00,  NNN,NNN,NNN, C_CMD+0,        "FWAIT" },
  { 0x0000FF, 0x0000D7, 1,00,  NNN,NNN,NNN, C_CMD+0,        "XLATB" },
  { 0x00FFFF, 0x00C40F, 2,00,  RMX,RR4,IM1, C_MMX+2,        "PINSRW" },
  { 0x00FFFF, 0x0020CD, 2,00,  VXD,NNN,NNN, C_CAL+C_RARE+0, "VxDCall" },
  // Pseudocommands used by Assembler for masked search only.
  { 0x0000F0, 0x000070, 1,CC,  JOB,NNN,NNN, C_JMC+0,        "JCC" },
  { 0x00F0FF, 0x00800F, 2,CC,  JOW,NNN,NNN, C_JMC+0,        "JCC" },
  { 0x00F0FF, 0x00900F, 2,CC,  MR1,NNN,NNN, C_CMD+1,        "SETCC" },
  { 0x00F0FF, 0x00400F, 2,CC,  REG,MRG,NNN, C_CMD+0,        "CMOVCC" },
  // End of command table.
  { 0x000000, 0x000000, 0,00,  NNN,NNN,NNN, C_CMD+0,        "" }
};

const t_cmddata vxdcmd =               // Decoding of VxD calls (Win95/98)
  { 0x00FFFF, 0x0020CD, 2,00,  VXD,NNN,NNN, C_CAL+C_RARE+0, "VxDCall" };

// Bit combinations that can be potentially dangerous when executed:
const t_cmddata dangerous[] = {
  { 0x00FFFF, 0x00DCF7, 0,0,0,0,0,C_DANGER95,
              "Win95/98 may crash when NEG ESP is executed" },
  { 0x00FFFF, 0x00D4F7, 0,0,0,0,0,C_DANGER95,
              "Win95/98 may crash when NOT ESP is executed" },
  { 0x00FFFF, 0x0020CD, 0,0,0,0,0,C_DANGER95,
              "Win95/98 may crash when VxD call is executed in user mode" },
  { 0xF8FFFF, 0xC8C70F, 0,0,0,0,1,C_DANGERLOCK,
              "LOCK CMPXCHG8B may crash some processors when executed" },
  { 0x000000, 0x000000, 0,0,0,0,0,0, "" }
};

// Decodes address into symb (nsymb bytes long, including the terminating zero
// character) and comments its possible meaning. Returns number of bytes in
// symb not including terminating zero.
int Decodeaddress(ulong addr,char *symb,int nsymb,char *comment) {


  // Environment-specific routine! Do it yourself!


  return 0;
};

// Decodes and prints 32-bit float f into string s (which must be at least 16
// bytes long). Returns resulting length of the string.
int Printfloat4(char *s,float f) {
  int k;
  if (*(ulong *)&f==0x7F800000L)
    k=sprintf(s,"+INF 7F800000");
  else if (*(ulong *)&f==0xFF800000L)
    k=sprintf(s,"-INF FF800000");
  else if ((*(ulong *)&f & 0xFF800000L)==0x7F800000L)
    k=sprintf(s,"+NAN "LFMT08,*(ulong *)&f);
  else if ((*(ulong *)&f & 0xFF800000L)==0xFF800000L)
    k=sprintf(s,"-NAN "LFMT08,*(ulong *)&f);
#if 0
  else if (f==0.0)                     // By default, 0 is printed without
    k=sprintf(s,"0.0");                // decimal point, which I don't want.
#endif
  else
    k=sprintf(s,"%#.7g",f);
  return k;
};

// Decodes and prints 64-bit double d into string s (at least 25 bytes long).
// Returns resulting length of the string.
int Printfloat8(char *s,double d) {
  int k;
  ulong lod,hid;
  lod=((ulong *)&d)[0];
  hid=((ulong *)&d)[1];
  if (lod==0 && hid==0x7F800000L)
    k=sprintf(s,"+INF 7F800000 00000000");
  else if (lod==0 && hid==0xFF800000L)
    k=sprintf(s,"-INF FF800000 00000000");
  else if ((hid & 0xFFF00000L)==0x7FF00000)
    k=sprintf(s,"+NAN "LFMT08" "LFMT08,hid,lod);
  else if ((hid & 0xFFF00000L)==0xFFF00000)
    k=sprintf(s,"-NAN "LFMT08" "LFMT08,hid,lod);
  else if (d==0.0)                     // Print 0 with decimal point
    k=sprintf(s,"0.0");
  else
    k=sprintf(s,"%#.16lg",d);
  return k;
};

// Decodes and prints 80-bit long double ext into string s (at least 32 bytes
// long). Procedure correctly displays all, even invalid, numbers without
// arithmetical exceptions. Returns resulting length of the string.
int Printfloat10(char *s,long double ext) {
  int k;
  char *e=(char *)&ext;
  if (*(ulong *)e==0 && *(unsigned short *)(e+4)==0 && *(ulong *)(e+6)==0x7FFF8000L)
    k=sprintf(s,"+INF 7FFF 80000000 00000000");
  else if (*(ulong *)e==0 && *(unsigned short *)(e+4)==0 &&
    *(ulong *)(e+6)==0xFFFF8000L)
    k=sprintf(s,"-INF FFFF 80000000 00000000");
  else if ((*(ulong *)(e+6) & 0x7FFF8000L)==0x7FFF8000L)
    k=sprintf(s,"%cNAN %04X "LFMT08" "LFMT08,(e[9] & 0x80)==0?'+':'-',
    (int)(*(unsigned short *)(e+8)),*(ulong *)(e+4),*(ulong *)e);
  else if ((*(ulong *)(e+6) & 0x7FFF0000L)==0x7FFF0000L)
    k=sprintf(s,"%c??? %04X "LFMT08" "LFMT08,(e[9] & 0x80)==0?'+':'-',
    (int)(*(unsigned short *)(e+8)),*(ulong *)(e+4),*(ulong *)e);
  else if ((*(ulong *)(e+6) & 0x7FFF0000L)!=0 &&
    (*(ulong *)(e+6) & 0x00008000)==0)
    k=sprintf(s,"%cUNORM %04X "LFMT08" "LFMT08,(e[9] & 0x80)==0?'+':'-',
    (int)(*(unsigned short *)(e+8)),*(ulong *)(e+4),*(ulong *)e);
  else if (*(ulong *)e==0 && *(unsigned short *)(e+4)==0 &&
    *(ulong *)(e+6)==0x80000000L)
    k=sprintf(s,"-0.0");               // Negative floating 0.0
  else if (ext==0.0)
    k=sprintf(s,"0.0");                // Print 0 with decimal point
#if 0
 // Visual Studio only?
  else if ((ext>=-1.e10 && ext<-1.0) || (ext>1.0 && ext<=1.e10))
    k=sprintf(s,"%#.20lg",ext);
  else if ((ext>=-1.0 && ext<=-1.e-5) || (ext>=1.e-5 && ext<=1.0))
    k=sprintf(s,"%#.19lf",ext);
  else
    k=sprintf(s,"%#.19le",ext);
#else
  else if ((ext>=-1.e10 && ext<-1.0) || (ext>1.0 && ext<=1.e10))
    k=sprintf(s,"%#.20Lg",ext);
  else if ((ext>=-1.0 && ext<=-1.e-5) || (ext>=1.e-5 && ext<=1.0))
    k=sprintf(s,"%#.19Lf",ext);
  else
    k=sprintf(s,"%#.19Le",ext);
#endif
  return k;
};

// Decodes and prints 64-bit 3DNow! element f into string s (which must be at
// least 30 bytes long). Returns resulting length of the string.
int Print3dnow(char *s,char *f) {
  int n;
  n=Printfloat4(s,*(float *)(f+4));
  n+=sprintf(s+n,", ");
  n+=Printfloat4(s+n,*(float *)f);
  return n;
};

// Function attempts to calculate address of assembler instruction which is n
// lines back in the listing. Maximal stepback is limited to 127. In general,
// this is rather non-trivial task. Proposed solution may cause problems which
// however are not critical here.
ulong Disassembleback(unsigned char *block,ulong base,ulong size,ulong ip,int n) {
  int i;
  ulong abuf[131],addr,back,cmdsize;
  unsigned char *pdata;
  t_disasm da;
  abuf[0] = 0;
  if (block==NULL) return 0;           // Error, no code!
  if (n<0) n=0; else if (n>127) n=127; // Try to correct obvious errors
  if (ip>base+size) ip=base+size;
  if (n==0) return ip;                 // Obvious answers
  if (ip<=base+n) return base;
  back=MAXCMDSIZE*(n+3);               // Command length limited to MAXCMDSIZE
  if (ip<base+back) back=ip-base;
  addr=ip-back;
  pdata=block+(addr-base);
  for (i=0; addr<ip; i++) {
    abuf[i%128]=addr;
    cmdsize=Disasm(pdata,back,addr,&da,DISASM_SIZE);
    pdata+=cmdsize;
    addr+=cmdsize;
    back-=cmdsize; };
  if (i<n) return abuf[0];
  else return abuf[(i-n+128)%128];
};

// Function attempts to calculate address of assembler instruction which is n
// lines forward in the listing.
ulong Disassembleforward(unsigned char *block,ulong base,ulong size,ulong ip,int n) {
  int i;
  ulong cmdsize;
  unsigned char *pdata;
  t_disasm da;
  if (block==NULL) return 0;           // Error, no code!
  if (ip<base) ip=base;                // Try to correct obvious errors
  if (ip>base+size) ip=base+size;
  if (n<=0) return ip;
  pdata=block+(ip-base);
  size-=(ip-base);
  for (i=0; i<n && size>0; i++) {
    cmdsize=Disasm(pdata,size,ip,&da,DISASM_SIZE);
    pdata+=cmdsize;
    ip+=cmdsize;
    size-=cmdsize; };
  return ip;
};

// Service function, checks whether command at offset addr in data is a valid
// filling command (usually some kind of NOP) used to align code to a specified
// (align=power of 2, 0 means no alignment) border. Returns length of filling
// command in bytes or 0 if command is not a recognized filling.
int Isfilling(ulong addr,unsigned char *data,ulong size,ulong align) {
  if (data==NULL) return 0;            // Invalid parameters
  // Convert power of 2 to bitmask.
  align--;
  // Many compilers and assemblers use NOP or INT3 as filling:
  if (addr<size && (data[addr]==NOP || data[addr]==INT3) &&
    (addr & align)!=0)
    return 1;
  // Borland compilers use XCHG EBX,EBX (87,DB) to fill holes. For the sake of
  // completeness, allow any XCHG or MOV of register with self.
  if (addr+1<size &&
    ((data[addr] & 0xFE)==0x86 || (data[addr] & 0xFC)==0x88) &&
    (data[addr+1] & 0xC0)==0xC0 &&
    (((data[addr+1]>>3)^data[addr+1]) & 0x07)==0 &&
    (addr & align)!=0x0F && (addr & align)!=0x00)
    return 2;
  // Some other programs use LEA EAX,[EAX] (8D,40,00). For completeness, allow
  // any register except ESP (here address is constructed differently):
  if (addr+2<size &&
    data[addr]==0x8D && (data[addr+1] & 0xC0)==0x40 && data[addr+2]==0x00 &&
    (data[addr+1] & 0x07)!=GREG_ESP &&
    (((data[addr+1]>>3)^data[addr+1]) & 0x07)==0)
    return 3;
  // WATCOM compilers use LEA EAX,[EAX] with SIB and 8-bit zero (8D,44,20,00)
  // and without SIB but with 32-bit immediate zero (8D,80,00,00,00,00) and
  // alike:
  if (addr+3<size &&
    data[addr]==0x8D && (data[addr+1] & 0xC0)==0x40 && data[addr+3]==0x00 &&
    (((data[addr+1]>>3)^data[addr+2]) & 0x07)==0)
    return 4;
  if (addr+5<size && data[addr]==0x8D &&
    (data[addr+1] & 0xC0)==0x80 && *(ulong *)(data+addr+2)==0 &&
    (data[addr+1] & 0x07)!=GREG_ESP &&
    (((data[addr+1]>>3)^data[addr+1]) & 0x07)==0)
    return 6;
  // Unable to recognize this code as a valid filling.
  return 0;
};

