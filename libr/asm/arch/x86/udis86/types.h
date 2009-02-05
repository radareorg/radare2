/* -----------------------------------------------------------------------------
 * types.h
 *
 * Copyright (c) 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */
#ifndef UD_TYPES_H
#define UD_TYPES_H

#include <stdio.h>

#ifdef _MSC_VER
# define FMT64 "%I64"
  typedef unsigned __int8 uint8_t;
  typedef unsigned __int16 uint16_t;
  typedef unsigned __int32 uint32_t;
  typedef unsigned __int64 uint64_t;
  typedef __int8 int8_t;
  typedef __int16 int16_t;
  typedef __int32 int32_t;
  typedef __int64 int64_t;
#else
# define FMT64 "%ll"
# include <inttypes.h>
#endif

#include "itab.h"

/* -----------------------------------------------------------------------------
 * All possible "types" of objects in udis86. Order is Important!
 * -----------------------------------------------------------------------------
 */
enum ud_type
{
  UD_NONE,

  /* 8 bit GPRs */
  UD_R_AL,	UD_R_CL,	UD_R_DL,	UD_R_BL,
  UD_R_AH,	UD_R_CH,	UD_R_DH,	UD_R_BH,
  UD_R_SPL,	UD_R_BPL,	UD_R_SIL,	UD_R_DIL,
  UD_R_R8B,	UD_R_R9B,	UD_R_R10B,	UD_R_R11B,
  UD_R_R12B,	UD_R_R13B,	UD_R_R14B,	UD_R_R15B,

  /* 16 bit GPRs */
  UD_R_AX,	UD_R_CX,	UD_R_DX,	UD_R_BX,
  UD_R_SP,	UD_R_BP,	UD_R_SI,	UD_R_DI,
  UD_R_R8W,	UD_R_R9W,	UD_R_R10W,	UD_R_R11W,
  UD_R_R12W,	UD_R_R13W,	UD_R_R14W,	UD_R_R15W,
	
  /* 32 bit GPRs */
  UD_R_EAX,	UD_R_ECX,	UD_R_EDX,	UD_R_EBX,
  UD_R_ESP,	UD_R_EBP,	UD_R_ESI,	UD_R_EDI,
  UD_R_R8D,	UD_R_R9D,	UD_R_R10D,	UD_R_R11D,
  UD_R_R12D,	UD_R_R13D,	UD_R_R14D,	UD_R_R15D,
	
  /* 64 bit GPRs */
  UD_R_RAX,	UD_R_RCX,	UD_R_RDX,	UD_R_RBX,
  UD_R_RSP,	UD_R_RBP,	UD_R_RSI,	UD_R_RDI,
  UD_R_R8,	UD_R_R9,	UD_R_R10,	UD_R_R11,
  UD_R_R12,	UD_R_R13,	UD_R_R14,	UD_R_R15,

  /* segment registers */
  UD_R_ES,	UD_R_CS,	UD_R_SS,	UD_R_DS,
  UD_R_FS,	UD_R_GS,	

  /* control registers*/
  UD_R_CR0,	UD_R_CR1,	UD_R_CR2,	UD_R_CR3,
  UD_R_CR4,	UD_R_CR5,	UD_R_CR6,	UD_R_CR7,
  UD_R_CR8,	UD_R_CR9,	UD_R_CR10,	UD_R_CR11,
  UD_R_CR12,	UD_R_CR13,	UD_R_CR14,	UD_R_CR15,
	
  /* debug registers */
  UD_R_DR0,	UD_R_DR1,	UD_R_DR2,	UD_R_DR3,
  UD_R_DR4,	UD_R_DR5,	UD_R_DR6,	UD_R_DR7,
  UD_R_DR8,	UD_R_DR9,	UD_R_DR10,	UD_R_DR11,
  UD_R_DR12,	UD_R_DR13,	UD_R_DR14,	UD_R_DR15,

  /* mmx registers */
  UD_R_MM0,	UD_R_MM1,	UD_R_MM2,	UD_R_MM3,
  UD_R_MM4,	UD_R_MM5,	UD_R_MM6,	UD_R_MM7,

  /* x87 registers */
  UD_R_ST0,	UD_R_ST1,	UD_R_ST2,	UD_R_ST3,
  UD_R_ST4,	UD_R_ST5,	UD_R_ST6,	UD_R_ST7, 

  /* extended multimedia registers */
  UD_R_XMM0,	UD_R_XMM1,	UD_R_XMM2,	UD_R_XMM3,
  UD_R_XMM4,	UD_R_XMM5,	UD_R_XMM6,	UD_R_XMM7,
  UD_R_XMM8,	UD_R_XMM9,	UD_R_XMM10,	UD_R_XMM11,
  UD_R_XMM12,	UD_R_XMM13,	UD_R_XMM14,	UD_R_XMM15,

  UD_R_RIP,

  /* Operand Types */
  UD_OP_REG,	UD_OP_MEM,	UD_OP_PTR,	UD_OP_IMM,	
  UD_OP_JIMM,	UD_OP_CONST
};

/* -----------------------------------------------------------------------------
 * struct ud_operand - Disassembled instruction Operand.
 * -----------------------------------------------------------------------------
 */
struct ud_operand 
{
  enum ud_type		type;
  uint8_t		size;
  union {
	int8_t		sbyte;
	uint8_t		ubyte;
	int16_t		sword;
	uint16_t	uword;
	int32_t		sdword;
	uint32_t	udword;
	int64_t		sqword;
	uint64_t	uqword;

	struct {
		uint16_t seg;
		uint32_t off;
	} ptr;
  } lval;

  enum ud_type		base;
  enum ud_type		index;
  uint8_t		offset;
  uint8_t		scale;	
};

/* -----------------------------------------------------------------------------
 * struct ud - The udis86 object.
 * -----------------------------------------------------------------------------
 */
struct ud
{
  int 			(*inp_hook) (struct ud*);
  uint8_t		inp_curr;
  uint8_t		inp_fill;
  FILE*			inp_file;
  uint8_t		inp_ctr;
  uint8_t*		inp_buff;
  uint8_t*		inp_buff_end;
  uint8_t		inp_end;
  void			(*translator)(struct ud*);
  uint64_t		insn_offset;
  char			insn_hexcode[32];
  char			insn_buffer[64];
  unsigned int		insn_fill;
  uint8_t		dis_mode;
  uint64_t		pc;
  uint8_t		vendor;
  struct map_entry*	mapen;
  enum ud_mnemonic_code	mnemonic;
  struct ud_operand	operand[3];
  uint8_t		error;
  uint8_t	 	pfx_rex;
  uint8_t 		pfx_seg;
  uint8_t 		pfx_opr;
  uint8_t 		pfx_adr;
  uint8_t 		pfx_lock;
  uint8_t 		pfx_rep;
  uint8_t 		pfx_repe;
  uint8_t 		pfx_repne;
  uint8_t 		pfx_insn;
  uint8_t		default64;
  uint8_t		opr_mode;
  uint8_t		adr_mode;
  uint8_t		br_far;
  uint8_t		br_near;
  uint8_t		implicit_addr;
  uint8_t		c1;
  uint8_t		c2;
  uint8_t		c3;
  uint8_t 		inp_cache[256];
  uint8_t		inp_sess[64];
  struct ud_itab_entry * itab_entry;
};

/* -----------------------------------------------------------------------------
 * Type-definitions
 * -----------------------------------------------------------------------------
 */
typedef enum ud_type 		ud_type_t;
typedef enum ud_mnemonic_code	ud_mnemonic_code_t;

typedef struct ud 		ud_t;
typedef struct ud_operand 	ud_operand_t;

#define UD_SYN_INTEL		ud_translate_intel
#define UD_SYN_ATT		ud_translate_att
#define UD_EOI			-1
#define UD_INP_CACHE_SZ		32
#define UD_VENDOR_AMD		0
#define UD_VENDOR_INTEL		1

#define bail_out(ud,error_code) longjmp( (ud)->bailout, error_code )
#define try_decode(ud) if ( setjmp( (ud)->bailout ) == 0 )
#define catch_error() else

#endif
