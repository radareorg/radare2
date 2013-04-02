/* udis86 - libudis86/decode.c
 * 
 * Copyright (c) 2002-2009 Vivek Thampi
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice, 
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, 
 *       this list of conditions and the following disclaimer in the documentation 
 *       and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "udint.h"
#include "types.h"
#include "input.h"
#include "decode.h"

#ifndef __UD_STANDALONE__
# include <string.h>
#endif /* __UD_STANDALONE__ */

/* The max number of prefixes to an instruction */
#define MAX_PREFIXES    15

/* rex prefix bits */
#define REX_W(r)        ( ( 0xF & ( r ) )  >> 3 )
#define REX_R(r)        ( ( 0x7 & ( r ) )  >> 2 )
#define REX_X(r)        ( ( 0x3 & ( r ) )  >> 1 )
#define REX_B(r)        ( ( 0x1 & ( r ) )  >> 0 )
#define REX_PFX_MASK(n) ( ( P_REXW(n) << 3 ) | \
                          ( P_REXR(n) << 2 ) | \
                          ( P_REXX(n) << 1 ) | \
                          ( P_REXB(n) << 0 ) )

/* scable-index-base bits */
#define SIB_S(b)        ( ( b ) >> 6 )
#define SIB_I(b)        ( ( ( b ) >> 3 ) & 7 )
#define SIB_B(b)        ( ( b ) & 7 )

/* modrm bits */
#define MODRM_REG(b)    ( ( ( b ) >> 3 ) & 7 )
#define MODRM_NNN(b)    ( ( ( b ) >> 3 ) & 7 )
#define MODRM_MOD(b)    ( ( ( b ) >> 6 ) & 3 )
#define MODRM_RM(b)     ( ( b ) & 7 )

static int decode_ext(struct ud *u, uint16_t ptr);

enum reg_class { /* register classes */
  REGCLASS_NONE,
  REGCLASS_GPR,
  REGCLASS_MMX,
  REGCLASS_CR,
  REGCLASS_DB,
  REGCLASS_SEG,
  REGCLASS_XMM
};


/*
 * inp_uint8
 * int_uint16
 * int_uint32
 * int_uint64
 *    Load little-endian values from input
 */
static uint8_t 
inp_uint8(struct ud* u)
{
  return ud_inp_next(u);
}

static uint16_t 
inp_uint16(struct ud* u)
{
  uint16_t r, ret;

  ret = ud_inp_next(u);
  r = ud_inp_next(u);
  return ret | (r << 8);
}

static uint32_t 
inp_uint32(struct ud* u)
{
  uint32_t r, ret;

  ret = ud_inp_next(u);
  r = ud_inp_next(u);
  ret = ret | (r << 8);
  r = ud_inp_next(u);
  ret = ret | (r << 16);
  r = ud_inp_next(u);
  return ret | (r << 24);
}

static uint64_t 
inp_uint64(struct ud* u)
{
  uint64_t r, ret;

  ret = ud_inp_next(u);
  r = ud_inp_next(u);
  ret = ret | (r << 8);
  r = ud_inp_next(u);
  ret = ret | (r << 16);
  r = ud_inp_next(u);
  ret = ret | (r << 24);
  r = ud_inp_next(u);
  ret = ret | (r << 32);
  r = ud_inp_next(u);
  ret = ret | (r << 40);
  r = ud_inp_next(u);
  ret = ret | (r << 48);
  r = ud_inp_next(u);
  return ret | (r << 56);
}


static inline int
eff_opr_mode(int dis_mode, int rex_w, int pfx_opr)
{
  if (dis_mode == 64) {
    return rex_w ? 64 : (pfx_opr ? 16 : 32);
  } else if (dis_mode == 32) {
    return pfx_opr ? 16 : 32;
  } else {
    UD_ASSERT(dis_mode == 16);
    return pfx_opr ? 32 : 16;
  }
}


static inline int
eff_adr_mode(int dis_mode, int pfx_adr)
{
  if (dis_mode == 64) {
    return pfx_adr ? 32 : 64;
  } else if (dis_mode == 32) {
    return pfx_adr ? 16 : 32;
  } else {
    UD_ASSERT(dis_mode == 16);
    return pfx_adr ? 32 : 16;
  }
}


/* Looks up mnemonic code in the mnemonic string table
 * Returns NULL if the mnemonic code is invalid
 */
const char*
ud_lookup_mnemonic(enum ud_mnemonic_code c)
{
  if (c < UD_MAX_MNEMONIC_CODE) {
    return ud_mnemonics_str[c];
  } else {
    return NULL;
  }
}


/* 
 * decode_prefixes
 *
 *  Extracts instruction prefixes.
 */
static int 
decode_prefixes(struct ud *u)
{
    unsigned int have_pfx = 1;
    unsigned int i;
    uint8_t curr;

    /* if in error state, bail out */
    if ( u->error ) 
        return -1; 

    /* keep going as long as there are prefixes available */
    for ( i = 0; have_pfx ; ++i ) {

        /* Get next byte. */
        ud_inp_next(u); 
        if ( u->error ) 
            return -1;
        curr = inp_curr( u );

        /* rex prefixes in 64bit mode */
        if ( u->dis_mode == 64 && ( curr & 0xF0 ) == 0x40 ) {
            u->pfx_rex = curr;  
        } else {
            switch ( curr )  
            {
            case 0x2E : 
                u->pfx_seg = UD_R_CS; 
                u->pfx_rex = 0;
                break;
            case 0x36 :     
                u->pfx_seg = UD_R_SS; 
                u->pfx_rex = 0;
                break;
            case 0x3E : 
                u->pfx_seg = UD_R_DS; 
                u->pfx_rex = 0;
                break;
            case 0x26 : 
                u->pfx_seg = UD_R_ES; 
                u->pfx_rex = 0;
                break;
            case 0x64 : 
                u->pfx_seg = UD_R_FS; 
                u->pfx_rex = 0;
                break;
            case 0x65 : 
                u->pfx_seg = UD_R_GS; 
                u->pfx_rex = 0;
                break;
            case 0x67 : /* adress-size override prefix */ 
                u->pfx_adr = 0x67;
                u->pfx_rex = 0;
                break;
            case 0xF0 : 
                u->pfx_lock = 0xF0;
                u->pfx_rex  = 0;
                break;
            case 0x66: 
                /* the 0x66 sse prefix is only effective if no other sse prefix
                 * has already been specified.
                 */
                if ( !u->pfx_insn ) u->pfx_insn = 0x66;
                u->pfx_opr = 0x66;           
                u->pfx_rex = 0;
                break;
            case 0xF2:
                u->pfx_insn  = 0xF2;
                u->pfx_repne = 0xF2; 
                u->pfx_rex   = 0;
                break;
            case 0xF3:
                u->pfx_insn = 0xF3;
                u->pfx_rep  = 0xF3; 
                u->pfx_repe = 0xF3; 
                u->pfx_rex  = 0;
                break;
            default : 
                /* No more prefixes */
                have_pfx = 0;
                break;
            }
        }

        /* check if we reached max instruction length */
        if ( i + 1 == MAX_INSN_LENGTH ) {
          UDERR(u, "max instruction length");
          break;
        }
    }

    /* return status */
    if ( u->error ) 
        return -1; 

    /* rewind back one byte in stream, since the above loop 
     * stops with a non-prefix byte. 
     */
    inp_back(u);
    return 0;
}


static inline unsigned int modrm( struct ud * u )
{
    if ( !u->have_modrm ) {
        u->modrm = ud_inp_next( u );
        u->have_modrm = 1;
    }
    return u->modrm;
}


static unsigned int
resolve_operand_size( const struct ud * u, unsigned int s )
{
    switch ( s ) 
    {
    case SZ_V:
        return ( u->opr_mode );
    case SZ_Z:  
        return ( u->opr_mode == 16 ) ? 16 : 32;
    case SZ_Y:
        return ( u->opr_mode == 16 ) ? 32 : u->opr_mode;
    case SZ_RDQ:
        return ( u->dis_mode == 64 ) ? 64 : 32;
    default:
        return s;
    }
}


static int resolve_mnemonic( struct ud* u )
{
  /* resolve 3dnow weirdness. */
  if ( u->mnemonic == UD_I3dnow ) {
    u->mnemonic = ud_itab[ u->le->table[ inp_curr( u )  ] ].mnemonic;
  }
  /* SWAPGS is only valid in 64bits mode */
  if ( u->mnemonic == UD_Iswapgs && u->dis_mode != 64 ) {
    UDERR(u, "swapgs invalid in 64bits mode");
    return -1;
  }

  if (u->mnemonic == UD_Ixchg) {
    if ((u->operand[0].type == UD_OP_REG && u->operand[0].base == UD_R_AX  &&
         u->operand[1].type == UD_OP_REG && u->operand[1].base == UD_R_AX) ||
        (u->operand[0].type == UD_OP_REG && u->operand[0].base == UD_R_EAX &&
         u->operand[1].type == UD_OP_REG && u->operand[1].base == UD_R_EAX)) {
      u->operand[0].type = UD_NONE;
      u->operand[1].type = UD_NONE;
      u->mnemonic = UD_Inop;
    }
  }

  if (u->mnemonic == UD_Inop && u->pfx_rep) {
    u->pfx_rep = 0;
    u->mnemonic = UD_Ipause;
  }
  return 0;
}


/* -----------------------------------------------------------------------------
 * decode_a()- Decodes operands of the type seg:offset
 * -----------------------------------------------------------------------------
 */
static void 
decode_a(struct ud* u, struct ud_operand *op)
{
  if (u->opr_mode == 16) {  
    /* seg16:off16 */
    op->type = UD_OP_PTR;
    op->size = 32;
    op->lval.ptr.off = inp_uint16(u);
    op->lval.ptr.seg = inp_uint16(u);
  } else {
    /* seg16:off32 */
    op->type = UD_OP_PTR;
    op->size = 48;
    op->lval.ptr.off = inp_uint32(u);
    op->lval.ptr.seg = inp_uint16(u);
  }
}

/* -----------------------------------------------------------------------------
 * decode_gpr() - Returns decoded General Purpose Register 
 * -----------------------------------------------------------------------------
 */
static enum ud_type 
decode_gpr(register struct ud* u, unsigned int s, unsigned char rm)
{
  switch (s) {
    case 64:
        return UD_R_RAX + rm;
    case 32:
        return UD_R_EAX + rm;
    case 16:
        return UD_R_AX  + rm;
    case  8:
        if (u->dis_mode == 64 && u->pfx_rex) {
            if (rm >= 4)
                return UD_R_SPL + (rm-4);
            return UD_R_AL + rm;
        } else return UD_R_AL + rm;
    default:
        UD_ASSERT(!"invalid operand size");
        return 0;
  }
}

static void
decode_reg(struct ud *u, 
           struct ud_operand *opr,
           int type,
           int num,
           int size)
{
  int reg;
  size = resolve_operand_size(u, size);
  switch (type) {
    case REGCLASS_GPR : reg = decode_gpr(u, size, num); break;
    case REGCLASS_MMX : reg = UD_R_MM0  + (num & 7); break;
    case REGCLASS_XMM : reg = UD_R_XMM0 + num; break;
    case REGCLASS_CR : reg = UD_R_CR0  + num; break;
    case REGCLASS_DB : reg = UD_R_DR0  + num; break;
    case REGCLASS_SEG : {
      /*
       * Only 6 segment registers, anything else is an error.
       */
      if ((num & 7) > 5) {
        UDERR(u, "invalid segment register value");
        return;
      } else {
        reg = UD_R_ES + (num & 7);
      }
      break;
    }
    default:
      UD_ASSERT(!"invalid register type");
      break;
  }
  opr->type = UD_OP_REG;
  opr->base = reg;
  opr->size = size;
}


/*
 * decode_imm 
 *
 *    Decode Immediate values.
 */
static void 
decode_imm(struct ud* u, unsigned int size, struct ud_operand *op)
{
  op->size = resolve_operand_size(u, size);
  op->type = UD_OP_IMM;

  switch (op->size) {
  case  8: op->lval.sbyte = inp_uint8(u);   break;
  case 16: op->lval.uword = inp_uint16(u);  break;
  case 32: op->lval.udword = inp_uint32(u); break;
  case 64: op->lval.uqword = inp_uint64(u); break;
  default: return;
  }
}


/* 
 * decode_mem_disp
 *
 *    Decode mem address displacement.
 */
static void 
decode_mem_disp(struct ud* u, unsigned int size, struct ud_operand *op)
{
  switch (size) {
  case 8:
    op->offset = 8; 
    op->lval.ubyte  = inp_uint8(u);
    break;
  case 16:
    op->offset = 16; 
    op->lval.uword  = inp_uint16(u); 
    break;
  case 32:
    op->offset = 32; 
    op->lval.udword = inp_uint32(u); 
    break;
  case 64:
    op->offset = 64; 
    op->lval.uqword = inp_uint64(u); 
    break;
  default:
      return;
  }
}


/*
 * decode_modrm_reg
 *
 *    Decodes reg field of mod/rm byte
 * 
 */
static inline void
decode_modrm_reg(struct ud         *u, 
                 struct ud_operand *operand,
                 unsigned int       type,
                 unsigned int       size)
{
  uint8_t reg = (REX_R(u->pfx_rex) << 3) | MODRM_REG(modrm(u));
  decode_reg(u, operand, type, reg, size);
}


/*
 * decode_modrm_rm
 *
 *    Decodes rm field of mod/rm byte
 * 
 */
static void 
decode_modrm_rm(struct ud         *u, 
                struct ud_operand *op,
                unsigned char      type,    /* register type */
                unsigned int       size)    /* operand size */

{
  size_t offset = 0;
  unsigned char mod, rm;

  /* get mod, r/m and reg fields */
  mod = MODRM_MOD(modrm(u));
  rm  = (REX_B(u->pfx_rex) << 3) | MODRM_RM(modrm(u));

  /* 
   * If mod is 11b, then the modrm.rm specifies a register.
   *
   */
  if (mod == 3) {
    decode_reg(u, op, type, rm, size);
    return;
  }

  /* 
   * !11b => Memory Address
   */  
  op->type = UD_OP_MEM;
  op->size = resolve_operand_size(u, size);

  if (u->adr_mode == 64) {
    op->base = UD_R_RAX + rm;
    if (mod == 1) {
      offset = 8;
    } else if (mod == 2) {
      offset = 32;
    } else if (mod == 0 && (rm & 7) == 5) {           
      op->base = UD_R_RIP;
      offset = 32;
    } else {
      offset = 0;
    }
    /* 
     * Scale-Index-Base (SIB) 
     */
    if ((rm & 7) == 4) {
      ud_inp_next(u);
      
      op->scale = (1 << SIB_S(inp_curr(u))) & ~1;
      op->index = UD_R_RAX + (SIB_I(inp_curr(u)) | (REX_X(u->pfx_rex) << 3));
      op->base  = UD_R_RAX + (SIB_B(inp_curr(u)) | (REX_B(u->pfx_rex) << 3));

      /* special conditions for base reference */
      if (op->index == UD_R_RSP) {
        op->index = UD_NONE;
        op->scale = UD_NONE;
      }

      if (op->base == UD_R_RBP || op->base == UD_R_R13) {
        if (mod == 0) {
          op->base = UD_NONE;
        } 
        if (mod == 1) {
          offset = 8;
        } else {
          offset = 32;
        }
      }
    }
  } else if (u->adr_mode == 32) {
    op->base = UD_R_EAX + rm;
    if (mod == 1) {
      offset = 8;
    } else if (mod == 2) {
      offset = 32;
    } else if (mod == 0 && rm == 5) {
      op->base = UD_NONE;
      offset = 32;
    } else {
      offset = 0;
    }

    /* Scale-Index-Base (SIB) */
    if ((rm & 7) == 4) {
      ud_inp_next(u);

      op->scale = (1 << SIB_S(inp_curr(u))) & ~1;
      op->index = UD_R_EAX + (SIB_I(inp_curr(u)) | (REX_X(u->pfx_rex) << 3));
      op->base  = UD_R_EAX + (SIB_B(inp_curr(u)) | (REX_B(u->pfx_rex) << 3));

      if (op->index == UD_R_ESP) {
        op->index = UD_NONE;
        op->scale = UD_NONE;
      }

      /* special condition for base reference */
      if (op->base == UD_R_EBP) {
        if (mod == 0) {
          op->base = UD_NONE;
        } 
        if (mod == 1) {
          offset = 8;
        } else {
          offset = 32;
        }
      }
    }
  } else {
    const unsigned int bases[]   = { UD_R_BX, UD_R_BX, UD_R_BP, UD_R_BP,
                                     UD_R_SI, UD_R_DI, UD_R_BP, UD_R_BX };
    const unsigned int indices[] = { UD_R_SI, UD_R_DI, UD_R_SI, UD_R_DI,
                                     UD_NONE, UD_NONE, UD_NONE, UD_NONE };
    op->base  = bases[rm & 7];
    op->index = indices[rm & 7];
    if (mod == 0 && rm == 6) {
      offset = 16;
      op->base = UD_NONE;
    } else if (mod == 1) {
      offset = 8;
    } else if (mod == 2) { 
      offset = 16;
    }
  }

  if (offset) {
    decode_mem_disp(u, offset, op);
  }
}


/* 
 * decode_moffset
 *    Decode offset-only memory operand
 */
static void
decode_moffset(struct ud *u, unsigned int size, struct ud_operand *opr)
{
  opr->type = UD_OP_MEM;
  opr->size = resolve_operand_size(u, size);
  decode_mem_disp(u, u->adr_mode, opr);
}


/* -----------------------------------------------------------------------------
 * decode_operands() - Disassembles Operands.
 * -----------------------------------------------------------------------------
 */
static int
decode_operand(struct ud           *u, 
               struct ud_operand   *operand,
               enum ud_operand_code type,
               unsigned int         size)
{
  operand->_oprcode = type;

  switch (type) {
    case OP_A :
      decode_a(u, operand);
      break;
    case OP_MR:
      decode_modrm_rm(u, operand, REGCLASS_GPR, 
                      MODRM_MOD(modrm(u)) == 3 ? 
                        Mx_reg_size(size) : Mx_mem_size(size));
      break;
    case OP_F:
      if (type == OP_F) {
        u->br_far  = 1;
      }
      /* intended fall through */
    case OP_M:
      if (MODRM_MOD(modrm(u)) == 3) {
        UDERR(u, "expected modrm.mod != 3");
      }
      /* intended fall through */
    case OP_E:
      decode_modrm_rm(u, operand, REGCLASS_GPR, size);
      break;
    case OP_G:
      decode_modrm_reg(u, operand, REGCLASS_GPR, size);
      break;
    case OP_sI:
    case OP_I:
      decode_imm(u, size, operand);
      break;
    case OP_I1:
      operand->type = UD_OP_CONST;
      operand->lval.udword = 1;
      break;
    case OP_N:
      if (MODRM_MOD(modrm(u)) != 3) {
        UDERR(u, "expected modrm.mod == 3");
      }
      /* intended fall through */
    case OP_Q:
      decode_modrm_rm(u, operand, REGCLASS_MMX, size);
      break;
    case OP_P:
      decode_modrm_reg(u, operand, REGCLASS_MMX, size);
      break;
    case OP_U:
      if (MODRM_MOD(modrm(u)) != 3) {
        UDERR(u, "expected modrm.mod == 3");
      }
      /* intended fall through */
    case OP_W:
      decode_modrm_rm(u, operand, REGCLASS_XMM, size);
      break;
    case OP_V:
      decode_modrm_reg(u, operand, REGCLASS_XMM, size);
      break;
    case OP_MU:
      decode_modrm_rm(u, operand, REGCLASS_XMM, 
                      MODRM_MOD(modrm(u)) == 3 ? 
                        Mx_reg_size(size) : Mx_mem_size(size));
      break;
    case OP_S:
      decode_modrm_reg(u, operand, REGCLASS_SEG, size);
      break;
    case OP_O:
      decode_moffset(u, size, operand);
      break;
    case OP_R0: 
    case OP_R1: 
    case OP_R2: 
    case OP_R3: 
    case OP_R4: 
    case OP_R5: 
    case OP_R6: 
    case OP_R7:
      decode_reg(u, operand, REGCLASS_GPR, 
                 (REX_B(u->pfx_rex) << 3) | (type - OP_R0), size);
      break;
    case OP_AL:
    case OP_AX:
    case OP_eAX:
    case OP_rAX:
      decode_reg(u, operand, REGCLASS_GPR, 0, size);
      break;
    case OP_CL:
    case OP_CX:
    case OP_eCX:
      decode_reg(u, operand, REGCLASS_GPR, 1, size);
      break;
    case OP_DL:
    case OP_DX:
    case OP_eDX:
      decode_reg(u, operand, REGCLASS_GPR, 2, size);
      break;
    case OP_ES: 
    case OP_CS: 
    case OP_DS:
    case OP_SS: 
    case OP_FS: 
    case OP_GS:
      /* in 64bits mode, only fs and gs are allowed */
      if (u->dis_mode == 64) {
        if (type != OP_FS && type != OP_GS) {
          UDERR(u, "invalid segment register in 64bits");
        }
      }
      operand->type = UD_OP_REG;
      operand->base = (type - OP_ES) + UD_R_ES;
      operand->size = 16;
      break;
    case OP_J :
      decode_imm(u, size, operand);
      operand->type = UD_OP_JIMM;
      break ;
    case OP_R :
      decode_modrm_rm(u, operand, REGCLASS_GPR, size);
      break;
    case OP_C:
      decode_modrm_reg(u, operand, REGCLASS_CR, size);
      break;
    case OP_D:
      decode_modrm_reg(u, operand, REGCLASS_DB, size);
      break;
    case OP_I3 :
      operand->type = UD_OP_CONST;
      operand->lval.sbyte = 3;
      break;
    case OP_ST0: 
    case OP_ST1: 
    case OP_ST2: 
    case OP_ST3:
    case OP_ST4:
    case OP_ST5: 
    case OP_ST6: 
    case OP_ST7:
      operand->type = UD_OP_REG;
      operand->base = (type - OP_ST0) + UD_R_ST0;
      operand->size = 80;
      break;
    default :
      break;
  }
  return 0;
}


/* 
 * decode_operands
 *
 *    Disassemble upto 3 operands of the current instruction being
 *    disassembled. By the end of the function, the operand fields
 *    of the ud structure will have been filled.
 */
static int
decode_operands(struct ud* u)
{
  decode_operand(u, &u->operand[0],
                    u->itab_entry->operand1.type,
                    u->itab_entry->operand1.size);
  decode_operand(u, &u->operand[1],
                    u->itab_entry->operand2.type,
                    u->itab_entry->operand2.size);
  decode_operand(u, &u->operand[2],
                    u->itab_entry->operand3.type,
                    u->itab_entry->operand3.size);
  return 0;
}
    
/* -----------------------------------------------------------------------------
 * clear_insn() - clear instruction structure
 * -----------------------------------------------------------------------------
 */
static void
clear_insn(register struct ud* u)
{
  u->error     = 0;
  u->pfx_seg   = 0;
  u->pfx_opr   = 0;
  u->pfx_adr   = 0;
  u->pfx_lock  = 0;
  u->pfx_repne = 0;
  u->pfx_rep   = 0;
  u->pfx_repe  = 0;
  u->pfx_rex   = 0;
  u->pfx_insn  = 0;
  u->mnemonic  = UD_Inone;
  u->itab_entry = NULL;
  u->have_modrm = 0;
  u->br_far    = 0;

  memset( &u->operand[ 0 ], 0, sizeof( struct ud_operand ) );
  memset( &u->operand[ 1 ], 0, sizeof( struct ud_operand ) );
  memset( &u->operand[ 2 ], 0, sizeof( struct ud_operand ) );
}

static int
resolve_mode( struct ud* u )
{
  /* if in error state, bail out */
  if ( u->error ) return -1; 

  /* propagate prefix effects */
  if ( u->dis_mode == 64 ) {  /* set 64bit-mode flags */

    /* Check validity of  instruction m64 */
    if ( P_INV64( u->itab_entry->prefix ) ) {
      UDERR(u, "instruction invalid in 64bits");
      return -1;
    }

    /* effective rex prefix is the  effective mask for the 
     * instruction hard-coded in the opcode map.
     */
    u->pfx_rex = ( u->pfx_rex & 0x40 ) | 
                 ( u->pfx_rex & REX_PFX_MASK( u->itab_entry->prefix ) ); 

    /* whether this instruction has a default operand size of 
     * 64bit, also hardcoded into the opcode map.
     */
    u->default64 = P_DEF64( u->itab_entry->prefix ); 
    /* calculate effective operand size */
    if ( REX_W( u->pfx_rex ) ) {
        u->opr_mode = 64;
    } else if ( u->pfx_opr ) {
        u->opr_mode = 16;
    } else {
        /* unless the default opr size of instruction is 64,
         * the effective operand size in the absence of rex.w
         * prefix is 32.
         */
        u->opr_mode = ( u->default64 ) ? 64 : 32;
    }

    /* calculate effective address size */
    u->adr_mode = (u->pfx_adr) ? 32 : 64;
  } else if ( u->dis_mode == 32 ) { /* set 32bit-mode flags */
    u->opr_mode = ( u->pfx_opr ) ? 16 : 32;
    u->adr_mode = ( u->pfx_adr ) ? 16 : 32;
  } else if ( u->dis_mode == 16 ) { /* set 16bit-mode flags */
    u->opr_mode = ( u->pfx_opr ) ? 32 : 16;
    u->adr_mode = ( u->pfx_adr ) ? 32 : 16;
  }

  /* set flags for implicit addressing */
  u->implicit_addr = P_IMPADDR( u->itab_entry->prefix );

  return 0;
}


static inline int
decode_insn(struct ud *u, uint16_t ptr)
{
  UD_ASSERT((ptr & 0x8000) == 0);
  u->itab_entry = &ud_itab[ ptr ];
  u->mnemonic = u->itab_entry->mnemonic;
  return (resolve_mode(u)     == 0 &&
          decode_operands(u)  == 0 &&
          resolve_mnemonic(u) == 0) ? 0 : -1;
}


/*
 * decode_3dnow()
 *
 *    Decoding 3dnow is a little tricky because of its strange opcode
 *    structure. The final opcode disambiguation depends on the last
 *    byte that comes after the operands have been decoded. Fortunately,
 *    all 3dnow instructions have the same set of operand types. So we
 *    go ahead and decode the instruction by picking an arbitrarily chosen
 *    valid entry in the table, decode the operands, and read the final
 *    byte to resolve the menmonic.
 */
static inline int
decode_3dnow(struct ud* u)
{
  uint16_t ptr;
  UD_ASSERT(u->le->type == UD_TAB__OPC_3DNOW);
  UD_ASSERT(u->le->table[0xc] != 0);
  decode_insn(u, u->le->table[0xc]);
  ud_inp_next(u); 
  if (u->error) {
    return -1;
  }
  ptr = u->le->table[inp_curr(u)]; 
  UD_ASSERT((ptr & 0x8000) == 0);
  u->mnemonic = ud_itab[ptr].mnemonic;
  return 0;
}


static int
decode_ssepfx(struct ud *u)
{
  uint8_t idx = ((u->pfx_insn & 0xf) + 1) / 2;
  if (u->le->table[idx] == 0) {
    idx = 0;
  }
  if (idx && u->le->table[idx] != 0) {
    /*
     * "Consume" the prefix as a part of the opcode, so it is no
     * longer exported as an instruction prefix.
     */
    switch (u->pfx_insn) {
      case 0xf2: 
        u->pfx_repne = 0;
        break;
      case 0xf3: 
        u->pfx_rep = 0;
        u->pfx_repe = 0;
        break;
      case 0x66: 
        u->pfx_opr = 0;
        break;
    }
  }
  return decode_ext(u, u->le->table[idx]);
}


/*
 * decode_ext()
 *
 *    Decode opcode extensions (if any)
 */
static int
decode_ext(struct ud *u, uint16_t ptr)
{
  uint8_t idx = 0;
  if ((ptr & 0x8000) == 0) {
    return decode_insn(u, ptr); 
  }
  u->le = &ud_lookup_table_list[(~0x8000 & ptr)];
  if (u->le->type == UD_TAB__OPC_3DNOW) {
    return decode_3dnow(u);
  }

  switch (u->le->type) {
    case UD_TAB__OPC_MOD:
      /* !11 = 0, 11 = 1 */
      idx = (MODRM_MOD(modrm(u)) + 1) / 4;
      break;
      /* disassembly mode/operand size/address size based tables.
       * 16 = 0,, 32 = 1, 64 = 2
       */
    case UD_TAB__OPC_MODE:
      idx = u->dis_mode != 64 ? 0 : 1;
      break;
    case UD_TAB__OPC_OSIZE:
      idx = eff_opr_mode(u->dis_mode, REX_W(u->pfx_rex), u->pfx_opr) / 32;
      break;
    case UD_TAB__OPC_ASIZE:
      idx = eff_adr_mode(u->dis_mode, u->pfx_adr) / 32;
      break;
    case UD_TAB__OPC_X87:
      idx = modrm(u) - 0xC0;
      break;
    case UD_TAB__OPC_VENDOR:
      if (u->vendor == UD_VENDOR_ANY) {
        /* choose a valid entry */
        idx = (u->le->table[idx] != 0) ? 0 : 1;
      } else if (u->vendor == UD_VENDOR_AMD) {
        idx = 0;
      } else {
        idx = 1;
      }
      break;
    case UD_TAB__OPC_RM:
      idx = MODRM_RM(modrm(u));
      break;
    case UD_TAB__OPC_REG:
      idx = MODRM_REG(modrm(u));
      break;
    case UD_TAB__OPC_SSE:
      return decode_ssepfx(u);
    default:
      UD_ASSERT(!"not reached");
      break;
  }

  return decode_ext(u, u->le->table[idx]);
}


static inline int
decode_opcode(struct ud *u)
{
  uint16_t ptr;
  UD_ASSERT(u->le->type == UD_TAB__OPC_TABLE);
  ud_inp_next(u); 
  if (u->error) {
    return -1;
  }
  u->primary_opcode = inp_curr(u);
  ptr = u->le->table[inp_curr(u)];
  if (ptr & 0x8000) {
    u->le = &ud_lookup_table_list[ptr & ~0x8000];
    if (u->le->type == UD_TAB__OPC_TABLE) {
      return decode_opcode(u);
    }
  }
  return decode_ext(u, ptr);
}

 
/* =============================================================================
 * ud_decode() - Instruction decoder. Returns the number of bytes decoded.
 * =============================================================================
 */
unsigned int
ud_decode(struct ud *u)
{
  inp_start(u);
  clear_insn(u);
  u->le = &ud_lookup_table_list[0];
  u->error = decode_prefixes(u) == -1 || 
             decode_opcode(u)   == -1 ||
             u->error;
  /* Handle decode error. */
  if (u->error) {
    /* clear out the decode data. */
    clear_insn(u);
    /* mark the sequence of bytes as invalid. */
    u->itab_entry = &ud_itab[0]; /* entry 0 is invalid */
    u->mnemonic = u->itab_entry->mnemonic;
  } 

    /* maybe this stray segment override byte
     * should be spewed out?
     */
    if ( !P_SEG( u->itab_entry->prefix ) && 
            u->operand[0].type != UD_OP_MEM &&
            u->operand[1].type != UD_OP_MEM )
        u->pfx_seg = 0;

  u->insn_offset = u->pc; /* set offset of instruction */
  u->asm_buf_fill = 0;   /* set translation buffer index to 0 */
  u->pc += u->inp_ctr;    /* move program counter by bytes decoded */

  /* return number of bytes disassembled. */
  return u->inp_ctr;
}

/*
vim: set ts=2 sw=2 expandtab
*/
