/* $VER: m68k_disasm.h V0.4 (18.04.2002)
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
 * v0.4  (18.04.2002) phx
 *       FETOXM1 was missing.
 * v0.1  (26.06.2000) phx
 *       Made the interface compatible to PPC disassembler module.
 *       Included/fixed missing PACK, CMPM, SBCD, CALLM instructions.
 * v0.0  (06.03.1999) phx
 *       File created.
 */


#ifndef M68K_DISASM_H
#define M68K_DISASM_H

/* version/revision */
#define M68KDISASM_VER 0
#define M68KDISASM_REV 4

typedef unsigned short m68k_word;  /* pointer to 16-bit instruction word */


#define ENCB(b7,b6,b5,b4,b3,b2,b1,b0) \
  ((b7 << 7) | (b6 << 6) | (b5 << 5) | (b4 << 4) | \
  (b3 << 3) | (b2 << 2) | (b1 << 1) | (b0))

  
#define ENCW(b15,b14,b13,b12,b11,b10,b9,b8,b7,b6,b5,b4,b3,b2,b1,b0) \
  ((ENCB(b15,b14,b13,b12,b11,b10,b9,b8) << 8) |\
  ENCB(b7,b6,b5,b4,b3,b2,b1,b0))

/*
 * Group Bit-manip (0000)
 */
#define ANDITOCCR_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1)
#define ANDIROSR_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1)
#define EORITOCCR_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1)
#define EORITOSR_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1)
#define ORITOCCR_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1)
#define ORITOSR_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1)
#define ANDITOCCR_INST  ENCW(0,0,0,0, 0,0,1,0, 0,0,1,1, 1,1,0,0)
#define ANDIROSR_INST ENCW(0,0,0,0, 0,0,1,0, 0,1,1,1, 1,1,0,0)
#define EORITOCCR_INST  ENCW(0,0,0,0, 1,0,1,0, 0,0,1,1, 1,1,0,0)
#define EORITOSR_INST ENCW(0,0,0,0, 1,0,1,0, 0,1,1,1, 1,1,0,0)
#define ORITOCCR_INST ENCW(0,0,0,0, 0,0,0,0, 0,0,1,1, 1,1,0,0)
#define ORITOSR_INST  ENCW(0,0,0,0, 0,0,0,0, 0,1,1,1, 1,1,0,0)

#define RTM_MASK   ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 0,0,0,0)
#define RTM_INST   ENCW(0,0,0,0, 0,1,1,0, 1,1,0,0, 0,0,0,0)

/* Note: bit eight being 1 here allows these to be check before all else */

/* Note: for movp bits 5-3, specify a mode An, which all the other
 * bit 8 set commands do not, so have check first. */
#define MOVEP_MASK  ENCW(1,1,1,1, 0,0,0,1, 0,0,1,1, 1,0,0,0)
#define MOVEP_INST  ENCW(0,0,0,0, 0,0,0,1, 0,0,0,0, 1,0,0,0)

#define BCHGD_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define BCLRD_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define BSETD_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define BTSTD_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define BCHGD_INST  ENCW(0,0,0,0, 0,0,0,1, 0,1,0,0, 0,0,0,0)
#define BCLRD_INST  ENCW(0,0,0,0, 0,0,0,1, 1,0,0,0, 0,0,0,0)
#define BSETD_INST  ENCW(0,0,0,0, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define BTSTD_INST  ENCW(0,0,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0)

#define BCHGS_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BCLRS_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BSETS_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BTSTS_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BCHGS_INST  ENCW(0,0,0,0, 1,0,0,0, 0,1,0,0, 0,0,0,0)
#define BCLRS_INST  ENCW(0,0,0,0, 1,0,0,0, 1,0,0,0, 0,0,0,0)
#define BSETS_INST  ENCW(0,0,0,0, 1,0,0,0, 1,1,0,0, 0,0,0,0)
#define BTSTS_INST  ENCW(0,0,0,0, 1,0,0,0, 0,0,0,0, 0,0,0,0)

#define CAS2_MASK ENCW(1,1,1,1, 1,1,0,1, 1,1,1,1, 1,1,1,1)
#define CAS2_INST ENCW(0,0,0,0, 1,1,0,0, 1,1,1,1, 1,1,0,0)

#define CAS_MASK  ENCW(1,1,1,1, 1,0,0,1, 1,1,0,0, 0,0,0,0)
#define CHK2_MASK ENCW(1,1,1,1, 1,0,0,1, 1,1,0,0, 0,0,0,0)
#define CMP2_MASK ENCW(1,1,1,1, 1,0,0,1, 1,1,0,0, 0,0,0,0)
#define CAS_INST  ENCW(0,0,0,0, 1,0,0,0, 1,1,0,0, 0,0,0,0)
#define CHK2_INST ENCW(0,0,0,0, 0,0,0,0, 1,1,0,0, 0,0,0,0)
#define CMP2_INST ENCW(0,0,0,0, 0,0,0,0, 1,1,0,0, 0,0,0,0)

/* close ties with Bxxx but bit eight here is 0 and there 1 */
/* also above (cas,chk2,cmp2) bits 7-6 here are size and never 11 */
#define ADDI_MASK ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define ANDI_MASK ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define CMPI_MASK ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define EORI_MASK ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define MOVES_MASK  ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define ORI_MASK  ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define SUBI_MASK ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define CALLM_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define ADDI_INST ENCW(0,0,0,0, 0,1,1,0, 0,0,0,0, 0,0,0,0)
#define ANDI_INST ENCW(0,0,0,0, 0,0,1,0, 0,0,0,0, 0,0,0,0)
#define CMPI_INST ENCW(0,0,0,0, 1,1,0,0, 0,0,0,0, 0,0,0,0)
#define EORI_INST ENCW(0,0,0,0, 1,0,1,0, 0,0,0,0, 0,0,0,0)
#define MOVES_INST  ENCW(0,0,0,0, 1,1,1,0, 0,0,0,0, 0,0,0,0)
#define ORI_INST  ENCW(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define SUBI_INST ENCW(0,0,0,0, 0,1,0,0, 0,0,0,0, 0,0,0,0)
#define CALLM_INST ENCW(0,0,0,0, 0,1,1,0, 1,1,0,0, 0,0,0,0)

/*
 * Group misc. (0100)
 */     
#define BGND_MASK 0xffff
#define ILLEGAL_MASK  0xffff
#define MOVEFRC_MASK  0xffff
#define MOVETOC_MASK  0xffff
#define NOP_MASK  0xffff
#define RESET_MASK  0xffff
#define RTD_MASk  0xffff
#define RTE_MASK  0xffff
#define RTR_MASK  0xffff
#define RTS_MASK  0xffff
#define STOP_MASK 0xffff
#define TRAPV_MASK  0xffff
#define BGND_INST ENCW(0,1,0,0, 1,0,1,0, 1,1,1,1, 1,0,1,0)
#define ILLEGAL_INST  ENCW(0,1,0,0, 1,0,1,0, 1,1,1,1, 1,1,0,0)
#define MOVEFRC_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 1,0,1,0)
#define MOVETOC_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 1,0,1,1)
#define NOP_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 0,0,0,1)
#define RESET_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 0,0,0,0)
#define RTD_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 0,1,0,0)
#define RTE_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 0,0,1,1)
#define RTR_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 0,1,1,1)
#define RTS_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 0,1,0,1)
#define STOP_INST ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 0,0,1,0)
#define TRAPV_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,1, 0,1,1,0)
#define SWAP_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define SWAP_INST ENCW(0,1,0,0, 1,0,0,0, 0,1,0,0, 0,0,0,0)

#define BKPT_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define EXTBW_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define EXTWL_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define EXTBL_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define LINKW_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define LINKL_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define MOVEFRUSP_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define MOVETOUSP_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#define UNLK_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 1,0,0,0)
#undef BKPT_INST
#define BKPT_INST ENCW(0,1,0,0, 1,0,0,0, 0,1,0,0, 1,0,0,0)
#define EXTBW_INST  ENCW(0,1,0,0, 1,0,0,0, 1,0,0,0, 0,0,0,0)
#define EXTWL_INST  ENCW(0,1,0,0, 1,0,0,0, 1,1,0,0, 0,0,0,0)
#define EXTBL_INST  ENCW(0,1,0,0, 1,0,0,1, 1,1,0,0, 0,0,0,0)
#define LINKW_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,0,1, 0,0,0,0)
#define LINKL_INST  ENCW(0,1,0,0, 1,0,0,0, 0,0,0,0, 1,0,0,0)
#define MOVETOUSP_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,0, 0,0,0,0)
#define MOVEFRUSP_INST  ENCW(0,1,0,0, 1,1,1,0, 0,1,1,0, 1,0,0,0)
#define UNLK_INST ENCW(0,1,0,0, 1,1,1,0, 0,1,0,1, 1,0,0,0)

#define TRAP_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,1,1, 0,0,0,0)
#define TRAP_INST ENCW(0,1,0,0, 1,1,1,0, 0,1,0,0, 0,0,0,0)

#define DIVSL_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define DIVUL_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define JMP_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define JSR_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define MOVEFRCCR_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define MOVETOCCR_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define MOVEFRSR_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define MOVETOSR_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define MULSL_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define MULUL_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define NBCD_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define PEA_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define TAS_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define DIVSL_INST  ENCW(0,1,0,0, 1,1,0,0, 0,1,0,0, 0,0,0,0)
#define DIVUL_INST  DIVSL_INST
#define JMP_INST  ENCW(0,1,0,0, 1,1,1,0, 1,1,0,0, 0,0,0,0)
#define JSR_INST  ENCW(0,1,0,0, 1,1,1,0, 1,0,0,0, 0,0,0,0)
#define MOVEFRCCR_INST  ENCW(0,1,0,0, 0,0,1,0, 1,1,0,0, 0,0,0,0)
#define MOVETOCCR_INST  ENCW(0,1,0,0, 0,1,0,0, 1,1,0,0, 0,0,0,0)
#define MOVEFRSR_INST ENCW(0,1,0,0, 0,0,0,0, 1,1,0,0, 0,0,0,0)
#define MOVETOSR_INST ENCW(0,1,0,0, 0,1,1,0, 1,1,0,0, 0,0,0,0)
#define MULSL_INST  ENCW(0,1,0,0, 1,1,0,0, 0,0,0,0, 0,0,0,0)
#define MULUL_INST  MULSL_INST
#define NBCD_INST ENCW(0,1,0,0, 1,0,0,0, 0,0,0,0, 0,0,0,0)
#define PEA_INST  ENCW(0,1,0,0, 1,0,0,0, 0,1,0,0, 0,0,0,0)
#define TAS_INST  ENCW(0,1,0,0, 1,0,1,0, 1,1,0,0, 0,0,0,0)

#define MOVEM_MASK  ENCW(1,1,1,1, 1,0,1,1, 1,0,0,0, 0,0,0,0)
#define MOVEM_INST  ENCW(0,1,0,0, 1,0,0,0, 1,0,0,0, 0,0,0,0)

#define CLR_MASK  ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define NEG_MASK  ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define NEGX_MASK ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define NOT_MASK  ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define TST_MASK  ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define CLR_INST  ENCW(0,1,0,0, 0,0,1,0, 0,0,0,0, 0,0,0,0)
#define NEG_INST  ENCW(0,1,0,0, 0,1,0,0, 0,0,0,0, 0,0,0,0)
#define NEGX_INST ENCW(0,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define NOT_INST  ENCW(0,1,0,0, 0,1,1,0, 0,0,0,0, 0,0,0,0)
  /* Note: very similatr to MOVEM but bit 9 differentiates. */
#define TST_INST  ENCW(0,1,0,0, 1,0,1,0, 0,0,0,0, 0,0,0,0)

#define LEA_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define LEA_INST  ENCW(0,1,0,0, 0,0,0,1, 1,1,0,0, 0,0,0,0)

#define CHK_MASK  ENCW(1,1,1,1, 0,0,0,1, 0,1,0,0, 0,0,0,0)
#define CHK_INST  ENCW(0,1,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0)

/*
 * Group bitfield/Shift/Rotate. (1110)
 */
#define BFCHG_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BFCLR_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BFEXTS_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BFEXTU_MASK ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BFFFO_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BFINS_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BFSET_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BFTST_MASK  ENCW(1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0)

#define BFCHG_INST  ENCW(1,1,1,0, 1,0,1,0, 1,1,0,0, 0,0,0,0)
#define BFCLR_INST  ENCW(1,1,1,0, 1,1,0,0, 1,1,0,0, 0,0,0,0)
#define BFEXTS_INST ENCW(1,1,1,0, 1,0,1,1, 1,1,0,0, 0,0,0,0)
#define BFEXTU_INST ENCW(1,1,1,0, 1,0,0,1, 1,1,0,0, 0,0,0,0)
#define BFFFO_INST  ENCW(1,1,1,0, 1,1,0,1, 1,1,0,0, 0,0,0,0)
#define BFINS_INST  ENCW(1,1,1,0, 1,1,1,1, 1,1,0,0, 0,0,0,0)
#define BFSET_INST  ENCW(1,1,1,0, 1,1,1,0, 1,1,0,0, 0,0,0,0)
#define BFTST_INST  ENCW(1,1,1,0, 1,0,0,0, 1,1,0,0, 0,0,0,0)

#define AS_TYPE   0x0
#define LS_TYPE   0x1
#define RO_TYPE   0x3
#define ROX_TYPE  0x2

/*
 * Group DBcc/TRAPcc/ADDQ/SUBQ (0101)
 */
#define DBcc_MASK ENCW(1,1,1,1, 0,0,0,0, 1,1,1,1, 1,0,0,0)
#define TRAPcc_MASK ENCW(1,1,1,1, 0,0,0,0, 1,1,1,1, 1,0,0,0)
#define Scc_MASK  ENCW(1,1,1,1, 0,0,0,0, 1,1,0,0, 0,0,0,0)
#define ADDQ_MASK ENCW(1,1,1,1, 0,0,0,1, 0,0,0,0, 0,0,0,0)
#define SUBQ_MASK ENCW(1,1,1,1, 0,0,0,1, 0,0,0,0, 0,0,0,0)
#define DBcc_INST ENCW(0,1,0,1, 0,0,0,0, 1,1,0,0, 1,0,0,0)
#define TRAPcc_INST ENCW(0,1,0,1, 0,0,0,0, 1,1,1,1, 1,0,0,0)
#define Scc_INST  ENCW(0,1,0,1, 0,0,0,0, 1,1,0,0, 0,0,0,0)
#define ADDQ_INST ENCW(0,1,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define SUBQ_INST ENCW(0,1,0,1, 0,0,0,1, 0,0,0,0, 0,0,0,0)

/*
 * Group ADD/ADDX (1101)
 */
#define ADDX_MASK ENCW(1,1,1,1, 0,0,0,1, 0,0,1,1, 0,0,0,0)
#define ADDX_INST ENCW(1,1,0,1, 0,0,0,1, 0,0,0,0, 0,0,0,0)
#define ADD_MASK  ENCW(1,1,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define ADD_INST  ENCW(1,1,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)

/*
 * Group SUB/SUBX (1001)
 */
#define SUBX_MASK ENCW(1,1,1,1, 0,0,0,1, 0,0,1,1, 0,0,0,0)
#define SUBX_INST ENCW(1,0,0,1, 0,0,0,1, 0,0,0,0, 0,0,0,0)
#define SUB_MASK  ENCW(1,1,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define SUB_INST  ENCW(1,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)

/*
 * Group CMP/CMPA/EOR (1011)
 */
#define CMPA_MASK ENCW(1,1,1,1, 0,0,0,0, 1,1,0,0, 0,0,0,0)
#define CMPA_INST ENCW(1,0,1,1, 0,0,0,0, 1,1,0,0, 0,0,0,0)

#define CMP_MASK  ENCW(1,1,1,1, 0,0,0,1, 0,0,0,0, 0,0,0,0)
#define CMP_INST  ENCW(1,0,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)

#define CMPM_MASK ENCW(1,1,1,1, 0,0,0,1, 0,0,1,1, 1,0,0,0)
#define CMPM_INST ENCW(1,0,1,1, 0,0,0,1, 0,0,0,0, 1,0,0,0)

#define EOR_MASK  ENCW(1,1,1,1, 0,0,0,1, 0,0,0,0, 0,0,0,0)
#define EOR_INST  ENCW(1,0,1,1, 0,0,0,1, 0,0,0,0, 0,0,0,0)

/*
 * Group branch. (0110)
 */
#define BRA_MASK  ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define BSR_MASK  ENCW(1,1,1,1, 1,1,1,1, 0,0,0,0, 0,0,0,0)
#define Bcc_MASK  ENCW(1,1,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define BRA_INST  ENCW(0,1,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define BSR_INST  ENCW(0,1,1,0, 0,0,0,1, 0,0,0,0, 0,0,0,0)
#define Bcc_INST  ENCW(0,1,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)


/*
 * Group SBCD/DIVx/OR (1000)
 */

#define PACKA_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,1,1, 1,0,0,0)
#define PACKD_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,1,1, 1,0,0,0)
#define PACKA_INST  ENCW(1,0,0,0, 0,0,0,1, 0,1,0,0, 1,0,0,0)
#define PACKD_INST  ENCW(1,0,0,0, 0,0,0,1, 0,1,0,0, 0,0,0,0)
#define UNPKA_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,1,1, 1,0,0,0)
#define UNPKD_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,1,1, 1,0,0,0)
#define UNPKA_INST  ENCW(1,0,0,0, 0,0,0,1, 1,0,0,0, 1,0,0,0)
#define UNPKD_INST  ENCW(1,0,0,0, 0,0,0,1, 1,0,0,0, 0,0,0,0)
#define SBCDA_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,1,1, 1,0,0,0)
#define SBCDD_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,1,1, 1,0,0,0)
#define SBCDA_INST  ENCW(1,0,0,0, 0,0,0,1, 0,0,0,0, 1,0,0,0)
#define SBCDD_INST  ENCW(1,0,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0)

#define DIVSW_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define DIVUW_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define DIVSW_INST  ENCW(1,0,0,0, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define DIVUW_INST  ENCW(1,0,0,0, 0,0,0,0, 1,1,0,0, 0,0,0,0)

#define OR_MASK   ENCW(1,1,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define OR_INST   ENCW(1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)

/*
 * Group AND/MUL/ABCD/EXG (1100)
 */
#define ABCDA_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,1,1, 1,0,0,0)
#define ABCDD_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,1,1, 1,0,0,0)
#define ABCDA_INST  ENCW(1,1,0,0, 0,0,0,1, 0,0,0,0, 1,0,0,0)
#define ABCDD_INST  ENCW(1,1,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0)
  
#define MULSW_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define MULUW_MASK  ENCW(1,1,1,1, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define MULSW_INST  ENCW(1,1,0,0, 0,0,0,1, 1,1,0,0, 0,0,0,0)
#define MULUW_INST  ENCW(1,1,0,0, 0,0,0,0, 1,1,0,0, 0,0,0,0)

#define EXG_MASK  ENCW(1,1,1,1, 0,0,0,1, 0,0,1,1, 0,0,0,0)
#define EXG_INST  ENCW(1,1,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0)  

#define AND_MASK  ENCW(1,1,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define AND_INST  ENCW(1,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)

#define ENCFT(b5,b4,b3,b2,b1,b0) ENCB(0,0,b5,b4,b3,b2,b1,b0)

#define FABS  ENCFT(0,1,1,0,0,0)
#define FACOS ENCFT(0,1,1,1,0,0)
#define FADD  ENCFT(1,0,0,0,1,0)
#define FASIN ENCFT(0,0,1,1,0,0)
#define FATAN ENCFT(0,0,1,0,1,0)
#define FATANH  ENCFT(0,0,1,1,0,1)
#define FCMP  ENCFT(1,1,1,0,0,0)
#define FCOS  ENCFT(0,1,1,1,0,1)
#define FCOSH ENCFT(0,1,1,0,0,1)
#define FDIV  ENCFT(1,0,0,0,0,0)
#define FETOX ENCFT(0,1,0,0,0,0)
#define FETOXM1 ENCFT(0,0,1,0,0,0)
#define FGETEXP ENCFT(0,1,1,1,1,0)
#define FGETMAN ENCFT(0,1,1,1,1,1)
#define FINT  ENCFT(0,0,0,0,0,1)
#define FINTRZ  ENCFT(0,0,0,0,1,1)
#define FLOG10  ENCFT(0,1,0,1,0,1)
#define FLOG2 ENCFT(0,1,0,1,1,0)
#define FLOGN ENCFT(0,1,0,1,0,0)
#define FLOGNP1 ENCFT(0,0,0,1,1,0)
#define FMOD  ENCFT(1,0,0,0,0,1)
#define FMOVE ENCFT(0,0,0,0,0,0)
#define FMUL  ENCFT(1,0,0,0,1,1)
#define FNEG  ENCFT(0,1,1,0,1,0)
#define FREM  ENCFT(1,0,0,1,0,1)
#undef FSCALE
#define FSCALE  ENCFT(1,0,0,1,1,0)
#define FSGLDIV ENCFT(1,0,0,1,0,0)
#define FSGLMUL ENCFT(1,0,0,1,1,1)
#define FSIN  ENCFT(0,0,1,1,1,0)
#define FSINH ENCFT(0,0,0,0,1,0)
#define FSQRT ENCFT(0,0,0,1,0,0)
#define FSUB  ENCFT(1,0,1,0,0,0)
#define FTAN  ENCFT(0,0,1,1,1,1)
#define FTANH ENCFT(0,0,1,0,0,1)
#define FTENTOX ENCFT(0,1,0,0,1,0)
#define FTST  ENCFT(1,1,1,0,1,0)
#define FTWOTOX ENCFT(0,1,0,0,0,1)

enum getmod_flag { GETMOD_BEFORE = -1, GETMOD_AFTER = -2 };

enum opcode_flags {
  CPU_000 = 0x1, CPU_010 = 0x2, CPU_020 = 0x4, CPU_030 = 0x8,
  CPU_040 = 0x10, FPU_881 = 0x40, FPU_882 = 0x80, FPU_040 = 0x100,
  MMU_851 = 0x400, MMU_030 = 0x800, MMU_040 = 0x1000,

  CPU_ANY = CPU_000 | CPU_010 | CPU_020 | CPU_030 | CPU_040,
  FPU_ANY = FPU_881 | FPU_882 | FPU_040,
  MMU_ANY = MMU_851 | MMU_030 | MMU_040,
  CPU_020UP = CPU_020 | CPU_030 | CPU_040
};

enum mod_types {
  DR_DIR = 0,
  AR_DIR, AR_IND, AR_INC, AR_DEC,
  AR_DIS, AR_IDX, MOD_SPECIAL
};

enum sizes { SIZE_BYTE = sizeof(char), SIZE_WORD = sizeof(short),
    SIZE_LONG = sizeof(long), SIZE_SINGLE = 5, SIZE_QUAD = 6,
    SIZE_DOUBLE = SIZE_QUAD, SIZE_EXTENDED = 7, SIZE_PACKED = 8 };


/* Disassembler structure, the interface to the application */

struct DisasmPara_68k {
  m68k_word *instr;             /* pointer to instruction to disassemble */
  m68k_word *iaddr;             /* instr.addr., usually the same as instr */
  char *opcode;                 /* buffer for opcode, min. 16 chars. */
  char *operands;               /* operand buffer, min. 128 chars. */
  int radix;                    /* base 2, 8, 10, 16 ... */
/* call-back functions for symbolic debugger support */
  unsigned long (*get_areg)(int);  /* returns current value of reg. An */
  char *(*find_symbol)(unsigned long,unsigned long *);
                                /* finds closest symbol to addr and */
                                /*  returns (positive) difference and name */
/* changed by disassembler: */
  unsigned char type;           /* type of instruction, see below */
  unsigned char flags;          /* additional flags */
  char reserved;
  char areg;                    /* address reg. for displacement (PC=-1) */
  int displacement;             /* branch- or d16-displacement */
};


struct dis_buffer {
  struct DisasmPara_68k *dp;  /* link to DisasmPara */
  short *val;   /* (real) pointer to memory. */
  short *sval;  /* simulated memory pointer for address calculations (phx) */
  char *dasm;   /* actual dasm. */
  char *casm;   /* current position in dasm. */
  char *info;   /* extra info. */
  char *cinfo;  /* current position in info. */
  int   used;   /* length used. */
  int   mit;    /* use mit syntax. */
};
typedef struct dis_buffer dis_buffer_t;

#define ISBITSET(val,b) ((val) & (1 << (b)))
#define BITFIELD_MASK(sb,eb)  (((1 << ((sb) + 1))-1) & (~((1 << (eb))-1)))
#define BITFIELD(val,sb,eb) ((BITFIELD_MASK(sb,eb) & (val)) >> (eb))
#define OPCODE_MAP(x) (BITFIELD(x,15,12))
#ifdef __STDC__
#define IS_INST(inst,val) ((inst ## _MASK & (val)) == inst ## _INST)
#else
#define IS_INST(inst,val) ((inst/**/_MASK & (val)) == inst/**/_INST)
#endif
#define PRINT_FPREG(dbuf, reg) addstr(dbuf, reg<8?fpregs[reg]:"f?")
#define PRINT_DREG(dbuf, reg) addstr(dbuf, reg<8?dregs[reg]:"d?")
#define PRINT_AREG(dbuf, reg) addstr(dbuf, reg<8?aregs[reg]:"a?")

#undef NBBY
#define NBBY 256  /*@@@*/
#ifndef INT_MAX
#define INT_MAX 0x7fffffff;
#endif
#define DB_STGY_PROC 0  /*@@@*/
#define DB_STGY_ANY 0  /*@@@*/

/* common Unix typedefs used in m68k_disasm.c */
#if !defined(_SYS_TYPES_H)
#define u_char unsigned char
#define u_short unsigned short
#define u_int unsigned int
#define u_long unsigned long
#endif
typedef unsigned long vm68k_offset_t;
typedef unsigned long db_expr_t; /*@@@*/
typedef const char *db_sym_t;  /*@@@*/


/* m68k_disasm.o prototypes */
#ifndef M68K_DISASM_C
extern m68k_word *M68k_Disassemble(struct DisasmPara_68k *);

#if 0
extern void get_modregstr_moto(dis_buffer_t *dbuf, int bit, int mod,
                               int sz, int dd);
extern void get_modregstr_mit(dis_buffer_t *dbuf, int bit, int mod,
                              int sz, int dd));
extern u_long get_areg_val(int reg);
#endif
#endif

#endif /* M68K_DISASM_H */
