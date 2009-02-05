/* -----------------------------------------------------------------------------
 * syn-att.c
 *
 * Copyright (c) 2004, 2005, 2006 Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See (LICENSE)
 * -----------------------------------------------------------------------------
 */

#include "types.h"
#include "extern.h"
#include "decode.h"
#include "itab.h"
#include "syn.h"

/* -----------------------------------------------------------------------------
 * opr_cast() - Prints an operand cast.
 * -----------------------------------------------------------------------------
 */
static void 
opr_cast(struct ud* u, struct ud_operand* op)
{
  switch(op->size) {
	case 16 : case 32 :
		mkasm(u, "*");   break;
	default: break;
  }
}

/* -----------------------------------------------------------------------------
 * gen_operand() - Generates assembly output for each operand.
 * -----------------------------------------------------------------------------
 */
static void 
gen_operand(struct ud* u, struct ud_operand* op)
{
  switch(op->type) {
	case UD_OP_REG:
		mkasm(u, "%%%s", ud_reg_tab[op->base - UD_R_AL]);
		break;

	case UD_OP_MEM:
		if (u->br_far) opr_cast(u, op);
		if (u->pfx_seg)
			mkasm(u, "%%%s:", ud_reg_tab[u->pfx_seg - UD_R_AL]);
		if (op->offset == 8) {
			if (op->lval.sbyte < 0)
				mkasm(u, "-0x%x", (-op->lval.sbyte) & 0xff);
			else	mkasm(u, "0x%x", op->lval.sbyte);
		} 
		else if (op->offset == 16) 
			mkasm(u, "0x%x", op->lval.uword);
		else if (op->offset == 32) 
			mkasm(u, "0x%lx", op->lval.udword);
		else if (op->offset == 64) 
			mkasm(u, "0x" FMT64 "x", op->lval.uqword);

		if (op->base)
			mkasm(u, "(%%%s", ud_reg_tab[op->base - UD_R_AL]);
		if (op->index) {
			if (op->base)
				mkasm(u, ",");
			else mkasm(u, "(");
			mkasm(u, "%%%s", ud_reg_tab[op->index - UD_R_AL]);
		}
		if (op->scale)
			mkasm(u, ",%d", op->scale);
		if (op->base || op->index)
			mkasm(u, ")");
		break;

	case UD_OP_IMM:
		switch (op->size) {
			case  8: mkasm(u, "$0x%x", op->lval.ubyte);    break;
			case 16: mkasm(u, "$0x%x", op->lval.uword);    break;
			case 32: mkasm(u, "$0x%lx", op->lval.udword);  break;
			case 64: mkasm(u, "$0x" FMT64 "x", op->lval.uqword); break;
			default: break;
		}
		break;

	case UD_OP_JIMM:
		switch (op->size) {
			case  8:
				mkasm(u, "0x" FMT64 "x", u->pc + op->lval.sbyte); 
				break;
			case 16:
				mkasm(u, "0x" FMT64 "x", u->pc + op->lval.sword);
				break;
			case 32:
				mkasm(u, "0x" FMT64 "x", u->pc + op->lval.sdword);
				break;
			default:break;
		}
		break;

	case UD_OP_PTR:
		switch (op->size) {
			case 32:
				mkasm(u, "$0x%x, $0x%x", op->lval.ptr.seg, 
					op->lval.ptr.off & 0xFFFF);
				break;
			case 48:
				mkasm(u, "$0x%x, $0x%lx", op->lval.ptr.seg, 
					op->lval.ptr.off);
				break;
		}
		break;
			
	default: return;
  }
}

/* =============================================================================
 * translates to AT&T syntax 
 * =============================================================================
 */
extern void 
ud_translate_att(struct ud *u)
{
  int size = 0;

  /* check if P_OSO prefix is used */
  if (! P_OSO(u->itab_entry->prefix) && u->pfx_opr) {
	switch (u->dis_mode) {
		case 16: 
			mkasm(u, "o32 ");
			break;
		case 32:
		case 64:
 			mkasm(u, "o16 ");
			break;
	}
  }

  /* check if P_ASO prefix was used */
  if (! P_ASO(u->itab_entry->prefix) && u->pfx_adr) {
	switch (u->dis_mode) {
		case 16: 
			mkasm(u, "a32 ");
			break;
		case 32:
 			mkasm(u, "a16 ");
			break;
		case 64:
 			mkasm(u, "a32 ");
			break;
	}
  }

  if (u->pfx_lock)
  	mkasm(u,  "lock ");
  if (u->pfx_rep)
	mkasm(u,  "rep ");
  if (u->pfx_repne)
		mkasm(u,  "repne ");

  /* special instructions */
  switch (u->mnemonic) {
	case UD_Iretf: 
		mkasm(u, "lret "); 
		break;
	case UD_Idb:
		mkasm(u, ".byte 0x%x", u->operand[0].lval.ubyte);
		return;
	case UD_Ijmp:
	case UD_Icall:
		if (u->br_far) mkasm(u,  "l");
		mkasm(u, "%s", ud_lookup_mnemonic(u->mnemonic));
		break;
	case UD_Ibound:
	case UD_Ienter:
		if (u->operand[0].type != UD_NONE)
			gen_operand(u, &u->operand[0]);
		if (u->operand[1].type != UD_NONE) {
			mkasm(u, ",");
			gen_operand(u, &u->operand[1]);
		}
		return;
	default:
		mkasm(u, "%s", ud_lookup_mnemonic(u->mnemonic));
  }

  if (u->c1)
	size = u->operand[0].size;
  else if (u->c2)
	size = u->operand[1].size;
  else if (u->c3)
	size = u->operand[2].size;

  if (size == 8)
	mkasm(u, "b");
  else if (size == 16)
	mkasm(u, "w");
  else if (size == 64)
 	mkasm(u, "q");

  mkasm(u, " ");

  if (u->operand[2].type != UD_NONE) {
	gen_operand(u, &u->operand[2]);
	mkasm(u, ", ");
  }

  if (u->operand[1].type != UD_NONE) {
	gen_operand(u, &u->operand[1]);
	mkasm(u, ", ");
  }

  if (u->operand[0].type != UD_NONE)
	gen_operand(u, &u->operand[0]);
}
