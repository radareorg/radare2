/* Instruction printing code for the ARC.
   Copyright (C) 1994-2026 Free Software Foundation, Inc.

   Contributed by Claudiu Zissulescu (claziss@synopsys.com)

   This file is part of libopcodes.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "../../../include/sysdep.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../../../include/disas-asm.h"
#include "arc.h"
#include "elf-arc.h"
#include "arc-dis.h"
#include "arc-ext.h"
#include "../../../include/elf-bfd.h"
#include "../../../include/libiberty.h"
#include "../../../include/opintl.h"

/* Compatibility macros for radare2 */
#define bfd_mach_arc_arc600 6
#define bfd_mach_arc_arc601 6
#define bfd_mach_arc_arc700 7
#define bfd_mach_arc_arcv2  8

/* fprintf_styled_func compatibility - ignore style argument */
#define dis_style_text 0
#define dis_style_mnemonic 0
#define dis_style_immediate 0
#define dis_style_register 0
#define dis_style_address 0
#define dis_style_address_offset 0
#define dis_style_assembler_directive 0
#define dis_style_comment_start 0

/* Map fprintf_styled_func to fprintf_func by wrapping it */
#define arc_fprintf_styled(info, stream, style, ...) (info)->fprintf_func(stream, __VA_ARGS__)

#define startswith(str, prefix) (strncmp ((str), (prefix), strlen (prefix)) == 0)
#define _bfd_error_handler(...) do {} while(0)

/* Structure used to iterate over, and extract the values for, operands of
   an opcode.  */

struct arc_operand_iterator
{
  /* The complete instruction value to extract operands from.  */
  unsigned long long insn;

  /* The LIMM if this is being tracked separately.  This field is only
     valid if we find the LIMM operand in the operand list.  */
  unsigned limm;

  /* The opcode this iterator is operating on.  */
  const struct arc_opcode *opcode;

  /* The index into the opcodes operand index list.  */
  const unsigned char *opidx;
};

/* A private data used by ARC decoder.  */
struct arc_disassemble_info
{
  /* The current disassembled arc opcode.  */
  const struct arc_opcode *opcode;

  /* Instruction length w/o limm field.  */
  unsigned insn_len;

  /* TRUE if we have limm.  */
  bool limm_p;

  /* LIMM value, if exists.  */
  unsigned limm;

  /* Condition code, if exists.  */
  unsigned condition_code;

  /* Writeback mode.  */
  unsigned writeback_mode;

  /* Number of operands.  */
  unsigned operands_count;

  struct arc_insn_operand operands[MAX_INSN_ARGS];

  /* Classes of extension instructions to be considered.  */
#define MAX_DECODES 25
  struct
  {
    insn_class_t insn_class;
    insn_subclass_t subclass;
  } decode[MAX_DECODES];

  /* Current size of the above array.  */
  unsigned decode_count;

  /* ISA mask value via disassembler info options, or bfd.  */
  unsigned isa_mask;

  /* True if we want to print using only hex numbers.  */
  bool print_hex;
};

/* Globals variables.  */

static const char * const regnames[64] =
{
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
  "r24", "r25", "gp", "fp", "sp", "ilink", "r30", "blink",

  "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",
  "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",
  "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",
  "r56", "r57", "r58", "r59", "lp_count", "reserved", "LIMM", "pcl"
};

static const char * const addrtypenames[ARC_NUM_ADDRTYPES] =
{
  "bd", "jid", "lbd", "mbd", "sd", "sm", "xa", "xd",
  "cd", "cbd", "cjid", "clbd", "cm", "csd", "cxa", "cxd"
};

/* Macros section.  */

#ifdef DEBUG
# define pr_debug(fmt, args...) fprintf (stderr, fmt, ##args)
#else
# define pr_debug(fmt, args...)
#endif

#define ARRANGE_ENDIAN(info, buf)					\
  (info->endian == BFD_ENDIAN_LITTLE ? bfd_getm32 (bfd_getl32 (buf))	\
   : bfd_getb32 (buf))

#define BITS(word,s,e)  (((word) >> (s)) & ((1ull << ((e) - (s)) << 1) - 1))
#define OPCODE_32BIT_INSN(word)	(BITS ((word), 27, 31))

/* Functions implementation.  */

/* Initialize private data.  */
static bool
init_arc_disasm_info (struct disassemble_info *info)
{
  struct arc_disassemble_info *arc_infop = calloc (1, sizeof (*arc_infop));

  info->private_data = arc_infop;
  return arc_infop != NULL;
}

/* Add a new element to the decode list.  */

static void
add_to_decode (struct arc_disassemble_info *arc_infop,
	       insn_class_t insn_class,
	       insn_subclass_t subclass)
{
  unsigned int i;
  for (i = 0; i < arc_infop->decode_count; i++)
    if (arc_infop->decode[i].insn_class == insn_class
	&& arc_infop->decode[i].subclass == subclass)
      return;

  assert (i < MAX_DECODES);
  arc_infop->decode[i].insn_class = insn_class;
  arc_infop->decode[i].subclass = subclass;
  arc_infop->decode_count = i + 1;
}

/* Return TRUE if we need to skip the opcode from being
   disassembled.  */

static bool
skip_this_opcode (struct disassemble_info *info, const struct arc_opcode *opcode)
{
  /* Check opcode for major 0x06, return if it is not in.  */
  if (arc_opcode_len (opcode) == 4
      && (OPCODE_32BIT_INSN (opcode->opcode) != 0x06
	  /* Can be an APEX extensions.  */
	  && OPCODE_32BIT_INSN (opcode->opcode) != 0x07))
    return false;

  /* or not a known truble class.  */
  switch (opcode->insn_class)
    {
    case FLOAT:
    case DSP:
    case ARITH:
    case MPY:
      break;
    default:
      return false;
    }

  struct arc_disassemble_info *arc_infop = info->private_data;
  for (unsigned int i = 0; i < arc_infop->decode_count; i++)
    if (arc_infop->decode[i].insn_class == opcode->insn_class
	&& arc_infop->decode[i].subclass == opcode->subclass)
      return false;

  return true;
}

static bfd_vma
bfd_getm32 (unsigned int data)
{
  bfd_vma value = 0;

  value = ((data & 0xff00) | (data & 0xff)) << 16;
  value |= ((data & 0xff0000) | (data & 0xff000000)) >> 16;
  return value;
}

static bool
special_flag_p (const char *opname,
		const char *flgname)
{
  const struct arc_flag_special *flg_spec;
  unsigned i, j, flgidx;

  for (i = 0; i < arc_num_flag_special; i++)
    {
      flg_spec = &arc_flag_special_cases[i];

      if (strcmp (opname, flg_spec->name))
	continue;

      /* Found potential special case instruction.  */
      for (j=0;; ++j)
	{
	  flgidx = flg_spec->flags[j];
	  if (flgidx == 0)
	    break; /* End of the array.  */

	  if (strcmp (flgname, arc_flag_operands[flgidx].name) == 0)
	    return true;
	}
    }
  return false;
}

/* Find opcode from ARC_TABLE given the instruction described by INSN and
   INSNLEN.  The ISA_MASK restricts the possible matches in ARC_TABLE.  */

static const struct arc_opcode *
find_format_from_table (struct disassemble_info *info,
			const struct arc_opcode *arc_table,
                        unsigned long long insn,
			unsigned int insn_len,
                        unsigned isa_mask,
			bool *has_limm,
			bool overlaps)
{
  unsigned int i = 0;
  const struct arc_opcode *opcode = NULL;
  const struct arc_opcode *t_op = NULL;
  const unsigned char *opidx;
  const unsigned char *flgidx;
  bool warn_p = false;

  do
    {
      bool invalid = false;

      opcode = &arc_table[i++];

      if (!(opcode->cpu & isa_mask))
	continue;

      if (arc_opcode_len (opcode) != (int) insn_len)
	continue;

      if ((insn & opcode->mask) != opcode->opcode)
	continue;

      *has_limm = false;

      /* Possible candidate, check the operands.  */
      for (opidx = opcode->operands; *opidx; opidx++)
	{
	  int value, limmind;
	  const struct arc_operand *operand = &arc_operands[*opidx];

	  if (operand->flags & ARC_OPERAND_FAKE)
	    continue;

	  if (operand->extract)
	    value = (*operand->extract) (insn, &invalid);
	  else
	    value = (insn >> operand->shift) & ((1ull << operand->bits) - 1);

	  /* Check for LIMM indicator.  If it is there, then make sure
	     we pick the right format.  */
	  limmind = (isa_mask & ARC_OPCODE_ARCV2) ? 0x1E : 0x3E;
	  if (operand->flags & ARC_OPERAND_IR
	      && !(operand->flags & ARC_OPERAND_LIMM))
	    {
	      if ((value == 0x3E && insn_len == 4)
		  || (value == limmind && insn_len == 2))
		{
		  invalid = true;
		  break;
		}
	    }

	  if (operand->flags & ARC_OPERAND_LIMM
	      && !(operand->flags & ARC_OPERAND_DUPLICATE))
	    *has_limm = true;
	}

      /* Check the flags.  */
      for (flgidx = opcode->flags; *flgidx; flgidx++)
	{
	  /* Get a valid flag class.  */
	  const struct arc_flag_class *cl_flags = &arc_flag_classes[*flgidx];
	  const unsigned *flgopridx;
	  int foundA = 0, foundB = 0;
	  unsigned int value;

	  /* Check first the extensions.  */
	  if (cl_flags->flag_class & F_CLASS_EXTEND)
	    {
	      value = (insn & 0x1F);
	      if (arcExtMap_condCodeName (value))
		continue;
	    }

	  /* Check for the implicit flags.  */
	  if (cl_flags->flag_class & F_CLASS_IMPLICIT)
	    continue;

	  for (flgopridx = cl_flags->flags; *flgopridx; ++flgopridx)
	    {
	      const struct arc_flag_operand *flg_operand =
		&arc_flag_operands[*flgopridx];

	      value = (insn >> flg_operand->shift)
		& ((1 << flg_operand->bits) - 1);
	      if (value == flg_operand->code)
		foundA = 1;
	      if (value)
		foundB = 1;
	    }

	  if (!foundA && foundB)
	    {
	      invalid = true;
	      break;
	    }
	}

      if (invalid)
	continue;

      if (insn_len == 4
	  && overlaps)
	{
	  warn_p = true;
	  t_op = opcode;
	  if (skip_this_opcode (info, opcode))
	    continue;
	}

      /* The instruction is valid.  */
      return opcode;
    }
  while (opcode->mask);

  if (warn_p)
    {
      info->fprintf_func
	(info->stream, dis_style_text,
	 _("\nWarning: disassembly may be wrong due to "
	   "guessed opcode class choice.\n"
	   "Use -M<class[,class]> to select the correct "
	   "opcode class(es).\n\t\t\t\t"));
      return t_op;
    }

  return NULL;
}

/* Find opcode for INSN, trying various different sources.  The instruction
   length in INSN_LEN will be updated if the instruction requires a LIMM
   extension.

   A pointer to the opcode is placed into OPCODE_RESULT, and ITER is
   initialised, ready to iterate over the operands of the found opcode.  If
   the found opcode requires a LIMM then the LIMM value will be loaded into a
   field of ITER.

   This function returns TRUE in almost all cases, FALSE is reserved to
   indicate an error (failing to find an opcode is not an error) a returned
   result of FALSE would indicate that the disassembler can't continue.

   If no matching opcode is found then the returned result will be TRUE, the
   value placed into OPCODE_RESULT will be NULL, ITER will be undefined, and
   INSN_LEN will be unchanged.

   If a matching opcode is found, then the returned result will be TRUE, the
   opcode pointer is placed into OPCODE_RESULT, INSN_LEN will be increased by
   4 if the instruction requires a LIMM, and the LIMM value will have been
   loaded into a field of ITER.  Finally, ITER will have been initialised so
   that calls to OPERAND_ITERATOR_NEXT will iterate over the opcode's
   operands.  */

static bool
find_format (bfd_vma                       memaddr,
	     unsigned long long            insn,
	     unsigned int *                insn_len,
             unsigned                      isa_mask,
	     struct disassemble_info *     info,
             const struct arc_opcode **    opcode_result,
             struct arc_operand_iterator * iter)
{
  const struct arc_opcode *opcode = NULL;
  bool needs_limm = false;
  const extInstruction_t *einsn, *i;
  unsigned limm = 0;
  struct arc_disassemble_info *arc_infop = info->private_data;

  /* First, try the extension instructions.  */
  if (*insn_len == 4)
    {
      einsn = arcExtMap_insn (OPCODE_32BIT_INSN (insn), insn);
      for (i = einsn; (i != NULL) && (opcode == NULL); i = i->next)
	{
	  const char *errmsg = NULL;

	  opcode = arcExtMap_genOpcode (i, isa_mask, &errmsg);
	  if (opcode == NULL)
	    {
	      info->fprintf_func
		(info->stream,
		 _("An error occurred while generating "
		   "the extension instruction operations"));
	      *opcode_result = NULL;
	      return false;
	    }

	  opcode = find_format_from_table (info, opcode, insn, *insn_len,
					   isa_mask, &needs_limm, false);
	}
    }

  /* Then, try finding the first match in the opcode table.  */
  if (opcode == NULL)
    opcode = find_format_from_table (info, arc_opcodes, insn, *insn_len,
				     isa_mask, &needs_limm, true);

  if (opcode != NULL && needs_limm)
    {
      bfd_byte buffer[4];
      int status;

      status = (*info->read_memory_func) (memaddr + *insn_len, buffer,
                                          4, info);
      if (status != 0)
        {
          opcode = NULL;
        }
      else
        {
          limm = ARRANGE_ENDIAN (info, buffer);
          *insn_len += 4;
        }
    }

  if (opcode != NULL)
    {
      iter->insn = insn;
      iter->limm = limm;
      iter->opcode = opcode;
      iter->opidx = opcode->operands;
    }

  *opcode_result = opcode;

  /* Update private data.  */
  arc_infop->opcode = opcode;
  arc_infop->limm = limm;
  arc_infop->limm_p = needs_limm;

  return true;
}

static void
print_flags (const struct arc_opcode *opcode,
	     unsigned long long *insn,
	     struct disassemble_info *info)
{
  const unsigned char *flgidx;
  unsigned int value;
  struct arc_disassemble_info *arc_infop = info->private_data;

  /* Now extract and print the flags.  */
  for (flgidx = opcode->flags; *flgidx; flgidx++)
    {
      /* Get a valid flag class.  */
      const struct arc_flag_class *cl_flags = &arc_flag_classes[*flgidx];
      const unsigned *flgopridx;

      /* Check first the extensions.  */
      if (cl_flags->flag_class & F_CLASS_EXTEND)
	{
	  const char *name;
	  value = (insn[0] & 0x1F);

	  name = arcExtMap_condCodeName (value);
	  if (name)
	    {
	      info->fprintf_func (info->stream,
					    ".%s", name);
	      continue;
	    }
	}

      for (flgopridx = cl_flags->flags; *flgopridx; ++flgopridx)
	{
	  const struct arc_flag_operand *flg_operand =
	    &arc_flag_operands[*flgopridx];

	  /* Implicit flags are only used for the insn decoder.  */
	  if (cl_flags->flag_class & F_CLASS_IMPLICIT)
	    {
	      if (cl_flags->flag_class & F_CLASS_COND)
		arc_infop->condition_code = flg_operand->code;
	      else if (cl_flags->flag_class & F_CLASS_WB)
		arc_infop->writeback_mode = flg_operand->code;
	      else if (cl_flags->flag_class & F_CLASS_ZZ)
		info->data_size = flg_operand->code;
	      continue;
	    }

	  if (!flg_operand->favail)
	    continue;

	  value = (insn[0] >> flg_operand->shift)
	    & ((1 << flg_operand->bits) - 1);
	  if (value == flg_operand->code)
	    {
	       /* FIXME!: print correctly nt/t flag.  */
	      if (!special_flag_p (opcode->name, flg_operand->name))
		info->fprintf_func (info->stream, ".");
	      else if (info->insn_type == dis_dref)
		{
		  switch (flg_operand->name[0])
		    {
		    case 'b':
		      info->data_size = 1;
		      break;
		    case 'h':
		    case 'w':
		      info->data_size = 2;
		      break;
		    default:
		      info->data_size = 4;
		      break;
		    }
		}
	      if (flg_operand->name[0] == 'd'
		  && flg_operand->name[1] == 0)
		info->branch_delay_insns = 1;

	      /* Check if it is a conditional flag.  */
	      if (cl_flags->flag_class & F_CLASS_COND)
		{
		  if (info->insn_type == dis_jsr)
		    info->insn_type = dis_condjsr;
		  else if (info->insn_type == dis_branch)
		    info->insn_type = dis_condbranch;
		  arc_infop->condition_code = flg_operand->code;
		}

	      /* Check for the write back modes.  */
	      if (cl_flags->flag_class & F_CLASS_WB)
		arc_infop->writeback_mode = flg_operand->code;

	      info->fprintf_func (info->stream,
					    "%s", flg_operand->name);
	    }
	}
    }
}

static const char *
get_auxreg (const struct arc_opcode *opcode,
	    int value,
	    unsigned isa_mask)
{
  const char *name;
  unsigned int i;
  const struct arc_aux_reg *auxr = &arc_aux_regs[0];

  if (opcode->insn_class != AUXREG)
    return NULL;

  name = arcExtMap_auxRegName (value);
  if (name)
    return name;

  for (i = 0; i < arc_num_aux_regs; i++, auxr++)
    {
      if (!(auxr->cpu & isa_mask))
	continue;

      if (auxr->subclass != NONE)
	return NULL;

      if (auxr->address == value)
	return auxr->name;
    }
  return NULL;
}

/* Convert a value representing an address type to a string used to refer to
   the address type in assembly code.  */

static const char *
get_addrtype (unsigned int value)
{
  if (value >= ARC_NUM_ADDRTYPES)
    return "unknown";

  return addrtypenames[value];
}

/* Calculate the instruction length for an instruction starting with MSB
   and LSB, the most and least significant byte.  The ISA_MASK is used to
   filter the instructions considered to only those that are part of the
   current architecture.

   The instruction lengths are calculated from the ARC_OPCODE table, and
   cached for later use.  */

static unsigned int
arc_insn_length (bfd_byte msb, bfd_byte lsb, struct disassemble_info *info)
{
  bfd_byte major_opcode = msb >> 3;

  switch (info->mach)
    {
    case bfd_mach_arc_arc700:
      /* The nps400 extension set requires this special casing of the
	 instruction length calculation.  Right now this is not causing any
	 problems as none of the known extensions overlap in opcode space,
	 but, if they ever do then we might need to start carrying
	 information around in the elf about which extensions are in use.  */
      if (major_opcode == 0xb)
        {
          bfd_byte minor_opcode = lsb & 0x1f;

	  if (minor_opcode < 4)
	    return 6;
	  else if (minor_opcode == 0x10 || minor_opcode == 0x11)
	    return 8;
        }
      if (major_opcode == 0xa)
        {
          return 8;
        }
      /* Fall through.  */
    case bfd_mach_arc_arc600:
      return (major_opcode > 0xb) ? 2 : 4;
      break;

    case bfd_mach_arc_arcv2:
      return (major_opcode > 0x7) ? 2 : 4;
      break;

    default:
      return 0;
    }
}

/* Extract and return the value of OPERAND from the instruction whose value
   is held in the array INSN.  */

static int
extract_operand_value (const struct arc_operand *operand,
		       unsigned long long insn,
		       unsigned limm)
{
  int value;

  /* Read the limm operand, if required.  */
  if (operand->flags & ARC_OPERAND_LIMM)
    /* The second part of the instruction value will have been loaded as
       part of the find_format call made earlier.  */
    value = limm;
  else
    {
      if (operand->extract)
	value = (*operand->extract) (insn, (bool *) NULL);
      else
        {
          if (operand->flags & ARC_OPERAND_ALIGNED32)
            {
              value = (insn >> operand->shift)
                & ((1 << (operand->bits - 2)) - 1);
              value = value << 2;
            }
          else
            {
              value = (insn >> operand->shift) & ((1 << operand->bits) - 1);
            }
          if (operand->flags & ARC_OPERAND_SIGNED)
            {
              int signbit = 1 << (operand->bits - 1);
              value = (value ^ signbit) - signbit;
            }
        }
    }

  return value;
}

/* Find the next operand, and the operands value from ITER.  Return TRUE if
   there is another operand, otherwise return FALSE.  If there is an
   operand returned then the operand is placed into OPERAND, and the value
   into VALUE.  If there is no operand returned then OPERAND and VALUE are
   unchanged.  */

static bool
operand_iterator_next (struct arc_operand_iterator *iter,
                       const struct arc_operand **operand,
                       int *value)
{
  if (*iter->opidx == 0)
    {
      *operand = NULL;
      return false;
    }

  *operand = &arc_operands[*iter->opidx];
  *value = extract_operand_value (*operand, iter->insn, iter->limm);
  iter->opidx++;

  return true;
}

/* Helper for parsing the options.  */

#if 0
static void
parse_option (struct arc_disassemble_info *arc_infop, const char *option)
{
  if (strcmp (option, "dsp") == 0)
    add_to_decode (arc_infop, DSP, NONE);

  else if (strcmp (option, "spfp") == 0)
    add_to_decode (arc_infop, FLOAT, SPX);

  else if (strcmp (option, "dpfp") == 0)
    add_to_decode (arc_infop, FLOAT, DPX);

  else if (strcmp (option, "quarkse_em") == 0)
    {
      add_to_decode (arc_infop, FLOAT, DPX);
      add_to_decode (arc_infop, FLOAT, SPX);
      add_to_decode (arc_infop, FLOAT, QUARKSE1);
      add_to_decode (arc_infop, FLOAT, QUARKSE2);
    }

  else if (strcmp (option, "fpuda") == 0)
    add_to_decode (arc_infop, FLOAT, DPA);

  else if (strcmp (option, "nps400") == 0)
    {
      add_to_decode (arc_infop, ACL, NPS400);
      add_to_decode (arc_infop, ARITH, NPS400);
      add_to_decode (arc_infop, BITOP, NPS400);
      add_to_decode (arc_infop, BMU, NPS400);
      add_to_decode (arc_infop, CONTROL, NPS400);
      add_to_decode (arc_infop, DMA, NPS400);
      add_to_decode (arc_infop, DPI, NPS400);
      add_to_decode (arc_infop, MEMORY, NPS400);
      add_to_decode (arc_infop, MISC, NPS400);
      add_to_decode (arc_infop, NET, NPS400);
      add_to_decode (arc_infop, PMU, NPS400);
      add_to_decode (arc_infop, PROTOCOL_DECODE, NPS400);
      add_to_decode (arc_infop, ULTRAIP, NPS400);
    }

  else if (strcmp (option, "fpus") == 0)
    {
      add_to_decode (arc_infop, FLOAT, SP);
      add_to_decode (arc_infop, FLOAT, CVT);
    }

  else if (strcmp (option, "fpud") == 0)
    {
      add_to_decode (arc_infop, FLOAT, DP);
      add_to_decode (arc_infop, FLOAT, CVT);
    }
  else if (startswith (option, "hex"))
    arc_infop->print_hex = true;
  else
    /* xgettext:c-format */
    opcodes_error_handler (_("unrecognised disassembler option: %s"), option);
}
#endif

#define ARC_CPU_TYPE_A6xx(NAME,EXTRA)			\
  { #NAME, ARC_OPCODE_ARC600, "ARC600" }
#define ARC_CPU_TYPE_A7xx(NAME,EXTRA)			\
  { #NAME, ARC_OPCODE_ARC700, "ARC700" }
#define ARC_CPU_TYPE_AV2EM(NAME,EXTRA)			\
  { #NAME,  ARC_OPCODE_ARCv2EM, "ARC EM" }
#define ARC_CPU_TYPE_AV2HS(NAME,EXTRA)			\
  { #NAME,  ARC_OPCODE_ARCv2HS, "ARC HS" }
#define ARC_CPU_TYPE_NONE				\
  { 0, 0, 0 }

/* A table of CPU names and opcode sets.  */
static const struct cpu_type
{
  const char *name;
  unsigned flags;
  const char *isa;
}
  cpu_types[] =
{
  #include "./arc-cpu.def"
};

/* Helper for parsing the CPU options.  Accept any of the ARC architectures
   values.  OPTION should be a value passed to cpu=.  */

static unsigned
parse_cpu_option (const char *option)
{
  int i;

  for (i = 0; cpu_types[i].name; ++i)
    if (strcmp (cpu_types[i].name, option) == 0)
      return cpu_types[i].flags;

  /* xgettext:c-format */
  opcodes_error_handler (_("unrecognised disassembler CPU option: %s"), option);
  return ARC_OPCODE_NONE;
}

#if 0 /* Disabled for radare2 - unused function */
static bool
arc_parse_option (const char *option, void *data)
{
  struct arc_disassemble_info *arc_infop = data;

  if (strncmp (option, "cpu=", 4) == 0)
    /* Strip leading `cpu=`.  */
    arc_infop->isa_mask = parse_cpu_option (option + 4);
  else
    parse_option (arc_infop, option);
  return true;
}
#endif

/* Go over the options list and parse it.  */

static void
parse_disassembler_options (struct disassemble_info *info)
{
  struct arc_disassemble_info *arc_infop = info->private_data;

  arc_infop->isa_mask = ARC_OPCODE_NONE;

  /* TODO: parse disassembler options */
  // for_each_disassembler_option (info, arc_parse_option, arc_infop);

  /* Figure out CPU type, unless it was enforced via disassembler options.  */
  if (arc_infop->isa_mask == ARC_OPCODE_NONE)
    {
      switch (info->mach)
	{
	case bfd_mach_arc_arc700:
	  arc_infop->isa_mask = ARC_OPCODE_ARC700;
	  break;

	case bfd_mach_arc_arc600:
	  arc_infop->isa_mask = ARC_OPCODE_ARC600;
	  break;

	case bfd_mach_arc_arcv2:
	default:
	  {
	    Elf_Internal_Ehdr *header = NULL;

	    if (info->section && info->section->owner)
	      header = elf_elfheader (info->section->owner);
	    arc_infop->isa_mask = ARC_OPCODE_ARCv2EM;
	    if (header != NULL
		&& (header->e_flags & EF_ARC_MACH_MSK) == EF_ARC_CPU_ARCV2HS)
	      arc_infop->isa_mask = ARC_OPCODE_ARCv2HS;
	  }
	  break;
	}
    }

  if (arc_infop->isa_mask == ARC_OPCODE_ARCv2HS)
    {
      /* FPU instructions are not extensions for HS.  */
      add_to_decode (arc_infop, FLOAT, SP);
      add_to_decode (arc_infop, FLOAT, DP);
      add_to_decode (arc_infop, FLOAT, CVT);
    }
}

/* Return the instruction type for an instruction described by OPCODE.  */

static enum dis_insn_type
arc_opcode_to_insn_type (const struct arc_opcode *opcode)
{
  enum dis_insn_type insn_type;

  switch (opcode->insn_class)
    {
    case BRANCH:
    case BBIT0:
    case BBIT1:
    case BI:
    case BIH:
    case BRCC:
    case DBNZ:
    case EI:
    case JLI:
    case JUMP:
    case LOOP:
      if (!strncmp (opcode->name, "bl", 2)
	  || !strncmp (opcode->name, "jl", 2))
	{
	  if (opcode->subclass == COND)
	    insn_type = dis_condjsr;
	  else
	    insn_type = dis_jsr;
	}
      else
	{
	  if (opcode->subclass == COND)
	    insn_type = dis_condbranch;
	  else
	    insn_type = dis_branch;
	}
      break;
    case LOAD:
    case STORE:
    case MEMORY:
    case ENTER:
    case PUSH:
    case POP:
      insn_type = dis_dref;
      break;
    case LEAVE:
      insn_type = dis_branch;
      break;
    default:
      insn_type = dis_nonbranch;
      break;
    }

  return insn_type;
}

/* Disassemble ARC instructions.  */

static int
print_insn_arc (bfd_vma memaddr,
		struct disassemble_info *info)
{
  bfd_byte buffer[8];
  unsigned int highbyte, lowbyte;
  int status;
  unsigned int insn_len;
  unsigned long long insn = 0;
  const struct arc_opcode *opcode;
  bool need_comma;
  bool open_braket;
  int size;
  const struct arc_operand *operand;
  int value, vpcl;
  struct arc_operand_iterator iter;
  struct arc_disassemble_info *arc_infop;
  bool rpcl = false, rset = false;

  if (info->private_data == NULL)
    {
      if (!init_arc_disasm_info (info))
	return -1;

      parse_disassembler_options (info);
    }

  memset (&iter, 0, sizeof (iter));
  highbyte = info->endian == BFD_ENDIAN_LITTLE ? 1 : 0;
  lowbyte = info->endian == BFD_ENDIAN_LITTLE ? 0 : 1;

  /* This variable may be set by the instruction decoder.  It suggests
     the number of bytes objdump should display on a single line.  If
     the instruction decoder sets this, it should always set it to
     the same value in order to get reasonable looking output.  */
  info->bytes_per_line  = 8;

  /* In the next lines, we set two info variables control the way
     objdump displays the raw data.  For example, if bytes_per_line is
     8 and bytes_per_chunk is 4, the output will look like this:
     00:   00000000 00000000
     with the chunks displayed according to "display_endian".  */
  if (info->section
      && !(info->section->flags & SEC_CODE))
    {
      /* This is not a CODE section.  */
      switch (info->section->size)
	{
	case 1:
	case 2:
	case 4:
	  size = info->section->size;
	  break;
	default:
	  size = (info->section->size & 0x01) ? 1 : 4;
	  break;
	}
      info->bytes_per_chunk = 1;
      info->display_endian = info->endian;
    }
  else
    {
      size = 2;
      info->bytes_per_chunk = 2;
      info->display_endian = info->endian;
    }

  /* Read the insn into a host word.  */
  status = (*info->read_memory_func) (memaddr, buffer, size, info);

  if (status != 0)
    {
      (*info->memory_error_func) (status, memaddr, info);
      return -1;
    }

  if (info->section
      && !(info->section->flags & SEC_CODE))
    {
      /* Data section.  */
      unsigned long data;

      data = bfd_get_bits (buffer, size * 8,
			   info->display_endian == BFD_ENDIAN_BIG);
      switch (size)
	{
	case 1:
	  info->fprintf_func (info->stream, ".byte");
	  info->fprintf_func (info->stream, "\t");
	  info->fprintf_func (info->stream, "0x%02lx", data);
	  break;
	case 2:
	  info->fprintf_func (info->stream, ".short");
	  info->fprintf_func (info->stream, "\t");
	  info->fprintf_func (info->stream, "0x%04lx", data);
	  break;
	case 4:
	  info->fprintf_func (info->stream, ".word");
	  info->fprintf_func (info->stream, "\t");
	  info->fprintf_func (info->stream, "0x%08lx", data);
	  break;
	default:
	  return -1;
	}
      return size;
    }

  insn_len = arc_insn_length (buffer[highbyte], buffer[lowbyte], info);
  pr_debug ("instruction length = %d bytes\n", insn_len);
  if (insn_len == 0)
    return -1;

  arc_infop = info->private_data;
  arc_infop->insn_len = insn_len;

  switch (insn_len)
    {
    case 2:
      insn = (buffer[highbyte] << 8) | buffer[lowbyte];
      break;

    case 4:
      {
	/* This is a long instruction: Read the remaning 2 bytes.  */
	status = (*info->read_memory_func) (memaddr + 2, &buffer[2], 2, info);
	if (status != 0)
	  {
	    (*info->memory_error_func) (status, memaddr + 2, info);
	    return -1;
	  }
	insn = (unsigned long long) ARRANGE_ENDIAN (info, buffer);
      }
      break;

    case 6:
      {
	status = (*info->read_memory_func) (memaddr + 2, &buffer[2], 4, info);
	if (status != 0)
	  {
	    (*info->memory_error_func) (status, memaddr + 2, info);
	    return -1;
	  }
	insn = (unsigned long long) ARRANGE_ENDIAN (info, &buffer[2]);
	insn |= ((unsigned long long) buffer[highbyte] << 40)
	  | ((unsigned long long) buffer[lowbyte] << 32);
      }
      break;

    case 8:
      {
	status = (*info->read_memory_func) (memaddr + 2, &buffer[2], 6, info);
	if (status != 0)
	  {
	    (*info->memory_error_func) (status, memaddr + 2, info);
	    return -1;
	  }
	insn =
	  ((((unsigned long long) ARRANGE_ENDIAN (info, buffer)) << 32)
	   | ((unsigned long long) ARRANGE_ENDIAN (info, &buffer[4])));
      }
      break;

    default:
      /* There is no instruction whose length is not 2, 4, 6, or 8.  */
      return -1;
    }

  pr_debug ("instruction value = %llx\n", insn);

  /* Set some defaults for the insn info.  */
  info->insn_info_valid    = 1;
  info->branch_delay_insns = 0;
  info->data_size	   = 4;
  info->insn_type	   = dis_nonbranch;
  info->target		   = 0;
  info->target2		   = 0;

  /* FIXME to be moved in dissasemble_init_for_target.  */
  info->disassembler_needs_relocs = true;

  /* Find the first match in the opcode table.  */
  if (!find_format (memaddr, insn, &insn_len, arc_infop->isa_mask, info,
		    &opcode, &iter))
    return -1;

  if (!opcode)
    {
      switch (insn_len)
	{
	case 2:
	  info->fprintf_func (info->stream, ".short");
	  info->fprintf_func (info->stream, "\t");
	  info->fprintf_func (info->stream, "0x%04llx", insn & 0xffff);
	  break;

	case 4:
	  info->fprintf_func (info->stream, ".word");
	  info->fprintf_func (info->stream, "\t");
	  info->fprintf_func (info->stream, "0x%08llx", insn & 0xffffffff);
	  break;

	case 6:
	  info->fprintf_func (info->stream, ".long");
	  info->fprintf_func (info->stream, "\t");
	  info->fprintf_func (info->stream, "0x%08llx", insn & 0xffffffff);
	  info->fprintf_func (info->stream, " ");
	  info->fprintf_func (info->stream, "0x%04llx", (insn >> 32) & 0xffff);
	  break;

	case 8:
	  info->fprintf_func (info->stream, ".long");
	  info->fprintf_func (info->stream, "\t");
	  info->fprintf_func (info->stream, "0x%08llx", insn & 0xffffffff);
	  info->fprintf_func (info->stream, " ");
	  info->fprintf_func (info->stream, "0x%08llx", (insn >> 32));
	  break;

	default:
	  return -1;
	}

      info->insn_type = dis_noninsn;
      return insn_len;
    }

  /* Print the mnemonic.  */
  info->fprintf_func (info->stream,
				"%s", opcode->name);

  /* Preselect the insn class.  */
  info->insn_type = arc_opcode_to_insn_type (opcode);

  pr_debug ("%s: 0x%08llx\n", opcode->name, opcode->opcode);

  print_flags (opcode, &insn, info);

  if (opcode->operands[0] != 0)
    info->fprintf_func (info->stream, "\t");

  need_comma = false;
  open_braket = false;
  arc_infop->operands_count = 0;

  /* Now extract and print the operands.  */
  operand = NULL;
  vpcl = 0;
  while (operand_iterator_next (&iter, &operand, &value))
    {
      if (open_braket && (operand->flags & ARC_OPERAND_BRAKET))
	{
	  info->fprintf_func (info->stream, "]");
	  open_braket = false;
	  continue;
	}

      /* Only take input from real operands.  */
      if (ARC_OPERAND_IS_FAKE (operand))
	continue;

      if ((operand->flags & ARC_OPERAND_IGNORE)
	  && (operand->flags & ARC_OPERAND_IR)
	  && value == -1)
	continue;

      if (operand->flags & ARC_OPERAND_COLON)
	{
	  info->fprintf_func (info->stream, ":");
	  continue;
	}

      if (need_comma)
	info->fprintf_func (info->stream,",");

      if (!open_braket && (operand->flags & ARC_OPERAND_BRAKET))
	{
	  info->fprintf_func (info->stream, "[");
	  open_braket = true;
	  need_comma = false;
	  continue;
	}

      need_comma = true;

      if (operand->flags & ARC_OPERAND_PCREL)
	{
	  rpcl = true;
	  vpcl = value;
	  rset = true;

	  info->target = (bfd_vma) (memaddr & ~3) + value;
	}
      else if (!(operand->flags & ARC_OPERAND_IR))
	{
	  vpcl = value;
	  rset = true;
	}

      /* Print the operand as directed by the flags.  */
      if (operand->flags & ARC_OPERAND_IR)
	{
	  const char *rname;

	  assert (value >=0 && value < 64);
	  rname = arcExtMap_coreRegName (value);
	  if (!rname)
	    rname = regnames[value];
	  info->fprintf_func (info->stream,
					"%s", rname);

	  /* Check if we have a double register to print.  */
	  if (operand->flags & ARC_OPERAND_TRUNCATE)
	    {
	      if ((value & 0x01) == 0)
		{
		  rname = arcExtMap_coreRegName (value + 1);
		  if (!rname)
		    rname = regnames[value + 1];
		}
	      else
		rname = _("\nWarning: illegal use of double register "
			  "pair.\n");
	      info->fprintf_func (info->stream,
					    "%s", rname);
	    }
	  if (value == 63)
	    rpcl = true;
	  else
	    rpcl = false;
	}
      else if (operand->flags & ARC_OPERAND_LIMM)
	{
	  const char *rname = get_auxreg (opcode, value, arc_infop->isa_mask);

	  if (rname && open_braket)
	    info->fprintf_func (info->stream,
					  "%s", rname);
	  else
	    {
	      info->fprintf_func (info->stream,
					    "%#x", value);
	      if (info->insn_type == dis_branch
		  || info->insn_type == dis_jsr)
		info->target = (bfd_vma) value;
	    }
	}
      else if (operand->flags & ARC_OPERAND_SIGNED)
	{
	  const char *rname = get_auxreg (opcode, value, arc_infop->isa_mask);
	  if (rname && open_braket)
	    info->fprintf_func (info->stream,
					  "%s", rname);
	  else
	    {
	      if (arc_infop->print_hex)
		info->fprintf_func (info->stream,
					      "%#x", value);
	      else
		info->fprintf_func (info->stream,
					      "%d", value);
	    }
	}
      else if (operand->flags & ARC_OPERAND_ADDRTYPE)
	{
	  const char *addrtype = get_addrtype (value);
	  info->fprintf_func (info->stream,
					"%s", addrtype);
	  /* A colon follow an address type.  */
	  need_comma = false;
	}
      else
	{
	  if (operand->flags & ARC_OPERAND_TRUNCATE
	      && !(operand->flags & ARC_OPERAND_ALIGNED32)
	      && !(operand->flags & ARC_OPERAND_ALIGNED16)
	      && value >= 0 && value <= 14)
	    {
	      /* Leave/Enter mnemonics.  */
	      switch (value)
		{
		case 0:
		  need_comma = false;
		  break;
		case 1:
		  info->fprintf_func (info->stream, "r13");
		  break;
		default:
		  info->fprintf_func (info->stream, "r13");
		  info->fprintf_func (info->stream, "-");
		  info->fprintf_func (info->stream, "%s",
						regnames[13 + value - 1]);
		  break;
		}
	      rpcl = false;
	      rset = false;
	    }
	  else
	    {
	      const char *rname = get_auxreg (opcode, value,
					      arc_infop->isa_mask);
	      if (rname && open_braket)
		info->fprintf_func (info->stream,
					      "%s", rname);
	      else
		info->fprintf_func (info->stream,
					      "%#x", value);
	    }
	}

      if (operand->flags & ARC_OPERAND_LIMM)
	{
	  arc_infop->operands[arc_infop->operands_count].kind
	    = ARC_OPERAND_KIND_LIMM;
	  /* It is not important to have exactly the LIMM indicator
	     here.  */
	  arc_infop->operands[arc_infop->operands_count].value = 63;
	}
      else
	{
	  arc_infop->operands[arc_infop->operands_count].value = value;
	  arc_infop->operands[arc_infop->operands_count].kind
	    = (operand->flags & ARC_OPERAND_IR
	       ? ARC_OPERAND_KIND_REG
	       : ARC_OPERAND_KIND_SHIMM);
	}
      arc_infop->operands_count ++;
    }

  /* Pretty print extra info for pc-relative operands.  */
  if (rpcl && rset)
    {
      if (info->flags & INSN_HAS_RELOC)
	/* If the instruction has a reloc associated with it, then the
	   offset field in the instruction will actually be the addend
	   for the reloc.  (We are using REL type relocs).  In such
	   cases, we can ignore the pc when computing addresses, since
	   the addend is not currently pc-relative.  */
	memaddr = 0;

      info->fprintf_func (info->stream, "\t;");
      (*info->print_address_func) ((memaddr & ~3) + vpcl, info);
    }

  return insn_len;
}


disassembler_ftype
arc_get_disassembler (bfd *abfd)
{
  /* BFD my be absent, if opcodes is invoked from the debugger that
     has connected to remote target and doesn't have an ELF file.  */
  if (abfd != NULL)
    {
      /* Read the extension insns and registers, if any.  */
      build_ARC_extmap (abfd);
#ifdef DEBUG
      dump_ARC_extmap ();
#endif
    }

  return print_insn_arc;
}

/* Indices into option argument vector for options that do require
   an argument.  Use ARC_OPTION_ARG_NONE for options that don't
   expect an argument.  */
typedef enum
{
  ARC_OPTION_ARG_NONE = -1,
  ARC_OPTION_ARG_ARCH,
  ARC_OPTION_ARG_SIZE
} arc_option_arg_t;

/* Valid ARC disassembler options.  */
#if 0 /* Disabled for radare2 - unused variable */
static struct
{
  const char *name;
  const char *description;
  arc_option_arg_t arg;
} arc_options[] =
{
  { "cpu=",       N_("Enforce the designated architecture while decoding."),
		  ARC_OPTION_ARG_ARCH },
  { "dsp",	  N_("Recognize DSP instructions."),
		  ARC_OPTION_ARG_NONE },
  { "spfp",	  N_("Recognize FPX SP instructions."),
		  ARC_OPTION_ARG_NONE },
  { "dpfp",	  N_("Recognize FPX DP instructions."),
		  ARC_OPTION_ARG_NONE },
  { "quarkse_em", N_("Recognize FPU QuarkSE-EM instructions."),
		  ARC_OPTION_ARG_NONE },
  { "fpuda",	  N_("Recognize double assist FPU instructions."),
		  ARC_OPTION_ARG_NONE },
  { "fpus",	  N_("Recognize single precision FPU instructions."),
		  ARC_OPTION_ARG_NONE },
  { "fpud",	  N_("Recognize double precision FPU instructions."),
		  ARC_OPTION_ARG_NONE },
  { "nps400",	  N_("Recognize NPS400 instructions."),
		  ARC_OPTION_ARG_NONE },
  { "hex",	  N_("Use only hexadecimal number to print immediates."),
		  ARC_OPTION_ARG_NONE }
};
#endif

/* Populate the structure for representing ARC's disassembly options.
   Such a dynamic initialization is desired, because it makes the maintenance
   easier and also gdb uses this to enable the "disassembler-option".  */

#if 0 /* Disabled for radare2 - uses binutils-specific types */
const disasm_options_and_args_t *
disassembler_options_arc (void)
{
  static disasm_options_and_args_t *opts_and_args;

  if (opts_and_args == NULL)
    {
      disasm_option_arg_t *args;
      disasm_options_t *opts;
      size_t i;
      const size_t nr_of_options = ARRAY_SIZE (arc_options);
      /* There is a null element at the end of CPU_TYPES, therefore
	 NR_OF_CPUS is actually 1 more and that is desired here too.  */
      const size_t nr_of_cpus = ARRAY_SIZE (cpu_types);

      opts_and_args = XNEW (disasm_options_and_args_t);
      opts_and_args->args
	= XNEWVEC (disasm_option_arg_t, ARC_OPTION_ARG_SIZE + 1);
      opts_and_args->options.name
	= XNEWVEC (const char *, nr_of_options + 1);
      opts_and_args->options.description
	= XNEWVEC (const char *, nr_of_options + 1);
      opts_and_args->options.arg
	= XNEWVEC (const disasm_option_arg_t *, nr_of_options + 1);

      /* Populate the arguments for "cpu=" option.  */
      args = opts_and_args->args;
      args[ARC_OPTION_ARG_ARCH].name = "ARCH";
      args[ARC_OPTION_ARG_ARCH].values = XNEWVEC (const char *, nr_of_cpus);
      for (i = 0; i < nr_of_cpus; ++i)
	args[ARC_OPTION_ARG_ARCH].values[i] = cpu_types[i].name;
      args[ARC_OPTION_ARG_SIZE].name = NULL;
      args[ARC_OPTION_ARG_SIZE].values = NULL;

      /* Populate the options.  */
      opts = &opts_and_args->options;
      for (i = 0; i < nr_of_options; ++i)
	{
	  opts->name[i] = arc_options[i].name;
	  opts->description[i] = arc_options[i].description;
	  if (arc_options[i].arg != ARC_OPTION_ARG_NONE)
	    opts->arg[i] = &args[arc_options[i].arg];
	  else
	    opts->arg[i] = NULL;
	}
      opts->name[nr_of_options] = NULL;
      opts->description[nr_of_options] = NULL;
      opts->arg[nr_of_options] = NULL;
    }

  return opts_and_args;
}


void
print_arc_disassembler_options (FILE *stream)
{
  const disasm_options_and_args_t *opts_and_args;
  const disasm_option_arg_t *args;
  const disasm_options_t *opts;
  size_t i, j;
  size_t max_len = 0;

  opts_and_args = disassembler_options_arc ();
  opts = &opts_and_args->options;
  args = opts_and_args->args;

  fprintf (stream, _("\nThe following ARC specific disassembler options are"
		     " supported for use \nwith the -M switch (multiple"
		     " options should be separated by commas):\n"));

  /* Find the maximum length for printing options (and their arg name).  */
  for (i = 0; opts->name[i] != NULL; ++i)
    {
      size_t len = strlen (opts->name[i]);
      len += (opts->arg[i]) ? strlen (opts->arg[i]->name) : 0;
      max_len = (len > max_len) ? len : max_len;
    }

  /* Print the options, their arg and description, if any.  */
  for (i = 0, ++max_len; opts->name[i] != NULL; ++i)
    {
      fprintf (stream, "  %s", opts->name[i]);
      if (opts->arg[i] != NULL)
	fprintf (stream, "%s", opts->arg[i]->name);
      if (opts->description[i] != NULL)
	{
	  size_t len = strlen (opts->name[i]);
	  len += (opts->arg[i]) ? strlen (opts->arg[i]->name) : 0;
	  fprintf (stream,
		   "%*c %s", (int) (max_len - len), ' ', opts->description[i]);
	}
      fprintf (stream, _("\n"));
    }

  /* Print the possible values of an argument.  */
  for (i = 0; args[i].name != NULL; ++i)
    {
      size_t len = 3;
      if (args[i].values == NULL)
	continue;
      fprintf (stream, _("\n\
  For the options above, the following values are supported for \"%s\":\n   "),
	       args[i].name);
      for (j = 0; args[i].values[j] != NULL; ++j)
	{
	  fprintf (stream, " %s", args[i].values[j]);
	  len += strlen (args[i].values[j]) + 1;
	  /* reset line if printed too long.  */
	  if (len >= 78)
	    {
	      fprintf (stream, _("\n   "));
	      len = 3;
	    }
	}
      fprintf (stream, _("\n"));
    }

  fprintf (stream, _("\n"));
}
#endif /* Disabled for radare2 */

void arc_insn_decode (bfd_vma addr,
		      struct disassemble_info *info,
		      disassembler_ftype disasm_func,
		      struct arc_instruction *insn)
{
  const struct arc_opcode *opcode;
  struct arc_disassemble_info *arc_infop;

  /* Ensure that insn would be in the reset state.  */
  memset (insn, 0, sizeof (struct arc_instruction));

  /* There was an error when disassembling, for example memory read error.  */
  if (disasm_func (addr, info) < 0)
    {
      insn->valid = false;
      return;
    }

  assert (info->private_data != NULL);
  arc_infop = info->private_data;

  insn->length  = arc_infop->insn_len;;
  insn->address = addr;

  /* Quick exit if memory at this address is not an instruction.  */
  if (info->insn_type == dis_noninsn)
    {
      insn->valid = false;
      return;
    }

  insn->valid = true;

  opcode = (const struct arc_opcode *) arc_infop->opcode;
  insn->insn_class = opcode->insn_class;
  insn->limm_value = arc_infop->limm;
  insn->limm_p     = arc_infop->limm_p;

  insn->is_control_flow = (info->insn_type == dis_branch
			   || info->insn_type == dis_condbranch
			   || info->insn_type == dis_jsr
			   || info->insn_type == dis_condjsr);

  insn->has_delay_slot = info->branch_delay_insns;
  insn->writeback_mode
    = (enum arc_ldst_writeback_mode) arc_infop->writeback_mode;
  insn->data_size_mode = info->data_size;
  insn->condition_code = arc_infop->condition_code;
  memcpy (insn->operands, arc_infop->operands,
	  sizeof (struct arc_insn_operand) * MAX_INSN_ARGS);
  insn->operands_count = arc_infop->operands_count;
}

/* Compatibility wrapper for ARCTangent_decodeInstr (legacy A4 support) */
int
ARCTangent_decodeInstr (bfd_vma address, struct disassemble_info *info)
{
  /* Use the modern ARC disassembler for all architectures */
  return print_insn_arc (address, info);
}

/* Local variables:
   eval: (c-set-style "gnu")
   indent-tabs-mode: t
   End:  */
