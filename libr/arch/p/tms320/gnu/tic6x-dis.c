/* TI C6X disassembler.
   Copyright (C) 2010-2025 Free Software Foundation, Inc.
   Contributed by Joseph Myers <joseph@codesourcery.com>
   		  Bernd Schmidt  <bernds@codesourcery.com>

   This file is part of libopcodes.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "../../include/disas-asm.h"
// #include "disassemble.h"
#include "tic6x.h"
// #include "libiberty.h"

/* Define the instruction format table.  */
const tic6x_insn_format tic6x_insn_format_table[tic6x_insn_format_max] =
  {
#define FMT(name, num_bits, cst_bits, mask, fields) \
    { num_bits, cst_bits, mask, fields },
#include "opcode/tic6x-insn-formats.h"
#undef FMT
  };

/* Define the control register table.  */
const tic6x_ctrl tic6x_ctrl_table[tic6x_ctrl_max] =
  {
#define CTRL(name, isa, rw, crlo, crhi_mask)	\
    {						\
      STRINGX(name),				\
      CONCAT2(TIC6X_INSN_,isa),			\
      CONCAT2(tic6x_rw_,rw),			\
      crlo,					\
      crhi_mask					\
    },
#include "opcode/tic6x-control-registers.h"
#undef CTRL
  };

/* Define the opcode table.  */
const tic6x_opcode tic6x_opcode_table[tic6x_opcode_max] =
  {
#define INSNU(name, func_unit, format, type, isa, flags, fixed, ops, var) \
    {									\
      STRINGX(name),							\
      CONCAT2(tic6x_func_unit_,func_unit),				\
      CONCAT3(tic6x_insn_format,_,format),	      			\
      CONCAT2(tic6x_pipeline_,type),					\
      CONCAT2(TIC6X_INSN_,isa),						\
      flags,								\
      fixed,								\
      ops,								\
      var								\
    },
#define INSNUE(name, e, func_unit, format, type, isa, flags, fixed, ops, var) \
    {									\
      STRINGX(name),							\
      CONCAT2(tic6x_func_unit_,func_unit),				\
      CONCAT3(tic6x_insn_format,_,format),	      			\
      CONCAT2(tic6x_pipeline_,type),					\
      CONCAT2(TIC6X_INSN_,isa),						\
      flags,								\
      fixed,								\
      ops,								\
      var								\
    },
#define INSN(name, func_unit, format, type, isa, flags, fixed, ops, var) \
    {									\
      STRINGX(name),							\
      CONCAT2(tic6x_func_unit_,func_unit),				\
      CONCAT4(tic6x_insn_format_,func_unit,_,format),			\
      CONCAT2(tic6x_pipeline_,type),					\
      CONCAT2(TIC6X_INSN_,isa),						\
      flags,								\
      fixed,								\
      ops,								\
      var								\
    },
#define INSNE(name, e, func_unit, format, type, isa, flags, fixed, ops, var) \
    {									\
      STRINGX(name),							\
      CONCAT2(tic6x_func_unit_,func_unit),				\
      CONCAT4(tic6x_insn_format_,func_unit,_,format),			\
      CONCAT2(tic6x_pipeline_,type),					\
      CONCAT2(TIC6X_INSN_,isa),						\
      flags,								\
      fixed,								\
      ops,								\
      var								\
    },
#include "opcode/tic6x-opcode-table.h"
#undef INSN
#undef INSNE
#undef INSNU
#undef INSNUE
  };

/* If instruction format FMT has a field FIELD, return a pointer to
   the description of that field; otherwise return NULL.  */

const tic6x_insn_field *
tic6x_field_from_fmt (const tic6x_insn_format *fmt, tic6x_insn_field_id field)
{
  unsigned int f;

  for (f = 0; f < fmt->num_fields; f++)
    if (fmt->fields[f].field_id == field)
      return &fmt->fields[f];

  return NULL;
}

/* Extract the field width.  */

static unsigned int
tic6x_field_width (const tic6x_insn_field *field)
{
  unsigned int i;
  unsigned int width = 0;

  if (!field->num_bitfields)
    return field->bitfields[0].width;

  for (i = 0 ; i < field->num_bitfields ; i++)
    width += field->bitfields[i].width;

  return width;
}

/* Extract the bits corresponding to FIELD from OPCODE.  */

static unsigned int
tic6x_field_bits (unsigned int opcode, const tic6x_insn_field *field)
{
  unsigned int i;
  unsigned int val = 0;

  if (!field->num_bitfields)
    return (opcode >> field->bitfields[0].low_pos) & ((1u << field->bitfields[0].width) - 1);

  for (i = 0 ; i < field->num_bitfields ; i++)
    val |= ((opcode >> field->bitfields[i].low_pos) & ((1u << field->bitfields[i].width) - 1))
      << field->bitfields[i].pos;

  return val;
}

/* Extract a 32-bit value read from the instruction stream.  */

static unsigned int
tic6x_extract_32 (unsigned char *p, struct disassemble_info *info)
{
  if (info->endian == BFD_ENDIAN_LITTLE)
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned) p[3] << 24);
  else
    return p[3] | (p[2] << 8) | (p[1] << 16) | ((unsigned) p[0] << 24);
}

/* Extract a 16-bit value read from the instruction stream.  */

static unsigned int
tic6x_extract_16 (unsigned char *p, tic6x_fetch_packet_header *header,
                  struct disassemble_info *info)
{
  unsigned int op16;

  if (info->endian == BFD_ENDIAN_LITTLE)
    op16 = (p[0]) | (p[1] << 8);
  else
    op16 = (p[1]) | (p[0] << 8);
  op16 |= (header->sat << TIC6X_COMPACT_SAT_POS);
  op16 |= (header->br << TIC6X_COMPACT_BR_POS);
  op16 |= (header->dsz << TIC6X_COMPACT_DSZ_POS);
  return op16;
}

/* FP points to a fetch packet.  Return whether it is header-based; if
   it is, fill in HEADER.  */

static bool
tic6x_check_fetch_packet_header (unsigned char *fp,
				 tic6x_fetch_packet_header *header,
				 struct disassemble_info *info)
{
  int i;

  header->header = tic6x_extract_32 (fp + 28, info);

  if ((header->header & 0xf0000000) != 0xe0000000)
    {
      header->prot = 0;
      header->rs = 0;
      header->dsz = 0;
      header->br = 0;
      header->sat = 0;
      for (i = 0; i < 7; i++)
	header->word_compact[i] = false;
      for (i = 0; i < 14; i++)
	header->p_bits[i] = false;
      return false;
    }

  for (i = 0; i < 7; i++)
    header->word_compact[i]
      = (header->header & (1u << (21 + i))) != 0;

  header->prot = (header->header & (1u << 20)) != 0;
  header->rs = (header->header & (1u << 19)) != 0;
  header->dsz = (header->header >> 16) & 0x7;
  header->br = (header->header & (1u << 15)) != 0;
  header->sat = (header->header & (1u << 14)) != 0;

  for (i = 0; i < 14; i++)
    header->p_bits[i] = (header->header & (1u << i)) != 0;

  return true;
}

/* Disassemble the instruction at ADDR and print it using
   INFO->FPRINTF_FUNC and INFO->STREAM, returning the number of bytes
   consumed.  */

int
print_insn_tic6x (bfd_vma addr, struct disassemble_info *info)
{
  int status;
  bfd_vma fp_addr;
  bfd_vma fp_offset;
  unsigned char fp[32];
  unsigned int opcode;
  tic6x_opcode_id opcode_id;
  bool fetch_packet_header_based;
  tic6x_fetch_packet_header header;
  unsigned int num_bits;
  bool bad_offset = false;

  fp_offset = addr & 0x1f;
  fp_addr = addr - fp_offset;
  /* Read in a block of instructions.  Since there might be a
     symbol in the middle of this block, disable stop_vma.  */
  info->stop_vma = 0;
  status = info->read_memory_func (fp_addr, fp, 32, info);
  if (status)
    {
      info->memory_error_func (status, addr, info);
      return -1;
    }

  fetch_packet_header_based
    = tic6x_check_fetch_packet_header (fp, &header, info);
  if (fetch_packet_header_based)
    {
      if (fp_offset & 0x1)
	bad_offset = true;
      if ((fp_offset & 0x3) && (fp_offset >= 28
				|| !header.word_compact[fp_offset >> 2]))
	bad_offset = true;
      if (fp_offset == 28)
	{
	  info->bytes_per_chunk = 4;
	  info->fprintf_func (info->stream, "<fetch packet header 0x%.8x>",
			      header.header);
	  return 4;
	}
      num_bits = (header.word_compact[fp_offset >> 2] ? 16 : 32);
    }
  else
    {
      num_bits = 32;
      if (fp_offset & 0x3)
	bad_offset = true;
    }

  if (bad_offset)
    {
      info->bytes_per_chunk = 1;
      info->fprintf_func (info->stream, ".byte 0x%.2x", fp[fp_offset]);
      return 1;
    }

  if (num_bits == 16)
    {
      /* The least-significant part of a 32-bit word comes logically
	 before the most-significant part.  For big-endian, follow the
	 TI assembler in showing instructions in logical order by
	 pretending that the two halves of the word are in opposite
	 locations to where they actually are.  */
      if (info->endian == BFD_ENDIAN_LITTLE)
	opcode = tic6x_extract_16 (fp + fp_offset, &header, info);
      else
	opcode = tic6x_extract_16 (fp + (fp_offset ^ 2), &header, info);
    }
  else
    opcode = tic6x_extract_32 (fp + fp_offset, info);

  for (opcode_id = 0; opcode_id < tic6x_opcode_max; opcode_id++)
    {
      const tic6x_opcode *const opc = &tic6x_opcode_table[opcode_id];
      const tic6x_insn_format *const fmt
	= &tic6x_insn_format_table[opc->format];
      const tic6x_insn_field *creg_field;
      bool p_bit;
      const char *parallel;
      const char *cond = "";
      const char *func_unit;
      char func_unit_buf[8];
      unsigned int func_unit_side = 0;
      unsigned int func_unit_data_side = 0;
      unsigned int func_unit_cross = 0;
      unsigned int t_val = 0;
      /* The maximum length of the text of a non-PC-relative operand
	 is 24 bytes (SPMASK masking all eight functional units, with
	 separating commas and trailing NUL).  */
      char operands[TIC6X_MAX_OPERANDS][24] = { { 0 } };
      bfd_vma operands_addresses[TIC6X_MAX_OPERANDS] = { 0 };
      bool operands_text[TIC6X_MAX_OPERANDS] = { false };
      bool operands_pcrel[TIC6X_MAX_OPERANDS] = { false };
      unsigned int fix;
      unsigned int num_operands;
      unsigned int op_num;
      bool fixed_ok;
      bool operands_ok;
      bool have_t = false;

      if (opc->flags & TIC6X_FLAG_MACRO)
	continue;
      if (fmt->num_bits != num_bits)
	continue;
      if ((opcode & fmt->mask) != fmt->cst_bits)
	continue;

      /* If the format has a creg field, it is only a candidate for a
	 match if the creg and z fields have values indicating a valid
	 condition; reserved values indicate either an instruction
	 format without a creg field, or an invalid instruction.  */
      creg_field = tic6x_field_from_fmt (fmt, tic6x_field_creg);
      if (creg_field)
	{
	  const tic6x_insn_field *z_field;
	  unsigned int creg_value, z_value;
	  static const char *const conds[8][2] =
	    {
	      { "", NULL },
	      { "[b0] ", "[!b0] " },
	      { "[b1] ", "[!b1] " },
	      { "[b2] ", "[!b2] " },
	      { "[a1] ", "[!a1] " },
	      { "[a2] ", "[!a2] " },
	      { "[a0] ", "[!a0] " },
	      { NULL, NULL }
	    };

	  /* A creg field is not meaningful without a z field, so if
	     the z field is not present this is an error in the format
	     table.  */
	  z_field = tic6x_field_from_fmt (fmt, tic6x_field_z);
	  if (!z_field)
	    {
	      printf ("*** opcode %x: missing z field", opcode);
	      abort ();
	    }

	  creg_value = tic6x_field_bits (opcode, creg_field);
	  z_value = tic6x_field_bits (opcode, z_field);
	  cond = conds[creg_value][z_value];
	  if (cond == NULL)
	    continue;
	}

      if (opc->flags & TIC6X_FLAG_INSN16_SPRED)
	{
	  const tic6x_insn_field *cc_field;
          unsigned int s_value = 0;
          unsigned int z_value = 0;
          bool cond_known = false;
          static const char *const conds[2][2] =
            {
              { "[a0] ", "[!a0] " },
              { "[b0] ", "[!b0] " }
            };

          cc_field = tic6x_field_from_fmt (fmt, tic6x_field_cc);

          if (cc_field)
	    {
	      unsigned int cc_value;

	      cc_value = tic6x_field_bits (opcode, cc_field);
	      s_value = (cc_value & 0x2) >> 1;
	      z_value = (cc_value & 0x1);
	      cond_known = true;
	    }
	  else
	    {
	      const tic6x_insn_field *z_field;
	      const tic6x_insn_field *s_field;

	      s_field = tic6x_field_from_fmt (fmt, tic6x_field_s);

	      if (!s_field)
		{
		  printf ("opcode %x: missing compact insn predicate register field (s field)\n",
			  opcode);
		  abort ();
		}
	      s_value = tic6x_field_bits (opcode, s_field);
	      z_field = tic6x_field_from_fmt (fmt, tic6x_field_z);
	      if (!z_field)
		{
		  printf ("opcode %x: missing compact insn predicate z_value (z field)\n", opcode);
		  abort ();
		}

	      z_value = tic6x_field_bits (opcode, z_field);
	      cond_known = true;
	    }

          if (!cond_known)
	    {
	      printf ("opcode %x: unspecified ompact insn predicate\n", opcode);
	      abort ();
	    }
          cond = conds[s_value][z_value];
	}

      /* All fixed fields must have matching values; all fields with
	 restricted ranges must have values within those ranges.  */
      fixed_ok = true;
      for (fix = 0; fix < opc->num_fixed_fields; fix++)
	{
	  unsigned int field_bits;
	  const tic6x_insn_field *const field
	    = tic6x_field_from_fmt (fmt, opc->fixed_fields[fix].field_id);

	  if (!field)
	    {
	      printf ("opcode %x: missing field #%d for FIX #%d\n",
		      opcode, opc->fixed_fields[fix].field_id, fix);
	      abort ();
	    }

	  field_bits = tic6x_field_bits (opcode, field);
	  if (field_bits < opc->fixed_fields[fix].min_val
	      || field_bits > opc->fixed_fields[fix].max_val)
	    {
	      fixed_ok = false;
	      break;
	    }
	}
      if (!fixed_ok)
	continue;

      /* The instruction matches.  */

      /* The p-bit indicates whether this instruction is in parallel
	 with the *next* instruction, whereas the parallel bars
	 indicate the instruction is in parallel with the *previous*
	 instruction.  Thus, we must find the p-bit for the previous
	 instruction.  */
      if (num_bits == 16 && (fp_offset & 0x2) == 2)
	{
	  /* This is the logically second (most significant; second in
	     fp_offset terms because fp_offset relates to logical not
	     physical addresses) instruction of a compact pair; find
	     the p-bit for the first (least significant).  */
	  p_bit = header.p_bits[(fp_offset >> 2) << 1];
	}
      else if (fp_offset >= 4)
	{
	  /* Find the last instruction of the previous word in this
	     fetch packet.  For compact instructions, this is the most
	     significant 16 bits.  */
	  if (fetch_packet_header_based
	      && header.word_compact[(fp_offset >> 2) - 1])
	    p_bit = header.p_bits[(fp_offset >> 1) - 1];
	  else
	    {
	      unsigned int prev_opcode
		= tic6x_extract_32 (fp + (fp_offset & 0x1c) - 4, info);
	      p_bit = (prev_opcode & 0x1) != 0;
	    }
	}
      else
	{
	  /* Find the last instruction of the previous fetch
	     packet.  */
	  unsigned char fp_prev[32];

	  status = info->read_memory_func (fp_addr - 32, fp_prev, 32, info);
	  if (status)
	    /* No previous instruction to be parallel with.  */
	    p_bit = false;
	  else
	    {
	      bool prev_header_based;
	      tic6x_fetch_packet_header prev_header;

	      prev_header_based
		= tic6x_check_fetch_packet_header (fp_prev, &prev_header, info);
	      if (prev_header_based)
		{
		  if (prev_header.word_compact[6])
		    p_bit = prev_header.p_bits[13];
		  else
		    {
		      unsigned int prev_opcode = tic6x_extract_32 (fp_prev + 24,
								   info);
		      p_bit = (prev_opcode & 0x1) != 0;
		    }
		}
	      else
		{
		  unsigned int prev_opcode = tic6x_extract_32 (fp_prev + 28,
							       info);
		  p_bit = (prev_opcode & 0x1) != 0;
		}
	    }
	}
      parallel = p_bit ? "|| " : "";

      if (opc->func_unit == tic6x_func_unit_nfu)
	func_unit = "";
      else
	{
	  unsigned int fld_num;
	  char func_unit_char;
	  const char *data_str;
	  bool have_areg = false;
	  bool have_cross = false;

	  func_unit_side = (opc->flags & TIC6X_FLAG_SIDE_B_ONLY) ? 2 : 0;
	  func_unit_cross = 0;
	  func_unit_data_side = (opc->flags & TIC6X_FLAG_SIDE_T2_ONLY) ? 2 : 0;

	  for (fld_num = 0; fld_num < opc->num_variable_fields; fld_num++)
	    {
	      const tic6x_coding_field *const enc = &opc->variable_fields[fld_num];
	      const tic6x_insn_field *field;
	      unsigned int fld_val;

	      field = tic6x_field_from_fmt (fmt, enc->field_id);

	      if (!field)
		{
		  printf ("opcode %x: could not retrieve field (field_id:%d)\n",
			  opcode, fld_num);
		  abort ();
		}

	      fld_val = tic6x_field_bits (opcode, field);

	      switch (enc->coding_method)
		{
		case tic6x_coding_fu:
		  /* The side must be specified exactly once.  */
		  if (func_unit_side)
		    {
		      printf ("opcode %x: field #%d use tic6x_coding_fu, but func_unit_side is already set!\n",
			      opcode, fld_num);
		      abort ();
		    }
		  func_unit_side = (fld_val ? 2 : 1);
		  break;

		case tic6x_coding_data_fu:
		  /* The data side must be specified exactly once.  */
		  if (func_unit_data_side)
		    {
		      printf ("opcode %x: field #%d use tic6x_coding_fu, but func_unit_side is already set!\n",
			      opcode, fld_num);
		      abort ();
		    }
		  func_unit_data_side = (fld_val ? 2 : 1);
		  break;

		case tic6x_coding_xpath:
		  /* Cross path use must be specified exactly
		     once.  */
		  if (have_cross)
		    {
		      printf ("opcode %x: field #%d use tic6x_coding_xpath, have_cross is already set!\n",
			      opcode, fld_num);
		      abort ();
		    }
		  have_cross = true;
		  func_unit_cross = fld_val;
		  break;

                case tic6x_coding_rside:
                  /* If the format has a t field, use it for src/dst register side.  */
                  have_t = true;
                  t_val = fld_val;
                  func_unit_data_side = (t_val ? 2 : 1);
                  break;

		case tic6x_coding_areg:
		  have_areg = true;
		  break;

		default:
		  /* Don't relate to functional units.  */
		  break;
		}
	    }

	  /* The side of the functional unit used must now have been
	     determined either from the flags or from an instruction
	     field.  */
	  if (func_unit_side != 1 && func_unit_side != 2)
	    {
	      printf ("opcode %x: func_unit_side is not encoded!\n", opcode);
	      abort ();
	    }

	  /* Cross paths are not applicable when sides are specified
	     for both address and data paths.  */
	  if (func_unit_data_side && have_cross)
	    {
	      printf ("opcode %x: xpath not applicable when side are specified both for address and data!\n",
		      opcode);
	      abort ();
	    }

	  /* Separate address and data paths are only applicable for
	     the D unit.  */
	  if (func_unit_data_side && opc->func_unit != tic6x_func_unit_d)
	    {
	      printf ("opcode %x: separate address and data paths only applicable for D unit!\n",
		      opcode);
	      abort ();
          }

	  /* If an address register is being used but in ADDA rather
	     than a load or store, it uses a cross path for side-A
	     instructions, and the cross path use is not specified by
	     an instruction field.  */
	  if (have_areg && !func_unit_data_side)
	    {
	      if (have_cross)
		{
		  printf ("opcode %x: illegal cross path specifier in adda opcode!\n", opcode);
		  abort ();
		}
	      func_unit_cross = func_unit_side == 1;
	    }

	  switch (opc->func_unit)
	    {
	    case tic6x_func_unit_d:
	      func_unit_char = 'D';
	      break;

	    case tic6x_func_unit_l:
	      func_unit_char = 'L';
	      break;

	    case tic6x_func_unit_m:
	      func_unit_char = 'M';
	      break;

	    case tic6x_func_unit_s:
	      func_unit_char = 'S';
	      break;

	    default:
              printf ("opcode %x: illegal func_unit specifier %d\n", opcode, opc->func_unit);
	      abort ();
	    }

	  switch (func_unit_data_side)
	    {
	    case 0:
	      data_str = "";
	      break;

	    case 1:
	      data_str = "T1";
	      break;

	    case 2:
	      data_str = "T2";
	      break;

	    default:
              printf ("opcode %x: illegal data func_unit specifier %d\n",
		      opcode, func_unit_data_side);
	      abort ();
	    }

	  if (opc->flags & TIC6X_FLAG_INSN16_BSIDE && func_unit_side == 1)
	      func_unit_cross = 1;

	  snprintf (func_unit_buf, sizeof func_unit_buf, " .%c%u%s%s",
		    func_unit_char, func_unit_side,
		    (func_unit_cross ? "X" : ""), data_str);
	  func_unit = func_unit_buf;
	}

      /* For each operand there must be one or more fields set based
	 on that operand, that can together be used to derive the
	 operand value.  */
      operands_ok = true;
      num_operands = opc->num_operands;
      for (op_num = 0; op_num < num_operands; op_num++)
	{
	  unsigned int fld_num;
	  unsigned int mem_base_reg = 0;
	  bool mem_base_reg_known = false;
	  bool mem_base_reg_known_long = false;
	  unsigned int mem_offset = 0;
	  bool mem_offset_known = false;
	  bool mem_offset_known_long = false;
	  unsigned int mem_mode = 0;
	  bool mem_mode_known = false;
	  unsigned int mem_scaled = 0;
	  bool mem_scaled_known = false;
	  unsigned int crlo = 0;
	  bool crlo_known = false;
	  unsigned int crhi = 0;
	  bool crhi_known = false;
	  bool spmask_skip_operand = false;
	  unsigned int fcyc_bits = 0;
	  bool prev_sploop_found = false;

	  switch (opc->operand_info[op_num].form)
	    {
	    case tic6x_operand_b15reg:
	      /* Fully determined by the functional unit.  */
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "b15");
	      continue;

	    case tic6x_operand_zreg:
	      /* Fully determined by the functional unit.  */
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "%c0",
			(func_unit_side == 2 ? 'b' : 'a'));
	      continue;

	    case tic6x_operand_retreg:
	      /* Fully determined by the functional unit.  */
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "%c3",
			(func_unit_side == 2 ? 'b' : 'a'));
	      continue;

	    case tic6x_operand_irp:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "irp");
	      continue;

	    case tic6x_operand_nrp:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "nrp");
	      continue;

	    case tic6x_operand_ilc:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "ilc");
	      continue;

	    case tic6x_operand_hw_const_minus_1:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "-1");
	      continue;

	    case tic6x_operand_hw_const_0:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "0");
	      continue;

	    case tic6x_operand_hw_const_1:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "1");
	      continue;

	    case tic6x_operand_hw_const_5:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "5");
	      continue;

	    case tic6x_operand_hw_const_16:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "16");
	      continue;

	    case tic6x_operand_hw_const_24:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "24");
	      continue;

	    case tic6x_operand_hw_const_31:
	      operands_text[op_num] = true;
	      snprintf (operands[op_num], 24, "31");
	      continue;

	    default:
	      break;
	    }

	  for (fld_num = 0; fld_num < opc->num_variable_fields; fld_num++)
	    {
	      const tic6x_coding_field *const enc
		= &opc->variable_fields[fld_num];
	      const tic6x_insn_field *field;
	      unsigned int fld_val;
	      unsigned int reg_base = 0;
	      signed int signed_fld_val;
              char reg_side = '?';

	      if (enc->operand_num != op_num)
		continue;
	      field = tic6x_field_from_fmt (fmt, enc->field_id);
	      if (!field)
		{
		  printf ("opcode %x: missing field (field_id:%d) in format\n", opcode, enc->field_id);
		  abort ();
		}
              fld_val = tic6x_field_bits (opcode, field);
	      switch (enc->coding_method)
		{
                case tic6x_coding_cst_s3i:
                  (fld_val == 0x00) && (fld_val = 0x10);
                  (fld_val == 0x07) && (fld_val = 0x08);
                  /* Fall through.  */
		case tic6x_coding_ucst:
		case tic6x_coding_ulcst_dpr_byte:
		case tic6x_coding_ulcst_dpr_half:
		case tic6x_coding_ulcst_dpr_word:
		case tic6x_coding_lcst_low16:
		  switch (opc->operand_info[op_num].form)
		    {
		    case tic6x_operand_asm_const:
		    case tic6x_operand_link_const:
		      operands_text[op_num] = true;
		      snprintf (operands[op_num], 24, "%u", fld_val);
		      break;

		    case tic6x_operand_mem_long:
		      mem_offset = fld_val;
		      mem_offset_known_long = true;
		      break;

		    default:
                      printf ("opcode %x: illegal operand form for operand#%d\n", opcode, op_num);
		      abort ();
		    }
		  break;

		case tic6x_coding_lcst_high16:
		  operands_text[op_num] = true;
		  snprintf (operands[op_num], 24, "%u", fld_val << 16);
		  break;

                case tic6x_coding_scst_l3i:
		  operands_text[op_num] = true;
                  if (fld_val == 0)
		    {
		      signed_fld_val = 8;
		    }
		  else
		    {
		      signed_fld_val = (signed int) fld_val;
		      signed_fld_val ^= (1 << (tic6x_field_width (field) - 1));
		      signed_fld_val -= (1 << (tic6x_field_width (field) - 1));
		    }
		  snprintf (operands[op_num], 24, "%d", signed_fld_val);
		  break;

		case tic6x_coding_scst:
		  operands_text[op_num] = true;
		  signed_fld_val = (signed int) fld_val;
		  signed_fld_val ^= (1 << (tic6x_field_width (field) - 1));
		  signed_fld_val -= (1 << (tic6x_field_width (field) - 1));
		  snprintf (operands[op_num], 24, "%d", signed_fld_val);
		  break;

		case tic6x_coding_ucst_minus_one:
		  operands_text[op_num] = true;
		  snprintf (operands[op_num], 24, "%u", fld_val + 1);
		  break;

		case tic6x_coding_pcrel:
		case tic6x_coding_pcrel_half:
		  signed_fld_val = (signed int) fld_val;
		  signed_fld_val ^= (1 << (tic6x_field_width (field) - 1));
		  signed_fld_val -= (1 << (tic6x_field_width (field) - 1));
		  if (fetch_packet_header_based
		      && enc->coding_method == tic6x_coding_pcrel_half)
		    signed_fld_val *= 2;
		  else
		    signed_fld_val *= 4;
		  operands_pcrel[op_num] = true;
		  operands_addresses[op_num] = fp_addr + signed_fld_val;
		  break;

		case tic6x_coding_regpair_msb:
		  if (opc->operand_info[op_num].form != tic6x_operand_regpair)
		    abort ();
		  operands_text[op_num] = true;
		  snprintf (operands[op_num], 24, "%c%u:%c%u",
			    (func_unit_side == 2 ? 'b' : 'a'), (fld_val | 0x1),
			    (func_unit_side == 2 ? 'b' : 'a'), (fld_val | 0x1) - 1);
		  break;

		case tic6x_coding_pcrel_half_unsigned:
		  operands_pcrel[op_num] = true;
		  operands_addresses[op_num] = fp_addr + 2 * fld_val;
		  break;

		case tic6x_coding_reg_shift:
		  fld_val <<= 1;
		  /* Fall through.  */
		case tic6x_coding_reg:
                  if (num_bits == 16 && header.rs && !(opc->flags & TIC6X_FLAG_INSN16_NORS))
                    {
		      reg_base = 16;
                    }
		  switch (opc->operand_info[op_num].form)
		    {
		    case tic6x_operand_treg:
                      if (!have_t)
			{
			  printf ("opcode %x: operand treg but missing t field\n", opcode);
			  abort ();
			}
		      operands_text[op_num] = true;
                      reg_side = t_val ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u", reg_side, reg_base + fld_val);
		      break;

		    case tic6x_operand_reg:
		      operands_text[op_num] = true;
                      reg_side = (func_unit_side == 2) ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u", reg_side,  reg_base + fld_val);
		      break;

		    case tic6x_operand_reg_nors:
		      operands_text[op_num] = true;
                      reg_side = (func_unit_side == 2) ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u", reg_side, fld_val);
		      break;

		    case tic6x_operand_reg_bside:
		      operands_text[op_num] = true;
		      snprintf (operands[op_num], 24, "b%u", reg_base + fld_val);
		      break;

		    case tic6x_operand_reg_bside_nors:
		      operands_text[op_num] = true;
		      snprintf (operands[op_num], 24, "b%u", fld_val);
		      break;

		    case tic6x_operand_xreg:
		      operands_text[op_num] = true;
                      reg_side = ((func_unit_side == 2) ^ func_unit_cross) ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u", reg_side,  reg_base + fld_val);
		      break;

		    case tic6x_operand_dreg:
		      operands_text[op_num] = true;
                      reg_side = (func_unit_data_side == 2) ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u", reg_side,  reg_base + fld_val);
		      break;

		    case tic6x_operand_regpair:
		      operands_text[op_num] = true;
		      if (fld_val & 1)
			operands_ok = false;
                      reg_side = (func_unit_side == 2) ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u:%c%u",
                                reg_side, reg_base + fld_val + 1,
				reg_side, reg_base + fld_val);
		      break;

		    case tic6x_operand_xregpair:
		      operands_text[op_num] = true;
		      if (fld_val & 1)
			operands_ok = false;
                      reg_side = ((func_unit_side == 2) ^ func_unit_cross) ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u:%c%u",
				reg_side, reg_base + fld_val + 1,
				reg_side, reg_base + fld_val);
		      break;

		    case tic6x_operand_tregpair:
                      if (!have_t)
			{
			  printf ("opcode %x: operand tregpair but missing t field\n", opcode);
			  abort ();
			}
		      operands_text[op_num] = true;
		      if (fld_val & 1)
			operands_ok = false;
                      reg_side = t_val ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u:%c%u",
				reg_side, reg_base + fld_val + 1,
				reg_side, reg_base + fld_val);
		      break;

		    case tic6x_operand_dregpair:
		      operands_text[op_num] = true;
		      if (fld_val & 1)
			operands_ok = false;
                      reg_side = (func_unit_data_side) == 2 ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "%c%u:%c%u",
				reg_side, reg_base + fld_val + 1,
				reg_side, reg_base + fld_val);
		      break;

		    case tic6x_operand_mem_deref:
		      operands_text[op_num] = true;
                      reg_side = func_unit_side == 2 ? 'b' : 'a';
		      snprintf (operands[op_num], 24, "*%c%u", reg_side, reg_base + fld_val);
		      break;

		    case tic6x_operand_mem_short:
		    case tic6x_operand_mem_ndw:
		      mem_base_reg = fld_val;
		      mem_base_reg_known = true;
		      break;

		    default:
                      printf ("opcode %x: unexpected operand form %d for operand #%d",
			      opcode, opc->operand_info[op_num].form, op_num);
		      abort ();
		    }
		  break;

                case tic6x_coding_reg_ptr:
		  switch (opc->operand_info[op_num].form)
		    {
		    case tic6x_operand_mem_short:
		    case tic6x_operand_mem_ndw:
                      if (fld_val > 0x3u)
			{
			  printf("opcode %x: illegal field value for ptr register of operand #%d (%d)",
				 opcode, op_num, fld_val);
			  abort ();
			}
		      mem_base_reg = 0x4 | fld_val;
		      mem_base_reg_known = true;
		      break;

		    default:
                      printf ("opcode %x: unexpected operand form %d for operand #%d",
			      opcode, opc->operand_info[op_num].form, op_num);
		      abort ();
		    }
		  break;

		case tic6x_coding_areg:
		  switch (opc->operand_info[op_num].form)
		    {
		    case tic6x_operand_areg:
		      operands_text[op_num] = true;
		      snprintf (operands[op_num], 24, "b%u",
				fld_val ? 15u : 14u);
		      break;

		    case tic6x_operand_mem_long:
		      mem_base_reg = fld_val ? 15u : 14u;
		      mem_base_reg_known_long = true;
		      break;

		    default:
                      printf ("opcode %x: bad operand form\n", opcode);
		      abort ();
		    }
		  break;

		case tic6x_coding_mem_offset_minus_one_noscale:
		case tic6x_coding_mem_offset_minus_one:
		  fld_val += 1;
		  /* Fall through.  */
		case tic6x_coding_mem_offset_noscale:
		case tic6x_coding_mem_offset:
		  mem_offset = fld_val;
		  mem_offset_known = true;
		  if (num_bits == 16)
		    {
		      mem_mode_known = true;
		      mem_mode = TIC6X_INSN16_MEM_MODE_VAL (opc->flags);
		      mem_scaled_known = true;
		      mem_scaled = true;
		      if (opc->flags & TIC6X_FLAG_INSN16_B15PTR)
			{
			  mem_base_reg_known = true;
			  mem_base_reg = 15;
			}
		      if ( enc->coding_method == tic6x_coding_mem_offset_noscale
			   || enc->coding_method == tic6x_coding_mem_offset_noscale )
			mem_scaled = false;
		    }
		  break;

		case tic6x_coding_mem_mode:
		  mem_mode = fld_val;
		  mem_mode_known = true;
		  break;

		case tic6x_coding_scaled:
		  mem_scaled = fld_val;
		  mem_scaled_known = true;
		  break;

		case tic6x_coding_crlo:
		  crlo = fld_val;
		  crlo_known = true;
		  break;

		case tic6x_coding_crhi:
		  crhi = fld_val;
		  crhi_known = true;
		  break;

		case tic6x_coding_fstg:
		case tic6x_coding_fcyc:
		  if (!prev_sploop_found)
		    {
		      bfd_vma search_fp_addr = fp_addr;
		      bfd_vma search_fp_offset = fp_offset;
		      bool search_fp_header_based
			= fetch_packet_header_based;
		      tic6x_fetch_packet_header search_fp_header = header;
		      unsigned char search_fp[32];
		      unsigned int search_num_bits;
		      unsigned int search_opcode;
		      unsigned int sploop_ii = 0;
		      int i;

		      memcpy (search_fp, fp, 32);

		      /* To interpret these bits in an SPKERNEL
			 instruction, we must find the previous
			 SPLOOP-family instruction.  It may come up to
			 48 execute packets earlier.  */
		      for (i = 0; i < 48 * 8; i++)
			{
			  /* Find the previous instruction.  */
			  if (search_fp_offset & 2)
			    search_fp_offset -= 2;
			  else if (search_fp_offset >= 4)
			    {
			      if (search_fp_header_based
				  && (search_fp_header.word_compact
				      [(search_fp_offset >> 2) - 1]))
				search_fp_offset -= 2;
			      else
				search_fp_offset -= 4;
			    }
			  else
			    {
			      search_fp_addr -= 32;
			      status = info->read_memory_func (search_fp_addr,
							       search_fp,
							       32, info);
			      if (status)
				/* No previous SPLOOP instruction.  */
				break;
			      search_fp_header_based
				= (tic6x_check_fetch_packet_header
				   (search_fp, &search_fp_header, info));
			      if (search_fp_header_based)
				search_fp_offset
				  = search_fp_header.word_compact[6] ? 26 : 24;
			      else
				search_fp_offset = 28;
			    }

			  /* Extract the previous instruction.  */
			  if (search_fp_header_based)
			    search_num_bits
			      = (search_fp_header.word_compact[search_fp_offset
							       >> 2]
				 ? 16
				 : 32);
			  else
			    search_num_bits = 32;
			  if (search_num_bits == 16)
			    {
			      if (info->endian == BFD_ENDIAN_LITTLE)
				search_opcode
				  = (tic6x_extract_16
				     (search_fp + search_fp_offset, &header, info));
			      else
				search_opcode
				  = (tic6x_extract_16
				     (search_fp + (search_fp_offset ^ 2), &header,
				      info));
			    }
			  else
			    search_opcode
			      = tic6x_extract_32 (search_fp + search_fp_offset,
						  info);

			  /* Check whether it is an SPLOOP-family
			     instruction.  */
			  if (search_num_bits == 32
			      && ((search_opcode & 0x003ffffe) == 0x00038000
				  || (search_opcode & 0x003ffffe) == 0x0003a000
				  || ((search_opcode & 0x003ffffe)
				      == 0x0003e000)))
			    {
			      prev_sploop_found = true;
			      sploop_ii = ((search_opcode >> 23) & 0x1f) + 1;
			    }
			  else if (search_num_bits == 16
				   && (search_opcode & 0x3c7e) == 0x0c66)
			    {
			      prev_sploop_found = true;
			      sploop_ii
				= (((search_opcode >> 7) & 0x7)
				   | ((search_opcode >> 11) & 0x8)) + 1;
			    }
			  if (prev_sploop_found)
			    {
			      if (sploop_ii <= 0)
				{
				  printf ("opcode %x:  sloop index not found (%d)\n", opcode, sploop_ii);
				  abort ();
				}
			      else if (sploop_ii <= 1)
				fcyc_bits = 0;
			      else if (sploop_ii <= 2)
				fcyc_bits = 1;
			      else if (sploop_ii <= 4)
				fcyc_bits = 2;
			      else if (sploop_ii <= 8)
				fcyc_bits = 3;
			      else if (sploop_ii <= 14)
				fcyc_bits = 4;
			      else
				prev_sploop_found = false;
			    }
			  if (prev_sploop_found)
			    break;
			}
		    }
		  if (!prev_sploop_found)
		    {
		      operands_ok = false;
		      operands_text[op_num] = true;
		      break;
		    }
		  if (fcyc_bits > tic6x_field_width(field))
		    {
		      printf ("opcode %x: illegal fcyc value (%d)\n", opcode, fcyc_bits);
		      abort ();
		    }
		  if (enc->coding_method == tic6x_coding_fstg)
		    {
		      int i, t;
		      for (t = 0, i = fcyc_bits; i < 6; i++)
			t = (t << 1) | ((fld_val >> i) & 1);
		      operands_text[op_num] = true;
		      snprintf (operands[op_num], 24, "%u", t);
		    }
		  else
		    {
		      operands_text[op_num] = true;
		      snprintf (operands[op_num], 24, "%u",
				fld_val & ((1 << fcyc_bits) - 1));
		    }
		  break;

		case tic6x_coding_spmask:
		  if (fld_val == 0)
		    spmask_skip_operand = true;
		  else
		    {
		      char *p;
		      unsigned int i;

		      operands_text[op_num] = true;
		      p = operands[op_num];
		      for (i = 0; i < 8; i++)
			if (fld_val & (1 << i))
			  {
			    *p++ = "LSDM"[i/2];
			    *p++ = '1' + (i & 1);
			    *p++ = ',';
			  }
		      p[-1] = 0;
		    }
		  break;

		case tic6x_coding_fu:
		case tic6x_coding_data_fu:
		case tic6x_coding_xpath:
		case tic6x_coding_rside:
		  /* Don't relate to operands, so operand number is
		     meaningless.  */
		  break;

		default:
                  printf ("opcode %x: illegal field encoding (%d)\n", opcode, enc->coding_method);
		  abort ();
		}

	      if (mem_base_reg_known_long && mem_offset_known_long)
		{
		  if (operands_text[op_num] || operands_pcrel[op_num])
		    {
		      printf ("opcode %x: long access but operands already known ?\n", opcode);
		      abort ();
		    }
		  operands_text[op_num] = true;
		  snprintf (operands[op_num], 24, "*+b%u(%u)", mem_base_reg,
			    mem_offset * opc->operand_info[op_num].size);
		}

	      if (mem_base_reg_known && mem_offset_known && mem_mode_known
		  && (mem_scaled_known
		      || (opc->operand_info[op_num].form
			  != tic6x_operand_mem_ndw)))
		{
		  char side;
		  char base[4];
		  bool offset_is_reg;
		  bool offset_scaled;
		  char offset[4];
		  char offsetp[6];

		  if (operands_text[op_num] || operands_pcrel[op_num])
		    {
		      printf ("opcode %x: mem access operands already known ?\n", opcode);
		      abort ();
		    }

		  side = func_unit_side == 2 ? 'b' : 'a';
		  snprintf (base, 4, "%c%u", side, mem_base_reg);

		  offset_is_reg = (mem_mode & 4) != 0;
		  if (offset_is_reg)
		    {

		      if (num_bits == 16 && header.rs && !(opc->flags & TIC6X_FLAG_INSN16_NORS))
			{
			  reg_base = 16;
			}
		      snprintf (offset, 4, "%c%u", side, reg_base + mem_offset);
		      if (opc->operand_info[op_num].form
			  == tic6x_operand_mem_ndw)
			offset_scaled = mem_scaled != 0;
		      else
			offset_scaled = true;
		    }
		  else
		    {
		      if (opc->operand_info[op_num].form
			  == tic6x_operand_mem_ndw)
			{
			  offset_scaled = mem_scaled != 0;
			  snprintf (offset, 4, "%u", mem_offset);
			}
		      else
			{
			  offset_scaled = false;
			  snprintf (offset, 4, "%u",
				    (mem_offset
				     * opc->operand_info[op_num].size));
			}
		    }

		  if (offset_scaled)
		    snprintf (offsetp, 6, "[%s]", offset);
		  else
		    snprintf (offsetp, 6, "(%s)", offset);

		  operands_text[op_num] = true;
		  switch (mem_mode & ~4u)
		    {
		    case 0:
		      snprintf (operands[op_num], 24, "*-%s%s", base, offsetp);
		      break;

		    case 1:
		      snprintf (operands[op_num], 24, "*+%s%s", base, offsetp);
		      break;

		    case 2:
		    case 3:
		      operands_ok = false;
		      break;

		    case 8:
		      snprintf (operands[op_num], 24, "*--%s%s", base,
				offsetp);
		      break;

		    case 9:
		      snprintf (operands[op_num], 24, "*++%s%s", base,
				offsetp);
		      break;

		    case 10:
		      snprintf (operands[op_num], 24, "*%s--%s", base,
				offsetp);
		      break;

		    case 11:
		      snprintf (operands[op_num], 24, "*%s++%s", base,
				offsetp);
		      break;

		    default:
                      printf ("*** unknown mem_mode : %d \n", mem_mode);
		      abort ();
		    }
		}

	      if (crlo_known && crhi_known)
		{
		  tic6x_rw rw;
		  tic6x_ctrl_id crid;

		  if (operands_text[op_num] || operands_pcrel[op_num])
		    {
		      printf ("*** abort crlo crli\n");
		      abort ();
		    }

		  rw = opc->operand_info[op_num].rw;
		  if (rw != tic6x_rw_read
		      && rw != tic6x_rw_write)
		    {
		      printf ("*** abort rw : %d\n", rw);
		      abort ();
		    }

		  for (crid = 0; crid < tic6x_ctrl_max; crid++)
		    {
		      if (crlo == tic6x_ctrl_table[crid].crlo
			  && (crhi & tic6x_ctrl_table[crid].crhi_mask) == 0
			  && (rw == tic6x_rw_read
			      ? (tic6x_ctrl_table[crid].rw == tic6x_rw_read
				 || (tic6x_ctrl_table[crid].rw
				     == tic6x_rw_read_write))
			      : (tic6x_ctrl_table[crid].rw == tic6x_rw_write
				 || (tic6x_ctrl_table[crid].rw
				     == tic6x_rw_read_write))))
			break;
		    }
		  if (crid == tic6x_ctrl_max)
		    {
		      operands_text[op_num] = true;
		      operands_ok = false;
		    }
		  else
		    {
		      operands_text[op_num] = true;
		      snprintf (operands[op_num], 24, "%s",
				tic6x_ctrl_table[crid].name);
		    }
		}

	      if (operands_text[op_num] || operands_pcrel[op_num]
		  || spmask_skip_operand)
		break;
	    }
          /* end for fld_num */

	  if (spmask_skip_operand)
	    {
	      /* SPMASK operands are only valid as the single operand
		 in the opcode table.  */
	      if (num_operands != 1)
		{
		  printf ("opcode: %x, num_operands != 1 : %d\n", opcode, num_operands);
		  abort ();
		}
	      num_operands = 0;
	      break;
	    }

	  /* The operand must by now have been decoded.  */
	  if (!operands_text[op_num] && !operands_pcrel[op_num])
            {
              printf ("opcode: %x, operand #%d not decoded\n", opcode, op_num);
              abort ();
            }
        }
      /* end for op_num */

      if (!operands_ok)
	continue;

      info->bytes_per_chunk = num_bits / 8;
      info->fprintf_func (info->stream, "%s", parallel);
      info->fprintf_func (info->stream, "%s%s%s", cond, opc->name,
                          func_unit);
      for (op_num = 0; op_num < num_operands; op_num++)
	{
	  info->fprintf_func (info->stream, "%c", (op_num == 0 ? ' ' : ','));
	  if (operands_pcrel[op_num])
	    info->print_address_func (operands_addresses[op_num], info);
	  else
	    info->fprintf_func (info->stream, "%s", operands[op_num]);
	}
      if (fetch_packet_header_based && header.prot)
	info->fprintf_func (info->stream, " || nop 5");

      return num_bits / 8;
    }

  info->bytes_per_chunk = num_bits / 8;
  info->fprintf_func (info->stream, "<undefined instruction 0x%.*x>",
		      (int) num_bits / 4, opcode);
  return num_bits / 8;
}
