/* Instruction printing code for the Hexagon.
   Copyright 1994, 1995, 1997, 1998, 2000, 2001, 2002
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA
*/

#include "ansidecl.h"
#include "libiberty.h"
#include "disas-asm.h"
#include "opcode/hexagon.h"
#include "mybfd.h"
//#include "elf/hexagon.h"
#include <string.h>
#include "opintl.h"

#include <stdarg.h>
#include "safe-ctype.h"

static int
hexagon_dis_inst(
     bfd_vma address,
     hexagon_insn insn,
     char *instrBuffer,
     disassemble_info * info
)
{
  const hexagon_opcode *opcode;
  int len;
  char *errmsg = NULL;

  len = HEXAGON_INSN_LEN;

  opcode = hexagon_lookup_insn(insn);
  if (opcode) {

      if (!hexagon_dis_opcode(instrBuffer, insn, address, opcode, &errmsg)) {
        /* Some kind of error! */
        if (errmsg) {
          (*info->fprintf_func) (info->stream, "%s", errmsg);
          strcpy(instrBuffer, "");
        }
      }

      return len;
  }

  // Instruction not found
  strcpy(instrBuffer, "<unknown>");
  return 4;
}


/* Decode an instruction returning the size of the instruction
   in bytes or zero if unrecognized.  */
static int
hexagon_decode_inst(
    bfd_vma            address, /* Address of this instruction.  */
    disassemble_info * info
)
{
  int status;
  hexagon_insn insn;
  bfd_byte buffer[4];
  void *stream = info->stream; /* output stream  */
  fprintf_ftype func = info->fprintf_func;
  char instrBuffer[100];
  int bytes;
  char *str;

#if 0
  /* Decide if we have a 16-bit instruction */
  // Nope comment you are drunk.
  status = (*info->read_memory_func)(address, buffer, 2, info);
  if (status != 0) {
    (*info->memory_error_func)(status, address, info);
    return -1;
  }
  if (info->endian == BFD_ENDIAN_LITTLE) {
    insn = bfd_getl16 (buffer);
  }
  else {
    insn = bfd_getb16 (buffer);
  }
#endif

  status = (*info->read_memory_func)(address, buffer, 4, info);
  if (status != 0) {
    (*info->memory_error_func)(status, address, info);
    return -1;
  }
  if (info->endian == BFD_ENDIAN_LITTLE) {
    insn = bfd_getl32(buffer);
  }
  else {
    insn = bfd_getb32(buffer);
  }

  /* disassemble  */
  bytes = hexagon_dis_inst(address, insn, instrBuffer, info);

  /* display the disassembly instruction  */
  if (bytes == 2) {
    (*func) (stream, "    %04x ", insn);
  }
  else {
    (*func) (stream, "%08x ", insn);
  }
  (*func) (stream, "    ");

  /* Print the instruction buffer
     Watch out for placeholders where we want
     to print out the symbolic name for an address */
  str = instrBuffer;
  while (*str) {
    char ch = *str++;
    if (ch == '@') {
      bfd_vma addr = 0;
      while (ISDIGIT(*str)) {
        ch = *str++;
        addr = 10*addr + (ch - '0');
      }
      (*info->print_address_func)(addr, info);
    }
    else {
      (*func)(stream, "%c", ch);
    }
  }

  return bytes;
}

/* Return the print_insn function to use. */
disassembler_ftype
hexagon_get_disassembler_from_mach(
  unsigned long machine,
  unsigned long big_p
)
{
  hexagon_opcode_init_tables(hexagon_get_opcode_mach(machine, big_p));
  return hexagon_decode_inst;
}

disassembler_ftype
hexagon_get_disassembler(
    bfd *abfd
)
{
  unsigned long machine = 0; // XXX bfd_get_mach(abfd);
  unsigned long big_p = bfd_big_endian(abfd);
  return (hexagon_get_disassembler_from_mach(machine, big_p));
}

