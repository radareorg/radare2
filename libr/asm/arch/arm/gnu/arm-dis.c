/* Instruction printing code for the ARM
   Copyright 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003,
   2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012
   Free Software Foundation, Inc.
   Contributed by Richard Earnshaw (rwe@pegasus.esprit.ec.org)
   Modification by James G. Smith (jsmith@cygnus.co.uk)

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

#include "dis-asm.h"
#include "gnu-arm.h"
#include "opintl.h"

/* FIXME: This shouldn't be done here.  */
#include "elf-bfd.h"
#include "elf/internal.h"
#include "elfarm.h"

/* FIXME: Belongs in global header.  */
#ifndef strneq
#define strneq(a,b,n)	(strncmp ((a), (b), (n)) == 0)
#endif

#ifndef NUM_ELEM
#define NUM_ELEM(a)     (sizeof (a) / sizeof (a)[0])
#endif

#define COMMENTS 1

/* Cached mapping symbol state.  */
enum map_type
{
  MAP_ARM,
  MAP_THUMB,
  MAP_DATA
};

struct arm_private_data
{
  /* The features to use when disassembling optional instructions.  */
  arm_feature_set features;

  /* Whether any mapping symbols are present in the provided symbol
     table.  -1 if we do not know yet, otherwise 0 or 1.  */
  int has_mapping_symbols;

  /* Track the last type (although this doesn't seem to be useful) */
  enum map_type last_type;

  /* Tracking symbol table information */
  int last_mapping_sym;
  bfd_vma last_mapping_addr;
};

struct opcode32
{
  unsigned long arch;		/* Architecture defining this insn.  */
  unsigned long value;		/* If arch == 0 then value is a sentinel.  */
  unsigned long mask;		/* Recognise insn if (op & mask) == value.  */
  const char *  assembler;	/* How to disassemble this insn.  */
};

struct opcode16
{
  unsigned long arch;		/* Architecture defining this insn.  */
  unsigned short value, mask;	/* Recognise insn if (op & mask) == value.  */
  const char *assembler;	/* How to disassemble this insn.  */
};

/* print_insn_coprocessor recognizes the following format control codes:

   %%			%

   %c			print condition code (always bits 28-31 in ARM mode)
   %q			print shifter argument
   %u			print condition code (unconditional in ARM mode,
                          UNPREDICTABLE if not AL in Thumb)
   %A			print address for ldc/stc/ldf/stf instruction
   %B			print vstm/vldm register list
   %I                   print cirrus signed shift immediate: bits 0..3|4..6
   %F			print the COUNT field of a LFM/SFM instruction.
   %P			print floating point precision in arithmetic insn
   %Q			print floating point precision in ldf/stf insn
   %R			print floating point rounding mode

   %<bitfield>c		print as a condition code (for vsel)
   %<bitfield>r		print as an ARM register
   %<bitfield>R		as %<>r but r15 is UNPREDICTABLE
   %<bitfield>ru        as %<>r but each u register must be unique.
   %<bitfield>d		print the bitfield in decimal
   %<bitfield>k		print immediate for VFPv3 conversion instruction
   %<bitfield>x		print the bitfield in hex
   %<bitfield>X		print the bitfield as 1 hex digit without leading "0x"
   %<bitfield>f		print a floating point constant if >7 else a
			floating point register
   %<bitfield>w         print as an iWMMXt width field - [bhwd]ss/us
   %<bitfield>g         print as an iWMMXt 64-bit register
   %<bitfield>G         print as an iWMMXt general purpose or control register
   %<bitfield>D		print as a NEON D register
   %<bitfield>Q		print as a NEON Q register

   %y<code>		print a single precision VFP reg.
			  Codes: 0=>Sm, 1=>Sd, 2=>Sn, 3=>multi-list, 4=>Sm pair
   %z<code>		print a double precision VFP reg
			  Codes: 0=>Dm, 1=>Dd, 2=>Dn, 3=>multi-list

   %<bitfield>'c	print specified char iff bitfield is all ones
   %<bitfield>`c	print specified char iff bitfield is all zeroes
   %<bitfield>?ab...    select from array of values in big endian order
   
   %L			print as an iWMMXt N/M width field.
   %Z			print the Immediate of a WSHUFH instruction.
   %l			like 'A' except use byte offsets for 'B' & 'H'
			versions.
   %i			print 5-bit immediate in bits 8,3..0
			(print "32" when 0)
   %r			print register offset address for wldt/wstr instruction.  */

enum opcode_sentinel_enum
{
  SENTINEL_IWMMXT_START = 1,
  SENTINEL_IWMMXT_END,
  SENTINEL_GENERIC_START
} opcode_sentinels;

#define UNDEFINED_INSTRUCTION      "; <UNDEFINED> %0-31x"
#define UNPREDICTABLE_INSTRUCTION  "; <UNPREDICTABLE>"

/* Common coprocessor opcodes shared between Arm and Thumb-2.  */

static const struct opcode32 coprocessor_opcodes[] =
{
  /* XScale instructions.  */
  {ARM_CEXT_XSCALE, 0x0e200010, 0x0fff0ff0, "mia%c acc0, %0-3r, %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e280010, 0x0fff0ff0, "miaph%c acc0, %0-3r, %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e2c0010, 0x0ffc0ff0, "mia%17'T%17`B%16'T%16`B%c acc0, %0-3r, %12-15r"},
  {ARM_CEXT_XSCALE, 0x0c400000, 0x0ff00fff, "mar%c acc0, %12-15r, %16-19r"},
  {ARM_CEXT_XSCALE, 0x0c500000, 0x0ff00fff, "mra%c %12-15r, %16-19r, acc0"},

  /* Intel Wireless MMX technology instructions.  */
  { 0, SENTINEL_IWMMXT_START, 0, "" },
  {ARM_CEXT_IWMMXT, 0x0e130130, 0x0f3f0fff, "tandc%22-23w%c %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e400010, 0x0ff00f3f, "tbcst%6-7w%c %16-19g, %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e130170, 0x0f3f0ff8, "textrc%22-23w%c %12-15r, %0-2d"},
  {ARM_CEXT_XSCALE, 0x0e100070, 0x0f300ff0, "textrm%3?su%22-23w%c %12-15r, %16-19g, %0-2d"},
  {ARM_CEXT_XSCALE, 0x0e600010, 0x0ff00f38, "tinsr%6-7w%c %16-19g, %12-15r, %0-2d"},
  {ARM_CEXT_XSCALE, 0x0e000110, 0x0ff00fff, "tmcr%c %16-19G, %12-15r"},
  {ARM_CEXT_XSCALE, 0x0c400000, 0x0ff00ff0, "tmcrr%c %0-3g, %12-15r, %16-19r"},
  {ARM_CEXT_XSCALE, 0x0e2c0010, 0x0ffc0e10, "tmia%17?tb%16?tb%c %5-8g, %0-3r, %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e200010, 0x0fff0e10, "tmia%c %5-8g, %0-3r, %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e280010, 0x0fff0e10, "tmiaph%c %5-8g, %0-3r, %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e100030, 0x0f300fff, "tmovmsk%22-23w%c %12-15r, %16-19g"},
  {ARM_CEXT_XSCALE, 0x0e100110, 0x0ff00ff0, "tmrc%c %12-15r, %16-19G"},
  {ARM_CEXT_XSCALE, 0x0c500000, 0x0ff00ff0, "tmrrc%c %12-15r, %16-19r, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e130150, 0x0f3f0fff, "torc%22-23w%c %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e120190, 0x0f3f0fff, "torvsc%22-23w%c %12-15r"},
  {ARM_CEXT_XSCALE, 0x0e2001c0, 0x0f300fff, "wabs%22-23w%c %12-15g, %16-19g"},
  {ARM_CEXT_XSCALE, 0x0e0001c0, 0x0f300fff, "wacc%22-23w%c %12-15g, %16-19g"},
  {ARM_CEXT_XSCALE, 0x0e000180, 0x0f000ff0, "wadd%20-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e2001a0, 0x0fb00ff0, "waddbhus%22?ml%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0ea001a0, 0x0ff00ff0, "waddsubhx%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e000020, 0x0f800ff0, "waligni%c %12-15g, %16-19g, %0-3g, %20-22d"},
  {ARM_CEXT_XSCALE, 0x0e800020, 0x0fc00ff0, "walignr%20-21d%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e200000, 0x0fe00ff0, "wand%20'n%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e800000, 0x0fa00ff0, "wavg2%22?hb%20'r%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e400000, 0x0fe00ff0, "wavg4%20'r%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e000060, 0x0f300ff0, "wcmpeq%22-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e100060, 0x0f100ff0, "wcmpgt%21?su%22-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0xfc500100, 0xfe500f00, "wldrd %12-15g, %r"},
  {ARM_CEXT_XSCALE, 0xfc100100, 0xfe500f00, "wldrw %12-15G, %A"},
  {ARM_CEXT_XSCALE, 0x0c100000, 0x0e100e00, "wldr%L%c %12-15g, %l"},
  {ARM_CEXT_XSCALE, 0x0e400100, 0x0fc00ff0, "wmac%21?su%20'z%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e800100, 0x0fc00ff0, "wmadd%21?su%20'x%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0ec00100, 0x0fd00ff0, "wmadd%21?sun%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e000160, 0x0f100ff0, "wmax%21?su%22-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e000080, 0x0f100fe0, "wmerge%c %12-15g, %16-19g, %0-3g, %21-23d"},
  {ARM_CEXT_XSCALE, 0x0e0000a0, 0x0f800ff0, "wmia%21?tb%20?tb%22'n%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e800120, 0x0f800ff0, "wmiaw%21?tb%20?tb%22'n%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e100160, 0x0f100ff0, "wmin%21?su%22-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e000100, 0x0fc00ff0, "wmul%21?su%20?ml%23'r%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0ed00100, 0x0fd00ff0, "wmul%21?sumr%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0ee000c0, 0x0fe00ff0, "wmulwsm%20`r%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0ec000c0, 0x0fe00ff0, "wmulwum%20`r%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0eb000c0, 0x0ff00ff0, "wmulwl%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e8000a0, 0x0f800ff0, "wqmia%21?tb%20?tb%22'n%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e100080, 0x0fd00ff0, "wqmulm%21'r%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0ec000e0, 0x0fd00ff0, "wqmulwm%21'r%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e000000, 0x0ff00ff0, "wor%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e000080, 0x0f000ff0, "wpack%20-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0xfe300040, 0xff300ef0, "wror%22-23w %12-15g, %16-19g, %i"},
  {ARM_CEXT_XSCALE, 0x0e300040, 0x0f300ff0, "wror%22-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e300140, 0x0f300ff0, "wror%22-23wg%c %12-15g, %16-19g, %0-3G"},
  {ARM_CEXT_XSCALE, 0x0e000120, 0x0fa00ff0, "wsad%22?hb%20'z%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e0001e0, 0x0f000ff0, "wshufh%c %12-15g, %16-19g, %Z"},
  {ARM_CEXT_XSCALE, 0xfe100040, 0xff300ef0, "wsll%22-23w %12-15g, %16-19g, %i"},
  {ARM_CEXT_XSCALE, 0x0e100040, 0x0f300ff0, "wsll%22-23w%8'g%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e100148, 0x0f300ffc, "wsll%22-23w%8'g%c %12-15g, %16-19g, %0-3G"},
  {ARM_CEXT_XSCALE, 0xfe000040, 0xff300ef0, "wsra%22-23w %12-15g, %16-19g, %i"},
  {ARM_CEXT_XSCALE, 0x0e000040, 0x0f300ff0, "wsra%22-23w%8'g%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e000148, 0x0f300ffc, "wsra%22-23w%8'g%c %12-15g, %16-19g, %0-3G"},
  {ARM_CEXT_XSCALE, 0xfe200040, 0xff300ef0, "wsrl%22-23w %12-15g, %16-19g, %i"},
  {ARM_CEXT_XSCALE, 0x0e200040, 0x0f300ff0, "wsrl%22-23w%8'g%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e200148, 0x0f300ffc, "wsrl%22-23w%8'g%c %12-15g, %16-19g, %0-3G"},
  {ARM_CEXT_XSCALE, 0xfc400100, 0xfe500f00, "wstrd %12-15g, %r"},
  {ARM_CEXT_XSCALE, 0xfc000100, 0xfe500f00, "wstrw %12-15G, %A"},
  {ARM_CEXT_XSCALE, 0x0c000000, 0x0e100e00, "wstr%L%c %12-15g, %l"},
  {ARM_CEXT_XSCALE, 0x0e0001a0, 0x0f000ff0, "wsub%20-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0ed001c0, 0x0ff00ff0, "wsubaddhx%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e1001c0, 0x0f300ff0, "wabsdiff%22-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e0000c0, 0x0fd00fff, "wunpckeh%21?sub%c %12-15g, %16-19g"},
  {ARM_CEXT_XSCALE, 0x0e4000c0, 0x0fd00fff, "wunpckeh%21?suh%c %12-15g, %16-19g"},
  {ARM_CEXT_XSCALE, 0x0e8000c0, 0x0fd00fff, "wunpckeh%21?suw%c %12-15g, %16-19g"},
  {ARM_CEXT_XSCALE, 0x0e0000e0, 0x0f100fff, "wunpckel%21?su%22-23w%c %12-15g, %16-19g"},
  {ARM_CEXT_XSCALE, 0x0e1000c0, 0x0f300ff0, "wunpckih%22-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e1000e0, 0x0f300ff0, "wunpckil%22-23w%c %12-15g, %16-19g, %0-3g"},
  {ARM_CEXT_XSCALE, 0x0e100000, 0x0ff00ff0, "wxor%c %12-15g, %16-19g, %0-3g"},
  { 0, SENTINEL_IWMMXT_END, 0, "" },

  /* Floating point coprocessor (FPA) instructions.  */
  {FPU_FPA_EXT_V1, 0x0e000100, 0x0ff08f10, "adf%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e100100, 0x0ff08f10, "muf%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e200100, 0x0ff08f10, "suf%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e300100, 0x0ff08f10, "rsf%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e400100, 0x0ff08f10, "dvf%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e500100, 0x0ff08f10, "rdf%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e600100, 0x0ff08f10, "pow%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e700100, 0x0ff08f10, "rpw%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e800100, 0x0ff08f10, "rmf%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e900100, 0x0ff08f10, "fml%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ea00100, 0x0ff08f10, "fdv%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0eb00100, 0x0ff08f10, "frd%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ec00100, 0x0ff08f10, "pol%c%P%R %12-14f, %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e008100, 0x0ff08f10, "mvf%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e108100, 0x0ff08f10, "mnf%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e208100, 0x0ff08f10, "abs%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e308100, 0x0ff08f10, "rnd%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e408100, 0x0ff08f10, "sqt%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e508100, 0x0ff08f10, "log%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e608100, 0x0ff08f10, "lgn%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e708100, 0x0ff08f10, "exp%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e808100, 0x0ff08f10, "sin%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e908100, 0x0ff08f10, "cos%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ea08100, 0x0ff08f10, "tan%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0eb08100, 0x0ff08f10, "asn%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ec08100, 0x0ff08f10, "acs%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ed08100, 0x0ff08f10, "atn%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ee08100, 0x0ff08f10, "urd%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ef08100, 0x0ff08f10, "nrm%c%P%R %12-14f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0e000110, 0x0ff00f1f, "flt%c%P%R %16-18f, %12-15r"},
  {FPU_FPA_EXT_V1, 0x0e100110, 0x0fff0f98, "fix%c%R %12-15r, %0-2f"},
  {FPU_FPA_EXT_V1, 0x0e200110, 0x0fff0fff, "wfs%c %12-15r"},
  {FPU_FPA_EXT_V1, 0x0e300110, 0x0fff0fff, "rfs%c %12-15r"},
  {FPU_FPA_EXT_V1, 0x0e400110, 0x0fff0fff, "wfc%c %12-15r"},
  {FPU_FPA_EXT_V1, 0x0e500110, 0x0fff0fff, "rfc%c %12-15r"},
  {FPU_FPA_EXT_V1, 0x0e90f110, 0x0ff8fff0, "cmf%c %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0eb0f110, 0x0ff8fff0, "cnf%c %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ed0f110, 0x0ff8fff0, "cmfe%c %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0ef0f110, 0x0ff8fff0, "cnfe%c %16-18f, %0-3f"},
  {FPU_FPA_EXT_V1, 0x0c000100, 0x0e100f00, "stf%c%Q %12-14f, %A"},
  {FPU_FPA_EXT_V1, 0x0c100100, 0x0e100f00, "ldf%c%Q %12-14f, %A"},
  {FPU_FPA_EXT_V2, 0x0c000200, 0x0e100f00, "sfm%c %12-14f, %F, %A"},
  {FPU_FPA_EXT_V2, 0x0c100200, 0x0e100f00, "lfm%c %12-14f, %F, %A"},

  /* Register load/store.  */
  {FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d2d0b00, 0x0fbf0f01, "vpush%c %B"},
  {FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d200b00, 0x0fb00f01, "vstmdb%c %16-19r!, %B"},
  {FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d300b00, 0x0fb00f01, "vldmdb%c %16-19r!, %B"},
  {FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0c800b00, 0x0f900f01, "vstmia%c %16-19r%21'!, %B"},
  {FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0cbd0b00, 0x0fbf0f01, "vpop%c %B"},
  {FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0c900b00, 0x0f900f01, "vldmia%c %16-19r%21'!, %B"},
  {FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d000b00, 0x0f300f00, "vstr%c %12-15,22D, %A"},
  {FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d100b00, 0x0f300f00, "vldr%c %12-15,22D, %A"},
  {FPU_VFP_EXT_V1xD, 0x0d2d0a00, 0x0fbf0f00, "vpush%c %y3"},
  {FPU_VFP_EXT_V1xD, 0x0d200a00, 0x0fb00f00, "vstmdb%c %16-19r!, %y3"},
  {FPU_VFP_EXT_V1xD, 0x0d300a00, 0x0fb00f00, "vldmdb%c %16-19r!, %y3"},
  {FPU_VFP_EXT_V1xD, 0x0c800a00, 0x0f900f00, "vstmia%c %16-19r%21'!, %y3"},
  {FPU_VFP_EXT_V1xD, 0x0cbd0a00, 0x0fbf0f00, "vpop%c %y3"},
  {FPU_VFP_EXT_V1xD, 0x0c900a00, 0x0f900f00, "vldmia%c %16-19r%21'!, %y3"},
  {FPU_VFP_EXT_V1xD, 0x0d000a00, 0x0f300f00, "vstr%c %y1, %A"},
  {FPU_VFP_EXT_V1xD, 0x0d100a00, 0x0f300f00, "vldr%c %y1, %A"},

  {FPU_VFP_EXT_V1xD, 0x0d200b01, 0x0fb00f01, "fstmdbx%c %16-19r!, %z3 ;@ Deprecated"},
  {FPU_VFP_EXT_V1xD, 0x0d300b01, 0x0fb00f01, "fldmdbx%c %16-19r!, %z3 ;@ Deprecated"},
  {FPU_VFP_EXT_V1xD, 0x0c800b01, 0x0f900f01, "fstmiax%c %16-19r%21'!, %z3 ;@ Deprecated"},
  {FPU_VFP_EXT_V1xD, 0x0c900b01, 0x0f900f01, "fldmiax%c %16-19r%21'!, %z3 ;@ Deprecated"},

  /* Data transfer between ARM and NEON registers.  */
  {FPU_NEON_EXT_V1, 0x0e800b10, 0x0ff00f70, "vdup%c.32 %16-19,7D, %12-15r"},
  {FPU_NEON_EXT_V1, 0x0e800b30, 0x0ff00f70, "vdup%c.16 %16-19,7D, %12-15r"},
  {FPU_NEON_EXT_V1, 0x0ea00b10, 0x0ff00f70, "vdup%c.32 %16-19,7Q, %12-15r"},
  {FPU_NEON_EXT_V1, 0x0ea00b30, 0x0ff00f70, "vdup%c.16 %16-19,7Q, %12-15r"},
  {FPU_NEON_EXT_V1, 0x0ec00b10, 0x0ff00f70, "vdup%c.8 %16-19,7D, %12-15r"},
  {FPU_NEON_EXT_V1, 0x0ee00b10, 0x0ff00f70, "vdup%c.8 %16-19,7Q, %12-15r"},
  {FPU_NEON_EXT_V1, 0x0c400b10, 0x0ff00fd0, "vmov%c %0-3,5D, %12-15r, %16-19r"},
  {FPU_NEON_EXT_V1, 0x0c500b10, 0x0ff00fd0, "vmov%c %12-15r, %16-19r, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0x0e000b10, 0x0fd00f70, "vmov%c.32 %16-19,7D[%21d], %12-15r"},
  {FPU_NEON_EXT_V1, 0x0e100b10, 0x0f500f70, "vmov%c.32 %12-15r, %16-19,7D[%21d]"},
  {FPU_NEON_EXT_V1, 0x0e000b30, 0x0fd00f30, "vmov%c.16 %16-19,7D[%6,21d], %12-15r"},
  {FPU_NEON_EXT_V1, 0x0e100b30, 0x0f500f30, "vmov%c.%23?us16 %12-15r, %16-19,7D[%6,21d]"},
  {FPU_NEON_EXT_V1, 0x0e400b10, 0x0fd00f10, "vmov%c.8 %16-19,7D[%5,6,21d], %12-15r"},
  {FPU_NEON_EXT_V1, 0x0e500b10, 0x0f500f10, "vmov%c.%23?us8 %12-15r, %16-19,7D[%5,6,21d]"},
  /* Half-precision conversion instructions.  */
  {FPU_VFP_EXT_ARMV8, 0x0eb20b40, 0x0fbf0f50, "vcvt%7?tb%c.f64.f16 %z1, %y0"},
  {FPU_VFP_EXT_ARMV8, 0x0eb30b40, 0x0fbf0f50, "vcvt%7?tb%c.f16.f64 %y1, %z0"},
  {FPU_VFP_EXT_FP16, 0x0eb20a40, 0x0fbf0f50, "vcvt%7?tb%c.f32.f16 %y1, %y0"},
  {FPU_VFP_EXT_FP16, 0x0eb30a40, 0x0fbf0f50, "vcvt%7?tb%c.f16.f32 %y1, %y0"},

  /* Floating point coprocessor (VFP) instructions.  */
  {FPU_VFP_EXT_V1xD, 0x0ee00a10, 0x0fff0fff, "vmsr%c fpsid, %12-15r"},
  {FPU_VFP_EXT_V1xD, 0x0ee10a10, 0x0fff0fff, "vmsr%c fpscr, %12-15r"},
  {FPU_VFP_EXT_V1xD, 0x0ee60a10, 0x0fff0fff, "vmsr%c mvfr1, %12-15r"},
  {FPU_VFP_EXT_V1xD, 0x0ee70a10, 0x0fff0fff, "vmsr%c mvfr0, %12-15r"},
  {FPU_VFP_EXT_V1xD, 0x0ee80a10, 0x0fff0fff, "vmsr%c fpexc, %12-15r"},
  {FPU_VFP_EXT_V1xD, 0x0ee90a10, 0x0fff0fff, "vmsr%c fpinst, %12-15r @ Impl def"},
  {FPU_VFP_EXT_V1xD, 0x0eea0a10, 0x0fff0fff, "vmsr%c fpinst2, %12-15r @ Impl def"},
  {FPU_VFP_EXT_V1xD, 0x0ef00a10, 0x0fff0fff, "vmrs%c %12-15r, fpsid"},
  {FPU_VFP_EXT_V1xD, 0x0ef1fa10, 0x0fffffff, "vmrs%c APSR_nzcv, fpscr"},
  {FPU_VFP_EXT_V1xD, 0x0ef10a10, 0x0fff0fff, "vmrs%c %12-15r, fpscr"},
  {FPU_VFP_EXT_V1xD, 0x0ef60a10, 0x0fff0fff, "vmrs%c %12-15r, mvfr1"},
  {FPU_VFP_EXT_V1xD, 0x0ef70a10, 0x0fff0fff, "vmrs%c %12-15r, mvfr0"},
  {FPU_VFP_EXT_V1xD, 0x0ef80a10, 0x0fff0fff, "vmrs%c %12-15r, fpexc"},
  {FPU_VFP_EXT_V1xD, 0x0ef90a10, 0x0fff0fff, "vmrs%c %12-15r, fpinst @ Impl def"},
  {FPU_VFP_EXT_V1xD, 0x0efa0a10, 0x0fff0fff, "vmrs%c %12-15r, fpinst2 @ Impl def"},
  {FPU_VFP_EXT_V1, 0x0e000b10, 0x0fd00fff, "vmov%c.32 %z2[%21d], %12-15r"},
  {FPU_VFP_EXT_V1, 0x0e100b10, 0x0fd00fff, "vmov%c.32 %12-15r, %z2[%21d]"},
  {FPU_VFP_EXT_V1xD, 0x0ee00a10, 0x0ff00fff, "vmsr%c <impl def %16-19x>, %12-15r"},
  {FPU_VFP_EXT_V1xD, 0x0ef00a10, 0x0ff00fff, "vmrs%c %12-15r, <impl def %16-19x>"},
  {FPU_VFP_EXT_V1xD, 0x0e000a10, 0x0ff00f7f, "vmov%c %y2, %12-15r"},
  {FPU_VFP_EXT_V1xD, 0x0e100a10, 0x0ff00f7f, "vmov%c %12-15r, %y2"},
  {FPU_VFP_EXT_V1xD, 0x0eb50a40, 0x0fbf0f70, "vcmp%7'e%c.f32 %y1, #0.0"},
  {FPU_VFP_EXT_V1, 0x0eb50b40, 0x0fbf0f70, "vcmp%7'e%c.f64 %z1, #0.0"},
  {FPU_VFP_EXT_V1xD, 0x0eb00a40, 0x0fbf0fd0, "vmov%c.f32 %y1, %y0"},
  {FPU_VFP_EXT_V1xD, 0x0eb00ac0, 0x0fbf0fd0, "vabs%c.f32 %y1, %y0"},
  {FPU_VFP_EXT_V1, 0x0eb00b40, 0x0fbf0fd0, "vmov%c.f64 %z1, %z0"},
  {FPU_VFP_EXT_V1, 0x0eb00bc0, 0x0fbf0fd0, "vabs%c.f64 %z1, %z0"},
  {FPU_VFP_EXT_V1xD, 0x0eb10a40, 0x0fbf0fd0, "vneg%c.f32 %y1, %y0"},
  {FPU_VFP_EXT_V1xD, 0x0eb10ac0, 0x0fbf0fd0, "vsqrt%c.f32 %y1, %y0"},
  {FPU_VFP_EXT_V1, 0x0eb10b40, 0x0fbf0fd0, "vneg%c.f64 %z1, %z0"},
  {FPU_VFP_EXT_V1, 0x0eb10bc0, 0x0fbf0fd0, "vsqrt%c.f64 %z1, %z0"},
  {FPU_VFP_EXT_V1, 0x0eb70ac0, 0x0fbf0fd0, "vcvt%c.f64.f32 %z1, %y0"},
  {FPU_VFP_EXT_V1, 0x0eb70bc0, 0x0fbf0fd0, "vcvt%c.f32.f64 %y1, %z0"},
  {FPU_VFP_EXT_V1xD, 0x0eb80a40, 0x0fbf0f50, "vcvt%c.f32.%7?su32 %y1, %y0"},
  {FPU_VFP_EXT_V1, 0x0eb80b40, 0x0fbf0f50, "vcvt%c.f64.%7?su32 %z1, %y0"},
  {FPU_VFP_EXT_V1xD, 0x0eb40a40, 0x0fbf0f50, "vcmp%7'e%c.f32 %y1, %y0"},
  {FPU_VFP_EXT_V1, 0x0eb40b40, 0x0fbf0f50, "vcmp%7'e%c.f64 %z1, %z0"},
  {FPU_VFP_EXT_V3xD, 0x0eba0a40, 0x0fbe0f50, "vcvt%c.f32.%16?us%7?31%7?26 %y1, %y1, %5,0-3k"},
  {FPU_VFP_EXT_V3, 0x0eba0b40, 0x0fbe0f50, "vcvt%c.f64.%16?us%7?31%7?26 %z1, %z1, %5,0-3k"},
  {FPU_VFP_EXT_V1xD, 0x0ebc0a40, 0x0fbe0f50, "vcvt%7`r%c.%16?su32.f32 %y1, %y0"},
  {FPU_VFP_EXT_V1, 0x0ebc0b40, 0x0fbe0f50, "vcvt%7`r%c.%16?su32.f64 %y1, %z0"},
  {FPU_VFP_EXT_V3xD, 0x0ebe0a40, 0x0fbe0f50, "vcvt%c.%16?us%7?31%7?26.f32 %y1, %y1, %5,0-3k"},
  {FPU_VFP_EXT_V3, 0x0ebe0b40, 0x0fbe0f50, "vcvt%c.%16?us%7?31%7?26.f64 %z1, %z1, %5,0-3k"},
  {FPU_VFP_EXT_V1, 0x0c500b10, 0x0fb00ff0, "vmov%c %12-15r, %16-19r, %z0"},
  {FPU_VFP_EXT_V3xD, 0x0eb00a00, 0x0fb00ff0, "vmov%c.f32 %y1, %0-3,16-19d"},
  {FPU_VFP_EXT_V3, 0x0eb00b00, 0x0fb00ff0, "vmov%c.f64 %z1, %0-3,16-19d"},
  {FPU_VFP_EXT_V2, 0x0c400a10, 0x0ff00fd0, "vmov%c %y4, %12-15r, %16-19r"},
  {FPU_VFP_EXT_V2, 0x0c400b10, 0x0ff00fd0, "vmov%c %z0, %12-15r, %16-19r"},
  {FPU_VFP_EXT_V2, 0x0c500a10, 0x0ff00fd0, "vmov%c %12-15r, %16-19r, %y4"},
  {FPU_VFP_EXT_V1xD, 0x0e000a00, 0x0fb00f50, "vmla%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1xD, 0x0e000a40, 0x0fb00f50, "vmls%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1, 0x0e000b00, 0x0fb00f50, "vmla%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_V1, 0x0e000b40, 0x0fb00f50, "vmls%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_V1xD, 0x0e100a00, 0x0fb00f50, "vnmls%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1xD, 0x0e100a40, 0x0fb00f50, "vnmla%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1, 0x0e100b00, 0x0fb00f50, "vnmls%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_V1, 0x0e100b40, 0x0fb00f50, "vnmla%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_V1xD, 0x0e200a00, 0x0fb00f50, "vmul%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1xD, 0x0e200a40, 0x0fb00f50, "vnmul%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1, 0x0e200b00, 0x0fb00f50, "vmul%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_V1, 0x0e200b40, 0x0fb00f50, "vnmul%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_V1xD, 0x0e300a00, 0x0fb00f50, "vadd%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1xD, 0x0e300a40, 0x0fb00f50, "vsub%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1, 0x0e300b00, 0x0fb00f50, "vadd%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_V1, 0x0e300b40, 0x0fb00f50, "vsub%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_V1xD, 0x0e800a00, 0x0fb00f50, "vdiv%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_V1, 0x0e800b00, 0x0fb00f50, "vdiv%c.f64 %z1, %z2, %z0"},

  /* Cirrus coprocessor instructions.  */
  {ARM_CEXT_MAVERICK, 0x0d100400, 0x0f500f00, "cfldrs%c mvf%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0c100400, 0x0f500f00, "cfldrs%c mvf%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0d500400, 0x0f500f00, "cfldrd%c mvd%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0c500400, 0x0f500f00, "cfldrd%c mvd%12-15d, %A"}, 
  {ARM_CEXT_MAVERICK, 0x0d100500, 0x0f500f00, "cfldr32%c mvfx%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0c100500, 0x0f500f00, "cfldr32%c mvfx%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0d500500, 0x0f500f00, "cfldr64%c mvdx%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0c500500, 0x0f500f00, "cfldr64%c mvdx%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0d000400, 0x0f500f00, "cfstrs%c mvf%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0c000400, 0x0f500f00, "cfstrs%c mvf%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0d400400, 0x0f500f00, "cfstrd%c mvd%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0c400400, 0x0f500f00, "cfstrd%c mvd%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0d000500, 0x0f500f00, "cfstr32%c mvfx%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0c000500, 0x0f500f00, "cfstr32%c mvfx%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0d400500, 0x0f500f00, "cfstr64%c mvdx%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0c400500, 0x0f500f00, "cfstr64%c mvdx%12-15d, %A"},
  {ARM_CEXT_MAVERICK, 0x0e000450, 0x0ff00ff0, "cfmvsr%c mvf%16-19d, %12-15r"},
  {ARM_CEXT_MAVERICK, 0x0e100450, 0x0ff00ff0, "cfmvrs%c %12-15r, mvf%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000410, 0x0ff00ff0, "cfmvdlr%c mvd%16-19d, %12-15r"},
  {ARM_CEXT_MAVERICK, 0x0e100410, 0x0ff00ff0, "cfmvrdl%c %12-15r, mvd%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000430, 0x0ff00ff0, "cfmvdhr%c mvd%16-19d, %12-15r"},
  {ARM_CEXT_MAVERICK, 0x0e100430, 0x0ff00fff, "cfmvrdh%c %12-15r, mvd%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000510, 0x0ff00fff, "cfmv64lr%c mvdx%16-19d, %12-15r"},
  {ARM_CEXT_MAVERICK, 0x0e100510, 0x0ff00fff, "cfmvr64l%c %12-15r, mvdx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000530, 0x0ff00fff, "cfmv64hr%c mvdx%16-19d, %12-15r"},
  {ARM_CEXT_MAVERICK, 0x0e100530, 0x0ff00fff, "cfmvr64h%c %12-15r, mvdx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e200440, 0x0ff00fff, "cfmval32%c mvax%12-15d, mvfx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e100440, 0x0ff00fff, "cfmv32al%c mvfx%12-15d, mvax%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e200460, 0x0ff00fff, "cfmvam32%c mvax%12-15d, mvfx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e100460, 0x0ff00fff, "cfmv32am%c mvfx%12-15d, mvax%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e200480, 0x0ff00fff, "cfmvah32%c mvax%12-15d, mvfx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e100480, 0x0ff00fff, "cfmv32ah%c mvfx%12-15d, mvax%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e2004a0, 0x0ff00fff, "cfmva32%c mvax%12-15d, mvfx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e1004a0, 0x0ff00fff, "cfmv32a%c mvfx%12-15d, mvax%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e2004c0, 0x0ff00fff, "cfmva64%c mvax%12-15d, mvdx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e1004c0, 0x0ff00fff, "cfmv64a%c mvdx%12-15d, mvax%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e2004e0, 0x0fff0fff, "cfmvsc32%c dspsc, mvdx%12-15d"},
  {ARM_CEXT_MAVERICK, 0x0e1004e0, 0x0fff0fff, "cfmv32sc%c mvdx%12-15d, dspsc"},
  {ARM_CEXT_MAVERICK, 0x0e000400, 0x0ff00fff, "cfcpys%c mvf%12-15d, mvf%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000420, 0x0ff00fff, "cfcpyd%c mvd%12-15d, mvd%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000460, 0x0ff00fff, "cfcvtsd%c mvd%12-15d, mvf%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000440, 0x0ff00fff, "cfcvtds%c mvf%12-15d, mvd%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000480, 0x0ff00fff, "cfcvt32s%c mvf%12-15d, mvfx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e0004a0, 0x0ff00fff, "cfcvt32d%c mvd%12-15d, mvfx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e0004c0, 0x0ff00fff, "cfcvt64s%c mvf%12-15d, mvdx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e0004e0, 0x0ff00fff, "cfcvt64d%c mvd%12-15d, mvdx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e100580, 0x0ff00fff, "cfcvts32%c mvfx%12-15d, mvf%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e1005a0, 0x0ff00fff, "cfcvtd32%c mvfx%12-15d, mvd%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e1005c0, 0x0ff00fff, "cftruncs32%c mvfx%12-15d, mvf%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e1005e0, 0x0ff00fff, "cftruncd32%c mvfx%12-15d, mvd%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e000550, 0x0ff00ff0, "cfrshl32%c mvfx%16-19d, mvfx%0-3d, %12-15r"},
  {ARM_CEXT_MAVERICK, 0x0e000570, 0x0ff00ff0, "cfrshl64%c mvdx%16-19d, mvdx%0-3d, %12-15r"},
  {ARM_CEXT_MAVERICK, 0x0e000500, 0x0ff00f10, "cfsh32%c mvfx%12-15d, mvfx%16-19d, %I"},
  {ARM_CEXT_MAVERICK, 0x0e200500, 0x0ff00f10, "cfsh64%c mvdx%12-15d, mvdx%16-19d, %I"},
  {ARM_CEXT_MAVERICK, 0x0e100490, 0x0ff00ff0, "cfcmps%c %12-15r, mvf%16-19d, mvf%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e1004b0, 0x0ff00ff0, "cfcmpd%c %12-15r, mvd%16-19d, mvd%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e100590, 0x0ff00ff0, "cfcmp32%c %12-15r, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e1005b0, 0x0ff00ff0, "cfcmp64%c %12-15r, mvdx%16-19d, mvdx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e300400, 0x0ff00fff, "cfabss%c mvf%12-15d, mvf%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e300420, 0x0ff00fff, "cfabsd%c mvd%12-15d, mvd%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e300440, 0x0ff00fff, "cfnegs%c mvf%12-15d, mvf%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e300460, 0x0ff00fff, "cfnegd%c mvd%12-15d, mvd%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e300480, 0x0ff00ff0, "cfadds%c mvf%12-15d, mvf%16-19d, mvf%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e3004a0, 0x0ff00ff0, "cfaddd%c mvd%12-15d, mvd%16-19d, mvd%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e3004c0, 0x0ff00ff0, "cfsubs%c mvf%12-15d, mvf%16-19d, mvf%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e3004e0, 0x0ff00ff0, "cfsubd%c mvd%12-15d, mvd%16-19d, mvd%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e100400, 0x0ff00ff0, "cfmuls%c mvf%12-15d, mvf%16-19d, mvf%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e100420, 0x0ff00ff0, "cfmuld%c mvd%12-15d, mvd%16-19d, mvd%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e300500, 0x0ff00fff, "cfabs32%c mvfx%12-15d, mvfx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e300520, 0x0ff00fff, "cfabs64%c mvdx%12-15d, mvdx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e300540, 0x0ff00fff, "cfneg32%c mvfx%12-15d, mvfx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e300560, 0x0ff00fff, "cfneg64%c mvdx%12-15d, mvdx%16-19d"},
  {ARM_CEXT_MAVERICK, 0x0e300580, 0x0ff00ff0, "cfadd32%c mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e3005a0, 0x0ff00ff0, "cfadd64%c mvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e3005c0, 0x0ff00ff0, "cfsub32%c mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e3005e0, 0x0ff00ff0, "cfsub64%c mvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e100500, 0x0ff00ff0, "cfmul32%c mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e100520, 0x0ff00ff0, "cfmul64%c mvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e100540, 0x0ff00ff0, "cfmac32%c mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e100560, 0x0ff00ff0, "cfmsc32%c mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e000600, 0x0ff00f10, "cfmadd32%c mvax%5-7d, mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e100600, 0x0ff00f10, "cfmsub32%c mvax%5-7d, mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e200600, 0x0ff00f10, "cfmadda32%c mvax%5-7d, mvax%12-15d, mvfx%16-19d, mvfx%0-3d"},
  {ARM_CEXT_MAVERICK, 0x0e300600, 0x0ff00f10, "cfmsuba32%c mvax%5-7d, mvax%12-15d, mvfx%16-19d, mvfx%0-3d"},

  /* VFP Fused multiply add instructions.  */
  {FPU_VFP_EXT_FMA, 0x0ea00a00, 0x0fb00f50, "vfma%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_FMA, 0x0ea00b00, 0x0fb00f50, "vfma%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_FMA, 0x0ea00a40, 0x0fb00f50, "vfms%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_FMA, 0x0ea00b40, 0x0fb00f50, "vfms%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_FMA, 0x0e900a40, 0x0fb00f50, "vfnma%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_FMA, 0x0e900b40, 0x0fb00f50, "vfnma%c.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_FMA, 0x0e900a00, 0x0fb00f50, "vfnms%c.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_FMA, 0x0e900b00, 0x0fb00f50, "vfnms%c.f64 %z1, %z2, %z0"},

  /* FP v5.  */
  {FPU_VFP_EXT_ARMV8, 0xfe000a00, 0xff800f00, "vsel%20-21c%u.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_ARMV8, 0xfe000b00, 0xff800f00, "vsel%20-21c%u.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_ARMV8, 0xfe800a00, 0xffb00f40, "vmaxnm%u.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_ARMV8, 0xfe800b00, 0xffb00f40, "vmaxnm%u.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_ARMV8, 0xfe800a40, 0xffb00f40, "vminnm%u.f32 %y1, %y2, %y0"},
  {FPU_VFP_EXT_ARMV8, 0xfe800b40, 0xffb00f40, "vminnm%u.f64 %z1, %z2, %z0"},
  {FPU_VFP_EXT_ARMV8, 0xfebc0a40, 0xffbc0f50, "vcvt%16-17?mpna%u.%7?su32.f32 %y1, %y0"},
  {FPU_VFP_EXT_ARMV8, 0xfebc0b40, 0xffbc0f50, "vcvt%16-17?mpna%u.%7?su32.f64 %y1, %z0"},
  {FPU_VFP_EXT_ARMV8, 0x0eb60a40, 0x0fbe0f50, "vrint%7,16??xzr%c.f32.f32 %y1, %y0"},
  {FPU_VFP_EXT_ARMV8, 0x0eb60b40, 0x0fbe0f50, "vrint%7,16??xzr%c.f64.f64 %z1, %z0"},
  {FPU_VFP_EXT_ARMV8, 0xfeb80a40, 0xffbc0f50, "vrint%16-17?mpna%u.f32.f32 %y1, %y0"},
  {FPU_VFP_EXT_ARMV8, 0xfeb80b40, 0xffbc0f50, "vrint%16-17?mpna%u.f64.f64 %z1, %z0"},

  /* Generic coprocessor instructions.  */
  { 0, SENTINEL_GENERIC_START, 0, "" },
  {ARM_EXT_V5E, 0x0c400000, 0x0ff00000, "mcrr%c %8-11d, %4-7d, %12-15R, %16-19r, cr%0-3d"},
  {ARM_EXT_V5E, 0x0c500000, 0x0ff00000, "mrrc%c %8-11d, %4-7d, %12-15Ru, %16-19Ru, cr%0-3d"},
  {ARM_EXT_V2, 0x0e000000, 0x0f000010, "cdp%c %8-11d, %20-23d, cr%12-15d, cr%16-19d, cr%0-3d, {%5-7d}"},
  {ARM_EXT_V2, 0x0e10f010, 0x0f10f010, "mrc%c %8-11d, %21-23d, APSR_nzcv, cr%16-19d, cr%0-3d, {%5-7d}"},
  {ARM_EXT_V2, 0x0e100010, 0x0f100010, "mrc%c %8-11d, %21-23d, %12-15r, cr%16-19d, cr%0-3d, {%5-7d}"},
  {ARM_EXT_V2, 0x0e000010, 0x0f100010, "mcr%c %8-11d, %21-23d, %12-15R, cr%16-19d, cr%0-3d, {%5-7d}"},
  {ARM_EXT_V2, 0x0c000000, 0x0e100000, "stc%22'l%c %8-11d, cr%12-15d, %A"},
  {ARM_EXT_V2, 0x0c100000, 0x0e100000, "ldc%22'l%c %8-11d, cr%12-15d, %A"},

  /* V6 coprocessor instructions.  */
  {ARM_EXT_V6, 0xfc500000, 0xfff00000, "mrrc2%c %8-11d, %4-7d, %12-15Ru, %16-19Ru, cr%0-3d"},
  {ARM_EXT_V6, 0xfc400000, 0xfff00000, "mcrr2%c %8-11d, %4-7d, %12-15R, %16-19R, cr%0-3d"},

  /* V5 coprocessor instructions.  */
  {ARM_EXT_V5, 0xfc100000, 0xfe100000, "ldc2%22'l%c %8-11d, cr%12-15d, %A"},
  {ARM_EXT_V5, 0xfc000000, 0xfe100000, "stc2%22'l%c %8-11d, cr%12-15d, %A"},
  {ARM_EXT_V5, 0xfe000000, 0xff000010, "cdp2%c %8-11d, %20-23d, cr%12-15d, cr%16-19d, cr%0-3d, {%5-7d}"},
  {ARM_EXT_V5, 0xfe000010, 0xff100010, "mcr2%c %8-11d, %21-23d, %12-15R, cr%16-19d, cr%0-3d, {%5-7d}"},
  {ARM_EXT_V5, 0xfe100010, 0xff100010, "mrc2%c %8-11d, %21-23d, %12-15r, cr%16-19d, cr%0-3d, {%5-7d}"},

  {0, 0, 0, 0}
};

/* Neon opcode table:  This does not encode the top byte -- that is
   checked by the print_insn_neon routine, as it depends on whether we are
   doing thumb32 or arm32 disassembly.  */

/* print_insn_neon recognizes the following format control codes:

   %%			%

   %c			print condition code
   %u			print condition code (unconditional in ARM mode,
                          UNPREDICTABLE if not AL in Thumb)
   %A			print v{st,ld}[1234] operands
   %B			print v{st,ld}[1234] any one operands
   %C			print v{st,ld}[1234] single->all operands
   %D			print scalar
   %E			print vmov, vmvn, vorr, vbic encoded constant
   %F			print vtbl,vtbx register list

   %<bitfield>r		print as an ARM register
   %<bitfield>d		print the bitfield in decimal
   %<bitfield>e         print the 2^N - bitfield in decimal
   %<bitfield>D		print as a NEON D register
   %<bitfield>Q		print as a NEON Q register
   %<bitfield>R		print as a NEON D or Q register
   %<bitfield>Sn	print byte scaled width limited by n
   %<bitfield>Tn	print short scaled width limited by n
   %<bitfield>Un	print long scaled width limited by n
   
   %<bitfield>'c	print specified char iff bitfield is all ones
   %<bitfield>`c	print specified char iff bitfield is all zeroes
   %<bitfield>?ab...    select from array of values in big endian order.  */

static const struct opcode32 neon_opcodes[] =
{
  /* Extract.  */
  {FPU_NEON_EXT_V1, 0xf2b00840, 0xffb00850, "vext%c.8 %12-15,22R, %16-19,7R, %0-3,5R, %8-11d"},
  {FPU_NEON_EXT_V1, 0xf2b00000, 0xffb00810, "vext%c.8 %12-15,22R, %16-19,7R, %0-3,5R, %8-11d"},

  /* Move data element to all lanes.  */
  {FPU_NEON_EXT_V1, 0xf3b40c00, 0xffb70f90, "vdup%c.32 %12-15,22R, %0-3,5D[%19d]"},
  {FPU_NEON_EXT_V1, 0xf3b20c00, 0xffb30f90, "vdup%c.16 %12-15,22R, %0-3,5D[%18-19d]"},
  {FPU_NEON_EXT_V1, 0xf3b10c00, 0xffb10f90, "vdup%c.8 %12-15,22R, %0-3,5D[%17-19d]"},

  /* Table lookup.  */
  {FPU_NEON_EXT_V1, 0xf3b00800, 0xffb00c50, "vtbl%c.8 %12-15,22D, %F, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf3b00840, 0xffb00c50, "vtbx%c.8 %12-15,22D, %F, %0-3,5D"},
  
  /* Half-precision conversions.  */
  {FPU_VFP_EXT_FP16, 0xf3b60600, 0xffbf0fd0, "vcvt%c.f16.f32 %12-15,22D, %0-3,5Q"},
  {FPU_VFP_EXT_FP16, 0xf3b60700, 0xffbf0fd0, "vcvt%c.f32.f16 %12-15,22Q, %0-3,5D"},

  /* NEON fused multiply add instructions.  */
  {FPU_NEON_EXT_FMA, 0xf2000c10, 0xffa00f10, "vfma%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_FMA, 0xf2200c10, 0xffa00f10, "vfms%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},

  /* Two registers, miscellaneous.  */
  {FPU_NEON_EXT_ARMV8, 0xf3ba0400, 0xffbf0c10, "vrint%7-9?p?m?zaxn%u.f32.f32 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_ARMV8, 0xf3bb0000, 0xffbf0c10, "vcvt%8-9?mpna%u.%7?us32.f32 %12-15,22R, %0-3,5R"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3b00300, 0xffbf0fd0, "aese%u.8 %12-15,22Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3b00340, 0xffbf0fd0, "aesd%u.8 %12-15,22Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3b00380, 0xffbf0fd0, "aesmc%u.8 %12-15,22Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3b003c0, 0xffbf0fd0, "aesimc%u.8 %12-15,22Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3b902c0, 0xffbf0fd0, "sha1h%u.32 %12-15,22Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3ba0380, 0xffbf0fd0, "sha1su1%u.32 %12-15,22Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3ba03c0, 0xffbf0fd0, "sha256su0%u.32 %12-15,22Q, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf2880a10, 0xfebf0fd0, "vmovl%c.%24?us8 %12-15,22Q, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2900a10, 0xfebf0fd0, "vmovl%c.%24?us16 %12-15,22Q, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2a00a10, 0xfebf0fd0, "vmovl%c.%24?us32 %12-15,22Q, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf3b00500, 0xffbf0f90, "vcnt%c.8 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00580, 0xffbf0f90, "vmvn%c %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b20000, 0xffbf0f90, "vswp%c %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b20200, 0xffb30fd0, "vmovn%c.i%18-19T2 %12-15,22D, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf3b20240, 0xffb30fd0, "vqmovun%c.s%18-19T2 %12-15,22D, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf3b20280, 0xffb30fd0, "vqmovn%c.s%18-19T2 %12-15,22D, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf3b202c0, 0xffb30fd0, "vqmovn%c.u%18-19T2 %12-15,22D, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf3b20300, 0xffb30fd0, "vshll%c.i%18-19S2 %12-15,22Q, %0-3,5D, %18-19S2"},
  {FPU_NEON_EXT_V1, 0xf3bb0400, 0xffbf0e90, "vrecpe%c.%8?fu%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3bb0480, 0xffbf0e90, "vrsqrte%c.%8?fu%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00000, 0xffb30f90, "vrev64%c.%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00080, 0xffb30f90, "vrev32%c.%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00100, 0xffb30f90, "vrev16%c.%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00400, 0xffb30f90, "vcls%c.s%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00480, 0xffb30f90, "vclz%c.i%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00700, 0xffb30f90, "vqabs%c.s%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00780, 0xffb30f90, "vqneg%c.s%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b20080, 0xffb30f90, "vtrn%c.%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b20100, 0xffb30f90, "vuzp%c.%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b20180, 0xffb30f90, "vzip%c.%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b10000, 0xffb30b90, "vcgt%c.%10?fs%18-19S2 %12-15,22R, %0-3,5R, #0"},
  {FPU_NEON_EXT_V1, 0xf3b10080, 0xffb30b90, "vcge%c.%10?fs%18-19S2 %12-15,22R, %0-3,5R, #0"},
  {FPU_NEON_EXT_V1, 0xf3b10100, 0xffb30b90, "vceq%c.%10?fi%18-19S2 %12-15,22R, %0-3,5R, #0"},
  {FPU_NEON_EXT_V1, 0xf3b10180, 0xffb30b90, "vcle%c.%10?fs%18-19S2 %12-15,22R, %0-3,5R, #0"},
  {FPU_NEON_EXT_V1, 0xf3b10200, 0xffb30b90, "vclt%c.%10?fs%18-19S2 %12-15,22R, %0-3,5R, #0"},
  {FPU_NEON_EXT_V1, 0xf3b10300, 0xffb30b90, "vabs%c.%10?fs%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b10380, 0xffb30b90, "vneg%c.%10?fs%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00200, 0xffb30f10, "vpaddl%c.%7?us%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b00600, 0xffb30f10, "vpadal%c.%7?us%18-19S2 %12-15,22R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3b30600, 0xffb30e10, "vcvt%c.%7-8?usff%18-19Sa.%7-8?ffus%18-19Sa %12-15,22R, %0-3,5R"},

  /* Three registers of the same length.  */
  {FPU_CRYPTO_EXT_ARMV8, 0xf2000c40, 0xffb00f50, "sha1c%u.32 %12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf2100c40, 0xffb00f50, "sha1p%u.32 %12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf2200c40, 0xffb00f50, "sha1m%u.32 %12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf2300c40, 0xffb00f50, "sha1su0%u.32 %12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3000c40, 0xffb00f50, "sha256h%u.32 %12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3100c40, 0xffb00f50, "sha256h2%u.32 %12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {FPU_CRYPTO_EXT_ARMV8, 0xf3200c40, 0xffb00f50, "sha256su1%u.32 %12-15,22Q, %16-19,7Q, %0-3,5Q"},
  {FPU_NEON_EXT_ARMV8, 0xf3000f10, 0xffa00f10, "vmaxnm%u.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_ARMV8, 0xf3200f10, 0xffa00f10, "vminnm%u.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000110, 0xffb00f10, "vand%c %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2100110, 0xffb00f10, "vbic%c %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2200110, 0xffb00f10, "vorr%c %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2300110, 0xffb00f10, "vorn%c %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000110, 0xffb00f10, "veor%c %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3100110, 0xffb00f10, "vbsl%c %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3200110, 0xffb00f10, "vbit%c %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3300110, 0xffb00f10, "vbif%c %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000d00, 0xffa00f10, "vadd%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000d10, 0xffa00f10, "vmla%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000e00, 0xffa00f10, "vceq%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000f00, 0xffa00f10, "vmax%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000f10, 0xffa00f10, "vrecps%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2200d00, 0xffa00f10, "vsub%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2200d10, 0xffa00f10, "vmls%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2200f00, 0xffa00f10, "vmin%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2200f10, 0xffa00f10, "vrsqrts%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000d00, 0xffa00f10, "vpadd%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000d10, 0xffa00f10, "vmul%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000e00, 0xffa00f10, "vcge%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000e10, 0xffa00f10, "vacge%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000f00, 0xffa00f10, "vpmax%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3200d00, 0xffa00f10, "vabd%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3200e00, 0xffa00f10, "vcgt%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3200e10, 0xffa00f10, "vacgt%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3200f00, 0xffa00f10, "vpmin%c.f%20U0 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000800, 0xff800f10, "vadd%c.i%20-21S3 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000810, 0xff800f10, "vtst%c.%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000900, 0xff800f10, "vmla%c.i%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000b00, 0xff800f10, "vqdmulh%c.s%20-21S6 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000b10, 0xff800f10, "vpadd%c.i%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000800, 0xff800f10, "vsub%c.i%20-21S3 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000810, 0xff800f10, "vceq%c.i%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000900, 0xff800f10, "vmls%c.i%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf3000b00, 0xff800f10, "vqrdmulh%c.s%20-21S6 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000000, 0xfe800f10, "vhadd%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000010, 0xfe800f10, "vqadd%c.%24?us%20-21S3 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000100, 0xfe800f10, "vrhadd%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000200, 0xfe800f10, "vhsub%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000210, 0xfe800f10, "vqsub%c.%24?us%20-21S3 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000300, 0xfe800f10, "vcgt%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000310, 0xfe800f10, "vcge%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000400, 0xfe800f10, "vshl%c.%24?us%20-21S3 %12-15,22R, %0-3,5R, %16-19,7R"},
  {FPU_NEON_EXT_V1, 0xf2000410, 0xfe800f10, "vqshl%c.%24?us%20-21S3 %12-15,22R, %0-3,5R, %16-19,7R"},
  {FPU_NEON_EXT_V1, 0xf2000500, 0xfe800f10, "vrshl%c.%24?us%20-21S3 %12-15,22R, %0-3,5R, %16-19,7R"},
  {FPU_NEON_EXT_V1, 0xf2000510, 0xfe800f10, "vqrshl%c.%24?us%20-21S3 %12-15,22R, %0-3,5R, %16-19,7R"},
  {FPU_NEON_EXT_V1, 0xf2000600, 0xfe800f10, "vmax%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000610, 0xfe800f10, "vmin%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000700, 0xfe800f10, "vabd%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000710, 0xfe800f10, "vaba%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000910, 0xfe800f10, "vmul%c.%24?pi%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000a00, 0xfe800f10, "vpmax%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},
  {FPU_NEON_EXT_V1, 0xf2000a10, 0xfe800f10, "vpmin%c.%24?us%20-21S2 %12-15,22R, %16-19,7R, %0-3,5R"},

  /* One register and an immediate value.  */
  {FPU_NEON_EXT_V1, 0xf2800e10, 0xfeb80fb0, "vmov%c.i8 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800e30, 0xfeb80fb0, "vmov%c.i64 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800f10, 0xfeb80fb0, "vmov%c.f32 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800810, 0xfeb80db0, "vmov%c.i16 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800830, 0xfeb80db0, "vmvn%c.i16 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800910, 0xfeb80db0, "vorr%c.i16 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800930, 0xfeb80db0, "vbic%c.i16 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800c10, 0xfeb80eb0, "vmov%c.i32 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800c30, 0xfeb80eb0, "vmvn%c.i32 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800110, 0xfeb809b0, "vorr%c.i32 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800130, 0xfeb809b0, "vbic%c.i32 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800010, 0xfeb808b0, "vmov%c.i32 %12-15,22R, %E"},
  {FPU_NEON_EXT_V1, 0xf2800030, 0xfeb808b0, "vmvn%c.i32 %12-15,22R, %E"},

  /* Two registers and a shift amount.  */
  {FPU_NEON_EXT_V1, 0xf2880810, 0xffb80fd0, "vshrn%c.i16 %12-15,22D, %0-3,5Q, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880850, 0xffb80fd0, "vrshrn%c.i16 %12-15,22D, %0-3,5Q, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880810, 0xfeb80fd0, "vqshrun%c.s16 %12-15,22D, %0-3,5Q, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880850, 0xfeb80fd0, "vqrshrun%c.s16 %12-15,22D, %0-3,5Q, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880910, 0xfeb80fd0, "vqshrn%c.%24?us16 %12-15,22D, %0-3,5Q, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880950, 0xfeb80fd0, "vqrshrn%c.%24?us16 %12-15,22D, %0-3,5Q, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880a10, 0xfeb80fd0, "vshll%c.%24?us8 %12-15,22D, %0-3,5Q, %16-18d"},
  {FPU_NEON_EXT_V1, 0xf2900810, 0xffb00fd0, "vshrn%c.i32 %12-15,22D, %0-3,5Q, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900850, 0xffb00fd0, "vrshrn%c.i32 %12-15,22D, %0-3,5Q, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2880510, 0xffb80f90, "vshl%c.%24?us8 %12-15,22R, %0-3,5R, %16-18d"},
  {FPU_NEON_EXT_V1, 0xf3880410, 0xffb80f90, "vsri%c.8 %12-15,22R, %0-3,5R, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf3880510, 0xffb80f90, "vsli%c.8 %12-15,22R, %0-3,5R, %16-18d"},
  {FPU_NEON_EXT_V1, 0xf3880610, 0xffb80f90, "vqshlu%c.s8 %12-15,22R, %0-3,5R, %16-18d"},
  {FPU_NEON_EXT_V1, 0xf2900810, 0xfeb00fd0, "vqshrun%c.s32 %12-15,22D, %0-3,5Q, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900850, 0xfeb00fd0, "vqrshrun%c.s32 %12-15,22D, %0-3,5Q, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900910, 0xfeb00fd0, "vqshrn%c.%24?us32 %12-15,22D, %0-3,5Q, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900950, 0xfeb00fd0, "vqrshrn%c.%24?us32 %12-15,22D, %0-3,5Q, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900a10, 0xfeb00fd0, "vshll%c.%24?us16 %12-15,22D, %0-3,5Q, %16-19d"},
  {FPU_NEON_EXT_V1, 0xf2880010, 0xfeb80f90, "vshr%c.%24?us8 %12-15,22R, %0-3,5R, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880110, 0xfeb80f90, "vsra%c.%24?us8 %12-15,22R, %0-3,5R, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880210, 0xfeb80f90, "vrshr%c.%24?us8 %12-15,22R, %0-3,5R, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880310, 0xfeb80f90, "vrsra%c.%24?us8 %12-15,22R, %0-3,5R, %16-18e"},
  {FPU_NEON_EXT_V1, 0xf2880710, 0xfeb80f90, "vqshl%c.%24?us8 %12-15,22R, %0-3,5R, %16-18d"},
  {FPU_NEON_EXT_V1, 0xf2a00810, 0xffa00fd0, "vshrn%c.i64 %12-15,22D, %0-3,5Q, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00850, 0xffa00fd0, "vrshrn%c.i64 %12-15,22D, %0-3,5Q, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2900510, 0xffb00f90, "vshl%c.%24?us16 %12-15,22R, %0-3,5R, %16-19d"},
  {FPU_NEON_EXT_V1, 0xf3900410, 0xffb00f90, "vsri%c.16 %12-15,22R, %0-3,5R, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf3900510, 0xffb00f90, "vsli%c.16 %12-15,22R, %0-3,5R, %16-19d"},
  {FPU_NEON_EXT_V1, 0xf3900610, 0xffb00f90, "vqshlu%c.s16 %12-15,22R, %0-3,5R, %16-19d"},
  {FPU_NEON_EXT_V1, 0xf2a00a10, 0xfea00fd0, "vshll%c.%24?us32 %12-15,22D, %0-3,5Q, %16-20d"},
  {FPU_NEON_EXT_V1, 0xf2900010, 0xfeb00f90, "vshr%c.%24?us16 %12-15,22R, %0-3,5R, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900110, 0xfeb00f90, "vsra%c.%24?us16 %12-15,22R, %0-3,5R, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900210, 0xfeb00f90, "vrshr%c.%24?us16 %12-15,22R, %0-3,5R, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900310, 0xfeb00f90, "vrsra%c.%24?us16 %12-15,22R, %0-3,5R, %16-19e"},
  {FPU_NEON_EXT_V1, 0xf2900710, 0xfeb00f90, "vqshl%c.%24?us16 %12-15,22R, %0-3,5R, %16-19d"},
  {FPU_NEON_EXT_V1, 0xf2a00810, 0xfea00fd0, "vqshrun%c.s64 %12-15,22D, %0-3,5Q, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00850, 0xfea00fd0, "vqrshrun%c.s64 %12-15,22D, %0-3,5Q, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00910, 0xfea00fd0, "vqshrn%c.%24?us64 %12-15,22D, %0-3,5Q, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00950, 0xfea00fd0, "vqrshrn%c.%24?us64 %12-15,22D, %0-3,5Q, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00510, 0xffa00f90, "vshl%c.%24?us32 %12-15,22R, %0-3,5R, %16-20d"},
  {FPU_NEON_EXT_V1, 0xf3a00410, 0xffa00f90, "vsri%c.32 %12-15,22R, %0-3,5R, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf3a00510, 0xffa00f90, "vsli%c.32 %12-15,22R, %0-3,5R, %16-20d"},
  {FPU_NEON_EXT_V1, 0xf3a00610, 0xffa00f90, "vqshlu%c.s32 %12-15,22R, %0-3,5R, %16-20d"},
  {FPU_NEON_EXT_V1, 0xf2a00010, 0xfea00f90, "vshr%c.%24?us32 %12-15,22R, %0-3,5R, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00110, 0xfea00f90, "vsra%c.%24?us32 %12-15,22R, %0-3,5R, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00210, 0xfea00f90, "vrshr%c.%24?us32 %12-15,22R, %0-3,5R, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00310, 0xfea00f90, "vrsra%c.%24?us32 %12-15,22R, %0-3,5R, %16-20e"},
  {FPU_NEON_EXT_V1, 0xf2a00710, 0xfea00f90, "vqshl%c.%24?us32 %12-15,22R, %0-3,5R, %16-20d"},
  {FPU_NEON_EXT_V1, 0xf2800590, 0xff800f90, "vshl%c.%24?us64 %12-15,22R, %0-3,5R, %16-21d"},
  {FPU_NEON_EXT_V1, 0xf3800490, 0xff800f90, "vsri%c.64 %12-15,22R, %0-3,5R, %16-21e"},
  {FPU_NEON_EXT_V1, 0xf3800590, 0xff800f90, "vsli%c.64 %12-15,22R, %0-3,5R, %16-21d"},
  {FPU_NEON_EXT_V1, 0xf3800690, 0xff800f90, "vqshlu%c.s64 %12-15,22R, %0-3,5R, %16-21d"},
  {FPU_NEON_EXT_V1, 0xf2800090, 0xfe800f90, "vshr%c.%24?us64 %12-15,22R, %0-3,5R, %16-21e"},
  {FPU_NEON_EXT_V1, 0xf2800190, 0xfe800f90, "vsra%c.%24?us64 %12-15,22R, %0-3,5R, %16-21e"},
  {FPU_NEON_EXT_V1, 0xf2800290, 0xfe800f90, "vrshr%c.%24?us64 %12-15,22R, %0-3,5R, %16-21e"},
  {FPU_NEON_EXT_V1, 0xf2800390, 0xfe800f90, "vrsra%c.%24?us64 %12-15,22R, %0-3,5R, %16-21e"},
  {FPU_NEON_EXT_V1, 0xf2800790, 0xfe800f90, "vqshl%c.%24?us64 %12-15,22R, %0-3,5R, %16-21d"},
  {FPU_NEON_EXT_V1, 0xf2a00e10, 0xfea00e90, "vcvt%c.%24,8?usff32.%24,8?ffus32 %12-15,22R, %0-3,5R, %16-20e"},

  /* Three registers of different lengths.  */
  {FPU_CRYPTO_EXT_ARMV8, 0xf2a00e00, 0xfeb00f50, "vmull%c.p64 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800e00, 0xfea00f50, "vmull%c.p%20S0 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800400, 0xff800f50, "vaddhn%c.i%20-21T2 %12-15,22D, %16-19,7Q, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf2800600, 0xff800f50, "vsubhn%c.i%20-21T2 %12-15,22D, %16-19,7Q, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf2800900, 0xff800f50, "vqdmlal%c.s%20-21S6 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800b00, 0xff800f50, "vqdmlsl%c.s%20-21S6 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800d00, 0xff800f50, "vqdmull%c.s%20-21S6 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf3800400, 0xff800f50, "vraddhn%c.i%20-21T2 %12-15,22D, %16-19,7Q, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf3800600, 0xff800f50, "vrsubhn%c.i%20-21T2 %12-15,22D, %16-19,7Q, %0-3,5Q"},
  {FPU_NEON_EXT_V1, 0xf2800000, 0xfe800f50, "vaddl%c.%24?us%20-21S2 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800100, 0xfe800f50, "vaddw%c.%24?us%20-21S2 %12-15,22Q, %16-19,7Q, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800200, 0xfe800f50, "vsubl%c.%24?us%20-21S2 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800300, 0xfe800f50, "vsubw%c.%24?us%20-21S2 %12-15,22Q, %16-19,7Q, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800500, 0xfe800f50, "vabal%c.%24?us%20-21S2 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800700, 0xfe800f50, "vabdl%c.%24?us%20-21S2 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800800, 0xfe800f50, "vmlal%c.%24?us%20-21S2 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800a00, 0xfe800f50, "vmlsl%c.%24?us%20-21S2 %12-15,22Q, %16-19,7D, %0-3,5D"},
  {FPU_NEON_EXT_V1, 0xf2800c00, 0xfe800f50, "vmull%c.%24?us%20-21S2 %12-15,22Q, %16-19,7D, %0-3,5D"},

  /* Two registers and a scalar.  */
  {FPU_NEON_EXT_V1, 0xf2800040, 0xff800f50, "vmla%c.i%20-21S6 %12-15,22D, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800140, 0xff800f50, "vmla%c.f%20-21Sa %12-15,22D, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800340, 0xff800f50, "vqdmlal%c.s%20-21S6 %12-15,22Q, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800440, 0xff800f50, "vmls%c.i%20-21S6 %12-15,22D, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800540, 0xff800f50, "vmls%c.f%20-21S6 %12-15,22D, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800740, 0xff800f50, "vqdmlsl%c.s%20-21S6 %12-15,22Q, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800840, 0xff800f50, "vmul%c.i%20-21S6 %12-15,22D, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800940, 0xff800f50, "vmul%c.f%20-21Sa %12-15,22D, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800b40, 0xff800f50, "vqdmull%c.s%20-21S6 %12-15,22Q, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800c40, 0xff800f50, "vqdmulh%c.s%20-21S6 %12-15,22D, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800d40, 0xff800f50, "vqrdmulh%c.s%20-21S6 %12-15,22D, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf3800040, 0xff800f50, "vmla%c.i%20-21S6 %12-15,22Q, %16-19,7Q, %D"},
  {FPU_NEON_EXT_V1, 0xf3800140, 0xff800f50, "vmla%c.f%20-21Sa %12-15,22Q, %16-19,7Q, %D"},
  {FPU_NEON_EXT_V1, 0xf3800440, 0xff800f50, "vmls%c.i%20-21S6 %12-15,22Q, %16-19,7Q, %D"},
  {FPU_NEON_EXT_V1, 0xf3800540, 0xff800f50, "vmls%c.f%20-21Sa %12-15,22Q, %16-19,7Q, %D"},
  {FPU_NEON_EXT_V1, 0xf3800840, 0xff800f50, "vmul%c.i%20-21S6 %12-15,22Q, %16-19,7Q, %D"},
  {FPU_NEON_EXT_V1, 0xf3800940, 0xff800f50, "vmul%c.f%20-21Sa %12-15,22Q, %16-19,7Q, %D"},
  {FPU_NEON_EXT_V1, 0xf3800c40, 0xff800f50, "vqdmulh%c.s%20-21S6 %12-15,22Q, %16-19,7Q, %D"},
  {FPU_NEON_EXT_V1, 0xf3800d40, 0xff800f50, "vqrdmulh%c.s%20-21S6 %12-15,22Q, %16-19,7Q, %D"},
  {FPU_NEON_EXT_V1, 0xf2800240, 0xfe800f50, "vmlal%c.%24?us%20-21S6 %12-15,22Q, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800640, 0xfe800f50, "vmlsl%c.%24?us%20-21S6 %12-15,22Q, %16-19,7D, %D"},
  {FPU_NEON_EXT_V1, 0xf2800a40, 0xfe800f50, "vmull%c.%24?us%20-21S6 %12-15,22Q, %16-19,7D, %D"},

  /* Element and structure load/store.  */
  {FPU_NEON_EXT_V1, 0xf4a00fc0, 0xffb00fc0, "vld4%c.32 %C"},
  {FPU_NEON_EXT_V1, 0xf4a00c00, 0xffb00f00, "vld1%c.%6-7S2 %C"},
  {FPU_NEON_EXT_V1, 0xf4a00d00, 0xffb00f00, "vld2%c.%6-7S2 %C"},
  {FPU_NEON_EXT_V1, 0xf4a00e00, 0xffb00f00, "vld3%c.%6-7S2 %C"},
  {FPU_NEON_EXT_V1, 0xf4a00f00, 0xffb00f00, "vld4%c.%6-7S2 %C"},
  {FPU_NEON_EXT_V1, 0xf4000200, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3 %A"},
  {FPU_NEON_EXT_V1, 0xf4000300, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2 %A"},
  {FPU_NEON_EXT_V1, 0xf4000400, 0xff900f00, "v%21?ls%21?dt3%c.%6-7S2 %A"},
  {FPU_NEON_EXT_V1, 0xf4000500, 0xff900f00, "v%21?ls%21?dt3%c.%6-7S2 %A"},
  {FPU_NEON_EXT_V1, 0xf4000600, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3 %A"},
  {FPU_NEON_EXT_V1, 0xf4000700, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3 %A"},
  {FPU_NEON_EXT_V1, 0xf4000800, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2 %A"},
  {FPU_NEON_EXT_V1, 0xf4000900, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2 %A"},
  {FPU_NEON_EXT_V1, 0xf4000a00, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3 %A"},
  {FPU_NEON_EXT_V1, 0xf4000000, 0xff900e00, "v%21?ls%21?dt4%c.%6-7S2 %A"},
  {FPU_NEON_EXT_V1, 0xf4800000, 0xff900300, "v%21?ls%21?dt1%c.%10-11S2 %B"},
  {FPU_NEON_EXT_V1, 0xf4800100, 0xff900300, "v%21?ls%21?dt2%c.%10-11S2 %B"},
  {FPU_NEON_EXT_V1, 0xf4800200, 0xff900300, "v%21?ls%21?dt3%c.%10-11S2 %B"},
  {FPU_NEON_EXT_V1, 0xf4800300, 0xff900300, "v%21?ls%21?dt4%c.%10-11S2 %B"},

  {0,0 ,0, 0}
};

/* Opcode tables: ARM, 16-bit Thumb, 32-bit Thumb.  All three are partially
   ordered: they must be searched linearly from the top to obtain a correct
   match.  */

/* print_insn_arm recognizes the following format control codes:

   %%			%

   %a			print address for ldr/str instruction
   %s                   print address for ldr/str halfword/signextend instruction
   %S                   like %s but allow UNPREDICTABLE addressing
   %b			print branch destination
   %c			print condition code (always bits 28-31)
   %m			print register mask for ldm/stm instruction
   %o			print operand2 (immediate or register + shift)
   %p			print 'p' iff bits 12-15 are 15
   %t			print 't' iff bit 21 set and bit 24 clear
   %B			print arm BLX(1) destination
   %C			print the PSR sub type.
   %U			print barrier type.
   %P			print address for pli instruction.

   %<bitfield>r		print as an ARM register
   %<bitfield>T		print as an ARM register + 1
   %<bitfield>R		as %r but r15 is UNPREDICTABLE
   %<bitfield>{r|R}u    as %{r|R} but if matches the other %u field then is UNPREDICTABLE
   %<bitfield>{r|R}U    as %{r|R} but if matches the other %U field then is UNPREDICTABLE
   %<bitfield>d		print the bitfield in decimal
   %<bitfield>W         print the bitfield plus one in decimal 
   %<bitfield>x		print the bitfield in hex
   %<bitfield>X		print the bitfield as 1 hex digit without leading "0x"
   
   %<bitfield>'c	print specified char iff bitfield is all ones
   %<bitfield>`c	print specified char iff bitfield is all zeroes
   %<bitfield>?ab...    select from array of values in big endian order

   %e                   print arm SMI operand (bits 0..7,8..19).
   %E			print the LSB and WIDTH fields of a BFI or BFC instruction.
   %V                   print the 16-bit immediate field of a MOVT or MOVW instruction.
   %R			print the SPSR/CPSR or banked register of an MRS.  */

static const struct opcode32 arm_opcodes[] =
{
  /* ARM instructions.  */
  {ARM_EXT_V1, 0xe1a00000, 0xffffffff, "nop"}, //   ; (mov r0, r0)"},
  {ARM_EXT_V4T | ARM_EXT_V5, 0x012FFF10, 0x0ffffff0, "bx%c %0-3r"},
  {ARM_EXT_V2, 0x00000090, 0x0fe000f0, "mul%20's%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V2, 0x00200090, 0x0fe000f0, "mla%20's%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V2S, 0x01000090, 0x0fb00ff0, "swp%22'b%c %12-15RU, %0-3Ru, [%16-19RuU]"},
  {ARM_EXT_V3M, 0x00800090, 0x0fa000f0, "%22?sumull%20's%c %12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {ARM_EXT_V3M, 0x00a00090, 0x0fa000f0, "%22?sumlal%20's%c %12-15Ru, %16-19Ru, %0-3R, %8-11R"},

  /* V8 instructions.  */
  {ARM_EXT_V8,   0x0320f005, 0x0fffffff, "sevl"},
  {ARM_EXT_V8,   0xe1000070, 0xfff000f0, "hlt 0x%16-19X%12-15X%8-11X%0-3X"},
  {ARM_EXT_V8,	 0x01800e90, 0x0ff00ff0, "stlex%c %12-15r, %0-3r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01900e9f, 0x0ff00fff, "ldaex%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01a00e90, 0x0ff00ff0, "stlexd%c %12-15r, %0-3r, %0-3T, [%16-19R]"},
  {ARM_EXT_V8,	 0x01b00e9f, 0x0ff00fff, "ldaexd%c %12-15r, %12-15T, [%16-19R]"},
  {ARM_EXT_V8,	 0x01c00e90, 0x0ff00ff0, "stlexb%c %12-15r, %0-3r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01d00e9f, 0x0ff00fff, "ldaexb%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01e00e90, 0x0ff00ff0, "stlexh%c %12-15r, %0-3r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01f00e9f, 0x0ff00fff, "ldaexh%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8,	 0x0180fc90, 0x0ff0fff0, "stl%c %0-3r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01900c9f, 0x0ff00fff, "lda%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01c0fc90, 0x0ff0fff0, "stlb%c %0-3r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01d00c9f, 0x0ff00fff, "ldab%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01e0fc90, 0x0ff0fff0, "stlh%c %0-3r, [%16-19R]"},
  {ARM_EXT_V8,	 0x01f00c9f, 0x0ff00fff, "ldaexh%c %12-15r, [%16-19R]"},

  /* Virtualization Extension instructions.  */
  {ARM_EXT_VIRT, 0x0160006e, 0x0fffffff, "eret%c"},
  {ARM_EXT_VIRT, 0x01400070, 0x0ff000f0, "hvc%c %e"},

  /* Integer Divide Extension instructions.  */
  {ARM_EXT_ADIV, 0x0710f010, 0x0ff0f0f0, "sdiv%c %16-19r, %0-3r, %8-11r"},
  {ARM_EXT_ADIV, 0x0730f010, 0x0ff0f0f0, "udiv%c %16-19r, %0-3r, %8-11r"},

  /* MP Extension instructions.  */
  {ARM_EXT_MP, 0xf410f000, 0xfc70f000, "pldw %a"},

  /* V7 instructions.  */
  {ARM_EXT_V7, 0xf450f000, 0xfd70f000, "pli %P"},
  {ARM_EXT_V7, 0x0320f0f0, 0x0ffffff0, "dbg%c %0-3d"},
  {ARM_EXT_V8, 0xf57ff051, 0xfffffff3, "dmb %U"},
  {ARM_EXT_V8, 0xf57ff041, 0xfffffff3, "dsb %U"},
  {ARM_EXT_V7, 0xf57ff050, 0xfffffff0, "dmb %U"},
  {ARM_EXT_V7, 0xf57ff040, 0xfffffff0, "dsb %U"},
  {ARM_EXT_V7, 0xf57ff060, 0xfffffff0, "isb %U"},

  /* ARM V6T2 instructions.  */
  {ARM_EXT_V6T2, 0x07c0001f, 0x0fe0007f, "bfc%c %12-15R, %E"},
  {ARM_EXT_V6T2, 0x07c00010, 0x0fe00070, "bfi%c %12-15R, %0-3r, %E"},
  {ARM_EXT_V6T2, 0x00600090, 0x0ff000f0, "mls%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V6T2, 0x006000b0, 0x0f7000f0, "strht%c %12-15R, %S"},
  
  {ARM_EXT_V6T2, 0x00300090, 0x0f3000f0, UNDEFINED_INSTRUCTION },
  {ARM_EXT_V6T2, 0x00300090, 0x0f300090, "ldr%6's%5?hbt%c %12-15R, %S"},
  
  {ARM_EXT_V6T2, 0x03000000, 0x0ff00000, "movw%c %12-15R, %V"},
  {ARM_EXT_V6T2, 0x03400000, 0x0ff00000, "movt%c %12-15R, %V"},
  {ARM_EXT_V6T2, 0x06ff0f30, 0x0fff0ff0, "rbit%c %12-15R, %0-3R"},
  {ARM_EXT_V6T2, 0x07a00050, 0x0fa00070, "%22?usbfx%c %12-15r, %0-3r, %7-11d, %16-20W"},

  /* ARM Security extension instructions.  */
  {ARM_EXT_SEC, 0x01600070, 0x0ff000f0, "smc%c %e"},

  /* ARM V6K instructions.  */
  {ARM_EXT_V6K, 0xf57ff01f, 0xffffffff, "clrex"},
  {ARM_EXT_V6K, 0x01d00f9f, 0x0ff00fff, "ldrexb%c %12-15R, [%16-19R]"},
  {ARM_EXT_V6K, 0x01b00f9f, 0x0ff00fff, "ldrexd%c %12-15r, [%16-19R]"},
  {ARM_EXT_V6K, 0x01f00f9f, 0x0ff00fff, "ldrexh%c %12-15R, [%16-19R]"},
  {ARM_EXT_V6K, 0x01c00f90, 0x0ff00ff0, "strexb%c %12-15R, %0-3R, [%16-19R]"},
  {ARM_EXT_V6K, 0x01a00f90, 0x0ff00ff0, "strexd%c %12-15R, %0-3r, [%16-19R]"},
  {ARM_EXT_V6K, 0x01e00f90, 0x0ff00ff0, "strexh%c %12-15R, %0-3R, [%16-19R]"},

  /* ARM V6K NOP hints.  */
  {ARM_EXT_V6K, 0x0320f001, 0x0fffffff, "yield%c"},
  {ARM_EXT_V6K, 0x0320f002, 0x0fffffff, "wfe%c"},
  {ARM_EXT_V6K, 0x0320f003, 0x0fffffff, "wfi%c"},
  {ARM_EXT_V6K, 0x0320f004, 0x0fffffff, "sev%c"},
  {ARM_EXT_V6K, 0x0320f000, 0x0fffff00, "nop%c {%0-7d}"},

  /* ARM V6 instructions.  */
  {ARM_EXT_V6, 0xf1080000, 0xfffffe3f, "cpsie %8'a%7'i%6'f"},
  {ARM_EXT_V6, 0xf10a0000, 0xfffffe20, "cpsie %8'a%7'i%6'f,%0-4d"},
  {ARM_EXT_V6, 0xf10C0000, 0xfffffe3f, "cpsid %8'a%7'i%6'f"},
  {ARM_EXT_V6, 0xf10e0000, 0xfffffe20, "cpsid %8'a%7'i%6'f,%0-4d"},
  {ARM_EXT_V6, 0xf1000000, 0xfff1fe20, "cps %0-4d"},
  {ARM_EXT_V6, 0x06800010, 0x0ff00ff0, "pkhbt%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06800010, 0x0ff00070, "pkhbt%c %12-15R, %16-19R, %0-3R, lsl %7-11d"},
  {ARM_EXT_V6, 0x06800050, 0x0ff00ff0, "pkhtb%c %12-15R, %16-19R, %0-3R, asr #32"},
  {ARM_EXT_V6, 0x06800050, 0x0ff00070, "pkhtb%c %12-15R, %16-19R, %0-3R, asr %7-11d"},
  {ARM_EXT_V6, 0x01900f9f, 0x0ff00fff, "ldrex%c r%12-15d, [%16-19R]"},
  {ARM_EXT_V6, 0x06200f10, 0x0ff00ff0, "qadd16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06200f90, 0x0ff00ff0, "qadd8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06200f30, 0x0ff00ff0, "qasx%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06200f70, 0x0ff00ff0, "qsub16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06200ff0, 0x0ff00ff0, "qsub8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06200f50, 0x0ff00ff0, "qsax%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06100f10, 0x0ff00ff0, "sadd16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06100f90, 0x0ff00ff0, "sadd8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06100f30, 0x0ff00ff0, "sasx%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06300f10, 0x0ff00ff0, "shadd16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06300f90, 0x0ff00ff0, "shadd8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06300f30, 0x0ff00ff0, "shasx%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06300f70, 0x0ff00ff0, "shsub16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06300ff0, 0x0ff00ff0, "shsub8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06300f50, 0x0ff00ff0, "shsax%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06100f70, 0x0ff00ff0, "ssub16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06100ff0, 0x0ff00ff0, "ssub8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06100f50, 0x0ff00ff0, "ssax%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06500f10, 0x0ff00ff0, "uadd16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06500f90, 0x0ff00ff0, "uadd8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06500f30, 0x0ff00ff0, "uasx%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06700f10, 0x0ff00ff0, "uhadd16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06700f90, 0x0ff00ff0, "uhadd8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06700f30, 0x0ff00ff0, "uhasx%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06700f70, 0x0ff00ff0, "uhsub16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06700ff0, 0x0ff00ff0, "uhsub8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06700f50, 0x0ff00ff0, "uhsax%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06600f10, 0x0ff00ff0, "uqadd16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06600f90, 0x0ff00ff0, "uqadd8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06600f30, 0x0ff00ff0, "uqasx%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06600f70, 0x0ff00ff0, "uqsub16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06600ff0, 0x0ff00ff0, "uqsub8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06600f50, 0x0ff00ff0, "uqsax%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06500f70, 0x0ff00ff0, "usub16%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06500ff0, 0x0ff00ff0, "usub8%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06500f50, 0x0ff00ff0, "usax%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0x06bf0f30, 0x0fff0ff0, "rev%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0x06bf0fb0, 0x0fff0ff0, "rev16%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0x06ff0fb0, 0x0fff0ff0, "revsh%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0xf8100a00, 0xfe50ffff, "rfe%23?id%24?ba %16-19r%21'!"},
  {ARM_EXT_V6, 0x06bf0070, 0x0fff0ff0, "sxth%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0x06bf0470, 0x0fff0ff0, "sxth%c %12-15R, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06bf0870, 0x0fff0ff0, "sxth%c %12-15R, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06bf0c70, 0x0fff0ff0, "sxth%c %12-15R, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x068f0070, 0x0fff0ff0, "sxtb16%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0x068f0470, 0x0fff0ff0, "sxtb16%c %12-15R, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x068f0870, 0x0fff0ff0, "sxtb16%c %12-15R, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x068f0c70, 0x0fff0ff0, "sxtb16%c %12-15R, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06af0070, 0x0fff0ff0, "sxtb%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0x06af0470, 0x0fff0ff0, "sxtb%c %12-15R, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06af0870, 0x0fff0ff0, "sxtb%c %12-15R, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06af0c70, 0x0fff0ff0, "sxtb%c %12-15R, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06ff0070, 0x0fff0ff0, "uxth%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0x06ff0470, 0x0fff0ff0, "uxth%c %12-15R, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06ff0870, 0x0fff0ff0, "uxth%c %12-15R, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06ff0c70, 0x0fff0ff0, "uxth%c %12-15R, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06cf0070, 0x0fff0ff0, "uxtb16%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0x06cf0470, 0x0fff0ff0, "uxtb16%c %12-15R, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06cf0870, 0x0fff0ff0, "uxtb16%c %12-15R, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06cf0c70, 0x0fff0ff0, "uxtb16%c %12-15R, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06ef0070, 0x0fff0ff0, "uxtb%c %12-15R, %0-3R"},
  {ARM_EXT_V6, 0x06ef0470, 0x0fff0ff0, "uxtb%c %12-15R, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06ef0870, 0x0fff0ff0, "uxtb%c %12-15R, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06ef0c70, 0x0fff0ff0, "uxtb%c %12-15R, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06b00070, 0x0ff00ff0, "sxtah%c %12-15R, %16-19r, %0-3R"},
  {ARM_EXT_V6, 0x06b00470, 0x0ff00ff0, "sxtah%c %12-15R, %16-19r, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06b00870, 0x0ff00ff0, "sxtah%c %12-15R, %16-19r, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06b00c70, 0x0ff00ff0, "sxtah%c %12-15R, %16-19r, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06800070, 0x0ff00ff0, "sxtab16%c %12-15R, %16-19r, %0-3R"},
  {ARM_EXT_V6, 0x06800470, 0x0ff00ff0, "sxtab16%c %12-15R, %16-19r, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06800870, 0x0ff00ff0, "sxtab16%c %12-15R, %16-19r, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06800c70, 0x0ff00ff0, "sxtab16%c %12-15R, %16-19r, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06a00070, 0x0ff00ff0, "sxtab%c %12-15R, %16-19r, %0-3R"},
  {ARM_EXT_V6, 0x06a00470, 0x0ff00ff0, "sxtab%c %12-15R, %16-19r, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06a00870, 0x0ff00ff0, "sxtab%c %12-15R, %16-19r, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06a00c70, 0x0ff00ff0, "sxtab%c %12-15R, %16-19r, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06f00070, 0x0ff00ff0, "uxtah%c %12-15R, %16-19r, %0-3R"},
  {ARM_EXT_V6, 0x06f00470, 0x0ff00ff0, "uxtah%c %12-15R, %16-19r, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06f00870, 0x0ff00ff0, "uxtah%c %12-15R, %16-19r, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06f00c70, 0x0ff00ff0, "uxtah%c %12-15R, %16-19r, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06c00070, 0x0ff00ff0, "uxtab16%c %12-15R, %16-19r, %0-3R"},
  {ARM_EXT_V6, 0x06c00470, 0x0ff00ff0, "uxtab16%c %12-15R, %16-19r, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06c00870, 0x0ff00ff0, "uxtab16%c %12-15R, %16-19r, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06c00c70, 0x0ff00ff0, "uxtab16%c %12-15R, %16-19r, %0-3R, ROR #24"},
  {ARM_EXT_V6, 0x06e00070, 0x0ff00ff0, "uxtab%c %12-15R, %16-19r, %0-3R"},
  {ARM_EXT_V6, 0x06e00470, 0x0ff00ff0, "uxtab%c %12-15R, %16-19r, %0-3R, ror #8"},
  {ARM_EXT_V6, 0x06e00870, 0x0ff00ff0, "uxtab%c %12-15R, %16-19r, %0-3R, ror #16"},
  {ARM_EXT_V6, 0x06e00c70, 0x0ff00ff0, "uxtab%c %12-15R, %16-19r, %0-3R, ror #24"},
  {ARM_EXT_V6, 0x06800fb0, 0x0ff00ff0, "sel%c %12-15R, %16-19R, %0-3R"},
  {ARM_EXT_V6, 0xf1010000, 0xfffffc00, "setend %9?ble"},
  {ARM_EXT_V6, 0x0700f010, 0x0ff0f0d0, "smuad%5'x%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V6, 0x0700f050, 0x0ff0f0d0, "smusd%5'x%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V6, 0x07000010, 0x0ff000d0, "smlad%5'x%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V6, 0x07400010, 0x0ff000d0, "smlald%5'x%c %12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {ARM_EXT_V6, 0x07000050, 0x0ff000d0, "smlsd%5'x%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V6, 0x07400050, 0x0ff000d0, "smlsld%5'x%c %12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {ARM_EXT_V6, 0x0750f010, 0x0ff0f0d0, "smmul%5'r%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V6, 0x07500010, 0x0ff000d0, "smmla%5'r%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V6, 0x075000d0, 0x0ff000d0, "smmls%5'r%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V6, 0xf84d0500, 0xfe5fffe0, "srs%23?id%24?ba %16-19r%21'!, %0-4d"},
  {ARM_EXT_V6, 0x06a00010, 0x0fe00ff0, "ssat%c %12-15R, %16-20W, %0-3R"},
  {ARM_EXT_V6, 0x06a00010, 0x0fe00070, "ssat%c %12-15R, %16-20W, %0-3R, lsl %7-11d"},
  {ARM_EXT_V6, 0x06a00050, 0x0fe00070, "ssat%c %12-15R, %16-20W, %0-3R, asr %7-11d"},
  {ARM_EXT_V6, 0x06a00f30, 0x0ff00ff0, "ssat16%c %12-15r, %16-19W, %0-3r"},
  {ARM_EXT_V6, 0x01800f90, 0x0ff00ff0, "strex%c %12-15R, %0-3R, [%16-19R]"},
  {ARM_EXT_V6, 0x00400090, 0x0ff000f0, "umaal%c %12-15R, %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V6, 0x0780f010, 0x0ff0f0f0, "usad8%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V6, 0x07800010, 0x0ff000f0, "usada8%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V6, 0x06e00010, 0x0fe00ff0, "usat%c %12-15R, %16-20d, %0-3R"},
  {ARM_EXT_V6, 0x06e00010, 0x0fe00070, "usat%c %12-15R, %16-20d, %0-3R, lsl %7-11d"},
  {ARM_EXT_V6, 0x06e00050, 0x0fe00070, "usat%c %12-15R, %16-20d, %0-3R, asr %7-11d"},
  {ARM_EXT_V6, 0x06e00f30, 0x0ff00ff0, "usat16%c %12-15R, %16-19d, %0-3R"},

  /* V5J instruction.  */
  {ARM_EXT_V5J, 0x012fff20, 0x0ffffff0, "bxj%c %0-3R"},

  /* V5 Instructions.  */
  {ARM_EXT_V5, 0xe1200070, 0xfff000f0, "bkpt 0x%16-19X%12-15X%8-11X%0-3X"},
  {ARM_EXT_V5, 0xfa000000, 0xfe000000, "blx %B"},
  {ARM_EXT_V5, 0x012fff30, 0x0ffffff0, "blx%c %0-3R"},
  {ARM_EXT_V5, 0x016f0f10, 0x0fff0ff0, "clz%c %12-15R, %0-3R"},

  /* V5E "El Segundo" Instructions.  */    
  {ARM_EXT_V5E, 0x000000d0, 0x0e1000f0, "ldrd%c %12-15r, %s"},
  {ARM_EXT_V5E, 0x000000f0, 0x0e1000f0, "strd%c %12-15r, %s"},
  {ARM_EXT_V5E, 0xf450f000, 0xfc70f000, "pld %a"},
  {ARM_EXT_V5ExP, 0x01000080, 0x0ff000f0, "smlabb%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V5ExP, 0x010000a0, 0x0ff000f0, "smlatb%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V5ExP, 0x010000c0, 0x0ff000f0, "smlabt%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V5ExP, 0x010000e0, 0x0ff000f0, "smlatt%c %16-19r, %0-3r, %8-11R, %12-15R"},

  {ARM_EXT_V5ExP, 0x01200080, 0x0ff000f0, "smlawb%c %16-19R, %0-3R, %8-11R, %12-15R"},
  {ARM_EXT_V5ExP, 0x012000c0, 0x0ff000f0, "smlawt%c %16-19R, %0-3r, %8-11R, %12-15R"},

  {ARM_EXT_V5ExP, 0x01400080, 0x0ff000f0, "smlalbb%c %12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {ARM_EXT_V5ExP, 0x014000a0, 0x0ff000f0, "smlaltb%c %12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {ARM_EXT_V5ExP, 0x014000c0, 0x0ff000f0, "smlalbt%c %12-15Ru, %16-19Ru, %0-3R, %8-11R"},
  {ARM_EXT_V5ExP, 0x014000e0, 0x0ff000f0, "smlaltt%c %12-15Ru, %16-19Ru, %0-3R, %8-11R"},

  {ARM_EXT_V5ExP, 0x01600080, 0x0ff0f0f0, "smulbb%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V5ExP, 0x016000a0, 0x0ff0f0f0, "smultb%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V5ExP, 0x016000c0, 0x0ff0f0f0, "smulbt%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V5ExP, 0x016000e0, 0x0ff0f0f0, "smultt%c %16-19R, %0-3R, %8-11R"},

  {ARM_EXT_V5ExP, 0x012000a0, 0x0ff0f0f0, "smulwb%c %16-19R, %0-3R, %8-11R"},
  {ARM_EXT_V5ExP, 0x012000e0, 0x0ff0f0f0, "smulwt%c %16-19R, %0-3R, %8-11R"},

  {ARM_EXT_V5ExP, 0x01000050, 0x0ff00ff0,  "qadd%c %12-15R, %0-3R, %16-19R"},
  {ARM_EXT_V5ExP, 0x01400050, 0x0ff00ff0, "qdadd%c %12-15R, %0-3R, %16-19R"},
  {ARM_EXT_V5ExP, 0x01200050, 0x0ff00ff0,  "qsub%c %12-15R, %0-3R, %16-19R"},
  {ARM_EXT_V5ExP, 0x01600050, 0x0ff00ff0, "qdsub%c %12-15R, %0-3R, %16-19R"},

  /* ARM Instructions.  */
  {ARM_EXT_V1, 0x052d0004, 0x0fff0fff, "push%c {%12-15r}  ; (str%c %12-15r, %a)"},
  
  {ARM_EXT_V1, 0x04400000, 0x0e500000, "strb%t%c %12-15R, %a"},
  {ARM_EXT_V1, 0x04000000, 0x0e500000, "str%t%c %12-15r, %a"},
  {ARM_EXT_V1, 0x06400000, 0x0e500ff0, "strb%t%c %12-15R, %a"},
  {ARM_EXT_V1, 0x06000000, 0x0e500ff0, "str%t%c %12-15r, %a"},
  {ARM_EXT_V1, 0x04400000, 0x0c500010, "strb%t%c %12-15R, %a"},
  {ARM_EXT_V1, 0x04000000, 0x0c500010, "str%t%c %12-15r, %a"},
  
  {ARM_EXT_V1, 0x04400000, 0x0e500000, "strb%c %12-15R, %a"},
  {ARM_EXT_V1, 0x06400000, 0x0e500010, "strb%c %12-15R, %a"},
  {ARM_EXT_V1, 0x004000b0, 0x0e5000f0, "strh%c %12-15R, %s"},
  {ARM_EXT_V1, 0x000000b0, 0x0e500ff0, "strh%c %12-15R, %s"},

  {ARM_EXT_V1, 0x00500090, 0x0e5000f0, UNDEFINED_INSTRUCTION},
  {ARM_EXT_V1, 0x00500090, 0x0e500090, "ldr%6's%5?hb%c %12-15R, %s"},
  {ARM_EXT_V1, 0x00100090, 0x0e500ff0, UNDEFINED_INSTRUCTION},
  {ARM_EXT_V1, 0x00100090, 0x0e500f90, "ldr%6's%5?hb%c %12-15R, %s"},

  {ARM_EXT_V1, 0x02000000, 0x0fe00000, "and%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00000000, 0x0fe00010, "and%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00000010, 0x0fe00090, "and%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x02200000, 0x0fe00000, "eor%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00200000, 0x0fe00010, "eor%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00200010, 0x0fe00090, "eor%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x02400000, 0x0fe00000, "sub%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00400000, 0x0fe00010, "sub%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00400010, 0x0fe00090, "sub%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x02600000, 0x0fe00000, "rsb%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00600000, 0x0fe00010, "rsb%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00600010, 0x0fe00090, "rsb%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x02800000, 0x0fe00000, "add%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00800000, 0x0fe00010, "add%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00800010, 0x0fe00090, "add%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x02a00000, 0x0fe00000, "adc%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00a00000, 0x0fe00010, "adc%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00a00010, 0x0fe00090, "adc%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x02c00000, 0x0fe00000, "sbc%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00c00000, 0x0fe00010, "sbc%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00c00010, 0x0fe00090, "sbc%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x02e00000, 0x0fe00000, "rsc%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00e00000, 0x0fe00010, "rsc%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x00e00010, 0x0fe00090, "rsc%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_VIRT, 0x0120f200, 0x0fb0f200, "msr%c %C, %0-3r"},
  {ARM_EXT_V3, 0x0120f000, 0x0db0f000, "msr%c %C, %o"},
  {ARM_EXT_V3, 0x01000000, 0x0fb00cff, "mrs%c %12-15R, %R"},

  {ARM_EXT_V1, 0x03000000, 0x0fe00000, "tst%p%c %16-19r, %o"},
  {ARM_EXT_V1, 0x01000000, 0x0fe00010, "tst%p%c %16-19r, %o"},
  {ARM_EXT_V1, 0x01000010, 0x0fe00090, "tst%p%c %16-19R, %o"},

  {ARM_EXT_V1, 0x03200000, 0x0fe00000, "teq%p%c %16-19r, %o"},
  {ARM_EXT_V1, 0x01200000, 0x0fe00010, "teq%p%c %16-19r, %o"},
  {ARM_EXT_V1, 0x01200010, 0x0fe00090, "teq%p%c %16-19R, %o"},

  {ARM_EXT_V1, 0x03400000, 0x0fe00000, "cmp%p%c %16-19r, %o"},
  {ARM_EXT_V1, 0x01400000, 0x0fe00010, "cmp%p%c %16-19r, %o"},
  {ARM_EXT_V1, 0x01400010, 0x0fe00090, "cmp%p%c %16-19R, %o"},

  {ARM_EXT_V1, 0x03600000, 0x0fe00000, "cmn%p%c %16-19r, %o"},
  {ARM_EXT_V1, 0x01600000, 0x0fe00010, "cmn%p%c %16-19r, %o"},
  {ARM_EXT_V1, 0x01600010, 0x0fe00090, "cmn%p%c %16-19R, %o"},

  {ARM_EXT_V1, 0x03800000, 0x0fe00000, "orr%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x01800000, 0x0fe00010, "orr%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x01800010, 0x0fe00090, "orr%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x03a00000, 0x0fef0000, "mov%20's%c %12-15r, %o"},
  {ARM_EXT_V1, 0x01a00000, 0x0def0ff0, "mov%20's%c %12-15r, %0-3r"},
  {ARM_EXT_V1, 0x01a00000, 0x0def0060, "lsl%20's%c %12-15R, %q"},
  {ARM_EXT_V1, 0x01a00020, 0x0def0060, "lsr%20's%c %12-15R, %q"},
  {ARM_EXT_V1, 0x01a00040, 0x0def0060, "asr%20's%c %12-15R, %q"},
  {ARM_EXT_V1, 0x01a00060, 0x0def0ff0, "rrx%20's%c %12-15r, %0-3r"},
  {ARM_EXT_V1, 0x01a00060, 0x0def0060, "ror%20's%c %12-15R, %q"},

  {ARM_EXT_V1, 0x03c00000, 0x0fe00000, "bic%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x01c00000, 0x0fe00010, "bic%20's%c %12-15r, %16-19r, %o"},
  {ARM_EXT_V1, 0x01c00010, 0x0fe00090, "bic%20's%c %12-15R, %16-19R, %o"},

  {ARM_EXT_V1, 0x03e00000, 0x0fe00000, "mvn%20's%c %12-15r, %o"},
  {ARM_EXT_V1, 0x01e00000, 0x0fe00010, "mvn%20's%c %12-15r, %o"},
  {ARM_EXT_V1, 0x01e00010, 0x0fe00090, "mvn%20's%c %12-15R, %o"},

  {ARM_EXT_V1, 0x06000010, 0x0e000010, UNDEFINED_INSTRUCTION},
  {ARM_EXT_V1, 0x049d0004, 0x0fff0fff, "pop%c {%12-15r}  ; (ldr%c %12-15r, %a)"},
  
  {ARM_EXT_V1, 0x04500000, 0x0c500000, "ldrb%t%c %12-15R, %a"},

  {ARM_EXT_V1, 0x04300000, 0x0d700000, "ldrt%c %12-15R, %a"},
  {ARM_EXT_V1, 0x04100000, 0x0c500000, "ldr%c %12-15r, %a"},
  
  {ARM_EXT_V1, 0x092d0001, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0002, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0004, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0008, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0010, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0020, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0040, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0080, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0100, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0200, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0400, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0800, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d1000, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d2000, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d4000, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d8000, 0x0fffffff, "stmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x092d0000, 0x0fff0000, "push%c %m"},
  {ARM_EXT_V1, 0x08800000, 0x0ff00000, "stm%c %16-19R%21'!, %m%22'^"},
  {ARM_EXT_V1, 0x08000000, 0x0e100000, "stm%23?id%24?ba%c %16-19R%21'!, %m%22'^"},

  {ARM_EXT_V1, 0x08bd0001, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0002, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0004, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0008, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0010, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0020, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0040, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0080, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0100, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0200, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0400, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0800, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd1000, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd2000, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd4000, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd8000, 0x0fffffff, "ldmfd%c %16-19R!, %m"},
  {ARM_EXT_V1, 0x08bd0000, 0x0fff0000, "pop%c %m"},
  {ARM_EXT_V1, 0x08900000, 0x0f900000, "ldm%c %16-19R%21'!, %m%22'^"},
  {ARM_EXT_V1, 0x08100000, 0x0e100000, "ldm%23?id%24?ba%c %16-19R%21'!, %m%22'^"},

  {ARM_EXT_V1, 0x0a000000, 0x0e000000, "b%24'l%c %b"},
  {ARM_EXT_V1, 0x0f000000, 0x0f000000, "svc%c %0-23x"},

  /* The rest.  */
  {ARM_EXT_V1, 0x00000000, 0x00000000, UNDEFINED_INSTRUCTION},
  {0, 0x00000000, 0x00000000, 0}
};

/* print_insn_thumb16 recognizes the following format control codes:

   %S                   print Thumb register (bits 3..5 as high number if bit 6 set)
   %D                   print Thumb register (bits 0..2 as high number if bit 7 set)
   %<bitfield>I         print bitfield as a signed decimal
   				(top bit of range being the sign bit)
   %N                   print Thumb register mask (with LR)
   %O                   print Thumb register mask (with PC)
   %M                   print Thumb register mask
   %b			print CZB's 6-bit unsigned branch destination
   %s			print Thumb right-shift immediate (6..10; 0 == 32).
   %c			print the condition code
   %C			print the condition code, or "s" if not conditional
   %x			print warning if conditional an not at end of IT block"
   %X			print " ; unpredictable <IT:code>" if conditional
   %I			print IT instruction suffix and operands
   %W			print Thumb Writeback indicator for LDMIA
   %<bitfield>r		print bitfield as an ARM register
   %<bitfield>d		print bitfield as a decimal
   %<bitfield>H         print (bitfield * 2) as a decimal
   %<bitfield>W         print (bitfield * 4) as a decimal
   %<bitfield>a         print (bitfield * 4) as a pc-rel offset + decoded symbol
   %<bitfield>B         print Thumb branch destination (signed displacement)
   %<bitfield>c         print bitfield as a condition code
   %<bitnum>'c		print specified char iff bit is one
   %<bitnum>?ab		print a if bit is one else print b.  */

static const struct opcode16 thumb_opcodes[] =
{
  /* Thumb instructions.  */

  /* ARM V8 instructions.  */
  {ARM_EXT_V8,  0xbf50, 0xffff, "sevl%c"},
  {ARM_EXT_V8,  0xba80, 0xffc0, "hlt %0-5x"},

  /* ARM V6K no-argument instructions.  */
  {ARM_EXT_V6K, 0xbf00, 0xffff, "nop%c"},
  {ARM_EXT_V6K, 0xbf10, 0xffff, "yield%c"},
  {ARM_EXT_V6K, 0xbf20, 0xffff, "wfe%c"},
  {ARM_EXT_V6K, 0xbf30, 0xffff, "wfi%c"},
  {ARM_EXT_V6K, 0xbf40, 0xffff, "sev%c"},
  {ARM_EXT_V6K, 0xbf00, 0xff0f, "nop%c {%4-7d}"},

  /* ARM V6T2 instructions.  */
  {ARM_EXT_V6T2, 0xb900, 0xfd00, "cbnz %0-2r, %b%X"},
  {ARM_EXT_V6T2, 0xb100, 0xfd00, "cbz %0-2r, %b%X"},
  {ARM_EXT_V6T2, 0xbf00, 0xff00, "it%I%X"},

  /* ARM V6.  */
  {ARM_EXT_V6, 0xb660, 0xfff8, "cpsie %2'a%1'i%0'f%X"},
  {ARM_EXT_V6, 0xb670, 0xfff8, "cpsid %2'a%1'i%0'f%X"},
  {ARM_EXT_V6, 0x4600, 0xffc0, "mov%c %0-2r, %3-5r"},
  {ARM_EXT_V6, 0xba00, 0xffc0, "rev%c %0-2r, %3-5r"},
  {ARM_EXT_V6, 0xba40, 0xffc0, "rev16%c %0-2r, %3-5r"},
  {ARM_EXT_V6, 0xbac0, 0xffc0, "revsh%c %0-2r, %3-5r"},
  {ARM_EXT_V6, 0xb650, 0xfff7, "setend %3?ble%X"},
  {ARM_EXT_V6, 0xb200, 0xffc0, "sxth%c %0-2r, %3-5r"},
  {ARM_EXT_V6, 0xb240, 0xffc0, "sxtb%c %0-2r, %3-5r"},
  {ARM_EXT_V6, 0xb280, 0xffc0, "uxth%c %0-2r, %3-5r"},
  {ARM_EXT_V6, 0xb2c0, 0xffc0, "uxtb%c %0-2r, %3-5r"},

  /* ARM V5 ISA extends Thumb.  */
  {ARM_EXT_V5T, 0xbe00, 0xff00, "bkpt %0-7x"}, /* Is always unconditional.  */
  /* This is BLX(2).  BLX(1) is a 32-bit instruction.  */
  {ARM_EXT_V5T, 0x4780, 0xff87, "blx%c %3-6r%x"},	/* note: 4 bit register number.  */
  /* ARM V4T ISA (Thumb v1).  */
  {ARM_EXT_V4T, 0x46C0, 0xFFFF, "nop%c   ; (mov r8, r8)"},
  /* Format 4.  */
  {ARM_EXT_V4T, 0x4000, 0xFFC0, "and%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4040, 0xFFC0, "eor%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4080, 0xFFC0, "lsl%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x40C0, 0xFFC0, "lsr%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4100, 0xFFC0, "asr%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4140, 0xFFC0, "adc%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4180, 0xFFC0, "sbc%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x41C0, 0xFFC0, "ror%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4200, 0xFFC0, "tst%c %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4240, 0xFFC0, "neg%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4280, 0xFFC0, "cmp%c %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x42C0, 0xFFC0, "cmn%c %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4300, 0xFFC0, "orr%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4340, 0xFFC0, "mul%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x4380, 0xFFC0, "bic%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x43C0, 0xFFC0, "mvn%C %0-2r, %3-5r"},
  /* format 13 */
  {ARM_EXT_V4T, 0xB000, 0xFF80, "add%c sp, %0-6W"},
  {ARM_EXT_V4T, 0xB080, 0xFF80, "sub%c sp, %0-6W"},
  /* format 5 */
  {ARM_EXT_V4T, 0x4700, 0xFF80, "bx%c %S%x"},
  {ARM_EXT_V4T, 0x4400, 0xFF00, "add%c %D, %S"},
  {ARM_EXT_V4T, 0x4500, 0xFF00, "cmp%c %D, %S"},
  {ARM_EXT_V4T, 0x4600, 0xFF00, "mov%c %D, %S"},
  /* format 14 */
  {ARM_EXT_V4T, 0xB400, 0xFE00, "push%c %N"},
  {ARM_EXT_V4T, 0xBC00, 0xFE00, "pop%c %O"},
  /* format 2 */
  {ARM_EXT_V4T, 0x1800, 0xFE00, "add%C %0-2r, %3-5r, %6-8r"},
  {ARM_EXT_V4T, 0x1A00, 0xFE00, "sub%C %0-2r, %3-5r, %6-8r"},
  {ARM_EXT_V4T, 0x1C00, 0xFE00, "add%C %0-2r, %3-5r, %6-8d"},
  {ARM_EXT_V4T, 0x1E00, 0xFE00, "sub%C %0-2r, %3-5r, %6-8d"},
  /* format 8 */
  {ARM_EXT_V4T, 0x5200, 0xFE00, "strh%c %0-2r, [%3-5r, %6-8r]"},
  {ARM_EXT_V4T, 0x5A00, 0xFE00, "ldrh%c %0-2r, [%3-5r, %6-8r]"},
  {ARM_EXT_V4T, 0x5600, 0xF600, "ldrs%11?hb%c %0-2r, [%3-5r, %6-8r]"},
  /* format 7 */
  {ARM_EXT_V4T, 0x5000, 0xFA00, "str%10'b%c %0-2r, [%3-5r, %6-8r]"},
  {ARM_EXT_V4T, 0x5800, 0xFA00, "ldr%10'b%c %0-2r, [%3-5r, %6-8r]"},
  /* format 1 */
  {ARM_EXT_V4T, 0x0000, 0xFFC0, "mov%C %0-2r, %3-5r"},
  {ARM_EXT_V4T, 0x0000, 0xF800, "lsl%C %0-2r, %3-5r, %6-10d"},
  {ARM_EXT_V4T, 0x0800, 0xF800, "lsr%C %0-2r, %3-5r, %s"},
  {ARM_EXT_V4T, 0x1000, 0xF800, "asr%C %0-2r, %3-5r, %s"},
  /* format 3 */
  {ARM_EXT_V4T, 0x2000, 0xF800, "mov%C %8-10r, %0-7d"},
  {ARM_EXT_V4T, 0x2800, 0xF800, "cmp%c %8-10r, %0-7d"},
  {ARM_EXT_V4T, 0x3000, 0xF800, "add%C %8-10r, %0-7d"},
  {ARM_EXT_V4T, 0x3800, 0xF800, "sub%C %8-10r, %0-7d"},
  /* format 6 */
  {ARM_EXT_V4T, 0x4800, 0xF800, "ldr%c %8-10r, [pc, %0-7W] ; (%0-7a)"},  /* TODO: Disassemble PC relative "LDR rD,=<symbolic>" */
  /* format 9 */
  {ARM_EXT_V4T, 0x6000, 0xF800, "str%c %0-2r, [%3-5r, %6-10W]"},
  {ARM_EXT_V4T, 0x6800, 0xF800, "ldr%c %0-2r, [%3-5r, %6-10W]"},
  {ARM_EXT_V4T, 0x7000, 0xF800, "strb%c %0-2r, [%3-5r, %6-10d]"},
  {ARM_EXT_V4T, 0x7800, 0xF800, "ldrb%c %0-2r, [%3-5r, %6-10d]"},
  /* format 10 */
  {ARM_EXT_V4T, 0x8000, 0xF800, "strh%c %0-2r, [%3-5r, %6-10H]"},
  {ARM_EXT_V4T, 0x8800, 0xF800, "ldrh%c %0-2r, [%3-5r, %6-10H]"},
  /* format 11 */
  {ARM_EXT_V4T, 0x9000, 0xF800, "str%c %8-10r, [sp, %0-7W]"},
  {ARM_EXT_V4T, 0x9800, 0xF800, "ldr%c %8-10r, [sp, %0-7W]"},
  /* format 12 */
  {ARM_EXT_V4T, 0xA000, 0xF800, "add%c %8-10r, pc, %0-7W ; (adr %8-10r, %0-7a)"},
  {ARM_EXT_V4T, 0xA800, 0xF800, "add%c %8-10r, sp, %0-7W"},
  /* format 15 */
  {ARM_EXT_V4T, 0xC000, 0xF800, "stmia%c %8-10r!, %M"},
  {ARM_EXT_V4T, 0xC800, 0xF800, "ldmia%c %8-10r%W, %M"},
  /* format 17 */
  {ARM_EXT_V4T, 0xDF00, 0xFF00, "svc%c %0-7d"},
  /* format 16 */
  {ARM_EXT_V4T, 0xDE00, 0xFE00, UNDEFINED_INSTRUCTION},
  {ARM_EXT_V4T, 0xD000, 0xF000, "b%8-11c.n %0-7B%X"},
  /* format 18 */
  {ARM_EXT_V4T, 0xE000, 0xF800, "b%c.n %0-10B%x"},

  /* The E800 .. FFFF range is unconditionally redirected to the
     32-bit table, because even in pre-V6T2 ISAs, BL and BLX(1) pairs
     are processed via that table.  Thus, we can never encounter a
     bare "second half of BL/BLX(1)" instruction here.  */
  {ARM_EXT_V1,  0x0000, 0x0000, UNDEFINED_INSTRUCTION},
  {0, 0, 0, 0}
};

/* Thumb32 opcodes use the same table structure as the ARM opcodes.
   We adopt the convention that hw1 is the high 16 bits of .value and
   .mask, hw2 the low 16 bits.

   print_insn_thumb32 recognizes the following format control codes:

       %%		%

       %I		print a 12-bit immediate from hw1[10],hw2[14:12,7:0]
       %M		print a modified 12-bit immediate (same location)
       %J		print a 16-bit immediate from hw1[3:0,10],hw2[14:12,7:0]
       %K		print a 16-bit immediate from hw2[3:0],hw1[3:0],hw2[11:4]
       %H		print a 16-bit immediate from hw2[3:0],hw1[11:0]
       %S		print a possibly-shifted Rm

       %L		print address for a ldrd/strd instruction
       %a		print the address of a plain load/store
       %w		print the width and signedness of a core load/store
       %m		print register mask for ldm/stm

       %E		print the lsb and width fields of a bfc/bfi instruction
       %F		print the lsb and width fields of a sbfx/ubfx instruction
       %b		print a conditional branch offset
       %B		print an unconditional branch offset
       %s		print the shift field of an SSAT instruction
       %R		print the rotation field of an SXT instruction
       %U		print barrier type.
       %P		print address for pli instruction.
       %c		print the condition code
       %x		print warning if conditional an not at end of IT block"
       %X		print " ; unpredictable <IT:code>" if conditional

       %<bitfield>d	print bitfield in decimal
       %<bitfield>W	print bitfield*4 in decimal
       %<bitfield>r	print bitfield as an ARM register
       %<bitfield>R	as %<>r bit r15 is UNPREDICTABLE
       %<bitfield>c	print bitfield as a condition code

       %<bitfield>'c	print specified char iff bitfield is all ones
       %<bitfield>`c	print specified char iff bitfield is all zeroes
       %<bitfield>?ab... select from array of values in big endian order

   With one exception at the bottom (done because BL and BLX(1) need
   to come dead last), this table was machine-sorted first in
   decreasing order of number of bits set in the mask, then in
   increasing numeric order of mask, then in increasing numeric order
   of opcode.  This order is not the clearest for a human reader, but
   is guaranteed never to catch a special-case bit pattern with a more
   general mask, which is important, because this instruction encoding
   makes heavy use of special-case bit patterns.  */
static const struct opcode32 thumb32_opcodes[] =
{
  /* V8 instructions.  */
  {ARM_EXT_V8, 0xf3af8005, 0xffffffff, "sevl%c.w"},
  {ARM_EXT_V8, 0xf78f8000, 0xfffffffc, "dcps%0-1d"},
  {ARM_EXT_V8, 0xe8c00f8f, 0xfff00fff, "stlb%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8c00f9f, 0xfff00fff, "stlh%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8c00faf, 0xfff00fff, "stl%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8c00fc0, 0xfff00ff0, "stlexb%c %0-3r, %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8c00fd0, 0xfff00ff0, "stlexh%c %0-3r, %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8c00fe0, 0xfff00ff0, "stlex%c %0-3r, %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8c000f0, 0xfff000f0, "stlexd%c %0-3r, %12-15r, %8-11r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8d00f8f, 0xfff00fff, "ldab%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8d00f9f, 0xfff00fff, "ldah%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8d00faf, 0xfff00fff, "lda%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8d00fcf, 0xfff00fff, "ldaexb%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8d00fdf, 0xfff00fff, "ldaexh%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8d00fef, 0xfff00fff, "ldaex%c %12-15r, [%16-19R]"},
  {ARM_EXT_V8, 0xe8d000ff, 0xfff000ff, "ldaexd%c %12-15r, %8-11r, [%16-19R]"},

  /* V7 instructions.  */
  {ARM_EXT_V7, 0xf910f000, 0xff70f000, "pli%c %a"},
  {ARM_EXT_V7, 0xf3af80f0, 0xfffffff0, "dbg%c %0-3d"},
  {ARM_EXT_V8, 0xf3bf8f51, 0xfffffff3, "dmb%c %U"},
  {ARM_EXT_V8, 0xf3bf8f41, 0xfffffff3, "dsb%c %U"},
  {ARM_EXT_V7, 0xf3bf8f50, 0xfffffff0, "dmb%c %U"},
  {ARM_EXT_V7, 0xf3bf8f40, 0xfffffff0, "dsb%c %U"},
  {ARM_EXT_V7, 0xf3bf8f60, 0xfffffff0, "isb%c %U"},
  {ARM_EXT_DIV, 0xfb90f0f0, 0xfff0f0f0, "sdiv%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_DIV, 0xfbb0f0f0, 0xfff0f0f0, "udiv%c %8-11r, %16-19r, %0-3r"},

  /* Virtualization Extension instructions.  */
  {ARM_EXT_VIRT, 0xf7e08000, 0xfff0f000, "hvc%c %V"},
  /* We skip ERET as that is SUBS pc, lr, #0.  */

  /* MP Extension instructions.  */
  {ARM_EXT_MP,   0xf830f000, 0xff70f000, "pldw%c %a"},

  /* Security extension instructions.  */
  {ARM_EXT_SEC,  0xf7f08000, 0xfff0f000, "smc%c %K"},

  /* Instructions defined in the basic V6T2 set.  */
  {ARM_EXT_V6T2, 0xf3af8000, 0xffffffff, "nop%c.w"},
  {ARM_EXT_V6T2, 0xf3af8001, 0xffffffff, "yield%c.w"},
  {ARM_EXT_V6T2, 0xf3af8002, 0xffffffff, "wfe%c.w"},
  {ARM_EXT_V6T2, 0xf3af8003, 0xffffffff, "wfi%c.w"},
  {ARM_EXT_V6T2, 0xf3af8004, 0xffffffff, "sev%c.w"},
  {ARM_EXT_V6T2, 0xf3af8000, 0xffffff00, "nop%c.w {%0-7d}"},

  {ARM_EXT_V6T2, 0xf3bf8f2f, 0xffffffff, "clrex%c"},
  {ARM_EXT_V6T2, 0xf3af8400, 0xffffff1f, "cpsie.w %7'a%6'i%5'f%X"},
  {ARM_EXT_V6T2, 0xf3af8600, 0xffffff1f, "cpsid.w %7'a%6'i%5'f%X"},
  {ARM_EXT_V6T2, 0xf3c08f00, 0xfff0ffff, "bxj%c %16-19r%x"},
  {ARM_EXT_V6T2, 0xe810c000, 0xffd0ffff, "rfedb%c %16-19r%21'!"},
  {ARM_EXT_V6T2, 0xe990c000, 0xffd0ffff, "rfeia%c %16-19r%21'!"},
  {ARM_EXT_V6T2, 0xf3e08000, 0xffe0f000, "mrs%c %8-11r, %D"},
  {ARM_EXT_V6T2, 0xf3af8100, 0xffffffe0, "cps %0-4d%X"},
  {ARM_EXT_V6T2, 0xe8d0f000, 0xfff0fff0, "tbb%c [%16-19r, %0-3r]%x"},
  {ARM_EXT_V6T2, 0xe8d0f010, 0xfff0fff0, "tbh%c [%16-19r, %0-3r, lsl #1]%x"},
  {ARM_EXT_V6T2, 0xf3af8500, 0xffffff00, "cpsie %7'a%6'i%5'f, %0-4d%X"},
  {ARM_EXT_V6T2, 0xf3af8700, 0xffffff00, "cpsid %7'a%6'i%5'f, %0-4d%X"},
  {ARM_EXT_V6T2, 0xf3de8f00, 0xffffff00, "subs%c pc, lr, %0-7d"},
  {ARM_EXT_V6T2, 0xf3808000, 0xffe0f000, "msr%c %C, %16-19r"},
  {ARM_EXT_V6T2, 0xe8500f00, 0xfff00fff, "ldrex%c %12-15r, [%16-19r]"},
  {ARM_EXT_V6T2, 0xe8d00f4f, 0xfff00fef, "ldrex%4?hb%c %12-15r, [%16-19r]"},
  {ARM_EXT_V6T2, 0xe800c000, 0xffd0ffe0, "srsdb%c %16-19r%21'!, %0-4d"},
  {ARM_EXT_V6T2, 0xe980c000, 0xffd0ffe0, "srsia%c %16-19r%21'!, %0-4d"},
  {ARM_EXT_V6T2, 0xfa0ff080, 0xfffff0c0, "sxth%c.w %8-11r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa1ff080, 0xfffff0c0, "uxth%c.w %8-11r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa2ff080, 0xfffff0c0, "sxtb16%c %8-11r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa3ff080, 0xfffff0c0, "uxtb16%c %8-11r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa4ff080, 0xfffff0c0, "sxtb%c.w %8-11r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa5ff080, 0xfffff0c0, "uxtb%c.w %8-11r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xe8400000, 0xfff000ff, "strex%c %8-11r, %12-15r, [%16-19r]"},
  {ARM_EXT_V6T2, 0xe8d0007f, 0xfff000ff, "ldrexd%c %12-15r, %8-11r, [%16-19r]"},
  {ARM_EXT_V6T2, 0xfa80f000, 0xfff0f0f0, "sadd8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa80f010, 0xfff0f0f0, "qadd8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa80f020, 0xfff0f0f0, "shadd8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa80f040, 0xfff0f0f0, "uadd8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa80f050, 0xfff0f0f0, "uqadd8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa80f060, 0xfff0f0f0, "uhadd8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa80f080, 0xfff0f0f0, "qadd%c %8-11r, %0-3r, %16-19r"},
  {ARM_EXT_V6T2, 0xfa80f090, 0xfff0f0f0, "qdadd%c %8-11r, %0-3r, %16-19r"},
  {ARM_EXT_V6T2, 0xfa80f0a0, 0xfff0f0f0, "qsub%c %8-11r, %0-3r, %16-19r"},
  {ARM_EXT_V6T2, 0xfa80f0b0, 0xfff0f0f0, "qdsub%c %8-11r, %0-3r, %16-19r"},
  {ARM_EXT_V6T2, 0xfa90f000, 0xfff0f0f0, "sadd16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa90f010, 0xfff0f0f0, "qadd16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa90f020, 0xfff0f0f0, "shadd16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa90f040, 0xfff0f0f0, "uadd16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa90f050, 0xfff0f0f0, "uqadd16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa90f060, 0xfff0f0f0, "uhadd16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa90f080, 0xfff0f0f0, "rev%c.w %8-11r, %16-19r"},
  {ARM_EXT_V6T2, 0xfa90f090, 0xfff0f0f0, "rev16%c.w %8-11r, %16-19r"},
  {ARM_EXT_V6T2, 0xfa90f0a0, 0xfff0f0f0, "rbit%c %8-11r, %16-19r"},
  {ARM_EXT_V6T2, 0xfa90f0b0, 0xfff0f0f0, "revsh%c.w %8-11r, %16-19r"},
  {ARM_EXT_V6T2, 0xfaa0f000, 0xfff0f0f0, "sasx%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfaa0f010, 0xfff0f0f0, "qasx%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfaa0f020, 0xfff0f0f0, "shasx%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfaa0f040, 0xfff0f0f0, "uasx%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfaa0f050, 0xfff0f0f0, "uqasx%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfaa0f060, 0xfff0f0f0, "uhasx%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfaa0f080, 0xfff0f0f0, "sel%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfab0f080, 0xfff0f0f0, "clz%c %8-11r, %16-19r"},
  {ARM_EXT_V6T2, 0xfac0f000, 0xfff0f0f0, "ssub8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfac0f010, 0xfff0f0f0, "qsub8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfac0f020, 0xfff0f0f0, "shsub8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfac0f040, 0xfff0f0f0, "usub8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfac0f050, 0xfff0f0f0, "uqsub8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfac0f060, 0xfff0f0f0, "uhsub8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfad0f000, 0xfff0f0f0, "ssub16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfad0f010, 0xfff0f0f0, "qsub16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfad0f020, 0xfff0f0f0, "shsub16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfad0f040, 0xfff0f0f0, "usub16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfad0f050, 0xfff0f0f0, "uqsub16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfad0f060, 0xfff0f0f0, "uhsub16%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfae0f000, 0xfff0f0f0, "ssax%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfae0f010, 0xfff0f0f0, "qsax%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfae0f020, 0xfff0f0f0, "shsax%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfae0f040, 0xfff0f0f0, "usax%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfae0f050, 0xfff0f0f0, "uqsax%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfae0f060, 0xfff0f0f0, "uhsax%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfb00f000, 0xfff0f0f0, "mul%c.w %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfb70f000, 0xfff0f0f0, "usad8%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa00f000, 0xffe0f0f0, "lsl%20's%c.w %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xfa20f000, 0xffe0f0f0, "lsr%20's%c.w %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xfa40f000, 0xffe0f0f0, "asr%20's%c.w %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xfa60f000, 0xffe0f0f0, "ror%20's%c.w %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xe8c00f40, 0xfff00fe0, "strex%4?hb%c %0-3r, %12-15r, [%16-19r]"},
  {ARM_EXT_V6T2, 0xf3200000, 0xfff0f0e0, "ssat16%c %8-11r, %0-4d, %16-19r"},
  {ARM_EXT_V6T2, 0xf3a00000, 0xfff0f0e0, "usat16%c %8-11r, %0-4d, %16-19r"},
  {ARM_EXT_V6T2, 0xfb20f000, 0xfff0f0e0, "smuad%4'x%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfb30f000, 0xfff0f0e0, "smulw%4?tb%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfb40f000, 0xfff0f0e0, "smusd%4'x%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfb50f000, 0xfff0f0e0, "smmul%4'r%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xfa00f080, 0xfff0f0c0, "sxtah%c %8-11r, %16-19r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa10f080, 0xfff0f0c0, "uxtah%c %8-11r, %16-19r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa20f080, 0xfff0f0c0, "sxtab16%c %8-11r, %16-19r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa30f080, 0xfff0f0c0, "uxtab16%c %8-11r, %16-19r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa40f080, 0xfff0f0c0, "sxtab%c %8-11r, %16-19r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfa50f080, 0xfff0f0c0, "uxtab%c %8-11r, %16-19r, %0-3r%R"},
  {ARM_EXT_V6T2, 0xfb10f000, 0xfff0f0c0, "smul%5?tb%4?tb%c %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xf36f0000, 0xffff8020, "bfc%c %8-11r, %E"},
  {ARM_EXT_V6T2, 0xea100f00, 0xfff08f00, "tst%c.w %16-19r, %S"},
  {ARM_EXT_V6T2, 0xea900f00, 0xfff08f00, "teq%c %16-19r, %S"},
  {ARM_EXT_V6T2, 0xeb100f00, 0xfff08f00, "cmn%c.w %16-19r, %S"},
  {ARM_EXT_V6T2, 0xebb00f00, 0xfff08f00, "cmp%c.w %16-19r, %S"},
  {ARM_EXT_V6T2, 0xf0100f00, 0xfbf08f00, "tst%c.w %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf0900f00, 0xfbf08f00, "teq%c %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf1100f00, 0xfbf08f00, "cmn%c.w %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf1b00f00, 0xfbf08f00, "cmp%c.w %16-19r, %M"},
  {ARM_EXT_V6T2, 0xea4f0000, 0xffef8000, "mov%20's%c.w %8-11r, %S"},
  {ARM_EXT_V6T2, 0xea6f0000, 0xffef8000, "mvn%20's%c.w %8-11r, %S"},
  {ARM_EXT_V6T2, 0xe8c00070, 0xfff000f0, "strexd%c %0-3r, %12-15r, %8-11r, [%16-19r]"},
  {ARM_EXT_V6T2, 0xfb000000, 0xfff000f0, "mla%c %8-11r, %16-19r, %0-3r, %12-15r"},
  {ARM_EXT_V6T2, 0xfb000010, 0xfff000f0, "mls%c %8-11r, %16-19r, %0-3r, %12-15r"},
  {ARM_EXT_V6T2, 0xfb700000, 0xfff000f0, "usada8%c %8-11R, %16-19R, %0-3R, %12-15R"},
  {ARM_EXT_V6T2, 0xfb800000, 0xfff000f0, "smull%c %12-15R, %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xfba00000, 0xfff000f0, "umull%c %12-15R, %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xfbc00000, 0xfff000f0, "smlal%c %12-15R, %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xfbe00000, 0xfff000f0, "umlal%c %12-15R, %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xfbe00060, 0xfff000f0, "umaal%c %12-15R, %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xe8500f00, 0xfff00f00, "ldrex%c %12-15r, [%16-19r, %0-7W]"},
  {ARM_EXT_V6T2, 0xf04f0000, 0xfbef8000, "mov%20's%c.w %8-11r, %M"},
  {ARM_EXT_V6T2, 0xf06f0000, 0xfbef8000, "mvn%20's%c.w %8-11r, %M"},
  {ARM_EXT_V6T2, 0xf810f000, 0xff70f000, "pld%c %a"},
  {ARM_EXT_V6T2, 0xfb200000, 0xfff000e0, "smlad%4'x%c %8-11R, %16-19R, %0-3R, %12-15R"},
  {ARM_EXT_V6T2, 0xfb300000, 0xfff000e0, "smlaw%4?tb%c %8-11R, %16-19R, %0-3R, %12-15R"},
  {ARM_EXT_V6T2, 0xfb400000, 0xfff000e0, "smlsd%4'x%c %8-11R, %16-19R, %0-3R, %12-15R"},
  {ARM_EXT_V6T2, 0xfb500000, 0xfff000e0, "smmla%4'r%c %8-11R, %16-19R, %0-3R, %12-15R"},
  {ARM_EXT_V6T2, 0xfb600000, 0xfff000e0, "smmls%4'r%c %8-11R, %16-19R, %0-3R, %12-15R"},
  {ARM_EXT_V6T2, 0xfbc000c0, 0xfff000e0, "smlald%4'x%c %12-15R, %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xfbd000c0, 0xfff000e0, "smlsld%4'x%c %12-15R, %8-11R, %16-19R, %0-3R"},
  {ARM_EXT_V6T2, 0xeac00000, 0xfff08030, "pkhbt%c %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xeac00020, 0xfff08030, "pkhtb%c %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xf3400000, 0xfff08020, "sbfx%c %8-11r, %16-19r, %F"},
  {ARM_EXT_V6T2, 0xf3c00000, 0xfff08020, "ubfx%c %8-11r, %16-19r, %F"},
  {ARM_EXT_V6T2, 0xf8000e00, 0xff900f00, "str%wt%c %12-15r, %a"},
  {ARM_EXT_V6T2, 0xfb100000, 0xfff000c0, "smla%5?tb%4?tb%c %8-11r, %16-19r, %0-3r, %12-15r"},
  {ARM_EXT_V6T2, 0xfbc00080, 0xfff000c0, "smlal%5?tb%4?tb%c %12-15r, %8-11r, %16-19r, %0-3r"},
  {ARM_EXT_V6T2, 0xf3600000, 0xfff08020, "bfi%c %8-11r, %16-19r, %E"},
  {ARM_EXT_V6T2, 0xf8100e00, 0xfe900f00, "ldr%wt%c %12-15r, %a"},
  {ARM_EXT_V6T2, 0xf3000000, 0xffd08020, "ssat%c %8-11r, %0-4d, %16-19r%s"},
  {ARM_EXT_V6T2, 0xf3800000, 0xffd08020, "usat%c %8-11r, %0-4d, %16-19r%s"},
  {ARM_EXT_V6T2, 0xf2000000, 0xfbf08000, "addw%c %8-11r, %16-19r, %I"},
  {ARM_EXT_V6T2, 0xf2400000, 0xfbf08000, "movw%c %8-11r, %J"},
  {ARM_EXT_V6T2, 0xf2a00000, 0xfbf08000, "subw%c %8-11r, %16-19r, %I"},
  {ARM_EXT_V6T2, 0xf2c00000, 0xfbf08000, "movt%c %8-11r, %J"},
  {ARM_EXT_V6T2, 0xea000000, 0xffe08000, "and%20's%c.w %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xea200000, 0xffe08000, "bic%20's%c.w %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xea400000, 0xffe08000, "orr%20's%c.w %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xea600000, 0xffe08000, "orn%20's%c %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xea800000, 0xffe08000, "eor%20's%c.w %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xeb000000, 0xffe08000, "add%20's%c.w %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xeb400000, 0xffe08000, "adc%20's%c.w %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xeb600000, 0xffe08000, "sbc%20's%c.w %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xeba00000, 0xffe08000, "sub%20's%c.w %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xebc00000, 0xffe08000, "rsb%20's%c %8-11r, %16-19r, %S"},
  {ARM_EXT_V6T2, 0xe8400000, 0xfff00000, "strex%c %8-11r, %12-15r, [%16-19r, %0-7W]"},
  {ARM_EXT_V6T2, 0xf0000000, 0xfbe08000, "and%20's%c.w %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf0200000, 0xfbe08000, "bic%20's%c.w %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf0400000, 0xfbe08000, "orr%20's%c.w %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf0600000, 0xfbe08000, "orn%20's%c %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf0800000, 0xfbe08000, "eor%20's%c.w %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf1000000, 0xfbe08000, "add%20's%c.w %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf1400000, 0xfbe08000, "adc%20's%c.w %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf1600000, 0xfbe08000, "sbc%20's%c.w %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf1a00000, 0xfbe08000, "sub%20's%c.w %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xf1c00000, 0xfbe08000, "rsb%20's%c %8-11r, %16-19r, %M"},
  {ARM_EXT_V6T2, 0xe8800000, 0xffd00000, "stmia%c.w %16-19r%21'!, %m"},
  {ARM_EXT_V6T2, 0xe8900000, 0xffd00000, "ldmia%c.w %16-19r%21'!, %m"},
  {ARM_EXT_V6T2, 0xe9000000, 0xffd00000, "stmdb%c %16-19r%21'!, %m"},
  {ARM_EXT_V6T2, 0xe9100000, 0xffd00000, "ldmdb%c %16-19r%21'!, %m"},
  {ARM_EXT_V6T2, 0xe9c00000, 0xffd000ff, "strd%c %12-15r, %8-11r, [%16-19r]"},
  {ARM_EXT_V6T2, 0xe9d00000, 0xffd000ff, "ldrd%c %12-15r, %8-11r, [%16-19r]"},
  {ARM_EXT_V6T2, 0xe9400000, 0xff500000, "strd%c %12-15r, %8-11r, [%16-19r, %23`-%0-7W]%21'!%L"},
  {ARM_EXT_V6T2, 0xe9500000, 0xff500000, "ldrd%c %12-15r, %8-11r, [%16-19r, %23`-%0-7W]%21'!%L"},
  {ARM_EXT_V6T2, 0xe8600000, 0xff700000, "strd%c %12-15r, %8-11r, [%16-19r], %23`-%0-7W%L"},
  {ARM_EXT_V6T2, 0xe8700000, 0xff700000, "ldrd%c %12-15r, %8-11r, [%16-19r], %23`-%0-7W%L"},
  {ARM_EXT_V6T2, 0xf8000000, 0xff100000, "str%w%c.w %12-15r, %a"},
  {ARM_EXT_V6T2, 0xf8100000, 0xfe100000, "ldr%w%c.w %12-15r, %a"},

  /* Filter out Bcc with cond=E or F, which are used for other instructions.  */
  {ARM_EXT_V6T2, 0xf3c08000, 0xfbc0d000, "undefined (bcc, cond=0xF)"},
  {ARM_EXT_V6T2, 0xf3808000, 0xfbc0d000, "undefined (bcc, cond=0xE)"},
  {ARM_EXT_V6T2, 0xf0008000, 0xf800d000, "b%22-25c.w %b%X"},
  {ARM_EXT_V6T2, 0xf0009000, 0xf800d000, "b%c.w %B%x"},

  /* These have been 32-bit since the invention of Thumb.  */
  {ARM_EXT_V4T,  0xf000c000, 0xf800d001, "blx%c %B%x"},
  {ARM_EXT_V4T,  0xf000d000, 0xf800d000, "bl%c %B%x"},

  /* Fallback.  */
  {ARM_EXT_V1,   0x00000000, 0x00000000, UNDEFINED_INSTRUCTION},
  {0, 0, 0, 0}
};

static const char *const arm_conditional[] =
{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
 "hi", "ls", "ge", "lt", "gt", "le", "al", "<und>", ""};

static const char *const arm_fp_const[] =
{"0.0", "1.0", "2.0", "3.0", "4.0", "5.0", "0.5", "10.0"};

static const char *const arm_shift[] =
{"lsl", "lsr", "asr", "ror"};

typedef struct
{
  const char *name;
  const char *description;
  const char *reg_names[16];
}
arm_regname;

static const arm_regname regnames[] =
{
  { "raw" , "Select raw register names",
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}},
  { "gcc",  "Select register names used by GCC",
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl",  "fp",  "ip",  "sp",  "lr",  "pc" }},
  { "std",  "Select register names used in ARM's ISA documentation",
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",  "lr",  "pc" }},
  { "apcs", "Select register names used in the APCS",
    { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "v4", "v5", "v6", "sl",  "fp",  "ip",  "sp",  "lr",  "pc" }},
  { "atpcs", "Select register names used in the ATPCS",
    { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "v4", "v5", "v6", "v7",  "v8",  "IP",  "SP",  "LR",  "PC" }},
  { "special-atpcs", "Select special register names used in the ATPCS",
    { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "WR", "v5", "SB", "SL",  "FP",  "IP",  "SP",  "LR",  "PC" }},
};

static const char *const iwmmxt_wwnames[] =
{"b", "h", "w", "d"};

static const char *const iwmmxt_wwssnames[] =
{"b", "bus", "bc", "bss",
 "h", "hus", "hc", "hss",
 "w", "wus", "wc", "wss",
 "d", "dus", "dc", "dss"
};

static const char *const iwmmxt_regnames[] =
{ "wr0", "wr1", "wr2", "wr3", "wr4", "wr5", "wr6", "wr7",
  "wr8", "wr9", "wr10", "wr11", "wr12", "wr13", "wr14", "wr15"
};

static const char *const iwmmxt_cregnames[] =
{ "wcid", "wcon", "wcssf", "wcasf", "reserved", "reserved", "reserved", "reserved",
  "wcgr0", "wcgr1", "wcgr2", "wcgr3", "reserved", "reserved", "reserved", "reserved"
};

/* Default to GCC register name set.  */
static unsigned int regname_selected = 1;

#define NUM_ARM_REGNAMES  NUM_ELEM (regnames)
#define arm_regnames      regnames[regname_selected].reg_names

static bfd_boolean force_thumb = FALSE;

/* Current IT instruction state.  This contains the same state as the IT
   bits in the CPSR.  */
static unsigned int ifthen_state;
/* IT state for the next instruction.  */
static unsigned int ifthen_next_state;
/* The address of the insn for which the IT state is valid.  */
static bfd_vma ifthen_address;
#define IFTHEN_COND ((ifthen_state >> 4) & 0xf)
/* Indicates that the current Conditional state is unconditional or outside
   an IT block.  */
#define COND_UNCOND 16


/* Functions.  */
int
get_arm_regname_num_options (void)
{
  return NUM_ARM_REGNAMES;
}

int
set_arm_regname_option (int option)
{
  int old = regname_selected;
  regname_selected = option;
  return old;
}

int
get_arm_regnames (int option,
		  const char **setname,
		  const char **setdescription,
		  const char *const **register_names)
{
  *setname = regnames[option].name;
  *setdescription = regnames[option].description;
  *register_names = regnames[option].reg_names;
  return 16;
}

/* Decode a bitfield of the form matching regexp (N(-N)?,)*N(-N)?.
   Returns pointer to following character of the format string and
   fills in *VALUEP and *WIDTHP with the extracted value and number of
   bits extracted.  WIDTHP can be NULL.  */

static const char *
arm_decode_bitfield (const char *ptr,
		     unsigned long insn,
		     unsigned long *valuep,
		     int *widthp)
{
  unsigned long value = 0;
  int width = 0;
  
  do 
    {
      int start, end;
      int bits;

      for (start = 0; *ptr >= '0' && *ptr <= '9'; ptr++)
	start = start * 10 + *ptr - '0';
      if (*ptr == '-')
	for (end = 0, ptr++; *ptr >= '0' && *ptr <= '9'; ptr++)
	  end = end * 10 + *ptr - '0';
      else
	end = start;
      bits = end - start;
      if (bits < 0)
	abort ();
      value |= ((insn >> start) & ((2ul << bits) - 1)) << width;
      width += bits + 1;
    }
  while (*ptr++ == ',');
  *valuep = value;
  if (widthp)
    *widthp = width;
  return ptr - 1;
}

static void
arm_decode_shift (long given, fprintf_ftype func, void *stream,
		  bfd_boolean print_shift)
{
  func (stream, "%s", arm_regnames[given & 0xf]);

  if ((given & 0xff0) != 0)
    {
      if ((given & 0x10) == 0)
	{
	  int amount = (given & 0xf80) >> 7;
	  int shift = (given & 0x60) >> 5;

	  if (amount == 0)
	    {
	      if (shift == 3)
		{
		  func (stream, ", rrx");
		  return;
		}

	      amount = 32;
	    }

	  if (print_shift)
	    func (stream, ", %s %d", arm_shift[shift], amount);
	  else
	    func (stream, ", %d", amount);
	}
      else if ((given & 0x80) == 0x80)
	func (stream, " ; <illegal shifter operand>");
      else if (print_shift)
	func (stream, ", %s %s", arm_shift[(given & 0x60) >> 5],
	      arm_regnames[(given & 0xf00) >> 8]);
      else
	func (stream, ", %s", arm_regnames[(given & 0xf00) >> 8]);
    }
}

#define W_BIT 21
#define I_BIT 22
#define U_BIT 23
#define P_BIT 24

#define WRITEBACK_BIT_SET   (given & (1 << W_BIT))
#define IMMEDIATE_BIT_SET   (given & (1 << I_BIT))
#define NEGATIVE_BIT_SET   ((given & (1 << U_BIT)) == 0)
#define PRE_BIT_SET         (given & (1 << P_BIT))

/* Print one coprocessor instruction on INFO->STREAM.
   Return TRUE if the instuction matched, FALSE if this is not a
   recognised coprocessor instruction.  */

static bfd_boolean
print_insn_coprocessor (bfd_vma pc,
			struct disassemble_info *info,
			long given,
			bfd_boolean thumb)
{
  const struct opcode32 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;
  unsigned long mask;
  unsigned long value = 0;
  struct arm_private_data *private_data = info->private_data;
  unsigned long allowed_arches = private_data->features.coproc;
  int cond;

  for (insn = coprocessor_opcodes; insn->assembler; insn++)
    {
      unsigned long u_reg = 16;
      bfd_boolean is_unpredictable = FALSE;
      signed long value_in_comment = 0;
      const char *c;

      if (insn->arch == 0)
	switch (insn->value)
	  {
#if 0
	  case SENTINEL_IWMMXT_START:
	    if (info->mach != bfd_mach_arm_XScale
		&& info->mach != bfd_mach_arm_iWMMXt
		&& info->mach != bfd_mach_arm_iWMMXT2)
	      do
		insn++;
	      while (insn->arch != 0 && insn->value != SENTINEL_IWMMXT_END);
	    continue;
#endif
	  case SENTINEL_IWMMXT_END:
	    continue;

	  case SENTINEL_GENERIC_START:
	    allowed_arches = private_data->features.core;
	    continue;

	  default:
	    abort ();
	  }

      mask = insn->mask;
      value = insn->value;
      if (thumb)
	{
	  /* The high 4 bits are 0xe for Arm conditional instructions, and
	     0xe for arm unconditional instructions.  The rest of the
	     encoding is the same.  */
	  mask |= 0xf0000000;
	  value |= 0xe0000000;
	  if (ifthen_state)
	    cond = IFTHEN_COND;
	  else
	    cond = COND_UNCOND;
	}
      else
	{
	  /* Only match unconditional instuctions against unconditional
	     patterns.  */
	  if ((given & 0xf0000000) == 0xf0000000)
	    {
	      mask |= 0xf0000000;
	      cond = COND_UNCOND;
	    }
	  else
	    {
	      cond = (given >> 28) & 0xf;
	      if (cond == 0xe)
		cond = COND_UNCOND;
	    }
	}
      
      if ((given & mask) != value)
	continue;

      if ((insn->arch & allowed_arches) == 0)
	continue;

      for (c = insn->assembler; *c; c++)
	{
	  if (*c == '%')
	    {
	      switch (*++c)
		{
		case '%':
		  func (stream, "%%");
		  break;

		case 'A':
		  {
		    int rn = (given >> 16) & 0xf;
  		    bfd_vma offset = given & 0xff;

		    func (stream, "[%s", arm_regnames [(given >> 16) & 0xf]);

		    if (PRE_BIT_SET || WRITEBACK_BIT_SET)
		      {
			/* Not unindexed.  The offset is scaled.  */
			offset = offset * 4;
			if (NEGATIVE_BIT_SET)
			  offset = - offset;
			if (rn != 15)
			  value_in_comment = offset;
		      }

		    if (PRE_BIT_SET)
		      {
			if (offset)
			  func (stream, ", %d]%s",
				(int) offset,
				WRITEBACK_BIT_SET ? "!" : "");
			else if (NEGATIVE_BIT_SET)
			  func (stream, ", #-0]");
			else
			  func (stream, "]");
		      }
		    else
		      {
			func (stream, "]");

			if (WRITEBACK_BIT_SET)
			  {
			    if (offset)
			      func (stream, ", %d", (int) offset);
			    else if (NEGATIVE_BIT_SET)
			      func (stream, ", #-0");
			  }
			else
			  {
			    func (stream, ", {%s%d}",
				  (NEGATIVE_BIT_SET && !offset) ? "-" : "",
				  (int) offset);
			    value_in_comment = offset;
			  }
		      }
		    if (rn == 15 && (PRE_BIT_SET || WRITEBACK_BIT_SET))
		      {
#if COMMENTS
			func (stream, " ; ");
			/* For unaligned PCs, apply off-by-alignment
			   correction.  */
			info->print_address_func (offset + pc 
						  + info->bytes_per_chunk * 2
						  - (pc & 3),
				 		  info);
#endif
		      }
		  }
		  break;

		case 'B':
		  {
		    int regno = ((given >> 12) & 0xf) | ((given >> (22 - 4)) & 0x10);
		    int offset = (given >> 1) & 0x3f;

		    if (offset == 1)
		      func (stream, "{d%d}", regno);
		    else if (regno + offset > 32)
		      func (stream, "{d%d-<overflow reg d%d>}", regno, regno + offset - 1);
		    else
		      func (stream, "{d%d-d%d}", regno, regno + offset - 1);
		  }
		  break;

		case 'u':
		  if (cond != COND_UNCOND)
		    is_unpredictable = TRUE;

		  /* Fall through.  */
		case 'c':
		  func (stream, "%s", arm_conditional[cond]);
		  break;

		case 'I':
		  /* Print a Cirrus/DSP shift immediate.  */
		  /* Immediates are 7bit signed ints with bits 0..3 in
		     bits 0..3 of opcode and bits 4..6 in bits 5..7
		     of opcode.  */
		  {
		    int imm;

		    imm = (given & 0xf) | ((given & 0xe0) >> 1);

		    /* Is ``imm'' a negative number?  */
		    if (imm & 0x40)
		      imm |= (-1 << 7);

		    func (stream, "%d", imm);
		  }

		  break;

		case 'F':
		  switch (given & 0x00408000)
		    {
		    case 0:
		      func (stream, "4");
		      break;
		    case 0x8000:
		      func (stream, "1");
		      break;
		    case 0x00400000:
		      func (stream, "2");
		      break;
		    default:
		      func (stream, "3");
		    }
		  break;

		case 'P':
		  switch (given & 0x00080080)
		    {
		    case 0:
		      func (stream, "s");
		      break;
		    case 0x80:
		      func (stream, "d");
		      break;
		    case 0x00080000:
		      func (stream, "e");
		      break;
		    default:
		      func (stream, _("<illegal precision>"));
		      break;
		    }
		  break;

		case 'Q':
		  switch (given & 0x00408000)
		    {
		    case 0:
		      func (stream, "s");
		      break;
		    case 0x8000:
		      func (stream, "d");
		      break;
		    case 0x00400000:
		      func (stream, "e");
		      break;
		    default:
		      func (stream, "p");
		      break;
		    }
		  break;

		case 'R':
		  switch (given & 0x60)
		    {
		    case 0:
		      break;
		    case 0x20:
		      func (stream, "p");
		      break;
		    case 0x40:
		      func (stream, "m");
		      break;
		    default:
		      func (stream, "z");
		      break;
		    }
		  break;

		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
		  {
		    int width;

		    c = arm_decode_bitfield (c, given, &value, &width);

		    switch (*c)
		      {
		      case 'R':
			if (value == 15)
			  is_unpredictable = TRUE;
			/* Fall through.  */
		      case 'r':
			if (c[1] == 'u')
			  {
			    /* Eat the 'u' character.  */
			    ++ c;

			    if (u_reg == value)
			      is_unpredictable = TRUE;
			    u_reg = value;
			  }
			func (stream, "%s", arm_regnames[value]);
			break;
		      case 'D':
			func (stream, "d%ld", value);
			break;
		      case 'Q':
			if (value & 1)
			  func (stream, "<illegal reg q%ld.5>", value >> 1);
			else
			  func (stream, "q%ld", value >> 1);
			break;
		      case 'd':
			func (stream, "%ld", value);
			value_in_comment = value;
			break;
		      case 'k':
			{
			  int from = (given & (1 << 7)) ? 32 : 16;
			  func (stream, "%ld", from - value);
			}
			break;

		      case 'f':
			if (value > 7)
			  func (stream, "%s", arm_fp_const[value & 7]);
			else
			  func (stream, "f%ld", value);
			break;

		      case 'w':
			if (width == 2)
			  func (stream, "%s", iwmmxt_wwnames[value]);
			else
			  func (stream, "%s", iwmmxt_wwssnames[value]);
			break;

		      case 'g':
			func (stream, "%s", iwmmxt_regnames[value]);
			break;
		      case 'G':
			func (stream, "%s", iwmmxt_cregnames[value]);
			break;

		      case 'x':
			func (stream, "0x%lx", (value & 0xffffffffUL));
			break;

		      case 'c':
			switch (value)
			  {
			  case 0:
			    func (stream, "eq");
			    break;

			  case 1:
			    func (stream, "vs");
			    break;

			  case 2:
			    func (stream, "ge");
			    break;

			  case 3:
			    func (stream, "gt");
			    break;

			  default:
			    func (stream, "??");
			    break;
			  }
			break;

		      case '`':
			c++;
			if (value == 0)
			  func (stream, "%c", *c);
			break;
		      case '\'':
			c++;
			if (value == ((1ul << width) - 1))
			  func (stream, "%c", *c);
			break;
		      case '?':
			func (stream, "%c", c[(1 << width) - (int) value]);
			c += 1 << width;
			break;
		      default:
			abort ();
		      }
		    break;

		  case 'y':
		  case 'z':
		    {
		      int single = *c++ == 'y';
		      int regno = 0;

		      switch (*c)
			{
			case '4': /* Sm pair */
			case '0': /* Sm, Dm */
			  regno = given & 0x0000000f;
			  if (single)
			    {
			      regno <<= 1;
			      regno += (given >> 5) & 1;
			    }
			  else
			    regno += ((given >> 5) & 1) << 4;
			  break;

			case '1': /* Sd, Dd */
			  regno = (given >> 12) & 0x0000000f;
			  if (single)
			    {
			      regno <<= 1;
			      regno += (given >> 22) & 1;
			    }
			  else
			    regno += ((given >> 22) & 1) << 4;
			  break;

			case '2': /* Sn, Dn */
			  regno = (given >> 16) & 0x0000000f;
			  if (single)
			    {
			      regno <<= 1;
			      regno += (given >> 7) & 1;
			    }
			  else
			    regno += ((given >> 7) & 1) << 4;
			  break;

			case '3': /* List */
			  func (stream, "{");
			  regno = (given >> 12) & 0x0000000f;
			  if (single)
			    {
			      regno <<= 1;
			      regno += (given >> 22) & 1;
			    }
			  else
			    regno += ((given >> 22) & 1) << 4;
			  break;

			default:
			  abort ();
			}

		      func (stream, "%c%d", single ? 's' : 'd', regno);

		      if (*c == '3')
			{
			  int count = given & 0xff;

			  if (single == 0)
			    count >>= 1;

			  if (--count)
			    {
			      func (stream, "-%c%d",
				    single ? 's' : 'd',
				    regno + count);
			    }

			  func (stream, "}");
			}
		      else if (*c == '4')
			func (stream, ", %c%d", single ? 's' : 'd',
			      regno + 1);
		    }
		    break;

		  case 'L':
		    switch (given & 0x00400100)
		      {
		      case 0x00000000: func (stream, "b"); break;
		      case 0x00400000: func (stream, "h"); break;
		      case 0x00000100: func (stream, "w"); break;
		      case 0x00400100: func (stream, "d"); break;
		      default:
			break;
		      }
		    break;

		  case 'Z':
		    {
		      /* given (20, 23) | given (0, 3) */
		      value = ((given >> 16) & 0xf0) | (given & 0xf);
		      func (stream, "%d", (int) value);
		    }
		    break;

		  case 'l':
		    /* This is like the 'A' operator, except that if
		       the width field "M" is zero, then the offset is
		       *not* multiplied by four.  */
		    {
		      int offset = given & 0xff;
		      int multiplier = (given & 0x00000100) ? 4 : 1;

		      func (stream, "[%s", arm_regnames [(given >> 16) & 0xf]);

		      if (multiplier > 1)
			{
			  value_in_comment = offset * multiplier;
			  if (NEGATIVE_BIT_SET)
			    value_in_comment = - value_in_comment;
			}

		      if (offset)
			{
			  if (PRE_BIT_SET)
			    func (stream, ", %s%d]%s",
				  NEGATIVE_BIT_SET ? "-" : "",
				  offset * multiplier,
				  WRITEBACK_BIT_SET ? "!" : "");
			  else
			    func (stream, "], %s%d",
				  NEGATIVE_BIT_SET ? "-" : "",
				  offset * multiplier);
			}
		      else
			func (stream, "]");
		    }
		    break;

		  case 'r':
		    {
		      int imm4 = (given >> 4) & 0xf;
		      int puw_bits = ((given >> 22) & 6) | ((given >> W_BIT) & 1);
		      int ubit = ! NEGATIVE_BIT_SET;
		      const char *rm = arm_regnames [given & 0xf];
		      const char *rn = arm_regnames [(given >> 16) & 0xf];

		      switch (puw_bits)
			{
			case 1:
			case 3:
			  func (stream, "[%s], %c%s", rn, ubit ? '+' : '-', rm);
			  if (imm4)
			    func (stream, ", lsl %d", imm4);
			  break;

			case 4:
			case 5:
			case 6:
			case 7:
			  func (stream, "[%s, %c%s", rn, ubit ? '+' : '-', rm);
			  if (imm4 > 0)
			    func (stream, ", lsl %d", imm4);
			  func (stream, "]");
			  if (puw_bits == 5 || puw_bits == 7)
			    func (stream, "!");
			  break;

			default:
			  func (stream, "INVALID");
			}
		    }
		    break;

		  case 'i':
		    {
		      long imm5;
		      imm5 = ((given & 0x100) >> 4) | (given & 0xf);
		      func (stream, "%ld", (imm5 == 0) ? 32 : imm5);
		    }
		    break;

		  default:
		    abort ();
		  }
		}
	    }
	  else
	    func (stream, "%c", *c);
	}


      if (is_unpredictable)
	func (stream, UNPREDICTABLE_INSTRUCTION);

      return TRUE;
    }
  return FALSE;
}

/* Decodes and prints ARM addressing modes.  Returns the offset
   used in the address, if any, if it is worthwhile printing the
   offset as a hexadecimal value in a comment at the end of the
   line of disassembly.  */

static signed long
print_arm_address (bfd_vma pc, struct disassemble_info *info, long given)
{
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;
  bfd_vma offset = 0;

  if (((given & 0x000f0000) == 0x000f0000)
      && ((given & 0x02000000) == 0))
    {
      offset = given & 0xfff;

      func (stream, "[pc");

      if (PRE_BIT_SET)
	{
	  /* Pre-indexed.  Elide offset of positive zero when
	     non-writeback.  */
	  if (WRITEBACK_BIT_SET || NEGATIVE_BIT_SET || offset)
	    func (stream, ", %s%d", NEGATIVE_BIT_SET ? "-" : "", (int) offset);

	  if (NEGATIVE_BIT_SET)
	    offset = -offset;

	  offset += pc + 8;

	  /* Cope with the possibility of write-back
	     being used.  Probably a very dangerous thing
	     for the programmer to do, but who are we to
	     argue ?  */
	  func (stream, "]%s", WRITEBACK_BIT_SET ? "!" : "");
	}
      else  /* Post indexed.  */
	{
	  func (stream, "], %s%d", NEGATIVE_BIT_SET ? "-" : "", (int) offset);

	  /* Ie ignore the offset.  */
	  offset = pc + 8;
	}

#if COMMENTS
      func (stream, " ; ");
      info->print_address_func (offset, info);
#endif
      offset = 0;
    }
  else
    {
      func (stream, "[%s",
	    arm_regnames[(given >> 16) & 0xf]);

      if (PRE_BIT_SET)
	{
	  if ((given & 0x02000000) == 0)
	    {
	      /* Elide offset of positive zero when non-writeback.  */
	      offset = given & 0xfff;
	      if (WRITEBACK_BIT_SET || NEGATIVE_BIT_SET || offset)
		func (stream, ", %s%d", NEGATIVE_BIT_SET ? "-" : "", (int) offset);
	    }
	  else
	    {
	      func (stream, ", %s", NEGATIVE_BIT_SET ? "-" : "");
	      arm_decode_shift (given, func, stream, TRUE);
	    }

	  func (stream, "]%s",
		WRITEBACK_BIT_SET ? "!" : "");
	}
      else
	{
	  if ((given & 0x02000000) == 0)
	    {
	      /* Always show offset.  */
	      offset = given & 0xfff;
	      func (stream, "], %s%d",
		    NEGATIVE_BIT_SET ? "-" : "", (int) offset);
	    }
	  else
	    {
	      func (stream, "], %s",
		    NEGATIVE_BIT_SET ? "-" : "");
	      arm_decode_shift (given, func, stream, TRUE);
	    }
	}
    }

  return (signed long) offset;
}

/* Print one neon instruction on INFO->STREAM.
   Return TRUE if the instuction matched, FALSE if this is not a
   recognised neon instruction.  */

static bfd_boolean
print_insn_neon (struct disassemble_info *info, long given, bfd_boolean thumb)
{
  const struct opcode32 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;

  if (thumb)
    {
      if ((given & 0xef000000) == 0xef000000)
	{
	  /* Move bit 28 to bit 24 to translate Thumb2 to ARM encoding.  */
	  unsigned long bit28 = given & (1 << 28);

	  given &= 0x00ffffff;
	  if (bit28)
            given |= 0xf3000000;
          else
	    given |= 0xf2000000;
	}
      else if ((given & 0xff000000) == 0xf9000000)
	given ^= 0xf9000000 ^ 0xf4000000;
      else
	return FALSE;
    }
  
  for (insn = neon_opcodes; insn->assembler; insn++)
    {
      if ((given & insn->mask) == insn->value)
	{
	  bfd_boolean is_unpredictable = FALSE;
	  const char *c;

	  for (c = insn->assembler; *c; c++)
	    {
	      if (*c == '%')
		{
		  switch (*++c)
		    {
		    case '%':
		      func (stream, "%%");
		      break;

		    case 'u':
		      if (thumb && ifthen_state)
			is_unpredictable = TRUE;

		      /* Fall through.  */
		    case 'c':
		      if (thumb && ifthen_state)
			func (stream, "%s", arm_conditional[IFTHEN_COND]);
		      break;

		    case 'A':
		      {
			static const unsigned char enc[16] = 
			{
			  0x4, 0x14, /* st4 0,1 */
			  0x4, /* st1 2 */
			  0x4, /* st2 3 */
			  0x3, /* st3 4 */
			  0x13, /* st3 5 */
			  0x3, /* st1 6 */
			  0x1, /* st1 7 */
			  0x2, /* st2 8 */
			  0x12, /* st2 9 */
			  0x2, /* st1 10 */
			  0, 0, 0, 0, 0
			};
			int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
			int rn = ((given >> 16) & 0xf);
			int rm = ((given >> 0) & 0xf);
			int align = ((given >> 4) & 0x3);
			int type = ((given >> 8) & 0xf);
			int n = enc[type] & 0xf;
			int stride = (enc[type] >> 4) + 1;
			int ix;
			
			func (stream, "{");
			if (stride > 1)
			  for (ix = 0; ix != n; ix++)
			    func (stream, "%sd%d", ix ? "," : "", rd + ix * stride);
			else if (n == 1)
			  func (stream, "d%d", rd);
			else
			  func (stream, "d%d-d%d", rd, rd + n - 1);
			func (stream, "}, [%s", arm_regnames[rn]);
			if (align)
			  func (stream, " :%d", 32 << align);
			func (stream, "]");
			if (rm == 0xd)
			  func (stream, "!");
			else if (rm != 0xf)
			  func (stream, ", %s", arm_regnames[rm]);
		      }
		      break;
		      
		    case 'B':
		      {
			int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
			int rn = ((given >> 16) & 0xf);
			int rm = ((given >> 0) & 0xf);
			int idx_align = ((given >> 4) & 0xf);
                        int align = 0;
			int size = ((given >> 10) & 0x3);
			int idx = idx_align >> (size + 1);
                        int length = ((given >> 8) & 3) + 1;
                        int stride = 1;
                        int i;

                        if (length > 1 && size > 0)
                          stride = (idx_align & (1 << size)) ? 2 : 1;
			
                        switch (length)
                          {
                          case 1:
                            {
                              int amask = (1 << size) - 1;
                              if ((idx_align & (1 << size)) != 0)
                                return FALSE;
                              if (size > 0)
                                {
                                  if ((idx_align & amask) == amask)
                                    align = 8 << size;
                                  else if ((idx_align & amask) != 0)
                                    return FALSE;
                                }
                              }
                            break;
                          
                          case 2:
                            if (size == 2 && (idx_align & 2) != 0)
                              return FALSE;
                            align = (idx_align & 1) ? 16 << size : 0;
                            break;
                          
                          case 3:
                            if ((size == 2 && (idx_align & 3) != 0)
                                || (idx_align & 1) != 0)
                              return FALSE;
                            break;
                          
                          case 4:
                            if (size == 2)
                              {
                                if ((idx_align & 3) == 3)
                                  return FALSE;
                                align = (idx_align & 3) * 64;
                              }
                            else
                              align = (idx_align & 1) ? 32 << size : 0;
                            break;
                          
                          default:
                            abort ();
                          }
                                
			func (stream, "{");
                        for (i = 0; i < length; i++)
                          func (stream, "%sd%d[%d]", (i == 0) ? "" : ",",
                            rd + i * stride, idx);
                        func (stream, "}, [%s", arm_regnames[rn]);
			if (align)
			  func (stream, " :%d", align);
			func (stream, "]");
			if (rm == 0xd)
			  func (stream, "!");
			else if (rm != 0xf)
			  func (stream, ", %s", arm_regnames[rm]);
		      }
		      break;
		      
		    case 'C':
		      {
			int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
			int rn = ((given >> 16) & 0xf);
			int rm = ((given >> 0) & 0xf);
			int align = ((given >> 4) & 0x1);
			int size = ((given >> 6) & 0x3);
			int type = ((given >> 8) & 0x3);
			int n = type + 1;
			int stride = ((given >> 5) & 0x1);
			int ix;
			
			if (stride && (n == 1))
			  n++;
			else
			  stride++;
			
			func (stream, "{");
			if (stride > 1)
			  for (ix = 0; ix != n; ix++)
			    func (stream, "%sd%d[]", ix ? "," : "", rd + ix * stride);
			else if (n == 1)
			  func (stream, "d%d[]", rd);
			else
			  func (stream, "d%d[]-d%d[]", rd, rd + n - 1);
			func (stream, "}, [%s", arm_regnames[rn]);
			if (align)
			  {
                            align = (8 * (type + 1)) << size;
                            if (type == 3)
                              align = (size > 1) ? align >> 1 : align;
			    if (type == 2 || (type == 0 && !size))
			      func (stream, " :<bad align %d>", align);
			    else
			      func (stream, " :%d", align);
			  }
			func (stream, "]");
			if (rm == 0xd)
			  func (stream, "!");
			else if (rm != 0xf)
			  func (stream, ", %s", arm_regnames[rm]);
		      }
		      break;
		      
		    case 'D':
		      {
			int raw_reg = (given & 0xf) | ((given >> 1) & 0x10);
			int size = (given >> 20) & 3;
			int reg = raw_reg & ((4 << size) - 1);
			int ix = raw_reg >> size >> 2;
			
			func (stream, "d%d[%d]", reg, ix);
		      }
		      break;
		      
		    case 'E':
		      /* Neon encoded constant for mov, mvn, vorr, vbic.  */
		      {
			int bits = 0;
			int cmode = (given >> 8) & 0xf;
			int op = (given >> 5) & 0x1;
			unsigned long value = 0, hival = 0;
			unsigned shift;
                        int size = 0;
                        int isfloat = 0;
			
			bits |= ((given >> 24) & 1) << 7;
			bits |= ((given >> 16) & 7) << 4;
			bits |= ((given >> 0) & 15) << 0;
			
			if (cmode < 8)
			  {
			    shift = (cmode >> 1) & 3;
			    value = (unsigned long) bits << (8 * shift);
                            size = 32;
			  }
			else if (cmode < 12)
			  {
			    shift = (cmode >> 1) & 1;
			    value = (unsigned long) bits << (8 * shift);
                            size = 16;
			  }
			else if (cmode < 14)
			  {
			    shift = (cmode & 1) + 1;
			    value = (unsigned long) bits << (8 * shift);
			    value |= (1ul << (8 * shift)) - 1;
                            size = 32;
			  }
			else if (cmode == 14)
			  {
			    if (op)
			      {
				/* Bit replication into bytes.  */
				int ix;
				unsigned long mask;
				
				value = 0;
                                hival = 0;
				for (ix = 7; ix >= 0; ix--)
				  {
				    mask = ((bits >> ix) & 1) ? 0xff : 0;
                                    if (ix <= 3)
				      value = (value << 8) | mask;
                                    else
                                      hival = (hival << 8) | mask;
				  }
                                size = 64;
			      }
                            else
                              {
                                /* Byte replication.  */
                                value = (unsigned long) bits;
                                size = 8;
                              }
			  }
			else if (!op)
			  {
			    /* Floating point encoding.  */
			    int tmp;
			    
			    value = (unsigned long)  (bits & 0x7f) << 19;
			    value |= (unsigned long) (bits & 0x80) << 24;
			    tmp = bits & 0x40 ? 0x3c : 0x40;
			    value |= (unsigned long) tmp << 24;
                            size = 32;
                            isfloat = 1;
			  }
			else
			  {
			    func (stream, "<illegal constant %.8x:%x:%x>",
                                  bits, cmode, op);
                            size = 32;
			    break;
			  }
                        switch (size)
                          {
                          case 8:
			    func (stream, "%ld", value); // ; 0x%.2lx", value, value);
                            break;
                          
                          case 16:
                            func (stream, "%ld", value); // ; 0x%.4lx", value, value);
                            break;

                          case 32:
                            if (isfloat)
                              {
                                unsigned char valbytes[4];
#if HAVE_FLOAT
                                double fvalue;
#endif
                                
                                /* Do this a byte at a time so we don't have to
                                   worry about the host's endianness.  */
                                valbytes[0] = value & 0xff;
                                valbytes[1] = (value >> 8) & 0xff;
                                valbytes[2] = (value >> 16) & 0xff;
                                valbytes[3] = (value >> 24) & 0xff;
                                
#if HAVE_FLOAT
                                floatformat_to_double 
                                  (& floatformat_ieee_single_little, valbytes,
                                  & fvalue);
                                                                
                                func (stream, "%.7g ; 0x%.8lx", fvalue,
                                      value);
#else
                                func (stream, "<TODO:float>");
#endif
                              }
                            else
                              { 
                                func (stream, "0x%lx", value);
#if 0
                                func (stream, "%ld ; 0x%.8lx",
				    (long) (((value & 0x80000000L) != 0) 
					    ? value | ~0xffffffffL : value),
				    value);
#endif
                              } 
                            break;

                          case 64:
                            func (stream, "0x%.8lx%.8lx", hival, value);
                            break;
                          
                          default:
                            abort ();
                          }
		      }
		      break;
		      
		    case 'F':
		      {
			int regno = ((given >> 16) & 0xf) | ((given >> (7 - 4)) & 0x10);
			int num = (given >> 8) & 0x3;
			
			if (!num)
			  func (stream, "{d%d}", regno);
			else if (num + regno >= 32)
			  func (stream, "{d%d-<overflow reg d%d}", regno, regno + num);
			else
			  func (stream, "{d%d-d%d}", regno, regno + num);
		      }
		      break;


		    case '0': case '1': case '2': case '3': case '4':
		    case '5': case '6': case '7': case '8': case '9':
		      {
			int width;
			unsigned long value;

			c = arm_decode_bitfield (c, given, &value, &width);
			
			switch (*c)
			  {
			  case 'r':
			    func (stream, "%s", arm_regnames[value]);
			    break;
			  case 'd':
			    func (stream, "%ld", value);
			    break;
			  case 'e':
			    func (stream, "%ld", (1ul << width) - value);
			    break;
			    
			  case 'S':
			  case 'T':
			  case 'U':
			    /* Various width encodings.  */
			    {
			      int base = 8 << (*c - 'S'); /* 8,16 or 32 */
			      int limit = 0;
			      unsigned low, high;

			      c++;
			      if (*c >= '0' && *c <= '9')
				limit = *c - '0';
			      else if (*c >= 'a' && *c <= 'f')
				limit = *c - 'a' + 10;
			      else
				abort ();
			      low = limit >> 2;
			      high = limit & 3;

			      if (value < low || value > high)
				func (stream, "<illegal width %d>", base << value);
			      else
				func (stream, "%d", base << value);
			    }
			    break;
			  case 'R':
			    if (given & (1 << 6))
			      goto Q;
			    /* FALLTHROUGH */
			  case 'D':
			    func (stream, "d%ld", value);
			    break;
			  case 'Q':
			  Q:
			    if (value & 1)
			      func (stream, "<illegal reg q%ld.5>", value >> 1);
			    else
			      func (stream, "q%ld", value >> 1);
			    break;
			    
			  case '`':
			    c++;
			    if (value == 0)
			      func (stream, "%c", *c);
			    break;
			  case '\'':
			    c++;
			    if (value == ((1ul << width) - 1))
			      func (stream, "%c", *c);
			    break;
			  case '?':
			    func (stream, "%c", c[(1 << width) - (int) value]);
			    c += 1 << width;
			    break;
			  default:
			    abort ();
			  }
			break;

		      default:
			abort ();
		      }
		    }
		}
	      else
		func (stream, "%c", *c);
	    }

	  if (is_unpredictable)
	    func (stream, UNPREDICTABLE_INSTRUCTION);

	  return TRUE;
	}
    }
  return FALSE;
}

/* Return the name of a v7A special register.  */

static const char * 
banked_regname (unsigned reg)
{
  switch (reg)
    {
      case 15: return "CPSR";
      case 32: return "R8_usr";
      case 33: return "R9_usr";
      case 34: return "R10_usr";
      case 35: return "R11_usr";
      case 36: return "R12_usr";
      case 37: return "SP_usr";
      case 38: return "LR_usr";
      case 40: return "R8_fiq";
      case 41: return "R9_fiq";
      case 42: return "R10_fiq";
      case 43: return "R11_fiq";
      case 44: return "R12_fiq";
      case 45: return "SP_fiq";
      case 46: return "LR_fiq";
      case 48: return "LR_irq";
      case 49: return "SP_irq";
      case 50: return "LR_svc";
      case 51: return "SP_svc";
      case 52: return "LR_abt";
      case 53: return "SP_abt";
      case 54: return "LR_und";
      case 55: return "SP_und";
      case 60: return "LR_mon";
      case 61: return "SP_mon";
      case 62: return "ELR_hyp";
      case 63: return "SP_hyp";
      case 79: return "SPSR";
      case 110: return "SPSR_fiq";
      case 112: return "SPSR_irq";
      case 114: return "SPSR_svc";
      case 116: return "SPSR_abt";
      case 118: return "SPSR_und";
      case 124: return "SPSR_mon";
      case 126: return "SPSR_hyp";
      default: return NULL;
    }
}

/* Return the name of the DMB/DSB option.  */
static const char *
data_barrier_option (unsigned option)
{
  switch (option & 0xf)
    {
    case 0xf: return "sy";
    case 0xe: return "st";
    case 0xd: return "ld";
    case 0xb: return "ish";
    case 0xa: return "ishst";
    case 0x9: return "ishld";
    case 0x7: return "un";
    case 0x6: return "unst";
    case 0x5: return "nshld";
    case 0x3: return "osh";
    case 0x2: return "oshst";
    case 0x1: return "oshld";
    default:  return NULL;
    }
}

/* Print one ARM instruction from PC on INFO->STREAM.  */

static void
print_insn_arm (bfd_vma pc, struct disassemble_info *info, long given)
{
  const struct opcode32 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;
  struct arm_private_data *private_data = info->private_data;

  if (print_insn_coprocessor (pc, info, given, FALSE))
    return;

  if (print_insn_neon (info, given, FALSE))
    return;

  for (insn = arm_opcodes; insn->assembler; insn++)
    {
      if ((given & insn->mask) != insn->value)
	continue;
    
      if ((insn->arch & private_data->features.core) == 0)
	continue;

      /* Special case: an instruction with all bits set in the condition field
	 (0xFnnn_nnnn) is only matched if all those bits are set in insn->mask,
	 or by the catchall at the end of the table.  */
      if ((given & 0xF0000000) != 0xF0000000
	  || (insn->mask & 0xF0000000) == 0xF0000000
	  || (insn->mask == 0 && insn->value == 0))
	{
	  unsigned long u_reg = 16;
	  unsigned long U_reg = 16;
	  bfd_boolean is_unpredictable = FALSE;
	  signed long value_in_comment = 0;
	  const char *c;

	  for (c = insn->assembler; *c; c++)
	    {
	      if (*c == '%')
		{
		  bfd_boolean allow_unpredictable = FALSE;

		  switch (*++c)
		    {
		    case '%':
		      func (stream, "%%");
		      break;

		    case 'a':
		      value_in_comment = print_arm_address (pc, info, given);
		      break;

		    case 'P':
		      /* Set P address bit and use normal address
			 printing routine.  */
		      value_in_comment = print_arm_address (pc, info, given | (1 << P_BIT));
		      break;

		    case 'S':
		      allow_unpredictable = TRUE;
		    case 's':
                      if ((given & 0x004f0000) == 0x004f0000)
			{
                          /* PC relative with immediate offset.  */
			  bfd_vma offset = ((given & 0xf00) >> 4) | (given & 0xf);

			  if (PRE_BIT_SET)
			    {
			      /* Elide positive zero offset.  */
			      if (offset || NEGATIVE_BIT_SET)
				func (stream, "[pc, %s%d] ; ",
				      NEGATIVE_BIT_SET ? "-" : "", (int) offset);
			      else
				func (stream, "[pc] ; ");
			      if (NEGATIVE_BIT_SET)
				offset = -offset;
			      info->print_address_func (offset + pc + 8, info);
			    }
			  else
			    {
			      /* Always show the offset.  */
			      func (stream, "[pc], %s%d",
				    NEGATIVE_BIT_SET ? "-" : "", (int) offset);
			      if (! allow_unpredictable)
				is_unpredictable = TRUE;
			    }
			}
		      else
			{
			  int offset = ((given & 0xf00) >> 4) | (given & 0xf);

			  func (stream, "[%s",
				arm_regnames[(given >> 16) & 0xf]);

			  if (PRE_BIT_SET)
			    {
			      if (IMMEDIATE_BIT_SET)
				{
				  /* Elide offset for non-writeback
				     positive zero.  */
				  if (WRITEBACK_BIT_SET || NEGATIVE_BIT_SET
				      || offset)
				    func (stream, ", %s%d",
					  NEGATIVE_BIT_SET ? "-" : "", offset);

				  if (NEGATIVE_BIT_SET)
				    offset = -offset;

				  value_in_comment = offset;
				}
			      else
				{
				  /* Register Offset or Register Pre-Indexed.  */
				  func (stream, ", %s%s",
					NEGATIVE_BIT_SET ? "-" : "",
					arm_regnames[given & 0xf]);

				  /* Writing back to the register that is the source/
				     destination of the load/store is unpredictable.  */
				  if (! allow_unpredictable
				      && WRITEBACK_BIT_SET
				      && ((given & 0xf) == ((given >> 12) & 0xf)))
				    is_unpredictable = TRUE;
				}

			      func (stream, "]%s",
				    WRITEBACK_BIT_SET ? "!" : "");
			    }
			  else
			    {
			      if (IMMEDIATE_BIT_SET)
				{
				  /* Immediate Post-indexed.  */
				  /* PR 10924: Offset must be printed, even if it is zero.  */
				  func (stream, "], %s%d",
					NEGATIVE_BIT_SET ? "-" : "", offset);
				  if (NEGATIVE_BIT_SET)
				    offset = -offset;
				  value_in_comment = offset;
				}
			      else
				{
				  /* Register Post-indexed.  */
				  func (stream, "], %s%s",
					NEGATIVE_BIT_SET ? "-" : "",
					arm_regnames[given & 0xf]);

				  /* Writing back to the register that is the source/
				     destination of the load/store is unpredictable.  */
				  if (! allow_unpredictable
				      && (given & 0xf) == ((given >> 12) & 0xf))
				    is_unpredictable = TRUE;
				}

			      if (! allow_unpredictable)
				{
				  /* Writeback is automatically implied by post- addressing.
				     Setting the W bit is unnecessary and ARM specify it as
				     being unpredictable.  */
				  if (WRITEBACK_BIT_SET
				      /* Specifying the PC register as the post-indexed
					 registers is also unpredictable.  */
				      || (! IMMEDIATE_BIT_SET && ((given & 0xf) == 0xf)))
				    is_unpredictable = TRUE;
				}
			    }
			}
		      break;

		    case 'b':
		      {
			bfd_vma disp = (((given & 0xffffff) ^ 0x800000) - 0x800000);
			info->print_address_func (disp * 4 + pc + 8, info);
		      }
		      break;

		    case 'c':
		      if (((given >> 28) & 0xf) != 0xe)
			func (stream, "%s",
			      arm_conditional [(given >> 28) & 0xf]);
		      break;

		    case 'm':
		      {
			int started = 0;
			int reg;

			func (stream, "{");
			for (reg = 0; reg < 16; reg++)
			  if ((given & (1 << reg)) != 0)
			    {
			      if (started)
				func (stream, ", ");
			      started = 1;
			      func (stream, "%s", arm_regnames[reg]);
			    }
			func (stream, "}");
			if (! started)
			  is_unpredictable = TRUE;
		      }
		      break;

		    case 'q':
		      arm_decode_shift (given, func, stream, FALSE);
		      break;

		    case 'o':
		      if ((given & 0x02000000) != 0)
			{
			  unsigned int rotate = (given & 0xf00) >> 7;
			  unsigned int immed = (given & 0xff);
			  unsigned int a, i;

			  a = (((immed << (32 - rotate))
				| (immed >> rotate)) & 0xffffffff);
			  /* If there is another encoding with smaller rotate,
			     the rotate should be specified directly.  */
			  for (i = 0; i < 32; i += 2)
			    if ((a << i | a >> (32 - i)) <= 0xff)
			      break;

			  if (i != rotate)
			    func (stream, "%d, %d", immed, rotate);
			  else
			    func (stream, "%d", a);
			  value_in_comment = a;
			}
		      else
			arm_decode_shift (given, func, stream, TRUE);
		      break;

		    case 'p':
		      if ((given & 0x0000f000) == 0x0000f000)
			{
			  /* The p-variants of tst/cmp/cmn/teq are the pre-V6
			     mechanism for setting PSR flag bits.  They are
			     obsolete in V6 onwards.  */
			  if ((private_data->features.core & ARM_EXT_V6) == 0)
			    func (stream, "p");
			}
		      break;

		    case 't':
		      if ((given & 0x01200000) == 0x00200000)
			func (stream, "t");
		      break;

		    case 'A':
		      {
			int offset = given & 0xff;

			value_in_comment = offset * 4;
			if (NEGATIVE_BIT_SET)
			  value_in_comment = - value_in_comment;

			func (stream, "[%s", arm_regnames [(given >> 16) & 0xf]);

			if (PRE_BIT_SET)
			  {
			    if (offset)
			      func (stream, ", %d]%s",
				    (int) value_in_comment,
				    WRITEBACK_BIT_SET ? "!" : "");
			    else
			      func (stream, "]");
			  }
			else
			  {
			    func (stream, "]");

			    if (WRITEBACK_BIT_SET)
			      {
				if (offset)
				  func (stream, ", %d", (int) value_in_comment);
			      }
			    else
			      {
				func (stream, ", {%d}", (int) offset);
				value_in_comment = offset;
			      }
			  }
		      }
		      break;

		    case 'B':
		      /* Print ARM V5 BLX(1) address: pc+25 bits.  */
		      {
			bfd_vma address;
			bfd_vma offset = 0;

			if (! NEGATIVE_BIT_SET)
			  /* Is signed, hi bits should be ones.  */
			  offset = (-1) ^ 0x00ffffff;

			/* Offset is (SignExtend(offset field)<<2).  */
			offset += given & 0x00ffffff;
			offset <<= 2;
			address = offset + pc + 8;

			if (given & 0x01000000)
			  /* H bit allows addressing to 2-byte boundaries.  */
			  address += 2;

		        info->print_address_func (address, info);
		      }
		      break;

		    case 'C':
		      if ((given & 0x02000200) == 0x200)
			{
			  const char * name;
			  unsigned sysm = (given & 0x004f0000) >> 16;

			  sysm |= (given & 0x300) >> 4;
			  name = banked_regname (sysm);

			  if (name != NULL)
			    func (stream, "%s", name);
			  else
			    func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
			}
		      else
			{
			  func (stream, "%cPSR_", 
				(given & 0x00400000) ? 'S' : 'C');
			  if (given & 0x80000)
			    func (stream, "f");
			  if (given & 0x40000)
			    func (stream, "s");
			  if (given & 0x20000)
			    func (stream, "x");
			  if (given & 0x10000)
			    func (stream, "c");
			}
		      break;

		    case 'U':
		      if ((given & 0xf0) == 0x60) 
			{
			  switch (given & 0xf)
			    {
			    case 0xf: func (stream, "sy"); break;
			    default:
			      func (stream, "%d", (int) given & 0xf);
			      break;
			    }
			} 
		      else 
			{
			  const char * opt = data_barrier_option (given & 0xf);
			  if (opt != NULL)
			    func (stream, "%s", opt);
			  else
			      func (stream, "%d", (int) given & 0xf);
			}
		      break;

		    case '0': case '1': case '2': case '3': case '4':
		    case '5': case '6': case '7': case '8': case '9':
		      {
			int width;
			unsigned long value;

			c = arm_decode_bitfield (c, given, &value, &width);
			
			switch (*c)
			  {
			  case 'R':
			    if (value == 15)
			      is_unpredictable = TRUE;
			    /* Fall through.  */
			  case 'r':
			  case 'T':
			    /* We want register + 1 when decoding T.  */
			    if (*c == 'T')
			      ++value;

			    if (c[1] == 'u')
			      {
				/* Eat the 'u' character.  */
				++ c;

				if (u_reg == value)
				  is_unpredictable = TRUE;
				u_reg = value;
			      }
			    if (c[1] == 'U')
			      {
				/* Eat the 'U' character.  */
				++ c;

				if (U_reg == value)
				  is_unpredictable = TRUE;
				U_reg = value;
			      }
			    func (stream, "%s", arm_regnames[value]);
			    break;
			  case 'd':
			    func (stream, "%ld", value);
			    value_in_comment = value;
			    break;
			  case 'b':
			    func (stream, "%ld", value * 8);
			    value_in_comment = value * 8;
			    break;
			  case 'W':
			    func (stream, "%ld", value + 1);
			    value_in_comment = value + 1;
			    break;
			  case 'x':
			    func (stream, "0x%08lx", value);

			    /* Some SWI instructions have special
			       meanings.  */
			    if ((given & 0x0fffffff) == 0x0FF00000)
			      func (stream, " ; IMB");
			    else if ((given & 0x0fffffff) == 0x0FF00001)
			      func (stream, " ; IMBRange");
			    break;
			  case 'X':
			    func (stream, "%01lx", value & 0xf);
			    value_in_comment = value;
			    break;
			  case '`':
			    c++;
			    if (value == 0)
			      func (stream, "%c", *c);
			    break;
			  case '\'':
			    c++;
			    if (value == ((1ul << width) - 1))
			      func (stream, "%c", *c);
			    break;
			  case '?':
			    func (stream, "%c", c[(1 << width) - (int) value]);
			    c += 1 << width;
			    break;
			  default:
			    abort ();
			  }
			break;

		      case 'e':
			{
			  int imm;

			  imm = (given & 0xf) | ((given & 0xfff00) >> 4);
			  func (stream, "%d", imm);
			  value_in_comment = imm;
			}
			break;

		      case 'E':
			/* LSB and WIDTH fields of BFI or BFC.  The machine-
			   language instruction encodes LSB and MSB.  */
			{
			  long msb = (given & 0x001f0000) >> 16;
			  long lsb = (given & 0x00000f80) >> 7;
			  long w = msb - lsb + 1;

			  if (w > 0)
			    func (stream, "%lu, %lu", lsb, w);
			  else
			    func (stream, "(invalid: %lu:%lu)", lsb, msb);
			}
			break;

		      case 'R':
			/* Get the PSR/banked register name.  */
			{
			  const char * name;
			  unsigned sysm = (given & 0x004f0000) >> 16;

			  sysm |= (given & 0x300) >> 4;
			  name = banked_regname (sysm);

			  if (name != NULL)
			    func (stream, "%s", name);
			  else
			    func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
			}
			break;

		      case 'V':
			/* 16-bit unsigned immediate from a MOVT or MOVW
			   instruction, encoded in bits 0:11 and 15:19.  */
			{
			  long hi = (given & 0x000f0000) >> 4;
			  long lo = (given & 0x00000fff);
			  long imm16 = hi | lo;

			  func (stream, "%lu", imm16);
			  value_in_comment = imm16;
			}
			break;

		      default:
			abort ();
		      }
		    }
		}
	      else
		func (stream, "%c", *c);
	    }
#if 0
	  if (value_in_comment > 32 || value_in_comment < -16)
	    func (stream, " ; 0x%lx", (value_in_comment & 0xffffffffUL));
#endif

	  if (is_unpredictable)
	    func (stream, UNPREDICTABLE_INSTRUCTION);

	  return;
	}
    }
  abort ();
}

/* Print one 16-bit Thumb instruction from PC on INFO->STREAM.  */

static void
print_insn_thumb16 (bfd_vma pc, struct disassemble_info *info, long given)
{
  const struct opcode16 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;

  for (insn = thumb_opcodes; insn->assembler; insn++)
    if ((given & insn->mask) == insn->value)
      {
	const char *c = insn->assembler;

	for (; *c; c++)
	  {
	    int domaskpc = 0;
	    int domasklr = 0;

	    if (*c != '%')
	      {
		func (stream, "%c", *c);
		continue;
	      }

	    switch (*++c)
	      {
	      case '%':
		func (stream, "%%");
		break;

	      case 'c':
		if (ifthen_state)
		  func (stream, "%s", arm_conditional[IFTHEN_COND]);
		break;

	      case 'C':
		if (ifthen_state)
		  func (stream, "%s", arm_conditional[IFTHEN_COND]);
		else
		  func (stream, "s");
		break;

	      case 'I':
		{
		  unsigned int tmp;

		  ifthen_next_state = given & 0xff;
		  for (tmp = given << 1; tmp & 0xf; tmp <<= 1)
		    func (stream, ((given ^ tmp) & 0x10) ? "e" : "t");
		  func (stream, " %s", arm_conditional[(given >> 4) & 0xf]);
		}
		break;

	      case 'x':
		if (ifthen_next_state)
		  func (stream, " ; unpredictable branch in IT block\n");
		break;

	      case 'X':
		if (ifthen_state)
		  func (stream, " ; unpredictable <IT:%s>",
			arm_conditional[IFTHEN_COND]);
		break;

	      case 'S':
		{
		  long reg;

		  reg = (given >> 3) & 0x7;
		  if (given & (1 << 6))
		    reg += 8;

		  func (stream, "%s", arm_regnames[reg]);
		}
		break;

	      case 'D':
		{
		  long reg;

		  reg = given & 0x7;
		  if (given & (1 << 7))
		    reg += 8;

		  func (stream, "%s", arm_regnames[reg]);
		}
		break;

	      case 'N':
		if (given & (1 << 8))
		  domasklr = 1;
		/* Fall through.  */
	      case 'O':
		if (*c == 'O' && (given & (1 << 8)))
		  domaskpc = 1;
		/* Fall through.  */
	      case 'M':
		{
		  int started = 0;
		  int reg;

		  func (stream, "{");

		  /* It would be nice if we could spot
		     ranges, and generate the rS-rE format: */
		  for (reg = 0; (reg < 8); reg++)
		    if ((given & (1 << reg)) != 0)
		      {
			if (started)
			  func (stream, ", ");
			started = 1;
			func (stream, "%s", arm_regnames[reg]);
		      }

		  if (domasklr)
		    {
		      if (started)
			func (stream, ", ");
		      started = 1;
		      func (stream, "%s", arm_regnames[14] /* "lr" */);
		    }

		  if (domaskpc)
		    {
		      if (started)
			func (stream, ", ");
		      func (stream, "%s", arm_regnames[15] /* "pc" */);
		    }

		  func (stream, "}");
		}
		break;

	      case 'W':
		/* Print writeback indicator for a LDMIA.  We are doing a
		   writeback if the base register is not in the register
		   mask.  */
		if ((given & (1 << ((given & 0x0700) >> 8))) == 0)
		  func (stream, "!");
	      	break;

	      case 'b':
		/* Print ARM V6T2 CZB address: pc+4+6 bits.  */
		{
		  bfd_vma address = (pc + 4
				     + ((given & 0x00f8) >> 2)
				     + ((given & 0x0200) >> 3));
		  info->print_address_func (address, info);
		}
		break;

	      case 's':
		/* Right shift immediate -- bits 6..10; 1-31 print
		   as themselves, 0 prints as 32.  */
		{
		  long imm = (given & 0x07c0) >> 6;
		  if (imm == 0)
		    imm = 32;
		  func (stream, "%ld", imm);
		}
		break;

	      case '0': case '1': case '2': case '3': case '4':
	      case '5': case '6': case '7': case '8': case '9':
		{
		  int bitstart = *c++ - '0';
		  int bitend = 0;

		  while (*c >= '0' && *c <= '9')
		    bitstart = (bitstart * 10) + *c++ - '0';

		  switch (*c)
		    {
		    case '-':
		      {
			bfd_vma reg;

			c++;
			while (*c >= '0' && *c <= '9')
			  bitend = (bitend * 10) + *c++ - '0';
			if (!bitend)
			  abort ();
			reg = given >> bitstart;
			reg &= (2 << (bitend - bitstart)) - 1;

			switch (*c)
			  {
			  case 'r':
			    func (stream, "%s", arm_regnames[reg]);
			    break;

			  case 'd':
			    func (stream, "%ld", (long) reg);
			    break;

			  case 'H':
			    func (stream, "%ld", (long) (reg << 1));
			    break;

			  case 'W':
			    func (stream, "%ld", (long) (reg << 2));
			    break;

			  case 'a':
			    /* PC-relative address -- the bottom two
			       bits of the address are dropped
			       before the calculation.  */
			    info->print_address_func
			      (((pc + 4) & ~3) + (reg << 2), info);
			    break;

			  case 'x':
			    func (stream, "0x%04lx", (long) reg);
			    break;

			  case 'B':
			    reg = ((reg ^ (1 << bitend)) - (1 << bitend));
			    info->print_address_func (reg * 2 + pc + 4, info);
			    break;

			  case 'c':
			    func (stream, "%s", arm_conditional [reg]);
			    break;

			  default:
			    abort ();
			  }
		      }
		      break;

		    case '\'':
		      c++;
		      if ((given & (1 << bitstart)) != 0)
			func (stream, "%c", *c);
		      break;

		    case '?':
		      ++c;
		      if ((given & (1 << bitstart)) != 0)
			func (stream, "%c", *c++);
		      else
			func (stream, "%c", *++c);
		      break;

		    default:
		      abort ();
		    }
		}
		break;

	      default:
		abort ();
	      }
	  }

	return;
      }

  /* No match.  */
  abort ();
}

/* Return the name of an V7M special register.  */

static const char *
psr_name (int regno)
{
  switch (regno)
    {
    case 0: return "APSR";
    case 1: return "IAPSR";
    case 2: return "EAPSR";
    case 3: return "PSR";
    case 5: return "IPSR";
    case 6: return "EPSR";
    case 7: return "IEPSR";
    case 8: return "MSP";
    case 9: return "PSP";
    case 16: return "PRIMASK";
    case 17: return "BASEPRI";
    case 18: return "BASEPRI_MAX";
    case 19: return "FAULTMASK";
    case 20: return "CONTROL";
    default: return "<unknown>";
    }
}

/* Print one 32-bit Thumb instruction from PC on INFO->STREAM.  */

static void
print_insn_thumb32 (bfd_vma pc, struct disassemble_info *info, long given)
{
  const struct opcode32 *insn;
  void *stream = info->stream;
  fprintf_ftype func = info->fprintf_func;

  if (print_insn_coprocessor (pc, info, given, TRUE))
    return;

  if (print_insn_neon (info, given, TRUE))
    return;

  for (insn = thumb32_opcodes; insn->assembler; insn++)
    if ((given & insn->mask) == insn->value)
      {
	bfd_boolean is_unpredictable = FALSE;
	signed long value_in_comment = 0;
	const char *c = insn->assembler;

	for (; *c; c++)
	  {
	    if (*c != '%')
	      {
		func (stream, "%c", *c);
		continue;
	      }

	    switch (*++c)
	      {
	      case '%':
		func (stream, "%%");
		break;

	      case 'c':
		if (ifthen_state)
		  func (stream, "%s", arm_conditional[IFTHEN_COND]);
		break;

	      case 'x':
		if (ifthen_next_state)
		  func (stream, " ; unpredictable branch in IT block\n");
		break;

	      case 'X':
		if (ifthen_state)
		  func (stream, " ; unpredictable <IT:%s>",
			arm_conditional[IFTHEN_COND]);
		break;

	      case 'I':
		{
		  unsigned int imm12 = 0;

		  imm12 |= (given & 0x000000ffu);
		  imm12 |= (given & 0x00007000u) >> 4;
		  imm12 |= (given & 0x04000000u) >> 15;
		  func (stream, "%u", imm12);
		  value_in_comment = imm12;
		}
		break;

	      case 'M':
		{
		  unsigned int bits = 0, imm, imm8, mod;

		  bits |= (given & 0x000000ffu);
		  bits |= (given & 0x00007000u) >> 4;
		  bits |= (given & 0x04000000u) >> 15;
		  imm8 = (bits & 0x0ff);
		  mod = (bits & 0xf00) >> 8;
		  switch (mod)
		    {
		    case 0: imm = imm8; break;
		    case 1: imm = ((imm8 << 16) | imm8); break;
		    case 2: imm = ((imm8 << 24) | (imm8 << 8)); break;
		    case 3: imm = ((imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8); break;
		    default:
		      mod  = (bits & 0xf80) >> 7;
		      imm8 = (bits & 0x07f) | 0x80;
		      imm  = (((imm8 << (32 - mod)) | (imm8 >> mod)) & 0xffffffff);
		    }
		  func (stream, "%u", imm);
		  value_in_comment = imm;
		}
		break;
		  
	      case 'J':
		{
		  unsigned int imm = 0;

		  imm |= (given & 0x000000ffu);
		  imm |= (given & 0x00007000u) >> 4;
		  imm |= (given & 0x04000000u) >> 15;
		  imm |= (given & 0x000f0000u) >> 4;
		  func (stream, "%u", imm);
		  value_in_comment = imm;
		}
		break;

	      case 'K':
		{
		  unsigned int imm = 0;

		  imm |= (given & 0x000f0000u) >> 16;
		  imm |= (given & 0x00000ff0u) >> 0;
		  imm |= (given & 0x0000000fu) << 12;
		  func (stream, "%u", imm);
		  value_in_comment = imm;
		}
		break;

	      case 'V':
		{
		  unsigned int imm = 0;

		  imm |= (given & 0x00000fffu);
		  imm |= (given & 0x000f0000u) >> 4;
		  func (stream, "%u", imm);
		  value_in_comment = imm;
		}
		break;

	      case 'S':
		{
		  unsigned int reg = (given & 0x0000000fu);
		  unsigned int stp = (given & 0x00000030u) >> 4;
		  unsigned int imm = 0;
		  imm |= (given & 0x000000c0u) >> 6;
		  imm |= (given & 0x00007000u) >> 10;

		  func (stream, "%s", arm_regnames[reg]);
		  switch (stp)
		    {
		    case 0:
		      if (imm > 0)
			func (stream, ", lsl %u", imm);
		      break;

		    case 1:
		      if (imm == 0)
			imm = 32;
		      func (stream, ", lsr %u", imm);
		      break;

		    case 2:
		      if (imm == 0)
			imm = 32;
		      func (stream, ", asr %u", imm);
		      break;

		    case 3:
		      if (imm == 0)
			func (stream, ", rrx");
		      else
			func (stream, ", ror %u", imm);
		    }
		}
		break;

	      case 'a':
		{
		  unsigned int Rn  = (given & 0x000f0000) >> 16;
		  unsigned int U   = ! NEGATIVE_BIT_SET;
		  unsigned int op  = (given & 0x00000f00) >> 8;
		  unsigned int i12 = (given & 0x00000fff);
		  unsigned int i8  = (given & 0x000000ff);
		  bfd_boolean writeback = FALSE, postind = FALSE;
		  bfd_vma offset = 0;

		  func (stream, "[%s", arm_regnames[Rn]);
		  if (U) /* 12-bit positive immediate offset.  */
		    {
		      offset = i12;
		      if (Rn != 15)
			value_in_comment = offset;
		    }
		  else if (Rn == 15) /* 12-bit negative immediate offset.  */
		    offset = - (int) i12;
		  else if (op == 0x0) /* Shifted register offset.  */
		    {
		      unsigned int Rm = (i8 & 0x0f);
		      unsigned int sh = (i8 & 0x30) >> 4;

		      func (stream, ", %s", arm_regnames[Rm]);
		      if (sh)
			func (stream, ", lsl %u", sh);
		      func (stream, "]");
		      break;
		    }
		  else switch (op)
		    {
		    case 0xE:  /* 8-bit positive immediate offset.  */
		      offset = i8;
		      break;

		    case 0xC:  /* 8-bit negative immediate offset.  */
		      offset = -i8;
		      break;

		    case 0xF:  /* 8-bit + preindex with wb.  */
		      offset = i8;
		      writeback = TRUE;
		      break;

		    case 0xD:  /* 8-bit - preindex with wb.  */
		      offset = -i8;
		      writeback = TRUE;
		      break;

		    case 0xB:  /* 8-bit + postindex.  */
		      offset = i8;
		      postind = TRUE;
		      break;

		    case 0x9:  /* 8-bit - postindex.  */
		      offset = -i8;
		      postind = TRUE;
		      break;

		    default:
		      func (stream, ", <undefined>]");
		      goto skip;
		    }

		  if (postind)
		    func (stream, "], %d", (int) offset);
		  else
		    {
		      if (offset)
			func (stream, ", %d", (int) offset);
		      func (stream, writeback ? "]!" : "]");
		    }

		  if (Rn == 15)
		    {
#if COMMENTS
		      func (stream, " ; ");
		      info->print_address_func (((pc + 4) & ~3) + offset, info);
#endif
		    }
		}
	      skip:
		break;

	      case 'A':
		{
		  unsigned int U   = ! NEGATIVE_BIT_SET;
		  unsigned int W   = WRITEBACK_BIT_SET;
		  unsigned int Rn  = (given & 0x000f0000) >> 16;
		  unsigned int off = (given & 0x000000ff);

		  func (stream, "[%s", arm_regnames[Rn]);

		  if (PRE_BIT_SET)
		    {
		      if (off || !U)
			{
			  func (stream, ", %c%u", U ? '+' : '-', off * 4);
			  value_in_comment = off * 4 * U ? 1 : -1;
			}
		      func (stream, "]");
		      if (W)
			func (stream, "!");
		    }
		  else
		    {
		      func (stream, "], ");
		      if (W)
			{
			  func (stream, "%c%u", U ? '+' : '-', off * 4);
			  value_in_comment = off * 4 * U ? 1 : -1;
			}
		      else
			{
			  func (stream, "{%u}", off);
			  value_in_comment = off;
			}
		    }
		}
		break;

	      case 'w':
		{
		  unsigned int Sbit = (given & 0x01000000) >> 24;
		  unsigned int type = (given & 0x00600000) >> 21;

		  switch (type)
		    {
		    case 0: func (stream, Sbit ? "sb" : "b"); break;
		    case 1: func (stream, Sbit ? "sh" : "h"); break;
		    case 2:
		      if (Sbit)
			func (stream, "??");
		      break;
		    case 3:
		      func (stream, "??");
		      break;
		    }
		}
		break;

	      case 'm':
		{
		  int started = 0;
		  int reg;

		  func (stream, "{");
		  for (reg = 0; reg < 16; reg++)
		    if ((given & (1 << reg)) != 0)
		      {
			if (started)
			  func (stream, ", ");
			started = 1;
			func (stream, "%s", arm_regnames[reg]);
		      }
		  func (stream, "}");
		}
		break;

	      case 'E':
		{
		  unsigned int msb = (given & 0x0000001f);
		  unsigned int lsb = 0;

		  lsb |= (given & 0x000000c0u) >> 6;
		  lsb |= (given & 0x00007000u) >> 10;
		  func (stream, "%u, %u", lsb, msb - lsb + 1);
		}
		break;

	      case 'F':
		{
		  unsigned int width = (given & 0x0000001f) + 1;
		  unsigned int lsb = 0;

		  lsb |= (given & 0x000000c0u) >> 6;
		  lsb |= (given & 0x00007000u) >> 10;
		  func (stream, "%u, %u", lsb, width);
		}
		break;

	      case 'b':
		{
		  unsigned int S = (given & 0x04000000u) >> 26;
		  unsigned int J1 = (given & 0x00002000u) >> 13;
		  unsigned int J2 = (given & 0x00000800u) >> 11;
		  bfd_vma offset = 0;

		  offset |= !S << 20;
		  offset |= J2 << 19;
		  offset |= J1 << 18;
		  offset |= (given & 0x003f0000) >> 4;
		  offset |= (given & 0x000007ff) << 1;
		  offset -= (1 << 20);

		  info->print_address_func (pc + 4 + offset, info);
		}
		break;

	      case 'B':
		{
		  unsigned int S = (given & 0x04000000u) >> 26;
		  unsigned int I1 = (given & 0x00002000u) >> 13;
		  unsigned int I2 = (given & 0x00000800u) >> 11;
		  bfd_vma offset = 0;

		  offset |= !S << 24;
		  offset |= !(I1 ^ S) << 23;
		  offset |= !(I2 ^ S) << 22;
		  offset |= (given & 0x03ff0000u) >> 4;
		  offset |= (given & 0x000007ffu) << 1;
		  offset -= (1 << 24);
		  offset += pc + 4;

		  /* BLX target addresses are always word aligned.  */
		  if ((given & 0x00001000u) == 0)
		      offset &= ~2u;

		  info->print_address_func (offset, info);
		}
		break;

	      case 's':
		{
		  unsigned int shift = 0;

		  shift |= (given & 0x000000c0u) >> 6;
		  shift |= (given & 0x00007000u) >> 10;
		  if (WRITEBACK_BIT_SET)
		    func (stream, ", asr %u", shift);
		  else if (shift)
		    func (stream, ", lsl %u", shift);
		  /* else print nothing - lsl #0 */
		}
		break;

	      case 'R':
		{
		  unsigned int rot = (given & 0x00000030) >> 4;

		  if (rot)
		    func (stream, ", ror %u", rot * 8);
		}
		break;

	      case 'U':
		if ((given & 0xf0) == 0x60) 
		  {
		    switch (given & 0xf)
		      {
			case 0xf: func (stream, "sy"); break;
			default:
			  func (stream, "%d", (int) given & 0xf);
			      break;
		      }
		  }
		else 
		  {
		    const char * opt = data_barrier_option (given & 0xf);
		    if (opt != NULL)
		      func (stream, "%s", opt);
		    else
		      func (stream, "%d", (int) given & 0xf);
		   }
		break;

	      case 'C':
		if ((given & 0xff) == 0)
		  {
		    func (stream, "%cPSR_", (given & 0x100000) ? 'S' : 'C');
		    if (given & 0x800)
		      func (stream, "f");
		    if (given & 0x400)
		      func (stream, "s");
		    if (given & 0x200)
		      func (stream, "x");
		    if (given & 0x100)
		      func (stream, "c");
		  }
		else if ((given & 0x20) == 0x20)
		  {
		    char const* name;
		    unsigned sysm = (given & 0xf00) >> 8;

		    sysm |= (given & 0x30);
		    sysm |= (given & 0x00100000) >> 14;
		    name = banked_regname (sysm);
		    
		    if (name != NULL)
		      func (stream, "%s", name);
		    else
		      func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
		  }
		else
		  {
		    func (stream, "%s", psr_name (given & 0xff));
		  }
		break;

	      case 'D':
		if (((given & 0xff) == 0)
		    || ((given & 0x20) == 0x20))
		  {
		    char const* name;
		    unsigned sm = (given & 0xf0000) >> 16;

		    sm |= (given & 0x30);
		    sm |= (given & 0x00100000) >> 14;
		    name = banked_regname (sm);

		    if (name != NULL)
		      func (stream, "%s", name);
		    else
		      func (stream, "(UNDEF: %lu)", (unsigned long) sm);
		  }
		else
		  func (stream, "%s", psr_name (given & 0xff));
		break;

	      case '0': case '1': case '2': case '3': case '4':
	      case '5': case '6': case '7': case '8': case '9':
		{
		  int width;
		  unsigned long val;

		  c = arm_decode_bitfield (c, given, &val, &width);
			
		  switch (*c)
		    {
		    case 'd':
		      func (stream, "%lu", val);
		      value_in_comment = val;
		      break;

		    case 'W':
		      func (stream, "%lu", val * 4);
		      value_in_comment = val * 4;
		      break;

		    case 'R':
		      if (val == 15)
			is_unpredictable = TRUE;
		      /* Fall through.  */
		    case 'r':
		      func (stream, "%s", arm_regnames[val]);
		      break;

		    case 'c':
		      func (stream, "%s", arm_conditional[val]);
		      break;

		    case '\'':
		      c++;
		      if (val == ((1ul << width) - 1))
			func (stream, "%c", *c);
		      break;
		      
		    case '`':
		      c++;
		      if (val == 0)
			func (stream, "%c", *c);
		      break;

		    case '?':
		      func (stream, "%c", c[(1 << width) - (int) val]);
		      c += 1 << width;
		      break;
		      
		    case 'x':
		      func (stream, "0x%lx", val & 0xffffffffUL);
		      break;

		    default:
		      abort ();
		    }
		}
		break;

	      case 'L':
		/* PR binutils/12534
		   If we have a PC relative offset in an LDRD or STRD
		   instructions then display the decoded address.  */
		if (((given >> 16) & 0xf) == 0xf)
		  {
		    bfd_vma offset = (given & 0xff) * 4;

		    if ((given & (1 << 23)) == 0)
		      offset = - offset;
#if COMMENTS
		    func (stream, " ; ");
		    info->print_address_func ((pc & ~3) + 4 + offset, info);
#endif
		  }
		break;

	      default:
		abort ();
	      }
	  }

#if COMMENTS
	if (value_in_comment > 64 || value_in_comment < -16)
	  func (stream, " ; 0x%lx", value_in_comment);
#endif

	if (is_unpredictable)
	  func (stream, UNPREDICTABLE_INSTRUCTION);

	return;
      }

  /* No match.  */
  abort ();
}

/* Print data bytes on INFO->STREAM.  */

static void
print_insn_data (bfd_vma pc ATTRIBUTE_UNUSED,
		 struct disassemble_info *info,
		 long given)
{
  switch (info->bytes_per_chunk)
    {
    case 1:
      info->fprintf_func (info->stream, ".byte 0x%02lx", given);
      break;
    case 2:
      info->fprintf_func (info->stream, ".short 0x%04lx", given);
      break;
    case 4:
      info->fprintf_func (info->stream, ".word 0x%08lx", given);
      break;
    default:
      abort ();
    }
}

/* Disallow mapping symbols ($a, $b, $d, $t etc) from
   being displayed in symbol relative addresses.  */

bfd_boolean
arm_symbol_is_valid (asymbol * sym,
		     struct disassemble_info * info ATTRIBUTE_UNUSED)
{
  const char * name;
  
  if (sym == NULL)
    return FALSE;

  name = bfd_asymbol_name (sym);

  return (name && *name != '$');
}

/* Parse an individual disassembler option.  */

void
parse_arm_disassembler_option (char *option)
{
  if (option == NULL)
    return;

  if (CONST_STRNEQ (option, "reg-names-"))
    {
      int i;

      option += 10;

      for (i = NUM_ARM_REGNAMES; i--;)
	if (strneq (option, regnames[i].name, strlen (regnames[i].name)))
	  {
	    regname_selected = i;
	    break;
	  }

      if (i < 0)
	/* XXX - should break 'option' at following delimiter.  */
	fprintf (stderr, _("Unrecognised register name set: %s\n"), option);
    }
  else if (CONST_STRNEQ (option, "force-thumb"))
    force_thumb = 1;
  else if (CONST_STRNEQ (option, "no-force-thumb"))
    force_thumb = 0;
  else
    /* XXX - should break 'option' at following delimiter.  */
    fprintf (stderr, _("Unrecognised disassembler option: %s\n"), option);

  return;
}

/* Parse the string of disassembler options, spliting it at whitespaces
   or commas.  (Whitespace separators supported for backwards compatibility).  */

#define ISSPACE(x) (x==' '||x=='\t')
static void
parse_disassembler_options (char *options)
{
  if (options == NULL)
    return;

  while (*options)
    {
      parse_arm_disassembler_option (options);

      /* Skip forward to next separator.  */
      while ((*options) && (! ISSPACE (*options)) && (*options != ','))
	++ options;
      /* Skip forward past separators.  */
      while (ISSPACE (*options) || (*options == ','))
	++ options;      
    }
}

/* Search back through the insn stream to determine if this instruction is
   conditionally executed.  */

static void
find_ifthen_state (bfd_vma pc,
		   struct disassemble_info *info,
		   bfd_boolean little)
{
  unsigned char b[2];
  unsigned int insn;
  int status;
  /* COUNT is twice the number of instructions seen.  It will be odd if we
     just crossed an instruction boundary.  */
  int count;
  int it_count;
  unsigned int seen_it;
  bfd_vma addr;

  ifthen_address = pc;
  ifthen_state = 0;

  addr = pc;
  count = 1;
  it_count = 0;
  seen_it = 0;
  /* Scan backwards looking for IT instructions, keeping track of where
     instruction boundaries are.  We don't know if something is actually an
     IT instruction until we find a definite instruction boundary.  */
  for (;;)
    {
      if (addr == 0 || info->symbol_at_address_func (addr, info))
	{
	  /* A symbol must be on an instruction boundary, and will not
	     be within an IT block.  */
	  if (seen_it && (count & 1))
	    break;

	  return;
	}
      addr -= 2;
      status = info->read_memory_func (addr, (bfd_byte *) b, 2, info);
      if (status)
	return;

      if (little)
	insn = (b[0]) | (b[1] << 8);
      else
	insn = (b[1]) | (b[0] << 8);
      if (seen_it)
	{
	  if ((insn & 0xf800) < 0xe800)
	    {
	      /* Addr + 2 is an instruction boundary.  See if this matches
	         the expected boundary based on the position of the last
		 IT candidate.  */
	      if (count & 1)
		break;
	      seen_it = 0;
	    }
	}
      if ((insn & 0xff00) == 0xbf00 && (insn & 0xf) != 0)
	{
	  /* This could be an IT instruction.  */
	  seen_it = insn;
	  it_count = count >> 1;
	}
      if ((insn & 0xf800) >= 0xe800)
	count++;
      else
	count = (count + 2) | 1;
      /* IT blocks contain at most 4 instructions.  */
      if (count >= 8 && !seen_it)
	return;
    }
  /* We found an IT instruction.  */
  ifthen_state = (seen_it & 0xe0) | ((seen_it << it_count) & 0x1f);
  if ((ifthen_state & 0xf) == 0)
    ifthen_state = 0;
}

/* Returns nonzero and sets *MAP_TYPE if the N'th symbol is a
   mapping symbol.  */

static int
is_mapping_symbol (struct disassemble_info *info, int n,
		   enum map_type *map_type)
{
  const char *name;

  name = bfd_asymbol_name (info->symtab[n]);
  if (name[0] == '$' && (name[1] == 'a' || name[1] == 't' || name[1] == 'd')
      && (name[2] == 0 || name[2] == '.'))
    {
      *map_type = ((name[1] == 'a') ? MAP_ARM
		   : (name[1] == 't') ? MAP_THUMB
		   : MAP_DATA);
      return TRUE;
    }

  return FALSE;
}

/* Try to infer the code type (ARM or Thumb) from a mapping symbol.
   Returns nonzero if *MAP_TYPE was set.  */

static int
get_map_sym_type (struct disassemble_info *info,
		  int n,
		  enum map_type *map_type)
{
  /* If the symbol is in a different section, ignore it.  */
  if (info->section != NULL && info->section != info->symtab[n]->section)
    return FALSE;

  return is_mapping_symbol (info, n, map_type);
}

/* Try to infer the code type (ARM or Thumb) from a non-mapping symbol.
   Returns nonzero if *MAP_TYPE was set.  */
#if 0

static int
get_sym_code_type (struct disassemble_info *info,
		   int n,
		   enum map_type *map_type)
{
  elf_symbol_type *es;
  unsigned int type;

  /* If the symbol is in a different section, ignore it.  */
  if (info->section != NULL && info->section != info->symtab[n]->section)
    return FALSE;

  es = *(elf_symbol_type **)(info->symtab + n);
  type = ELF_ST_TYPE (es->internal_elf_sym.st_info);

  /* If the symbol has function type then use that.  */
  if (type == STT_FUNC || type == STT_GNU_IFUNC)
    {
      if (ARM_SYM_BRANCH_TYPE (&es->internal_elf_sym) == ST_BRANCH_TO_THUMB)
	*map_type = MAP_THUMB;
      else
	*map_type = MAP_ARM;
      return TRUE;
    }

  return FALSE;
}
#endif

/* Given a bfd_mach_arm_XXX value, this function fills in the fields
   of the supplied arm_feature_set structure with bitmasks indicating
   the support base architectures and coprocessor extensions.

   FIXME: This could more efficiently implemented as a constant array,
   although it would also be less robust.  */

static void
select_arm_features (unsigned long mach,
		     arm_feature_set * features)
{
#undef  ARM_FEATURE
#define ARM_FEATURE(ARCH,CEXT) \
  features->core = (ARCH); \
  features->coproc = (CEXT) | FPU_FPA; \
  return

  switch (mach)
    {
    case bfd_mach_arm_2:       ARM_ARCH_V2;
    case bfd_mach_arm_2a:      ARM_ARCH_V2S;
    case bfd_mach_arm_3:       ARM_ARCH_V3;
    case bfd_mach_arm_3M:      ARM_ARCH_V3M;
    case bfd_mach_arm_4:       ARM_ARCH_V4;
    case bfd_mach_arm_4T:      ARM_ARCH_V4T;
    case bfd_mach_arm_5:       ARM_ARCH_V5;
    case bfd_mach_arm_5T:      ARM_ARCH_V5T;
    case bfd_mach_arm_5TE:     ARM_ARCH_V5TE;
    case bfd_mach_arm_XScale:  ARM_ARCH_XSCALE;
    case bfd_mach_arm_ep9312:  ARM_FEATURE (ARM_AEXT_V4T, ARM_CEXT_MAVERICK | FPU_MAVERICK);
    case bfd_mach_arm_iWMMXt:  ARM_ARCH_IWMMXT;
    case bfd_mach_arm_iWMMXt2: ARM_ARCH_IWMMXT2;
      /* If the machine type is unknown allow all
	 architecture types and all extensions.  */
    case bfd_mach_arm_unknown: ARM_FEATURE (-1UL, -1UL);
    default:
      abort ();
    }
}


/* NOTE: There are no checks in these routines that
   the relevant number of data bytes exist.  */

static int
print_insn (bfd_vma pc, struct disassemble_info *info, bfd_boolean little)
{
  unsigned char b[4];
  long		given;
  int           status;
  int           is_thumb = FALSE;
  int           is_data = FALSE;
  int           little_code;
  unsigned int	size = 4;
  void	 	(*printer) (bfd_vma, struct disassemble_info *, long);
  bfd_boolean   found = FALSE;
  struct arm_private_data *private_data;

  if (info->disassembler_options)
    {
      parse_disassembler_options (info->disassembler_options);

      /* To avoid repeated parsing of these options, we remove them here.  */
      info->disassembler_options = NULL;
    }

  /* PR 10288: Control which instructions will be disassembled.  */
  if (info->private_data == NULL)
    {
      static struct arm_private_data private;

      if ((info->flags & USER_SPECIFIED_MACHINE_TYPE) == 0)
	/* If the user did not use the -m command line switch then default to
	   disassembling all types of ARM instruction.
	   
	   The info->mach value has to be ignored as this will be based on
	   the default archictecture for the target and/or hints in the notes
	   section, but it will never be greater than the current largest arm
	   machine value (iWMMXt2), which is only equivalent to the V5TE
	   architecture.  ARM architectures have advanced beyond the machine
	   value encoding, and these newer architectures would be ignored if
	   the machine value was used.

	   Ie the -m switch is used to restrict which instructions will be
	   disassembled.  If it is necessary to use the -m switch to tell
	   objdump that an ARM binary is being disassembled, eg because the
	   input is a raw binary file, but it is also desired to disassemble
	   all ARM instructions then use "-marm".  This will select the
	   "unknown" arm architecture which is compatible with any ARM
	   instruction.  */
	  info->mach = bfd_mach_arm_unknown;

      /* Compute the architecture bitmask from the machine number.
	 Note: This assumes that the machine number will not change
	 during disassembly....  */
      select_arm_features (info->mach, & private.features);

      private.has_mapping_symbols = -1;
      private.last_mapping_sym = -1;
      private.last_mapping_addr = 0;

      info->private_data = & private;
    }

  private_data = info->private_data;

  /* Decide if our code is going to be little-endian, despite what the
     function argument might say.  */
  little_code = ((info->endian_code == BFD_ENDIAN_LITTLE) || little);

  /* For ELF, consult the symbol table to determine what kind of code
     or data we have.  */
  if (info->symtab_size != 0
      && bfd_asymbol_flavour (*info->symtab) == bfd_target_elf_flavour)
    {
      bfd_vma addr;
      int n, start;
      int last_sym = -1;
      enum map_type type = MAP_ARM;

      /* Start scanning at the start of the function, or wherever
	 we finished last time.  */
      /* PR 14006.  When the address is 0 we are either at the start of the
	 very first function, or else the first function in a new, unlinked
	 executable section (eg because uf -ffunction-sections).  Either way
	 start scanning from the beginning of the symbol table, not where we
	 left off last time.  */
      if (pc == 0)
	start = 0;
      else
	{
	  start = info->symtab_pos + 1;
	  if (start < private_data->last_mapping_sym)
	    start = private_data->last_mapping_sym;
	}
      found = FALSE;

      /* First, look for mapping symbols.  */
      if (private_data->has_mapping_symbols != 0)
	{
	  /* Scan up to the location being disassembled.  */
	  for (n = start; n < info->symtab_size; n++)
	    {
	      addr = bfd_asymbol_value (info->symtab[n]);
	      if (addr > pc)
		break;
	      if (get_map_sym_type (info, n, &type))
		{
		  last_sym = n;
		  found = TRUE;
		}
	    }

	  if (!found)
	    {
	      /* No mapping symbol found at this address.  Look backwards
		 for a preceding one.  */
	      for (n = start - 1; n >= 0; n--)
		{
		  if (get_map_sym_type (info, n, &type))
		    {
		      last_sym = n;
		      found = TRUE;
		      break;
		    }
		}
	    }

	  if (found)
	    private_data->has_mapping_symbols = 1;

	  /* No mapping symbols were found.  A leading $d may be
	     omitted for sections which start with data; but for
	     compatibility with legacy and stripped binaries, only
	     assume the leading $d if there is at least one mapping
	     symbol in the file.  */
	  if (!found && private_data->has_mapping_symbols == -1)
	    {
	      /* Look for mapping symbols, in any section.  */
	      for (n = 0; n < info->symtab_size; n++)
		if (is_mapping_symbol (info, n, &type))
		  {
		    private_data->has_mapping_symbols = 1;
		    break;
		  }
	      if (private_data->has_mapping_symbols == -1)
		private_data->has_mapping_symbols = 0;
	    }

	  if (!found && private_data->has_mapping_symbols == 1)
	    {
	      type = MAP_DATA;
	      found = TRUE;
	    }
	}

      /* Next search for function symbols to separate ARM from Thumb
	 in binaries without mapping symbols.  */
#if 0
      if (!found)
	{
	  /* Scan up to the location being disassembled.  */
	  for (n = start; n < info->symtab_size; n++)
	    {
	      addr = bfd_asymbol_value (info->symtab[n]);
	      if (addr > pc)
		break;
	      if (get_sym_code_type (info, n, &type))
		{
		  last_sym = n;
		  found = TRUE;
		}
	    }

	  if (!found)
	    {
	      /* No mapping symbol found at this address.  Look backwards
		 for a preceding one.  */
	      for (n = start - 1; n >= 0; n--)
		{
		  if (get_sym_code_type (info, n, &type))
		    {
		      last_sym = n;
		      found = TRUE;
		      break;
		    }
		}
	    }
	}
#endif

      private_data->last_mapping_sym = last_sym;
      private_data->last_type = type;
      is_thumb = (private_data->last_type == MAP_THUMB);
      is_data = (private_data->last_type == MAP_DATA);

      /* Look a little bit ahead to see if we should print out
	 two or four bytes of data.  If there's a symbol,
	 mapping or otherwise, after two bytes then don't
	 print more.  */
      if (is_data)
	{
	  size = 4 - (pc & 3);
	  for (n = last_sym + 1; n < info->symtab_size; n++)
	    {
	      addr = bfd_asymbol_value (info->symtab[n]);
	      if (addr > pc
		  && (info->section == NULL
		      || info->section == info->symtab[n]->section))
		{
		  if (addr - pc < size)
		    size = addr - pc;
		  break;
		}
	    }
	  /* If the next symbol is after three bytes, we need to
	     print only part of the data, so that we can use either
	     .byte or .short.  */
	  if (size == 3)
	    size = (pc & 1) ? 1 : 2;
	}
    }

#if 0
  if (info->symbols != NULL)
    {
      if (bfd_asymbol_flavour (*info->symbols) == bfd_target_coff_flavour)
	{
	  coff_symbol_type * cs;

	  cs = coffsymbol (*info->symbols);
	  is_thumb = (   cs->native->u.syment.n_sclass == C_THUMBEXT
		      || cs->native->u.syment.n_sclass == C_THUMBSTAT
		      || cs->native->u.syment.n_sclass == C_THUMBLABEL
		      || cs->native->u.syment.n_sclass == C_THUMBEXTFUNC
		      || cs->native->u.syment.n_sclass == C_THUMBSTATFUNC);
	}
      else if (bfd_asymbol_flavour (*info->symbols) == bfd_target_elf_flavour
	       && !found)
	{
	  /* If no mapping symbol has been found then fall back to the type
	     of the function symbol.  */
	  elf_symbol_type *  es;
	  unsigned int       type;

	  es = *(elf_symbol_type **)(info->symbols);
	  type = ELF_ST_TYPE (es->internal_elf_sym.st_info);

	  is_thumb = ((ARM_SYM_BRANCH_TYPE (&es->internal_elf_sym)
		       == ST_BRANCH_TO_THUMB)
		      || type == STT_ARM_16BIT);
	}
    }
#endif

  if (force_thumb)
    is_thumb = TRUE;

  if (is_data)
    info->display_endian = little ? BFD_ENDIAN_LITTLE : BFD_ENDIAN_BIG;
  else
    info->display_endian = little_code ? BFD_ENDIAN_LITTLE : BFD_ENDIAN_BIG;

  info->bytes_per_line = 4;

  /* PR 10263: Disassemble data if requested to do so by the user.  */
  if (is_data && ((info->flags & DISASSEMBLE_DATA) == 0))
    {
      int i;

      /* Size was already set above.  */
      info->bytes_per_chunk = size;
      printer = print_insn_data;

      status = info->read_memory_func (pc, (bfd_byte *) b, size, info);
      given = 0;
      if (little)
	for (i = size - 1; i >= 0; i--)
	  given = b[i] | (given << 8);
      else
	for (i = 0; i < (int) size; i++)
	  given = b[i] | (given << 8);
    }
  else if (!is_thumb)
    {
      /* In ARM mode endianness is a straightforward issue: the instruction
	 is four bytes long and is either ordered 0123 or 3210.  */
      printer = print_insn_arm;
      info->bytes_per_chunk = 4;
      size = 4;

      status = info->read_memory_func (pc, (bfd_byte *) b, 4, info);
      if (little_code)
	given = (b[0]) | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
      else
	given = (b[3]) | (b[2] << 8) | (b[1] << 16) | (b[0] << 24);
    }
  else
    {
      /* In Thumb mode we have the additional wrinkle of two
	 instruction lengths.  Fortunately, the bits that determine
	 the length of the current instruction are always to be found
	 in the first two bytes.  */
      printer = print_insn_thumb16;
      info->bytes_per_chunk = 2;
      size = 2;

      status = info->read_memory_func (pc, (bfd_byte *) b, 2, info);
      if (little_code)
	given = (b[0]) | (b[1] << 8);
      else
	given = (b[1]) | (b[0] << 8);

      if (!status)
	{
	  /* These bit patterns signal a four-byte Thumb
	     instruction.  */
	  if ((given & 0xF800) == 0xF800
	      || (given & 0xF800) == 0xF000
	      || (given & 0xF800) == 0xE800)
	    {
	      status = info->read_memory_func (pc + 2, (bfd_byte *) b, 2, info);
	      if (little_code)
		given = (b[0]) | (b[1] << 8) | (given << 16);
	      else
		given = (b[1]) | (b[0] << 8) | (given << 16);

	      printer = print_insn_thumb32;
	      size = 4;
	    }
	}

      if (ifthen_address != pc)
	find_ifthen_state (pc, info, little_code);

      if (ifthen_state)
	{
	  if ((ifthen_state & 0xf) == 0x8)
	    ifthen_next_state = 0;
	  else
	    ifthen_next_state = (ifthen_state & 0xe0)
				| ((ifthen_state & 0xf) << 1);
	}
    }

  if (status)
    {
      info->memory_error_func (status, pc, info);
      return -1;
    }
  if (info->flags & INSN_HAS_RELOC)
    /* If the instruction has a reloc associated with it, then
       the offset field in the instruction will actually be the
       addend for the reloc.  (We are using REL type relocs).
       In such cases, we can ignore the pc when computing
       addresses, since the addend is not currently pc-relative.  */
    pc = 0;

  printer (pc, info, given);

  if (is_thumb)
    {
      ifthen_state = ifthen_next_state;
      ifthen_address += size;
    }
  return size;
}

int
print_insn_big_arm (bfd_vma pc, struct disassemble_info *info)
{
  /* Detect BE8-ness and record it in the disassembler info.  */
  if (info->flavour == bfd_target_elf_flavour
      && info->section != NULL
      && (elf_elfheader (info->section->owner)->e_flags & EF_ARM_BE8))
    info->endian_code = BFD_ENDIAN_LITTLE;

  return print_insn (pc, info, FALSE);
}

int
print_insn_little_arm (bfd_vma pc, struct disassemble_info *info)
{
  return print_insn (pc, info, TRUE);
}

void
print_arm_disassembler_options (FILE *stream)
{
  int i;

  fprintf (stream, _("\n\
The following ARM specific disassembler options are supported for use with\n\
the -M switch:\n"));

  for (i = NUM_ARM_REGNAMES; i--;)
    fprintf (stream, "  reg-names-%s %*c%s\n",
	     regnames[i].name,
	     (int)(14 - strlen (regnames[i].name)), ' ',
	     regnames[i].description);

  fprintf (stream, "  force-thumb              Assume all insns are Thumb insns\n");
  fprintf (stream, "  no-force-thumb           Examine preceding label to determine an insn's type\n\n");
}
