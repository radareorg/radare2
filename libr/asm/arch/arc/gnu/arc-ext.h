/* ARC target-dependent stuff. Extension data structures.
   Copyright 1995, 1997, 2000, 2001, 2005, 2007 Free Software Foundation, Inc.

   Copyright 2008-2012 Synopsys Inc.

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


/******************************************************************************/
/*                                                                            */
/* Outline:                                                                   */
/*     This header file defines a table of extensions to the ARC processor    */
/*     architecture.  These extensions are read from the '.arcextmap' or      */
/*     '.gnu.linkonce.arcextmap.<type>.<N>' sections in the ELF file which is */
/*     identified by the bfd parameter to the build_ARC_extmap function.      */
/*                                                                            */
/*     These extensions may include:                                          */
/*         core registers                                                     */
/*         auxiliary registers                                                */
/*         instructions                                                       */
/*         condition codes                                                    */
/*                                                                            */
/*     Once the table has been constructed, accessor functions may be used to */
/*     retrieve information from it.                                          */
/*                                                                            */
/*     The build_ARC_extmap constructor function build_ARC_extmap may be      */
/*     called as many times as required; it will re-initialize the table each */
/*     time.                                                                  */
/*                                                                            */
/******************************************************************************/

#ifndef ARC_EXTENSIONS_H
#define ARC_EXTENSIONS_H

#define IGNORE_FIRST_OPD 1

/* Define this if we do not want to encode instructions based on the
   ARCompact Programmer's Reference.  */
#define UNMANGLED


/* this defines the kinds of extensions which may be read from the sections in
 * the executable files
 */
enum ExtOperType
{
  EXT_INSTRUCTION            = 0,
  EXT_CORE_REGISTER          = 1,
  EXT_AUX_REGISTER           = 2,
  EXT_COND_CODE              = 3,
  EXT_INSTRUCTION32          = 4,    /* why are there     */
  EXT_AC_INSTRUCTION         = 4,    /* two with value 4? */
  EXT_REMOVE_CORE_REG        = 5,
  EXT_LONG_CORE_REGISTER     = 6,
  EXT_AUX_REGISTER_EXTENDED  = 7,
  EXT_INSTRUCTION32_EXTENDED = 8,
  EXT_CORE_REGISTER_CLASS    = 9
};


enum ExtReadWrite
{
  REG_INVALID,
  REG_READ,
  REG_WRITE,
  REG_READWRITE
};


/* constructor function */
extern void build_ARC_extmap (void* text_bfd);

/* accessor functions */
extern enum ExtReadWrite arcExtMap_coreReadWrite (int  regnum);
extern const char*       arcExtMap_coreRegName   (int  regnum);
extern const char*       arcExtMap_auxRegName    (long regnum);
extern const char*       arcExtMap_condCodeName  (int  code);
extern const char*       arcExtMap_instName      (int  opcode, int insn, int* flags);

/* dump function (for debugging) */
extern void dump_ARC_extmap (void);

#endif /* ARC_EXTENSIONS_H */
/******************************************************************************/
