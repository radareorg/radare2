/* TI C6X control register information.
   Copyright (C) 2010-2025 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/* Define the CTRL macro before including this file; it takes as
   arguments the fields from tic6x_ctrl (defined in tic6x.h).  The
   control register name is given as an identifier; the isa_variants
   field without the leading TIC6X_INSN_; the rw field without the
   leading tic6x_rw_.  */

CTRL(amr, C62X, read_write, 0x0, 0x10)
CTRL(csr, C62X, read_write, 0x1, 0x10)
CTRL(dnum, C64XP, read, 0x11, 0x1f)
CTRL(ecr, C64XP, write, 0x1d, 0x1f)
CTRL(efr, C64XP, read, 0x1d, 0x1f)
CTRL(fadcr, C67X, read_write, 0x12, 0x1f)
CTRL(faucr, C67X, read_write, 0x13, 0x1f)
CTRL(fmcr, C67X, read_write, 0x14, 0x1f)
CTRL(gfpgfr, C64X, read_write, 0x18, 0x1f)
CTRL(gplya, C64XP, read_write, 0x16, 0x1f)
CTRL(gplyb, C64XP, read_write, 0x17, 0x1f)
CTRL(icr, C62X, write, 0x3, 0x10)
CTRL(ier, C62X, read_write, 0x4, 0x10)
CTRL(ierr, C64XP, read_write, 0x1f, 0x1f)
CTRL(ifr, C62X, read, 0x2, 0x1d)
CTRL(ilc, C64XP, read_write, 0xd, 0x1f)
CTRL(irp, C62X, read_write, 0x6, 0x10)
CTRL(isr, C62X, write, 0x2, 0x10)
CTRL(istp, C62X, read_write, 0x5, 0x10)
CTRL(itsr, C64XP, read_write, 0x1b, 0x1f)
CTRL(nrp, C62X, read_write, 0x7, 0x10)
CTRL(ntsr, C64XP, read_write, 0x1c, 0x1f)
CTRL(pce1, C62X, read, 0x10, 0xf)
CTRL(rep, C64XP, read_write, 0xf, 0x1f)
CTRL(rilc, C64XP, read_write, 0xe, 0x1f)
CTRL(ssr, C64XP, read_write, 0x15, 0x1f)
CTRL(tsch, C64XP, read, 0xb, 0x1f)
/* Contrary to Table 3-26 in SPRUFE8, this register is read-write, as
   documented in section 2.9.13.  */
CTRL(tscl, C64XP, read_write, 0xa, 0x1f)
CTRL(tsr, C64XP, read_write, 0x1a, 0x1f)
