/* trig.h - Trigonometric function support.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_TRIG_HEADER
#define GRUB_TRIG_HEADER 1

#define GRUB_TRIG_ANGLE_MAX 256
#define GRUB_TRIG_ANGLE_MASK 255
#define GRUB_TRIG_FRACTION_SCALE 16384

extern short grub_trig_sintab[];
extern short grub_trig_costab[];

static __inline int
grub_sin (int x)
{
  x &= GRUB_TRIG_ANGLE_MASK;
  return grub_trig_sintab[x];
}

static __inline int
grub_cos (int x)
{
  x &= GRUB_TRIG_ANGLE_MASK;
  return grub_trig_costab[x];
}

#endif /* ! GRUB_TRIG_HEADER */
