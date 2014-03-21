/*
 *  BURG - Brand-new Universal loadeR from GRUB
 *  Copyright 2010 Bean Lee - All Rights Reserved
 *
 *  BURG is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  BURG is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with BURG.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_FBFS_H
#define GRUB_FBFS_H	1

#define FB_MAGIC	"FBBF"
#define FB_MAGIC_LONG	0x46424246

#define FB_AR_MAGIC		"FBAR"
#define FB_AR_MAGIC_LONG	0x52414246

#define FB_VER_MAJOR	1
#define FB_VER_MINOR	6

struct fb_mbr
{
  grub_uint8_t jmp_code;
  grub_uint8_t jmp_ofs;
  grub_uint8_t boot_code[0x1ab];
  grub_uint8_t max_sec;		/* 0x1ad  */
  grub_uint16_t lba;		/* 0x1ae  */
  grub_uint8_t spt;		/* 0x1b0  */
  grub_uint8_t heads;		/* 0x1b1  */
  grub_uint16_t boot_base;	/* 0x1b2  */
  grub_uint32_t fb_magic;	/* 0x1b4  */
  grub_uint8_t mbr_table[0x46];	/* 0x1b8  */
  grub_uint16_t end_magic;	/* 0x1fe  */
} __attribute__((packed));

struct fb_data
{
  grub_uint16_t boot_size;	/* 0x200  */
  grub_uint16_t flags;		/* 0x202  */
  grub_uint8_t ver_major;	/* 0x204  */
  grub_uint8_t ver_minor;	/* 0x205  */
  grub_uint16_t list_used;	/* 0x206  */
  grub_uint16_t list_size;	/* 0x208  */
  grub_uint16_t pri_size;	/* 0x20a  */
  grub_uint32_t ext_size;	/* 0x20c  */
} __attribute__((packed));

struct fb_ar_data
{
  grub_uint32_t ar_magic;	/* 0x200  */
  grub_uint8_t ver_major;	/* 0x204  */
  grub_uint8_t ver_minor;	/* 0x205  */
  grub_uint16_t list_used;	/* 0x206  */
  grub_uint16_t list_size;	/* 0x208  */
  grub_uint16_t pri_size;	/* 0x20a  */
  grub_uint32_t ext_size;	/* 0x20c  */
} __attribute__((packed));

struct fbm_file
{
  grub_uint8_t size;
  grub_uint8_t flag;
  grub_uint32_t data_start;
  grub_uint32_t data_size;
  grub_uint32_t data_time;
  char name[0];
} __attribute__((packed));

#endif /* ! GRUB_FBFS_H */
