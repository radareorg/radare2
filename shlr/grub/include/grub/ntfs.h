/* ntfs.h - header for the NTFS filesystem */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2007,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_NTFS_H
#define GRUB_NTFS_H	1

#define FILE_MFT      0
#define FILE_MFTMIRR  1
#define FILE_LOGFILE  2
#define FILE_VOLUME   3
#define FILE_ATTRDEF  4
#define FILE_ROOT     5
#define FILE_BITMAP   6
#define FILE_BOOT     7
#define FILE_BADCLUS  8
#define FILE_QUOTA    9
#define FILE_UPCASE  10

#define AT_STANDARD_INFORMATION	0x10
#define AT_ATTRIBUTE_LIST	0x20
#define AT_FILENAME		0x30
#define AT_OBJECT_ID		0x40
#define AT_SECURITY_DESCRIPTOR	0x50
#define AT_VOLUME_NAME		0x60
#define AT_VOLUME_INFORMATION	0x70
#define AT_DATA			0x80
#define AT_INDEX_ROOT		0x90
#define AT_INDEX_ALLOCATION	0xA0
#define AT_BITMAP		0xB0
#define AT_SYMLINK		0xC0
#define AT_EA_INFORMATION	0xD0
#define AT_EA			0xE0

#define ATTR_READ_ONLY		0x1
#define ATTR_HIDDEN		0x2
#define ATTR_SYSTEM		0x4
#define ATTR_ARCHIVE		0x20
#define ATTR_DEVICE		0x40
#define ATTR_NORMAL		0x80
#define ATTR_TEMPORARY		0x100
#define ATTR_SPARSE		0x200
#define ATTR_REPARSE		0x400
#define ATTR_COMPRESSED		0x800
#define ATTR_OFFLINE		0x1000
#define ATTR_NOT_INDEXED	0x2000
#define ATTR_ENCRYPTED		0x4000
#define ATTR_DIRECTORY		0x10000000
#define ATTR_INDEX_VIEW		0x20000000

#define FLAG_COMPRESSED		1
#define FLAG_ENCRYPTED		0x4000
#define FLAG_SPARSE		0x8000

#define BLK_SHR		GRUB_DISK_SECTOR_BITS

#define MAX_MFT		(1024 >> BLK_SHR)
#define MAX_IDX		(16384 >> BLK_SHR)

#define COM_LEN		4096
#define COM_LOG_LEN	12
#define COM_SEC		(COM_LEN >> BLK_SHR)

#define AF_ALST		1
#define AF_MMFT		2
#define AF_GPOS		4

#define RF_COMP		1
#define RF_CBLK		2
#define RF_BLNK		4

#define valueat(buf,ofs,type)	*((type*)(((char*)buf)+ofs))

#define u16at(buf,ofs)	grub_le_to_cpu16(valueat(buf,ofs,grub_uint16_t))
#define u32at(buf,ofs)	grub_le_to_cpu32(valueat(buf,ofs,grub_uint32_t))
#define u64at(buf,ofs)	grub_le_to_cpu64(valueat(buf,ofs,grub_uint64_t))

#define v16at(buf,ofs)	valueat(buf,ofs,grub_uint16_t)
#define v32at(buf,ofs)	valueat(buf,ofs,grub_uint32_t)
#define v64at(buf,ofs)	valueat(buf,ofs,grub_uint64_t)

struct grub_ntfs_bpb
{
  grub_uint8_t jmp_boot[3];
  grub_uint8_t oem_name[8];
  grub_uint16_t bytes_per_sector;
  grub_uint8_t sectors_per_cluster;
  grub_uint8_t reserved_1[7];
  grub_uint8_t media;
  grub_uint16_t reserved_2;
  grub_uint16_t sectors_per_track;
  grub_uint16_t num_heads;
  grub_uint32_t num_hidden_sectors;
  grub_uint32_t reserved_3[2];
  grub_uint64_t num_total_sectors;
  grub_uint64_t mft_lcn;
  grub_uint64_t mft_mirr_lcn;
  grub_int8_t clusters_per_mft;
  grub_int8_t reserved_4[3];
  grub_int8_t clusters_per_index;
  grub_int8_t reserved_5[3];
  grub_uint64_t num_serial;
  grub_uint32_t checksum;
} __attribute__ ((packed));

#define grub_ntfs_file grub_fshelp_node

struct grub_ntfs_attr
{
  int flags;
  char *emft_buf, *edat_buf;
  char *attr_cur, *attr_nxt, *attr_end;
  grub_uint32_t save_pos;
  char *sbuf;
  struct grub_ntfs_file *mft;
};

struct grub_fshelp_node
{
  struct grub_ntfs_data *data;
  char *buf;
  grub_uint64_t size;
  grub_uint32_t ino;
  int inode_read;
  grub_uint32_t sector;
  struct grub_ntfs_attr attr;
};

struct grub_ntfs_data
{
  struct grub_ntfs_file cmft;
  struct grub_ntfs_file mmft;
  grub_disk_t disk;
  grub_uint32_t mft_size;
  grub_uint32_t idx_size;
  grub_uint32_t spc;
  grub_uint32_t blocksize;
  grub_uint32_t mft_start;
  grub_uint64_t uuid;
};

struct grub_ntfs_comp
{
  grub_disk_t disk;
  int comp_head, comp_tail;
  grub_uint32_t comp_table[16][2];
  grub_uint32_t cbuf_ofs, cbuf_vcn, spc;
  char *cbuf;
};

struct grub_ntfs_rlst
{
  int flags;
  grub_disk_addr_t target_vcn, curr_vcn, next_vcn, curr_lcn;
  char *cur_run;
  struct grub_ntfs_attr *attr;
  struct grub_ntfs_comp comp;
};

typedef grub_err_t (*ntfscomp_func_t) (struct grub_ntfs_attr * at, char *dest,
				       grub_uint32_t ofs, grub_uint32_t len,
				       struct grub_ntfs_rlst * ctx,
				       grub_uint32_t vcn);

extern ntfscomp_func_t grub_ntfscomp_func;

grub_err_t grub_ntfs_read_run_list (struct grub_ntfs_rlst *ctx);

#endif /* ! GRUB_NTFS_H */
