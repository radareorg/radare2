#ifndef MKSQUASHFS_H
#define MKSQUASHFS_H
/*
 * Squashfs
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
 * Phillip Lougher <phillip@lougher.demon.co.uK>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * mksquashfs.h
 *
 */

#if __BYTE_ORDER == __BIG_ENDIAN
#define SQUASHFS_SWAP_SHORTS(s, d, n) swap_le16_num(s, d, n)
#define SQUASHFS_SWAP_INTS(s, d, n) swap_le32_num(s, d, n)
#define SQUASHFS_SWAP_LONG_LONGS(s, d, n) swap_le64_num(s, d, n)

#define SWAP_LE16(s, d)		swap_le16(s, d)
#define SWAP_LE32(s, d)		swap_le32(s, d)
#define SWAP_LE64(s, d)		swap_le64(s, d)
#else
#define SQUASHFS_MEMCPY(s, d, n)	memcpy(d, s, n)
#define SQUASHFS_SWAP_SHORTS(s, d, n)	memcpy(d, s, n * sizeof(short))
#define SQUASHFS_SWAP_INTS(s, d, n)	memcpy(d, s, n * sizeof(int))
#define SQUASHFS_SWAP_LONG_LONGS(s, d, n) \
					memcpy(d, s, n * sizeof(long long))
#endif

struct dir_info {
	char			*pathname;
	unsigned int		count;
	unsigned int		directory_count;
	unsigned int		current_count;
	unsigned int		byte_count;
	int			depth;
	unsigned int		excluded;
	char			dir_is_ldir;
	struct dir_ent		*dir_ent;
	struct dir_ent		**list;
	DIR			*linuxdir;
};

struct dir_ent {
	char			*name;
	char			*pathname;
	struct inode_info	*inode;
	struct dir_info		*dir;
	struct dir_info		*our_dir;
};

struct inode_info {
	struct stat		buf;
	struct inode_info	*next;
	squashfs_inode		inode;
	unsigned int		inode_number;
	unsigned int		nlink;
	int			pseudo_id;
	char			type;
	char			read;
	char			root_entry;
	char			pseudo_file;
	char			no_fragments;
	char			always_use_fragments;
	char			noD;
	char			noF;
};
#endif

#define PSEUDO_FILE_OTHER	1
#define PSEUDO_FILE_PROCESS	2

#define IS_PSEUDO(a)		((a)->pseudo_file)
#define IS_PSEUDO_PROCESS(a)	((a)->pseudo_file & PSEUDO_FILE_PROCESS)
#define IS_PSEUDO_OTHER(a)	((a)->pseudo_file & PSEUDO_FILE_OTHER)

/* offset of data in compressed metadata blocks (allowing room for
 * compressed size */
#define BLOCK_OFFSET 2
