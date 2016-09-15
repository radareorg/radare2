/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009, 2010
 * Phillip Lougher <phillip@lougher.demon.co.uk>
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
 * unsquash-2.c
 */

#include "unsquashfs.h"
#include "squashfs_compat.h"

static squashfs_fragment_entry_2 *fragment_table;

void read_block_list_2(unsigned int *block_list, char *block_ptr, int blocks)
{
	TRACE("read_block_list: blocks %d\n", blocks);

	if(swap) {
		unsigned int sblock_list[blocks];
		memcpy(sblock_list, block_ptr, blocks * sizeof(unsigned int));
		SQUASHFS_SWAP_INTS_3(block_list, sblock_list, blocks);
	} else
		memcpy(block_list, block_ptr, blocks * sizeof(unsigned int));
}


int read_fragment_table_2()
{
	int res, i, indexes = SQUASHFS_FRAGMENT_INDEXES_2(sBlk.s.fragments);
	unsigned int fragment_table_index[indexes];

	TRACE("read_fragment_table: %d fragments, reading %d fragment indexes "
		"from 0x%llx\n", sBlk.s.fragments, indexes,
		sBlk.s.fragment_table_start);

	if(sBlk.s.fragments == 0)
		return TRUE;

	fragment_table = malloc(sBlk.s.fragments *
		sizeof(squashfs_fragment_entry_2));
	if(fragment_table == NULL)
		EXIT_UNSQUASH("read_fragment_table: failed to allocate "
			"fragment table\n");

	if(swap) {
		 unsigned int sfragment_table_index[indexes];

		 res = read_fs_bytes(fd, sBlk.s.fragment_table_start,
			SQUASHFS_FRAGMENT_INDEX_BYTES_2(sBlk.s.fragments),
			sfragment_table_index);
		if(res == FALSE) {
			ERROR("read_fragment_table: failed to read fragment "
				"table index\n");
			return FALSE;
		}
		SQUASHFS_SWAP_FRAGMENT_INDEXES_2(fragment_table_index,
			sfragment_table_index, indexes);
	} else {
		res = read_fs_bytes(fd, sBlk.s.fragment_table_start,
			SQUASHFS_FRAGMENT_INDEX_BYTES_2(sBlk.s.fragments),
			fragment_table_index);
		if(res == FALSE) {
			ERROR("read_fragment_table: failed to read fragment "
				"table index\n");
			return FALSE;
		}
	}

	for(i = 0; i < indexes; i++) {
		int length = read_block(fd, fragment_table_index[i], NULL,
			((char *) fragment_table) + (i *
			SQUASHFS_METADATA_SIZE));
		TRACE("Read fragment table block %d, from 0x%x, length %d\n", i,
			fragment_table_index[i], length);
		if(length == FALSE) {
			ERROR("read_fragment_table: failed to read fragment "
				"table block\n");
			return FALSE;
		}
	}

	if(swap) {
		squashfs_fragment_entry_2 sfragment;
		for(i = 0; i < sBlk.s.fragments; i++) {
			SQUASHFS_SWAP_FRAGMENT_ENTRY_2((&sfragment),
				(&fragment_table[i]));
			memcpy((char *) &fragment_table[i], (char *) &sfragment,
				sizeof(squashfs_fragment_entry_2));
		}
	}

	return TRUE;
}


void read_fragment_2(unsigned int fragment, long long *start_block, int *size)
{
	TRACE("read_fragment: reading fragment %d\n", fragment);

	squashfs_fragment_entry_2 *fragment_entry = &fragment_table[fragment];
	*start_block = fragment_entry->start_block;
	*size = fragment_entry->size;
}


struct inode *read_inode_2(unsigned int start_block, unsigned int offset)
{
	static union squashfs_inode_header_2 header;
	long long start = sBlk.s.inode_table_start + start_block;
	int bytes = lookup_entry(inode_table_hash, start);
	char *block_ptr = inode_table + bytes + offset;
	static struct inode i;

	TRACE("read_inode: reading inode [%d:%d]\n", start_block,  offset);

	if(bytes == -1)
		EXIT_UNSQUASH("read_inode: inode table block %lld not found\n",
			start); 

	if(swap) {
		squashfs_base_inode_header_2 sinode;
		memcpy(&sinode, block_ptr, sizeof(header.base));
		SQUASHFS_SWAP_BASE_INODE_HEADER_2(&header.base, &sinode,
			sizeof(squashfs_base_inode_header_2));
	} else
		memcpy(&header.base, block_ptr, sizeof(header.base));

	i.xattr = SQUASHFS_INVALID_XATTR;
	i.uid = (uid_t) uid_table[header.base.uid];
	i.gid = header.base.guid == SQUASHFS_GUIDS ? i.uid :
		(uid_t) guid_table[header.base.guid];
	i.mode = lookup_type[header.base.inode_type] | header.base.mode;
	i.type = header.base.inode_type;
	i.time = sBlk.s.mkfs_time;
	i.inode_number = inode_number++;

	switch(header.base.inode_type) {
		case SQUASHFS_DIR_TYPE: {
			squashfs_dir_inode_header_2 *inode = &header.dir;

			if(swap) {
				squashfs_dir_inode_header_2 sinode;
				memcpy(&sinode, block_ptr, sizeof(header.dir));
				SQUASHFS_SWAP_DIR_INODE_HEADER_2(&header.dir,
					&sinode);
			} else
				memcpy(&header.dir, block_ptr,
					sizeof(header.dir));

			i.data = inode->file_size;
			i.offset = inode->offset;
			i.start = inode->start_block;
			i.time = inode->mtime;
			break;
		}
		case SQUASHFS_LDIR_TYPE: {
			squashfs_ldir_inode_header_2 *inode = &header.ldir;

			if(swap) {
				squashfs_ldir_inode_header_2 sinode;
				memcpy(&sinode, block_ptr, sizeof(header.ldir));
				SQUASHFS_SWAP_LDIR_INODE_HEADER_2(&header.ldir,
					&sinode);
			} else
				memcpy(&header.ldir, block_ptr,
					sizeof(header.ldir));

			i.data = inode->file_size;
			i.offset = inode->offset;
			i.start = inode->start_block;
			i.time = inode->mtime;
			break;
		}
		case SQUASHFS_FILE_TYPE: {
			squashfs_reg_inode_header_2 *inode = &header.reg;

			if(swap) {
				squashfs_reg_inode_header_2 sinode;
				memcpy(&sinode, block_ptr, sizeof(sinode));
				SQUASHFS_SWAP_REG_INODE_HEADER_2(inode,
					&sinode);
			} else
				memcpy(inode, block_ptr, sizeof(*inode));

			i.data = inode->file_size;
			i.time = inode->mtime;
			i.frag_bytes = inode->fragment == SQUASHFS_INVALID_FRAG
				?  0 : inode->file_size % sBlk.s.block_size;
			i.fragment = inode->fragment;
			i.offset = inode->offset;
			i.blocks = inode->fragment == SQUASHFS_INVALID_FRAG ?
				(i.data + sBlk.s.block_size - 1) >>
				sBlk.s.block_log : i.data >>
				sBlk.s.block_log;
			i.start = inode->start_block;
			i.sparse = 0;
			i.block_ptr = block_ptr + sizeof(*inode);
			break;
		}	
		case SQUASHFS_SYMLINK_TYPE: {
			squashfs_symlink_inode_header_2 *inodep =
				&header.symlink;

			if(swap) {
				squashfs_symlink_inode_header_2 sinodep;
				memcpy(&sinodep, block_ptr, sizeof(sinodep));
				SQUASHFS_SWAP_SYMLINK_INODE_HEADER_2(inodep,
					&sinodep);
			} else
				memcpy(inodep, block_ptr, sizeof(*inodep));

			i.symlink = malloc(inodep->symlink_size + 1);
			if(i.symlink == NULL)
				EXIT_UNSQUASH("read_inode: failed to malloc "
					"symlink data\n");
			strncpy(i.symlink, block_ptr +
				sizeof(squashfs_symlink_inode_header_2),
				inodep->symlink_size);
			i.symlink[inodep->symlink_size] = '\0';
			i.data = inodep->symlink_size;
			break;
		}
 		case SQUASHFS_BLKDEV_TYPE:
	 	case SQUASHFS_CHRDEV_TYPE: {
			squashfs_dev_inode_header_2 *inodep = &header.dev;

			if(swap) {
				squashfs_dev_inode_header_2 sinodep;
				memcpy(&sinodep, block_ptr, sizeof(sinodep));
				SQUASHFS_SWAP_DEV_INODE_HEADER_2(inodep,
					&sinodep);
			} else
				memcpy(inodep, block_ptr, sizeof(*inodep));

			i.data = inodep->rdev;
			break;
			}
		case SQUASHFS_FIFO_TYPE:
		case SQUASHFS_SOCKET_TYPE:
			i.data = 0;
			break;
		default:
			EXIT_UNSQUASH("Unknown inode type %d in "
				"read_inode_header_2!\n",
				header.base.inode_type);
	}
	return &i;
}
