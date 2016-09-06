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
 * unsquash-3.c
 */

#include "unsquashfs.h"
#include "squashfs_compat.h"

static squashfs_fragment_entry_3 *fragment_table;

int read_fragment_table_3()
{
	int res, i, indexes = SQUASHFS_FRAGMENT_INDEXES_3(sBlk.s.fragments);
	long long fragment_table_index[indexes];

	TRACE("read_fragment_table: %d fragments, reading %d fragment indexes "
		"from 0x%llx\n", sBlk.s.fragments, indexes,
		sBlk.s.fragment_table_start);

	if(sBlk.s.fragments == 0)
		return TRUE;

	fragment_table = malloc(sBlk.s.fragments *
		sizeof(squashfs_fragment_entry_3));
	if(fragment_table == NULL)
		EXIT_UNSQUASH("read_fragment_table: failed to allocate "
			"fragment table\n");

	if(swap) {
		long long sfragment_table_index[indexes];

		res = read_fs_bytes(fd, sBlk.s.fragment_table_start,
			SQUASHFS_FRAGMENT_INDEX_BYTES_3(sBlk.s.fragments),
			sfragment_table_index);
		if(res == FALSE) {
			ERROR("read_fragment_table: failed to read fragment "
				"table index\n");       
			return FALSE;
		}
		SQUASHFS_SWAP_FRAGMENT_INDEXES_3(fragment_table_index,
			sfragment_table_index, indexes);
	} else {
		res = read_fs_bytes(fd, sBlk.s.fragment_table_start,
			SQUASHFS_FRAGMENT_INDEX_BYTES_3(sBlk.s.fragments),
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
		TRACE("Read fragment table block %d, from 0x%llx, length %d\n",
			i, fragment_table_index[i], length);
		if(length == FALSE) {
			ERROR("read_fragment_table: failed to read fragment "
				"table block\n");       
			return FALSE;
		}
	}

	if(swap) {
		squashfs_fragment_entry_3 sfragment;
		for(i = 0; i < sBlk.s.fragments; i++) {
			SQUASHFS_SWAP_FRAGMENT_ENTRY_3((&sfragment),
				(&fragment_table[i]));
			memcpy((char *) &fragment_table[i], (char *) &sfragment,
				sizeof(squashfs_fragment_entry_3));
		}
	}

	return TRUE;
}


void read_fragment_3(unsigned int fragment, long long *start_block, int *size)
{
	TRACE("read_fragment: reading fragment %d\n", fragment);

	squashfs_fragment_entry_3 *fragment_entry = &fragment_table[fragment];
	*start_block = fragment_entry->start_block;
	*size = fragment_entry->size;
}


struct inode *read_inode_3(unsigned int start_block, unsigned int offset)
{
	static union squashfs_inode_header_3 header;
	long long start = sBlk.s.inode_table_start + start_block;
	int bytes = lookup_entry(inode_table_hash, start);
	char *block_ptr = inode_table + bytes + offset;
	static struct inode i;

	TRACE("read_inode: reading inode [%d:%d]\n", start_block,  offset);

	if(bytes == -1)
		EXIT_UNSQUASH("read_inode: inode table block %lld not found\n",
			start); 

	if(swap) {
		squashfs_base_inode_header_3 sinode;
		memcpy(&sinode, block_ptr, sizeof(header.base));
		SQUASHFS_SWAP_BASE_INODE_HEADER_3(&header.base, &sinode,
			sizeof(squashfs_base_inode_header_3));
	} else
		memcpy(&header.base, block_ptr, sizeof(header.base));

	i.xattr = SQUASHFS_INVALID_XATTR;
	i.uid = (uid_t) uid_table[header.base.uid];
	i.gid = header.base.guid == SQUASHFS_GUIDS ? i.uid :
		(uid_t) guid_table[header.base.guid];
	i.mode = lookup_type[header.base.inode_type] | header.base.mode;
	i.type = header.base.inode_type;
	i.time = header.base.mtime;
	i.inode_number = header.base.inode_number;

	switch(header.base.inode_type) {
		case SQUASHFS_DIR_TYPE: {
			squashfs_dir_inode_header_3 *inode = &header.dir;

			if(swap) {
				squashfs_dir_inode_header_3 sinode;
				memcpy(&sinode, block_ptr, sizeof(header.dir));
				SQUASHFS_SWAP_DIR_INODE_HEADER_3(&header.dir,
					&sinode);
			} else
				memcpy(&header.dir, block_ptr,
					sizeof(header.dir));

			i.data = inode->file_size;
			i.offset = inode->offset;
			i.start = inode->start_block;
			break;
		}
		case SQUASHFS_LDIR_TYPE: {
			squashfs_ldir_inode_header_3 *inode = &header.ldir;

			if(swap) {
				squashfs_ldir_inode_header_3 sinode;
				memcpy(&sinode, block_ptr, sizeof(header.ldir));
				SQUASHFS_SWAP_LDIR_INODE_HEADER_3(&header.ldir,
					&sinode);
			} else
				memcpy(&header.ldir, block_ptr,
					sizeof(header.ldir));

			i.data = inode->file_size;
			i.offset = inode->offset;
			i.start = inode->start_block;
			break;
		}
		case SQUASHFS_FILE_TYPE: {
			squashfs_reg_inode_header_3 *inode = &header.reg;

			if(swap) {
				squashfs_reg_inode_header_3 sinode;
				memcpy(&sinode, block_ptr, sizeof(sinode));
				SQUASHFS_SWAP_REG_INODE_HEADER_3(inode,
					&sinode);
			} else
				memcpy(inode, block_ptr, sizeof(*inode));

			i.data = inode->file_size;
			i.frag_bytes = inode->fragment == SQUASHFS_INVALID_FRAG
				?  0 : inode->file_size % sBlk.s.block_size;
			i.fragment = inode->fragment;
			i.offset = inode->offset;
			i.blocks = inode->fragment == SQUASHFS_INVALID_FRAG ?
				(i.data + sBlk.s.block_size - 1) >>
				sBlk.s.block_log :
				i.data >> sBlk.s.block_log;
			i.start = inode->start_block;
			i.sparse = 1;
			i.block_ptr = block_ptr + sizeof(*inode);
			break;
		}	
		case SQUASHFS_LREG_TYPE: {
			squashfs_lreg_inode_header_3 *inode = &header.lreg;

			if(swap) {
				squashfs_lreg_inode_header_3 sinode;
				memcpy(&sinode, block_ptr, sizeof(sinode));
				SQUASHFS_SWAP_LREG_INODE_HEADER_3(inode,
					&sinode);
			} else
				memcpy(inode, block_ptr, sizeof(*inode));

			i.data = inode->file_size;
			i.frag_bytes = inode->fragment == SQUASHFS_INVALID_FRAG
				?  0 : inode->file_size % sBlk.s.block_size;
			i.fragment = inode->fragment;
			i.offset = inode->offset;
			i.blocks = inode->fragment == SQUASHFS_INVALID_FRAG ?
				(inode->file_size + sBlk.s.block_size - 1) >>
				sBlk.s.block_log :
				inode->file_size >> sBlk.s.block_log;
			i.start = inode->start_block;
			i.sparse = 1;
			i.block_ptr = block_ptr + sizeof(*inode);
			break;
		}	
		case SQUASHFS_SYMLINK_TYPE: {
			squashfs_symlink_inode_header_3 *inodep =
				&header.symlink;

			if(swap) {
				squashfs_symlink_inode_header_3 sinodep;
				memcpy(&sinodep, block_ptr, sizeof(sinodep));
				SQUASHFS_SWAP_SYMLINK_INODE_HEADER_3(inodep,
					&sinodep);
			} else
				memcpy(inodep, block_ptr, sizeof(*inodep));

			i.symlink = malloc(inodep->symlink_size + 1);
			if(i.symlink == NULL)
				EXIT_UNSQUASH("read_inode: failed to malloc "
					"symlink data\n");
			strncpy(i.symlink, block_ptr +
				sizeof(squashfs_symlink_inode_header_3),
				inodep->symlink_size);
			i.symlink[inodep->symlink_size] = '\0';
			i.data = inodep->symlink_size;
			break;
		}
 		case SQUASHFS_BLKDEV_TYPE:
	 	case SQUASHFS_CHRDEV_TYPE: {
			squashfs_dev_inode_header_3 *inodep = &header.dev;

			if(swap) {
				squashfs_dev_inode_header_3 sinodep;
				memcpy(&sinodep, block_ptr, sizeof(sinodep));
				SQUASHFS_SWAP_DEV_INODE_HEADER_3(inodep,
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
			EXIT_UNSQUASH("Unknown inode type %d in read_inode!\n",
				header.base.inode_type);
	}
	return &i;
}


struct dir *squashfs_opendir_3(unsigned int block_start, unsigned int offset,
	struct inode **i)
{
	squashfs_dir_header_3 dirh;
	char buffer[sizeof(squashfs_dir_entry_3) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	squashfs_dir_entry_3 *dire = (squashfs_dir_entry_3 *) buffer;
	long long start;
	int bytes;
	int dir_count, size;
	struct dir_ent *new_dir;
	struct dir *dir;

	TRACE("squashfs_opendir: inode start block %d, offset %d\n",
		block_start, offset);

	*i = s_ops.read_inode(block_start, offset);

	dir = malloc(sizeof(struct dir));
	if(dir == NULL)
		EXIT_UNSQUASH("squashfs_opendir: malloc failed!\n");

	dir->dir_count = 0;
	dir->cur_entry = 0;
	dir->mode = (*i)->mode;
	dir->uid = (*i)->uid;
	dir->guid = (*i)->gid;
	dir->mtime = (*i)->time;
	dir->xattr = (*i)->xattr;
	dir->dirs = NULL;

	if ((*i)->data == 3)
		/*
		 * if the directory is empty, skip the unnecessary
		 * lookup_entry, this fixes the corner case with
		 * completely empty filesystems where lookup_entry correctly
		 * returning -1 is incorrectly treated as an error
		 */
		return dir;

	start = sBlk.s.directory_table_start + (*i)->start;
	bytes = lookup_entry(directory_table_hash, start);

	if(bytes == -1)
		EXIT_UNSQUASH("squashfs_opendir: directory block %d not "
			"found!\n", block_start);

	bytes += (*i)->offset;
	size = (*i)->data + bytes - 3;

	while(bytes < size) {			
		if(swap) {
			squashfs_dir_header_3 sdirh;
			memcpy(&sdirh, directory_table + bytes, sizeof(sdirh));
			SQUASHFS_SWAP_DIR_HEADER_3(&dirh, &sdirh);
		} else
			memcpy(&dirh, directory_table + bytes, sizeof(dirh));
	
		dir_count = dirh.count + 1;
		TRACE("squashfs_opendir: Read directory header @ byte position "
			"%d, %d directory entries\n", bytes, dir_count);
		bytes += sizeof(dirh);

		/* dir_count should never be larger than 256 */
		if(dir_count > 256)
			goto corrupted;

		while(dir_count--) {
			if(swap) {
				squashfs_dir_entry_3 sdire;
				memcpy(&sdire, directory_table + bytes,
					sizeof(sdire));
				SQUASHFS_SWAP_DIR_ENTRY_3(dire, &sdire);
			} else
				memcpy(dire, directory_table + bytes,
					sizeof(*dire));
			bytes += sizeof(*dire);

			/* size should never be larger than SQUASHFS_NAME_LEN */
			if(dire->size > SQUASHFS_NAME_LEN)
				goto corrupted;

			memcpy(dire->name, directory_table + bytes,
				dire->size + 1);
			dire->name[dire->size + 1] = '\0';
			TRACE("squashfs_opendir: directory entry %s, inode "
				"%d:%d, type %d\n", dire->name,
				dirh.start_block, dire->offset, dire->type);
			if((dir->dir_count % DIR_ENT_SIZE) == 0) {
				new_dir = realloc(dir->dirs, (dir->dir_count +
					DIR_ENT_SIZE) * sizeof(struct dir_ent));
				if(new_dir == NULL)
					EXIT_UNSQUASH("squashfs_opendir: "
						"realloc failed!\n");
				dir->dirs = new_dir;
			}
			strcpy(dir->dirs[dir->dir_count].name, dire->name);
			dir->dirs[dir->dir_count].start_block =
				dirh.start_block;
			dir->dirs[dir->dir_count].offset = dire->offset;
			dir->dirs[dir->dir_count].type = dire->type;
			dir->dir_count ++;
			bytes += dire->size + 1;
		}
	}

	return dir;

corrupted:
	free(dir->dirs);
	free(dir);
	return NULL;
}
