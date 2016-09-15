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
 * unsquash-1.c
 */

#include "unsquashfs.h"
#include "squashfs_compat.h"

void read_block_list_1(unsigned int *block_list, char *block_ptr, int blocks)
{
	unsigned short block_size;
	int i;

	TRACE("read_block_list: blocks %d\n", blocks);

	for(i = 0; i < blocks; i++, block_ptr += 2) {
		if(swap) {
			unsigned short sblock_size;
			memcpy(&sblock_size, block_ptr, sizeof(unsigned short));
			SQUASHFS_SWAP_SHORTS_3((&block_size), &sblock_size, 1);
		} else
			memcpy(&block_size, block_ptr, sizeof(unsigned short));
		block_list[i] = SQUASHFS_COMPRESSED_SIZE(block_size) |
			(SQUASHFS_COMPRESSED(block_size) ? 0 :
			SQUASHFS_COMPRESSED_BIT_BLOCK);
	}
}


int read_fragment_table_1()
{
	TRACE("read_fragment_table\n");
	return TRUE;
}


struct inode *read_inode_1(unsigned int start_block, unsigned int offset)
{
	static union squashfs_inode_header_1 header;
	long long start = sBlk.s.inode_table_start + start_block;
	int bytes = lookup_entry(inode_table_hash, start);
	char *block_ptr = inode_table + bytes + offset;
	static struct inode i;

	TRACE("read_inode: reading inode [%d:%d]\n", start_block,  offset);

	if(bytes == -1)
		EXIT_UNSQUASH("read_inode: inode table block %lld not found\n",
			 start); 

	if(swap) {
		squashfs_base_inode_header_1 sinode;
		memcpy(&sinode, block_ptr, sizeof(header.base));
		SQUASHFS_SWAP_BASE_INODE_HEADER_1(&header.base, &sinode,
			sizeof(squashfs_base_inode_header_1));
	} else
		memcpy(&header.base, block_ptr, sizeof(header.base));

	i.uid = (uid_t) uid_table[(header.base.inode_type - 1) /
		SQUASHFS_TYPES * 16 + header.base.uid];
	if(header.base.inode_type == SQUASHFS_IPC_TYPE) {
		squashfs_ipc_inode_header_1 *inodep = &header.ipc;

		if(swap) {
			squashfs_ipc_inode_header_1 sinodep;
			memcpy(&sinodep, block_ptr, sizeof(sinodep));
			SQUASHFS_SWAP_IPC_INODE_HEADER_1(inodep, &sinodep);
		} else
			memcpy(inodep, block_ptr, sizeof(*inodep));

		if(inodep->type == SQUASHFS_SOCKET_TYPE) {
			i.mode = S_IFSOCK | header.base.mode;
			i.type = SQUASHFS_SOCKET_TYPE;
		} else {
			i.mode = S_IFIFO | header.base.mode;
			i.type = SQUASHFS_FIFO_TYPE;
		}
		i.uid = (uid_t) uid_table[inodep->offset * 16 + inodep->uid];
	} else {
		i.mode = lookup_type[(header.base.inode_type - 1) %
			SQUASHFS_TYPES + 1] | header.base.mode;
		i.type = (header.base.inode_type - 1) % SQUASHFS_TYPES + 1;
	}

	i.xattr = SQUASHFS_INVALID_XATTR;
	i.gid = header.base.guid == 15 ? i.uid :
		(uid_t) guid_table[header.base.guid];
	i.time = sBlk.s.mkfs_time;
	i.inode_number = inode_number ++;

	switch(i.type) {
		case SQUASHFS_DIR_TYPE: {
			squashfs_dir_inode_header_1 *inode = &header.dir;

			if(swap) {
				squashfs_dir_inode_header_1 sinode;
				memcpy(&sinode, block_ptr, sizeof(header.dir));
				SQUASHFS_SWAP_DIR_INODE_HEADER_1(inode,
					&sinode);
			} else
			memcpy(inode, block_ptr, sizeof(header.dir));

			i.data = inode->file_size;
			i.offset = inode->offset;
			i.start = inode->start_block;
			i.time = inode->mtime;
			break;
		}
		case SQUASHFS_FILE_TYPE: {
			squashfs_reg_inode_header_1 *inode = &header.reg;

			if(swap) {
				squashfs_reg_inode_header_1 sinode;
				memcpy(&sinode, block_ptr, sizeof(sinode));
				SQUASHFS_SWAP_REG_INODE_HEADER_1(inode,
					&sinode);
			} else
				memcpy(inode, block_ptr, sizeof(*inode));

			i.data = inode->file_size;
			i.time = inode->mtime;
			i.blocks = (i.data + sBlk.s.block_size - 1) >>
				sBlk.s.block_log;
			i.start = inode->start_block;
			i.block_ptr = block_ptr + sizeof(*inode);
			i.fragment = 0;
			i.frag_bytes = 0;
			i.offset = 0;
			i.sparse = 0;
			break;
		}	
		case SQUASHFS_SYMLINK_TYPE: {
			squashfs_symlink_inode_header_1 *inodep =
				&header.symlink;

			if(swap) {
				squashfs_symlink_inode_header_1 sinodep;
				memcpy(&sinodep, block_ptr, sizeof(sinodep));
				SQUASHFS_SWAP_SYMLINK_INODE_HEADER_1(inodep,
					&sinodep);
			} else
				memcpy(inodep, block_ptr, sizeof(*inodep));

			i.symlink = malloc(inodep->symlink_size + 1);
			if(i.symlink == NULL)
				EXIT_UNSQUASH("read_inode: failed to malloc "
					"symlink data\n");
			strncpy(i.symlink, block_ptr +
				sizeof(squashfs_symlink_inode_header_1),
				inodep->symlink_size);
			i.symlink[inodep->symlink_size] = '\0';
			i.data = inodep->symlink_size;
			break;
		}
 		case SQUASHFS_BLKDEV_TYPE:
	 	case SQUASHFS_CHRDEV_TYPE: {
			squashfs_dev_inode_header_1 *inodep = &header.dev;

			if(swap) {
				squashfs_dev_inode_header_1 sinodep;
				memcpy(&sinodep, block_ptr, sizeof(sinodep));
				SQUASHFS_SWAP_DEV_INODE_HEADER_1(inodep,
					&sinodep);
			} else
				memcpy(inodep, block_ptr, sizeof(*inodep));

			i.data = inodep->rdev;
			break;
			}
		case SQUASHFS_FIFO_TYPE:
		case SQUASHFS_SOCKET_TYPE: {
			i.data = 0;
			break;
			}
		default:
			EXIT_UNSQUASH("Unknown inode type %d in "
				" read_inode_header_1!\n",
				header.base.inode_type);
	}
	return &i;
}


struct dir *squashfs_opendir_1(unsigned int block_start, unsigned int offset,
	struct inode **i)
{
	squashfs_dir_header_2 dirh;
	char buffer[sizeof(squashfs_dir_entry_2) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	squashfs_dir_entry_2 *dire = (squashfs_dir_entry_2 *) buffer;
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

	if ((*i)->data == 0)
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
	size = (*i)->data + bytes;

	while(bytes < size) {			
		if(swap) {
			squashfs_dir_header_2 sdirh;
			memcpy(&sdirh, directory_table + bytes, sizeof(sdirh));
			SQUASHFS_SWAP_DIR_HEADER_2(&dirh, &sdirh);
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
				squashfs_dir_entry_2 sdire;
				memcpy(&sdire, directory_table + bytes,
					sizeof(sdire));
				SQUASHFS_SWAP_DIR_ENTRY_2(dire, &sdire);
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


int read_uids_guids_1()
{
	int res;

	TRACE("read_uids_guids: no_uids %d, no_guids %d\n", sBlk.no_uids,
		sBlk.no_guids);

	uid_table = malloc((sBlk.no_uids + sBlk.no_guids) *
		sizeof(unsigned int));
	if(uid_table == NULL) {
		ERROR("read_uids_guids: failed to allocate uid/gid table\n");
		return FALSE;
	}

	guid_table = uid_table + sBlk.no_uids;

	if(swap) {
		unsigned int suid_table[sBlk.no_uids + sBlk.no_guids];

		res = read_fs_bytes(fd, sBlk.uid_start, (sBlk.no_uids +
			sBlk.no_guids) * sizeof(unsigned int), suid_table);
		if(res == FALSE) {
			ERROR("read_uids_guids: failed to read uid/gid table"
				"\n");
			return FALSE;
		}
		SQUASHFS_SWAP_INTS_3(uid_table, suid_table,
			sBlk.no_uids + sBlk.no_guids);
	} else {
		res = read_fs_bytes(fd, sBlk.uid_start, (sBlk.no_uids +
			sBlk.no_guids) * sizeof(unsigned int), uid_table);
		if(res == FALSE) {
			ERROR("read_uids_guids: failed to read uid/gid table"
				"\n");
			return FALSE;
		}
	}

	return TRUE;
}
