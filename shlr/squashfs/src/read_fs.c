/*
 * Read a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
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
 * read_fs.c
 */

#define TRUE 1
#define FALSE 0
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#ifndef linux
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif

#include <stdlib.h>

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...) \
		do { \
			printf("mksquashfs: "s, ## args); \
		} while(0)
#else
#define TRACE(s, args...)
#endif

#define ERROR(s, args...) \
		do { \
			fprintf(stderr, s, ## args); \
		} while(0)

#include "squashfs_fs.h"
#include "squashfs_swap.h"
#include "read_fs.h"
#include "compressor.h"
#include "xattr.h"

extern int read_fs_bytes(int, long long, int, void *);
extern int add_file(long long, long long, long long, unsigned int *, int,
	unsigned int, int, int);
extern void *create_id(unsigned int);
extern unsigned int get_uid(unsigned int);
extern unsigned int get_guid(unsigned int);

static struct compressor *comp;

int read_block(int fd, long long start, long long *next, void *block)
{
	unsigned short c_byte;
	int res;
	
	res = read_fs_bytes(fd, start, 2, &c_byte);
	if(res == 0)
		return 0;

	SQUASHFS_INSWAP_SHORTS(&c_byte, 1);

	if(SQUASHFS_COMPRESSED(c_byte)) {
		char buffer[SQUASHFS_METADATA_SIZE];
		int error, res;

		c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte);
		res = read_fs_bytes(fd, start + 2, c_byte, buffer);
		if(res == 0)
			return 0;

		res = compressor_uncompress(comp, block, buffer, c_byte,
			SQUASHFS_METADATA_SIZE, &error);
		if(res == -1) {
			ERROR("%s uncompress failed with error code %d\n",
				comp->name, error);
			return 0;
		}
		if(next)
			*next = start + 2 + c_byte;
		return res;
	} else {
		c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte);
		res = read_fs_bytes(fd, start + 2, c_byte, block);
		if(res == 0)
			return 0;

		if(next)
			*next = start + 2 + c_byte;
		return c_byte;
	}
}


int scan_inode_table(int fd, long long start, long long end,
	long long root_inode_start, int root_inode_offset,
	struct squashfs_super_block *sBlk, union squashfs_inode_header *dir_inode,
	unsigned char **inode_table, unsigned int *root_inode_block,
	unsigned int *root_inode_size, long long *uncompressed_file,
	unsigned int *uncompressed_directory, int *file_count, int *sym_count,
	int *dev_count, int *dir_count, int *fifo_count, int *sock_count,
	unsigned int *id_table)
{
	unsigned char *cur_ptr;
	int byte, bytes = 0, size = 0, files = 0;
	struct squashfs_reg_inode_header inode;
	unsigned int directory_start_block;

	TRACE("scan_inode_table: start 0x%llx, end 0x%llx, root_inode_start "
		"0x%llx\n", start, end, root_inode_start);

	while(start < end) {
		if(start == root_inode_start) {
			TRACE("scan_inode_table: read compressed block 0x%llx "
				"containing root inode\n", start);
			*root_inode_block = bytes;
		}
		if(size - bytes < SQUASHFS_METADATA_SIZE) {
			*inode_table = realloc(*inode_table, size
				+= SQUASHFS_METADATA_SIZE);
			if(*inode_table == NULL)
				return FALSE;
		}
		TRACE("scan_inode_table: reading block 0x%llx\n", start);
		byte = read_block(fd, start, &start, *inode_table + bytes);
		if(byte == 0) {
			free(*inode_table);
			return FALSE;
		}
		bytes += byte;
	}

	/*
	 * Read last inode entry which is the root directory inode, and obtain
	 * the last directory start block index.  This is used when calculating
	 * the total uncompressed directory size.  The directory bytes in the
	 * last * block will be counted as normal.
	 *
	 * The root inode is ignored in the inode scan.  This ensures there is
	 * always enough bytes left to read a regular file inode entry
	 */
	*root_inode_size = bytes - (*root_inode_block + root_inode_offset);
	bytes = *root_inode_block + root_inode_offset;
	SQUASHFS_SWAP_BASE_INODE_HEADER(&dir_inode->base, *inode_table + bytes);
	if(dir_inode->base.inode_type == SQUASHFS_DIR_TYPE) {
		SQUASHFS_SWAP_DIR_INODE_HEADER(&dir_inode->dir,
			*inode_table + bytes);
		directory_start_block = dir_inode->dir.start_block;
	} else {
		SQUASHFS_SWAP_LDIR_INODE_HEADER(&dir_inode->ldir,
			*inode_table + bytes);
		directory_start_block = dir_inode->ldir.start_block;
	}
	get_uid(id_table[dir_inode->base.uid]);
	get_guid(id_table[dir_inode->base.guid]);

	for(cur_ptr = *inode_table; cur_ptr < *inode_table + bytes; files ++) {
		SQUASHFS_SWAP_REG_INODE_HEADER(&inode, cur_ptr);

		TRACE("scan_inode_table: processing inode @ byte position "
			"0x%x, type 0x%x\n",
			(unsigned int) (cur_ptr - *inode_table),
			inode.inode_type);

		get_uid(id_table[inode.uid]);
		get_guid(id_table[inode.guid]);

		switch(inode.inode_type) {
			case SQUASHFS_FILE_TYPE: {
				int frag_bytes = inode.fragment ==
					SQUASHFS_INVALID_FRAG ? 0 :
					inode.file_size % sBlk->block_size;
				int blocks = inode.fragment ==
					SQUASHFS_INVALID_FRAG ? (inode.file_size
					+ sBlk->block_size - 1) >>
					sBlk->block_log : inode.file_size >>
					sBlk->block_log;
				long long file_bytes = 0;
				int i;
				long long start = inode.start_block;
				unsigned int *block_list;

				TRACE("scan_inode_table: regular file, "
					"file_size %d, blocks %d\n",
					inode.file_size, blocks);

				block_list = malloc(blocks *
					sizeof(unsigned int));
				if(block_list == NULL) {
					ERROR("Out of memory in block list "
						"malloc\n");
					goto failed;
				}

				cur_ptr += sizeof(inode);
				SQUASHFS_SWAP_INTS(block_list, cur_ptr, blocks);

				*uncompressed_file += inode.file_size;
				(*file_count) ++;

				for(i = 0; i < blocks; i++)
					file_bytes +=
						SQUASHFS_COMPRESSED_SIZE_BLOCK
						(block_list[i]);

	                        add_file(start, inode.file_size, file_bytes,
					block_list, blocks, inode.fragment,
					inode.offset, frag_bytes);
				cur_ptr += blocks * sizeof(unsigned int);
				break;
			}	
			case SQUASHFS_LREG_TYPE: {
				struct squashfs_lreg_inode_header inode;
				int frag_bytes;
				int blocks;
				long long file_bytes = 0;
				int i;
				long long start;
				unsigned int *block_list;

				SQUASHFS_SWAP_LREG_INODE_HEADER(&inode, cur_ptr);

				frag_bytes = inode.fragment ==
					SQUASHFS_INVALID_FRAG ? 0 :
					inode.file_size % sBlk->block_size;
				blocks = inode.fragment == SQUASHFS_INVALID_FRAG
					?  (inode.file_size +
					sBlk->block_size - 1) >>
					sBlk->block_log : inode.file_size >>
					sBlk->block_log;
				start = inode.start_block;

				TRACE("scan_inode_table: extended regular "
					"file, file_size %lld, blocks %d\n",
					inode.file_size, blocks);

				block_list = malloc(blocks *
					sizeof(unsigned int));
				if(block_list == NULL) {
					ERROR("Out of memory in block list "
						"malloc\n");
					goto failed;
				}

				cur_ptr += sizeof(inode);
				SQUASHFS_SWAP_INTS(block_list, cur_ptr, blocks);

				*uncompressed_file += inode.file_size;
				(*file_count) ++;

				for(i = 0; i < blocks; i++)
					file_bytes +=
						SQUASHFS_COMPRESSED_SIZE_BLOCK
						(block_list[i]);

	                        add_file(start, inode.file_size, file_bytes,
					block_list, blocks, inode.fragment,
					inode.offset, frag_bytes);
				cur_ptr += blocks * sizeof(unsigned int);
				break;
			}	
			case SQUASHFS_SYMLINK_TYPE:
			case SQUASHFS_LSYMLINK_TYPE: {
				struct squashfs_symlink_inode_header inodep;
	
				SQUASHFS_SWAP_SYMLINK_INODE_HEADER(&inodep,
					cur_ptr);
				(*sym_count) ++;
				cur_ptr += sizeof(inodep) + inodep.symlink_size;

				if (inode.inode_type == SQUASHFS_LSYMLINK_TYPE)
					cur_ptr += sizeof(unsigned int);

				break;
			}
			case SQUASHFS_DIR_TYPE: {
				struct squashfs_dir_inode_header dir_inode;

				SQUASHFS_SWAP_DIR_INODE_HEADER(&dir_inode,
					cur_ptr);
				if(dir_inode.start_block < directory_start_block)
					*uncompressed_directory +=
					dir_inode.file_size;
				(*dir_count) ++;
				cur_ptr += sizeof(struct squashfs_dir_inode_header);
				break;
			}
			case SQUASHFS_LDIR_TYPE: {
				struct squashfs_ldir_inode_header dir_inode;
				int i;

				SQUASHFS_SWAP_LDIR_INODE_HEADER(&dir_inode,
					cur_ptr);
				if(dir_inode.start_block < directory_start_block)
					*uncompressed_directory +=
					dir_inode.file_size;
				(*dir_count) ++;
				cur_ptr += sizeof(struct squashfs_ldir_inode_header);
				for(i = 0; i < dir_inode.i_count; i++) {
					struct squashfs_dir_index index;

					SQUASHFS_SWAP_DIR_INDEX(&index,
						cur_ptr);
					cur_ptr += sizeof(struct squashfs_dir_index) +
						index.size + 1;
				}
				break;
			}
		 	case SQUASHFS_BLKDEV_TYPE:
		 	case SQUASHFS_CHRDEV_TYPE:
				(*dev_count) ++;
				cur_ptr += sizeof(struct squashfs_dev_inode_header);
				break;
		 	case SQUASHFS_LBLKDEV_TYPE:
		 	case SQUASHFS_LCHRDEV_TYPE:
				(*dev_count) ++;
				cur_ptr += sizeof(struct squashfs_ldev_inode_header);
				break;
			case SQUASHFS_FIFO_TYPE:
				(*fifo_count) ++;
				cur_ptr += sizeof(struct squashfs_ipc_inode_header);
				break;
			case SQUASHFS_LFIFO_TYPE:
				(*fifo_count) ++;
				cur_ptr += sizeof(struct squashfs_lipc_inode_header);
				break;
			case SQUASHFS_SOCKET_TYPE:
				(*sock_count) ++;
				cur_ptr += sizeof(struct squashfs_ipc_inode_header);
				break;
			case SQUASHFS_LSOCKET_TYPE:
				(*sock_count) ++;
				cur_ptr += sizeof(struct squashfs_lipc_inode_header);
				break;
		 	default:
				ERROR("Unknown inode type %d in "
					"scan_inode_table!\n",
					inode.inode_type);
				goto failed;
		}
	}
	
	printf("Read existing filesystem, %d inodes scanned\n", files);
	return TRUE;


failed:
	free(*inode_table);
	return FALSE;
}


struct compressor *read_super(int fd, struct squashfs_super_block *sBlk, char *source)
{
	int res, bytes = 0;
	char buffer[SQUASHFS_METADATA_SIZE] __attribute__ ((aligned));

	res = read_fs_bytes(fd, SQUASHFS_START, sizeof(struct squashfs_super_block),
		sBlk);
	if(res == 0)
		goto failed_mount;

	SQUASHFS_INSWAP_SUPER_BLOCK(sBlk);

	if(sBlk->s_magic != SQUASHFS_MAGIC) {
		if(sBlk->s_magic == SQUASHFS_MAGIC_SWAP)
			ERROR("Pre 4.0 big-endian filesystem on %s, appending"
				" to this is unsupported\n", source);
		else
			ERROR("Can't find a SQUASHFS superblock on %s\n",
				source);
		goto failed_mount;
	}

	/* Check the MAJOR & MINOR versions */
	if(sBlk->s_major != SQUASHFS_MAJOR || sBlk->s_minor > SQUASHFS_MINOR) {
		if(sBlk->s_major < 4)
			ERROR("Filesystem on %s is a SQUASHFS %d.%d filesystem."
				"  Appending\nto SQUASHFS %d.%d filesystems is "
				"not supported.  Please convert it to a "
				"SQUASHFS 4 filesystem\n", source,
				sBlk->s_major,
				sBlk->s_minor, sBlk->s_major, sBlk->s_minor);
		else
			ERROR("Filesystem on %s is %d.%d, which is a later "
				"filesystem version than I support\n",
				source, sBlk->s_major, sBlk->s_minor);
		goto failed_mount;
	}

	/* Check the compression type */
	comp = lookup_compressor_id(sBlk->compression);
	if(!comp->supported) {
		ERROR("Filesystem on %s uses %s compression, this is"
			"unsupported by this version\n", source, comp->name);
		ERROR("Compressors available:\n");
		display_compressors("", "");
		goto failed_mount;
	}

	/*
	 * Read extended superblock information from disk.
	 *
	 * Read compressor specific options from disk if present, and pass
	 * to compressor to set compressor options.
	 *
	 * Note, if there's no compressor options present, the compressor
	 * is still called to set the default options (the defaults may have
	 * been changed by the user specifying options on the command
	 * line which need to be over-ridden).
	 */
	if(SQUASHFS_COMP_OPTS(sBlk->flags)) {
		bytes = read_block(fd, sizeof(*sBlk), NULL, buffer);

		if(bytes == 0)
			goto failed_mount;
	}

	res = compressor_extract_options(comp, sBlk->block_size, buffer, bytes);
	if(res == -1) {
		ERROR("Compressor failed to set compressor options\n");
		goto failed_mount;
	}

	printf("Found a valid %sSQUASHFS superblock on %s.\n",
		SQUASHFS_EXPORTABLE(sBlk->flags) ? "exportable " : "", source);
	printf("\tCompression used %s\n", comp->name);
	printf("\tInodes are %scompressed\n",
		SQUASHFS_UNCOMPRESSED_INODES(sBlk->flags) ? "un" : "");
	printf("\tData is %scompressed\n",
		SQUASHFS_UNCOMPRESSED_DATA(sBlk->flags) ? "un" : "");
	printf("\tFragments are %scompressed\n",
		SQUASHFS_UNCOMPRESSED_FRAGMENTS(sBlk->flags) ? "un" : "");
	printf("\tXattrs are %scompressed\n",
		SQUASHFS_UNCOMPRESSED_XATTRS(sBlk->flags) ? "un" : "");
	printf("\tFragments are %spresent in the filesystem\n",
		SQUASHFS_NO_FRAGMENTS(sBlk->flags) ? "not " : "");
	printf("\tAlways_use_fragments option is %sspecified\n",
		SQUASHFS_ALWAYS_FRAGMENTS(sBlk->flags) ? "" : "not ");
	printf("\tDuplicates are %sremoved\n",
		SQUASHFS_DUPLICATES(sBlk->flags) ? "" : "not ");
	printf("\tXattrs are %sstored\n",
		SQUASHFS_NO_XATTRS(sBlk->flags) ? "not " : "");
	printf("\tFilesystem size %.2f Kbytes (%.2f Mbytes)\n",
		sBlk->bytes_used / 1024.0, sBlk->bytes_used
		/ (1024.0 * 1024.0));
	printf("\tBlock size %d\n", sBlk->block_size);
	printf("\tNumber of fragments %d\n", sBlk->fragments);
	printf("\tNumber of inodes %d\n", sBlk->inodes);
	printf("\tNumber of ids %d\n", sBlk->no_ids);
	TRACE("sBlk->inode_table_start %llx\n", sBlk->inode_table_start);
	TRACE("sBlk->directory_table_start %llx\n",
		sBlk->directory_table_start);
	TRACE("sBlk->id_table_start %llx\n", sBlk->id_table_start);
	TRACE("sBlk->fragment_table_start %llx\n", sBlk->fragment_table_start);
	TRACE("sBlk->lookup_table_start %llx\n", sBlk->lookup_table_start);
	TRACE("sBlk->xattr_id_table_start %llx\n", sBlk->xattr_id_table_start);
	printf("\n");

	return comp;

failed_mount:
	return NULL;
}


unsigned char *squashfs_readdir(int fd, int root_entries,
	unsigned int directory_start_block, int offset, int size,
	unsigned int *last_directory_block, struct squashfs_super_block *sBlk,
	void (push_directory_entry)(char *, squashfs_inode, int, int))
{
	struct squashfs_dir_header dirh;
	char buffer[sizeof(struct squashfs_dir_entry) + SQUASHFS_NAME_LEN + 1]
		__attribute__ ((aligned));
	struct squashfs_dir_entry *dire = (struct squashfs_dir_entry *) buffer;
	unsigned char *directory_table = NULL;
	int byte, bytes = 0, dir_count;
	long long start = sBlk->directory_table_start + directory_start_block,
		last_start_block = start; 

	size += offset;
	directory_table = malloc((size + SQUASHFS_METADATA_SIZE * 2 - 1) &
		~(SQUASHFS_METADATA_SIZE - 1));
	if(directory_table == NULL)
		return NULL;
	while(bytes < size) {
		TRACE("squashfs_readdir: reading block 0x%llx, bytes read so "
			"far %d\n", start, bytes);
		last_start_block = start;
		byte = read_block(fd, start, &start, directory_table + bytes);
		if(byte == 0) {
			free(directory_table);
			return NULL;
		}
		bytes += byte;
	}

	if(!root_entries)
		goto all_done;

	bytes = offset;
 	while(bytes < size) {			
		SQUASHFS_SWAP_DIR_HEADER(&dirh, directory_table + bytes);

		dir_count = dirh.count + 1;
		TRACE("squashfs_readdir: Read directory header @ byte position "
			"0x%x, 0x%x directory entries\n", bytes, dir_count);
		bytes += sizeof(dirh);

		while(dir_count--) {
			SQUASHFS_SWAP_DIR_ENTRY(dire, directory_table + bytes);
			bytes += sizeof(*dire);

			memcpy(dire->name, directory_table + bytes,
				dire->size + 1);
			dire->name[dire->size + 1] = '\0';
			TRACE("squashfs_readdir: pushing directory entry %s, "
				"inode %x:%x, type 0x%x\n", dire->name,
				dirh.start_block, dire->offset, dire->type);
			push_directory_entry(dire->name,
				SQUASHFS_MKINODE(dirh.start_block,
				dire->offset), dirh.inode_number +
				dire->inode_number, dire->type);
			bytes += dire->size + 1;
		}
	}

all_done:
	*last_directory_block = (unsigned int) last_start_block -
		sBlk->directory_table_start;
	return directory_table;
}


unsigned int *read_id_table(int fd, struct squashfs_super_block *sBlk)
{
	int indexes = SQUASHFS_ID_BLOCKS(sBlk->no_ids);
	long long index[indexes];
	int bytes = SQUASHFS_ID_BYTES(sBlk->no_ids);
	unsigned int *id_table;
	int res, i;

	id_table = malloc(bytes);
	if(id_table == NULL) {
		ERROR("Failed to allocate id table\n");
		return NULL;
	}

	res = read_fs_bytes(fd, sBlk->id_table_start,
		SQUASHFS_ID_BLOCK_BYTES(sBlk->no_ids), index);
	if(res == 0) {
		free(id_table);
		return NULL;
	}

	SQUASHFS_INSWAP_ID_BLOCKS(index, indexes);

	for(i = 0; i < indexes; i++) {
		int length = read_block(fd, index[i], NULL,
			((unsigned char *) id_table) +
			(i * SQUASHFS_METADATA_SIZE));
		TRACE("Read id table block %d, from 0x%llx, length %d\n", i,
			index[i], length);
		if(length == 0) {
			ERROR("Failed to read id table block %d, from 0x%llx, "
				"length %d\n", i, index[i], length);
			free(id_table);
			return NULL;
		}
	}

	SQUASHFS_INSWAP_INTS(id_table, sBlk->no_ids);

	for(i = 0; i < sBlk->no_ids; i++) {
		TRACE("Adding id %d to id tables\n", id_table[i]);
		create_id(id_table[i]);
	}

	return id_table;
}


int read_fragment_table(int fd, struct squashfs_super_block *sBlk,
	struct squashfs_fragment_entry **fragment_table)
{
	int res, i, indexes = SQUASHFS_FRAGMENT_INDEXES(sBlk->fragments);
	long long fragment_table_index[indexes];

	TRACE("read_fragment_table: %d fragments, reading %d fragment indexes "
		"from 0x%llx\n", sBlk->fragments, indexes,
		sBlk->fragment_table_start);
	if(sBlk->fragments == 0)
		return 1;

	*fragment_table = malloc(sBlk->fragments *
		sizeof(struct squashfs_fragment_entry));
	if(*fragment_table == NULL) {
		ERROR("Failed to allocate fragment table\n");
		return 0;
	}

	res = read_fs_bytes(fd, sBlk->fragment_table_start,
		SQUASHFS_FRAGMENT_INDEX_BYTES(sBlk->fragments),
		fragment_table_index);
	if(res == 0) {
		free(*fragment_table);
		return 0;
	}

	SQUASHFS_INSWAP_FRAGMENT_INDEXES(fragment_table_index, indexes);

	for(i = 0; i < indexes; i++) {
		int length = read_block(fd, fragment_table_index[i], NULL,
			((unsigned char *) *fragment_table) +
			(i * SQUASHFS_METADATA_SIZE));
		TRACE("Read fragment table block %d, from 0x%llx, length %d\n",
			i, fragment_table_index[i], length);
		if(length == 0) {
			ERROR("Failed to read fragment table block %d, from "
				"0x%llx, length %d\n", i,
				fragment_table_index[i], length);
			free(*fragment_table);
			return 0;
		}
	}

	for(i = 0; i < sBlk->fragments; i++)
		SQUASHFS_INSWAP_FRAGMENT_ENTRY(&(*fragment_table)[i]);

	return 1;
}


int read_inode_lookup_table(int fd, struct squashfs_super_block *sBlk,
	squashfs_inode **inode_lookup_table)
{
	int lookup_bytes = SQUASHFS_LOOKUP_BYTES(sBlk->inodes);
	int indexes = SQUASHFS_LOOKUP_BLOCKS(sBlk->inodes);
	long long index[indexes];
	int res, i;

	if(sBlk->lookup_table_start == SQUASHFS_INVALID_BLK)
		return 1;

	*inode_lookup_table = malloc(lookup_bytes);
	if(*inode_lookup_table == NULL) {
		ERROR("Failed to allocate inode lookup table\n");
		return 0;
	}

	res = read_fs_bytes(fd, sBlk->lookup_table_start,
		SQUASHFS_LOOKUP_BLOCK_BYTES(sBlk->inodes), index);
	if(res == 0) {
		free(*inode_lookup_table);
		return 0;
	}

	SQUASHFS_INSWAP_LONG_LONGS(index, indexes);

	for(i = 0; i <  indexes; i++) {
		int length = read_block(fd, index[i], NULL,
			((unsigned char *) *inode_lookup_table) +
			(i * SQUASHFS_METADATA_SIZE));
		TRACE("Read inode lookup table block %d, from 0x%llx, length "
			"%d\n", i, index[i], length);
		if(length == 0) {
			ERROR("Failed to read inode lookup table block %d, "
				"from 0x%llx, length %d\n", i, index[i],
				length);
			free(*inode_lookup_table);
			return 0;
		}
	}

	SQUASHFS_INSWAP_LONG_LONGS(*inode_lookup_table, sBlk->inodes);

	return 1;
}


long long read_filesystem(char *root_name, int fd, struct squashfs_super_block *sBlk,
	char **cinode_table, char **data_cache, char **cdirectory_table,
	char **directory_data_cache, unsigned int *last_directory_block,
	unsigned int *inode_dir_offset, unsigned int *inode_dir_file_size,
	unsigned int *root_inode_size, unsigned int *inode_dir_start_block,
	int *file_count, int *sym_count, int *dev_count, int *dir_count,
	int *fifo_count, int *sock_count, long long *uncompressed_file,
	unsigned int *uncompressed_inode, unsigned int *uncompressed_directory,
	unsigned int *inode_dir_inode_number,
	unsigned int *inode_dir_parent_inode,
	void (push_directory_entry)(char *, squashfs_inode, int, int),
	struct squashfs_fragment_entry **fragment_table,
	squashfs_inode **inode_lookup_table)
{
	unsigned char *inode_table = NULL, *directory_table;
	long long start = sBlk->inode_table_start;
	long long end = sBlk->directory_table_start;
	long long root_inode_start = start +
		SQUASHFS_INODE_BLK(sBlk->root_inode);
	unsigned int root_inode_offset =
		SQUASHFS_INODE_OFFSET(sBlk->root_inode);
	unsigned int root_inode_block;
	union squashfs_inode_header inode;
	unsigned int *id_table;
	int res;

	printf("Scanning existing filesystem...\n");

	if(get_xattrs(fd, sBlk) == 0)
		goto error;

	if(read_fragment_table(fd, sBlk, fragment_table) == 0)
		goto error;

	if(read_inode_lookup_table(fd, sBlk, inode_lookup_table) == 0)
		goto error;

	id_table = read_id_table(fd, sBlk);
	if(id_table == NULL)
		goto error;

	res = scan_inode_table(fd, start, end, root_inode_start,
		root_inode_offset, sBlk, &inode, &inode_table,
		&root_inode_block, root_inode_size, uncompressed_file,
		uncompressed_directory, file_count, sym_count, dev_count,
		dir_count, fifo_count, sock_count, id_table);
	if(res == 0) {
		ERROR("read_filesystem: inode table read failed\n");
		goto error;
	}

	*uncompressed_inode = root_inode_block;

	if(inode.base.inode_type == SQUASHFS_DIR_TYPE ||
			inode.base.inode_type == SQUASHFS_LDIR_TYPE) {
		if(inode.base.inode_type == SQUASHFS_DIR_TYPE) {
			*inode_dir_start_block = inode.dir.start_block;
			*inode_dir_offset = inode.dir.offset;
			*inode_dir_file_size = inode.dir.file_size - 3;
			*inode_dir_inode_number = inode.dir.inode_number;
			*inode_dir_parent_inode = inode.dir.parent_inode;
		} else {
			*inode_dir_start_block = inode.ldir.start_block;
			*inode_dir_offset = inode.ldir.offset;
			*inode_dir_file_size = inode.ldir.file_size - 3;
			*inode_dir_inode_number = inode.ldir.inode_number;
			*inode_dir_parent_inode = inode.ldir.parent_inode;
		}

		directory_table = squashfs_readdir(fd, !root_name,
			*inode_dir_start_block, *inode_dir_offset,
			*inode_dir_file_size, last_directory_block, sBlk,
			push_directory_entry);
		if(directory_table == NULL) {
			ERROR("read_filesystem: Could not read root directory"
				"\n");
			goto error;
		}

		root_inode_start -= start;
		*cinode_table = malloc(root_inode_start);
		if(*cinode_table == NULL) {
			ERROR("read_filesystem: failed to alloc space for "
				"existing filesystem inode table\n");
			goto error;
		}
	       	res = read_fs_bytes(fd, start, root_inode_start, *cinode_table);
		if(res == 0)
			goto error;

		*cdirectory_table = malloc(*last_directory_block);
		if(*cdirectory_table == NULL) {
			ERROR("read_filesystem: failed to alloc space for "
				"existing filesystem directory table\n");
			goto error;
		}
		res = read_fs_bytes(fd, sBlk->directory_table_start,
			*last_directory_block, *cdirectory_table);
		if(res == 0)
			goto error;

		*data_cache = malloc(root_inode_offset + *root_inode_size);
		if(*data_cache == NULL) {
			ERROR("read_filesystem: failed to alloc inode cache\n");
			goto error;
		}
		memcpy(*data_cache, inode_table + root_inode_block,
			root_inode_offset + *root_inode_size);

		*directory_data_cache = malloc(*inode_dir_offset +
			*inode_dir_file_size);
		if(*directory_data_cache == NULL) {
			ERROR("read_filesystem: failed to alloc directory "
				"cache\n");
			goto error;
		}
		memcpy(*directory_data_cache, directory_table,
			*inode_dir_offset + *inode_dir_file_size);

		free(inode_table);
		free(directory_table);
		return sBlk->inode_table_start;
	}

error:
	return 0;
}
