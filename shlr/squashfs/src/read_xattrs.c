/*
 * Read a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2010
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
 * read_xattrs.c
 */

/*
 * Common xattr read code shared between mksquashfs and unsquashfs
 */

#define TRUE 1
#define FALSE 0
#include <stdio.h>
#include <string.h>

#ifndef linux
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif

#include "squashfs_fs.h"
#include "squashfs_swap.h"
#include "read_fs.h"
#include "xattr.h"

#include <stdlib.h>

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...) \
		do { \
			printf("read_xattrs: "s, ## args); \
		} while(0)
#else
#define TRACE(s, args...)
#endif

#define ERROR(s, args...) \
		do { \
			fprintf(stderr, s, ## args); \
		} while(0)

extern int read_fs_bytes(int, long long, int, void *);
extern int read_block(int, long long, long long *, void *);

static struct hash_entry {
	long long		start;
	unsigned int		offset;
	struct hash_entry	*next;
} *hash_table[65536];

static struct squashfs_xattr_id *xattr_ids;
static void *xattrs = NULL;
static long long xattr_table_start;

/*
 * Prefix lookup table, storing mapping to/from prefix string and prefix id
 */
struct prefix prefix_table[] = {
	{ "user.", SQUASHFS_XATTR_USER },
	{ "trusted.", SQUASHFS_XATTR_TRUSTED },
	{ "security.", SQUASHFS_XATTR_SECURITY },
	{ "", -1 }
};

/*
 * store mapping from location of compressed block in fs ->
 * location of uncompressed block in memory
 */
static int save_xattr_block(long long start, int offset)
{
	struct hash_entry *hash_entry = malloc(sizeof(*hash_entry));
	int hash = start & 0xffff;

	TRACE("save_xattr_block: start %lld, offset %d\n", start, offset);

	if(hash_entry == NULL) {
		ERROR("Failed to allocate hash entry\n");
		return -1;
	}

	hash_entry->start = start;
	hash_entry->offset = offset;
	hash_entry->next = hash_table[hash];
	hash_table[hash] = hash_entry;

	return 1;
}


/*
 * map from location of compressed block in fs ->
 * location of uncompressed block in memory
 */
static int get_xattr_block(long long start)
{
	int hash = start & 0xffff;
	struct hash_entry *hash_entry = hash_table[hash];

	for(; hash_entry; hash_entry = hash_entry->next)
		if(hash_entry->start == start)
			break;

	TRACE("get_xattr_block: start %lld, offset %d\n", start,
		hash_entry ? hash_entry->offset : -1);

	return hash_entry ? hash_entry->offset : -1;
}


/*
 * construct the xattr_list entry from the fs xattr, including
 * mapping name and prefix into a full name
 */
int read_xattr_entry(struct xattr_list *xattr,
	struct squashfs_xattr_entry *entry, void *name)
{
	int i, len, type = entry->type & XATTR_PREFIX_MASK;

	for(i = 0; prefix_table[i].type != -1; i++)
		if(prefix_table[i].type == type)
			break;

	if(prefix_table[i].type == -1) {
		ERROR("Unrecognised type in read_xattr_entry\n");
		return 0;
	}

	len = strlen(prefix_table[i].prefix);
	xattr->full_name = malloc(len + entry->size + 1);
	if(xattr->full_name == NULL) {
		ERROR("Out of memory in read_xattr_entry\n");
		return -1;
	}
	memcpy(xattr->full_name, prefix_table[i].prefix, len);
	memcpy(xattr->full_name + len, name, entry->size);
	xattr->full_name[len + entry->size] = '\0';
	xattr->name = xattr->full_name + len;
	xattr->size = entry->size;
	xattr->type = type;

	return 1;
}


/*
 * Read and decompress the xattr id table and the xattr metadata.
 * This is cached in memory for later use by get_xattr()
 */
int read_xattrs_from_disk(int fd, struct squashfs_super_block *sBlk)
{
	int res, bytes, i, indexes, index_bytes, ids;
	long long *index, start, end;
	struct squashfs_xattr_table id_table;

	TRACE("read_xattrs_from_disk\n");

	if(sBlk->xattr_id_table_start == SQUASHFS_INVALID_BLK)
		return SQUASHFS_INVALID_BLK;

	/*
	 * Read xattr id table, containing start of xattr metadata and the
	 * number of xattrs in the file system
	 */
	res = read_fs_bytes(fd, sBlk->xattr_id_table_start, sizeof(id_table),
		&id_table);
	if(res == 0)
		return 0;

	SQUASHFS_INSWAP_XATTR_TABLE(&id_table);

	/*
	 * Allocate and read the index to the xattr id table metadata
	 * blocks
	 */
	ids = id_table.xattr_ids;
	xattr_table_start = id_table.xattr_table_start;
	index_bytes = SQUASHFS_XATTR_BLOCK_BYTES(ids);
	indexes = SQUASHFS_XATTR_BLOCKS(ids);
	index = malloc(index_bytes);
	if(index == NULL) {
		ERROR("Failed to allocate index array\n");
		return 0;
	}

	res = read_fs_bytes(fd, sBlk->xattr_id_table_start + sizeof(id_table),
		index_bytes, index);
	if(res ==0)
		goto failed1;

	SQUASHFS_INSWAP_LONG_LONGS(index, indexes);

	/*
	 * Allocate enough space for the uncompressed xattr id table, and
	 * read and decompress it
	 */
	bytes = SQUASHFS_XATTR_BYTES(ids);
	xattr_ids = malloc(bytes);
	if(xattr_ids == NULL) {
		ERROR("Failed to allocate xattr id table\n");
		goto failed1;
	}

	for(i = 0; i < indexes; i++) {
		int length = read_block(fd, index[i], NULL,
			((unsigned char *) xattr_ids) +
			(i * SQUASHFS_METADATA_SIZE));
		TRACE("Read xattr id table block %d, from 0x%llx, length "
			"%d\n", i, index[i], length);
		if(length == 0) {
			ERROR("Failed to read xattr id table block %d, "
				"from 0x%llx, length %d\n", i, index[i],
				length);
			goto failed2;
		}
	}

	/*
	 * Read and decompress the xattr metadata
	 *
	 * Note the first xattr id table metadata block is immediately after
	 * the last xattr metadata block, so we can use index[0] to work out
	 * the end of the xattr metadata
	 */
	start = xattr_table_start;
	end = index[0];
	for(i = 0; start < end; i++) {
		int length;
		void *x = realloc(xattrs, (i + 1) * SQUASHFS_METADATA_SIZE);
		if(x == NULL) {
			ERROR("Failed to realloc xattr data\n");
			goto failed3;
		}
		xattrs = x;

		/* store mapping from location of compressed block in fs ->
		 * location of uncompressed block in memory */
		res = save_xattr_block(start, i * SQUASHFS_METADATA_SIZE);
		if(res == -1)
			goto failed3;

		length = read_block(fd, start, &start,
			((unsigned char *) xattrs) +
			(i * SQUASHFS_METADATA_SIZE));
		TRACE("Read xattr block %d, length %d\n", i, length);
		if(length == 0) {
			ERROR("Failed to read xattr block %d\n", i);
			goto failed3;
		}
	}

	/* swap if necessary the xattr id entries */
	for(i = 0; i < ids; i++)
		SQUASHFS_INSWAP_XATTR_ID(&xattr_ids[i]);

	free(index);

	return ids;

failed3:
	free(xattrs);
failed2:
	free(xattr_ids);
failed1:
	free(index);

	return 0;
}


/*
 * Construct and return the list of xattr name:value pairs for the passed xattr
 * id
 */
struct xattr_list *get_xattr(int i, unsigned int *count)
{
	long long start;
	struct xattr_list *xattr_list = NULL;
	unsigned int offset;
	void *xptr;
	int j;

	TRACE("get_xattr\n");

	*count = xattr_ids[i].count;
	start = SQUASHFS_XATTR_BLK(xattr_ids[i].xattr) + xattr_table_start;
	offset = SQUASHFS_XATTR_OFFSET(xattr_ids[i].xattr);
	xptr = xattrs + get_xattr_block(start) + offset;

	TRACE("get_xattr: xattr_id %d, count %d, start %lld, offset %d\n", i,
			*count, start, offset);

	for(j = 0; j < *count; j++) {
		struct squashfs_xattr_entry entry;
		struct squashfs_xattr_val val;
		int res;

		xattr_list = realloc(xattr_list, (j + 1) *
						sizeof(struct xattr_list));
		if(xattr_list == NULL) {
			ERROR("Out of memory in get_xattrs\n");
			goto failed;
		}
			
		SQUASHFS_SWAP_XATTR_ENTRY(&entry, xptr);
		xptr += sizeof(entry);
		res = read_xattr_entry(&xattr_list[j], &entry, xptr);
		if(res != 1)
			goto failed;
		xptr += entry.size;
			
		TRACE("get_xattr: xattr %d, type %d, size %d, name %s\n", j,
			entry.type, entry.size, xattr_list[j].full_name); 

		if(entry.type & SQUASHFS_XATTR_VALUE_OOL) {
			long long xattr;
			void *ool_xptr;

			xptr += sizeof(val);
			SQUASHFS_SWAP_LONG_LONGS(&xattr, xptr, 1);
			xptr += sizeof(xattr);	
			start = SQUASHFS_XATTR_BLK(xattr) + xattr_table_start;
			offset = SQUASHFS_XATTR_OFFSET(xattr);
			ool_xptr = xattrs + get_xattr_block(start) + offset;
			SQUASHFS_SWAP_XATTR_VAL(&val, ool_xptr);
			xattr_list[j].value = ool_xptr + sizeof(val);
		} else {
			SQUASHFS_SWAP_XATTR_VAL(&val, xptr);
			xattr_list[j].value = xptr + sizeof(val);
			xptr += sizeof(val) + val.vsize;
		}

		TRACE("get_xattr: xattr %d, vsize %d\n", j, val.vsize);

		xattr_list[j].vsize = val.vsize;
	}

	return xattr_list;

failed:
	free(xattr_list);

	return NULL;
}
