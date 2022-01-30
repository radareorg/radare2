/* radare - LGPL - Copyright 2022 - pancake */
/*
 * bplist.c
 * Binary plist implementation
 *
 * Copyright (c) 2011-2017 Nikias Bassen, All Rights Reserved.
 * Copyright (c) 2008-2010 Jonathan Beck, All Rights Reserved.
 * Copyright (c) 2022      pancake, No Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */


#include <r_util.h>
#include <r_util/bplist.h>

/* Magic marker and size. */
#define BPLIST_MAGIC            ((ut8*)"bplist")
#define BPLIST_MAGIC_SIZE       6

#define BPLIST_VERSION          ((ut8*)"00")
#define BPLIST_VERSION_SIZE     2

R_PACKED (typedef struct {
	ut8 unused[6];
	ut8 offset_size;
	ut8 ref_size;
	ut64 num_objects;
	ut64 root_object_index;
	ut64 offset_table_offset;
}) BPlistTrailer;

enum {
	BPLIST_NULL = 0x00,
	BPLIST_FALSE = 0x08,
	BPLIST_TRUE = 0x09,
	BPLIST_FILL = 0x0F,			/* will be used for length grabbing */
	BPLIST_UINT = 0x10,
	BPLIST_REAL = 0x20,
	BPLIST_DATE = 0x30,
	BPLIST_DATA = 0x40,
	BPLIST_STRING = 0x50,
	BPLIST_UNICODE = 0x60,
	BPLIST_UNK_0x70 = 0x70,
	BPLIST_UID = 0x80,
	BPLIST_ARRAY = 0xA0,
	BPLIST_SET = 0xC0,
	BPLIST_DICT = 0xD0,
	BPLIST_MASK = 0xF0
};

#ifndef bswap32
#define bswap32(x)   ((((x) & 0xFF000000) >> 24) \
		| (((x) & 0x00FF0000) >>  8) \
		| (((x) & 0x0000FF00) <<  8) \
		| (((x) & 0x000000FF) << 24))
#endif

#ifndef bswap64
#define bswap64(x)   ((((x) & 0xFF00000000000000ull) >> 56) \
		| (((x) & 0x00FF000000000000ull) >> 40) \
		| (((x) & 0x0000FF0000000000ull) >> 24) \
		| (((x) & 0x000000FF00000000ull) >>  8) \
		| (((x) & 0x00000000FF000000ull) <<  8) \
		| (((x) & 0x0000000000FF0000ull) << 24) \
		| (((x) & 0x000000000000FF00ull) << 40) \
		| (((x) & 0x00000000000000FFull) << 56))
#endif

#ifndef be64toh
#ifdef __BIG_ENDIAN__
#define be64toh(x) (x)
#else
#define be64toh(x) bswap64 (x)
#endif
#endif

static ut64 UINT_TO_HOST(const char *data, int n) {
	switch (n) {
	case 1:
		return r_read_be8 (data);
	case 2:
		return r_read_be16 (data);
	case 4:
		return r_read_be32 (data);
	default:
		return r_read_be64 (data);
	}
	return 0;
}

#if (defined(__LITTLE_ENDIAN__) && !defined(__FLOAT_WORD_ORDER__)) \
	|| (defined(__FLOAT_WORD_ORDER__) && __FLOAT_WORD_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define float_bswap64(x) bswap64(x)
#define float_bswap32(x) bswap32(x)
#else
#define float_bswap64(x) (x)
#define float_bswap32(x) (x)
#endif

static bool parse_bin_node_at_index(RBPlist *bplist, ut32 node_index);

static bool parse_uint_node(RBPlist *bplist, const char **bnode, ut8 size) {
	size = 1 << size; // make length less misleading
#if 1
	switch (size) {
	case sizeof(ut8):
	case sizeof(ut16):
	case sizeof(ut32):
	case sizeof(ut64):
		// data.length = sizeof(ut64);
		break;
	case 16:
		// data.length = size;
		break;
	default:
		//free(data);
		eprintf ("%s: Invalid byte size for integer node\n", __func__);
		return false;
	};
#endif
	ut64 intval = UINT_TO_HOST (*bnode, size);
	(*bnode) += size;
	pj_i (bplist->pj, intval);
	// printf (" %lld", intval);
	return true;
}

static double parse_real(const char **bnode, ut8 size) {
	double realval = 0.0;
	ut64 data = 0;
	ut8 buf[8] = {0};
	memcpy (&data, *bnode, sizeof (buf));
	switch (1 << size) {
	case sizeof(ut32):
		*(ut32*)buf = float_bswap32 (data);
		realval = *(float *) buf;
		break;
	case sizeof(ut64):
		*(ut64*)buf = float_bswap64 (data);
		realval = *(double *) buf;
		break;
	default:
		eprintf ("%s: Invalid byte size for real node\n", __func__);
		return false;
	}
	return realval;
}

static bool parse_date_node(RBPlist *bplist, const char **bnode, ut8 size) {
	double realval = parse_real (bnode, size);
	// printf ("date(%d)", (int)(size_t)realval / 1000000);
	// realval = (double)sec + (double)usec / 1000000;
	pj_n (bplist->pj, (int)(size_t)realval / 1000000);
	return true;
}

static bool parse_string_node(RBPlist *bplist, const char **bnode, ut64 size) {
	char *s = r_str_ndup (*bnode, size);
	pj_s (bplist->pj, s);
	//printf (" \"%s\"", s);
	free (s);
	return true;
}

static bool parse_unicode_node(RBPlist *bplist, const char **bnode, ut64 size) {
	ut8 *dst = malloc (size + 1);
	if (!dst) {
		return false;
	}
	const ut8 *src = (const ut8*)*bnode;
 	if (!r_str_utf16_to_utf8 (dst, size, src, size, false)) {
		free (dst);
		return false;
	}
	//char *tmpstr = plist_utf16be_to_utf8 ((ut16*)(*bnode), size, &items_read, &items_written);
	pj_s (bplist->pj, (const char *)dst);
	//printf (" unicode(%s)", dst);
	free (dst);
	return true;
}

static bool parse_data_node(RBPlist *bplist, const char **bnode, ut64 size) {
	pj_r (bplist->pj, (const ut8*)(*bnode), size);
	return true;
}

static bool parse_dict_node(RBPlist *bplist, const char** bnode, ut64 size) {
	ut64 j;
	bool res = true;

	pj_o (bplist->pj);
	for (j = 0; j < size; j++) {
		ut64 str_i = j * bplist->ref_size;
		ut64 str_j = (j + size) * bplist->ref_size;
		const char *index1_ptr = (*bnode) + str_i;
		const char *index2_ptr = (*bnode) + str_j;

		if ((index1_ptr < bplist->data || index1_ptr + bplist->ref_size > bplist->offset_table) ||
				(index2_ptr < bplist->data || index2_ptr + bplist->ref_size > bplist->offset_table)) {
			eprintf ("%s: dict entry %" PRIu64 " is outside of valid range\n", __func__, j);
			return false;
		}

		ut64 index1 = UINT_TO_HOST(index1_ptr, bplist->ref_size);
		ut64 index2 = UINT_TO_HOST(index2_ptr, bplist->ref_size);

		if (index1 >= bplist->num_objects) {
			eprintf ("%s: dict entry %" PRIu64 ": key index (%" PRIu64 ") must be smaller than the number of objects (%" PRIu64 ")\n", __func__, j, index1, bplist->num_objects);
			return false;
		}
		if (index2 >= bplist->num_objects) {
			eprintf ("%s: dict entry %" PRIu64 ": value index (%" PRIu64 ") must be smaller than the number of objects (%" PRIu64 ")\n", __func__, j, index1, bplist->num_objects);
			return false;
		}
		/* key */
		if (!parse_bin_node_at_index (bplist, index1)) {
			eprintf ("cannot find key\n");
			return false;
		}
		pj_kraw (bplist->pj);
		/* value */
		if (!parse_bin_node_at_index (bplist, index2)) {
			res = false;
			break;
		}
	}
	pj_end (bplist->pj);
	return res;
}

static bool parse_array_node(RBPlist *bplist, const char** bnode, const ut64 size) {
	bool res = true;
	ut64 j;
	ut64 index1;

	pj_a (bplist->pj);
	for (j = 0; j < size; j++) {
		ut64 str_j = j * bplist->ref_size;
		const char *index1_ptr = (*bnode) + str_j;

		if (index1_ptr < bplist->data || index1_ptr + bplist->ref_size > bplist->offset_table) {
			eprintf ("%s: array item %" PRIu64 " is outside of valid range\n", __func__, j);
			return false;
		}

		index1 = UINT_TO_HOST(index1_ptr, bplist->ref_size);

		if (index1 >= bplist->num_objects) {
			eprintf ("%s: array item %" PRIu64 " object index (%" PRIu64 ") must be smaller than the number of objects (%" PRIu64 ")\n", __func__, j, index1, bplist->num_objects);
			return false;
		}

		/* process value node */
		if (!parse_bin_node_at_index (bplist, index1)) {
			res = false;
			break;
		}
	}
	pj_end (bplist->pj);
	return res;
}

static bool parse_uid_node(RBPlist *bplist, const char **bnode, ut8 size) {
	size++;
	long long intval = UINT_TO_HOST (*bnode, size);
	if (intval > UINT32_MAX) {
		eprintf ("%s: value %" PRIu64 " too large for UID node (must be <= %u)\n", __func__, (ut64)intval, UINT32_MAX);
		return NULL;
	}

	(*bnode) += size;
	pj_n (bplist->pj, (int)intval);
	return true;
}

static bool parse_bin_node(RBPlist *bplist, const char** object) {
	PJ *pj = bplist->pj;
	ut64 poffset_table = (uint64_t)(uintptr_t)bplist->offset_table;

	if (!object) {
		return false;
	}

	ut16 type = (**object) & BPLIST_MASK;
	ut64 size = (**object) & BPLIST_FILL;
	(*object)++;

	if (size == BPLIST_FILL) {
		switch (type) {
		case BPLIST_DATA:
		case BPLIST_STRING:
		case BPLIST_UNICODE:
		case BPLIST_ARRAY:
		case BPLIST_SET:
		case BPLIST_DICT:
			{
				ut16 next_size = **object & BPLIST_FILL;
				if ((**object & BPLIST_MASK) != BPLIST_UINT) {
					eprintf ("%s: invalid size node type for node type 0x%02x: found 0x%02x, expected 0x%02x\n", __func__, type, **object & BPLIST_MASK, BPLIST_UINT);
					return false;
				}
				(*object)++;
				next_size = 1 << next_size;
				if (*object + next_size > bplist->offset_table) {
					eprintf ("%s: size node data bytes for node type 0x%02x point outside of valid range\n", __func__, type);
					return false;
				}
				size = UINT_TO_HOST(*object, next_size);
				(*object) += next_size;
				break;
			}
		default:
			break;
		}
	}

	ut64 pobject = (uint64_t)(uintptr_t)*object;

	switch (type) {
	case BPLIST_NULL:
		switch (size) {
		case BPLIST_TRUE:
			pj_b (pj, true);
			return true;
		case BPLIST_FALSE:
			pj_b (pj, true);
			return true;
		case BPLIST_NULL:
			pj_null (pj);
			return true;
		default:
			return false;
		}
	case BPLIST_UINT:
		if (pobject + (ut64)(1 << size) > poffset_table) {
			eprintf ("%s: BPLIST_UINT data bytes point outside of valid range\n", __func__);
			return false;
		}
		return parse_uint_node (bplist, object, size);
	case BPLIST_REAL:
		if (pobject + (ut64)(1 << size) > poffset_table) {
			eprintf ("%s: BPLIST_REAL data bytes point outside of valid range\n", __func__);
			return false;
		}
		pj_d (bplist->pj, parse_real (object, size));
		return true;
	case BPLIST_DATE:
		if (3 != size) {
			eprintf ("%s: invalid data size for BPLIST_DATE node\n", __func__);
			return false;
		}
		if (pobject + (ut64)(1 << size) > poffset_table) {
			eprintf ("%s: BPLIST_DATE data bytes point outside of valid range\n", __func__);
			return false;
		}
		return parse_date_node (bplist, object, size);
	case BPLIST_DATA:
		if (pobject + size < pobject || pobject + size > poffset_table) {
			eprintf ("%s: BPLIST_DATA data bytes point outside of valid range\n", __func__);
			return false;
		}
		return parse_data_node (bplist, object, size);
	case BPLIST_STRING:
		if (pobject + size < pobject || pobject + size > poffset_table) {
			eprintf ("%s: BPLIST_STRING data bytes point outside of valid range\n", __func__);
			return false;
		}
		return parse_string_node (bplist, object, size);
	case BPLIST_UNICODE:
		if (size*2 < size) {
			eprintf ("%s: Integer overflow when calculating BPLIST_UNICODE data size.\n", __func__);
			return false;
		}
		if (pobject + size*2 < pobject || pobject + size*2 > poffset_table) {
			eprintf ("%s: BPLIST_UNICODE data bytes point outside of valid range\n", __func__);
			return false;
		}
		return parse_unicode_node (bplist, object, size);
	case BPLIST_SET:
	case BPLIST_ARRAY:
		if (pobject + size < pobject || pobject + size > poffset_table) {
			eprintf ("%s: BPLIST_ARRAY data bytes point outside of valid range\n", __func__);
			return false;
		}
		return parse_array_node(bplist, object, size);
	case BPLIST_UID:
		if (pobject + size + 1 > poffset_table) {
			eprintf ("%s: BPLIST_UID data bytes point outside of valid range\n", __func__);
			return false;
		}
		return parse_uid_node (bplist, object, size);
	case BPLIST_DICT:
		if (pobject + size < pobject || pobject + size > poffset_table) {
			eprintf ("%s: BPLIST_DICT data bytes point outside of valid range\n", __func__);
			return false;
		}
		return parse_dict_node (bplist, object, size);
	default:
		eprintf ("%s: unexpected node type 0x%02x\n", __func__, type);
		return false;
	}
	return true;
}

static bool parse_bin_node_at_index(RBPlist *bplist, ut32 node_index) {
	if (node_index >= bplist->num_objects) {
		eprintf ("node index (%u) must be smaller than the number of objects (%" PRIu64 ")\n", node_index, bplist->num_objects);
		return false;
	}
	const char *idx_ptr = bplist->offset_table + node_index * bplist->offset_size;
	if (idx_ptr < bplist->offset_table ||
			idx_ptr >= bplist->offset_table + bplist->num_objects * bplist->offset_size) {
		eprintf ("node index %u points outside of valid range\n", node_index);
		return false;
	}

	const char* ptr = bplist->data + UINT_TO_HOST(idx_ptr, bplist->offset_size);
	/* make sure the node offset is in a sane range */
	if ((ptr < bplist->data) || (ptr >= bplist->offset_table)) {
		eprintf ("offset for node index %u points outside of valid range\n", node_index);
		return false;
	}
	/* finally parse node */
	return parse_bin_node (bplist, &ptr);
}

static bool r_bplist_check(const ut8 *plist_data, ut32 length) {
	return length > 7 && !memcmp (plist_data, "bplist00", 8);
}

R_API bool r_bplist_parse(PJ *pj, const ut8 *data, size_t data_len) {
	r_return_val_if_fail (data && data_len > 0, false);
	if (!r_bplist_check (data, data_len)) {
		return false;
	}

	if (data_len < BPLIST_MAGIC_SIZE + BPLIST_VERSION_SIZE + sizeof (BPlistTrailer)) {
		eprintf ("plist data is to small to hold a binary plist\n");
		return false;
	}
	// check version
	if (memcmp (data + BPLIST_MAGIC_SIZE, BPLIST_VERSION, BPLIST_VERSION_SIZE)) {
		eprintf ("unsupported binary plist version '%.2s\n", data+BPLIST_MAGIC_SIZE);
		return false;
	}

	const ut8 *start_data = data + BPLIST_MAGIC_SIZE + BPLIST_VERSION_SIZE;
	const ut8 *end_data = data + data_len - sizeof (BPlistTrailer);

	// now parse trailer
	BPlistTrailer *trailer = (BPlistTrailer*)end_data;
	ut8 offset_size = trailer->offset_size;
	ut8 ref_size = trailer->ref_size;
	ut64 num_objects = be64toh (trailer->num_objects);
	ut64 root_object = be64toh (trailer->root_object_index);
	const ut8 *offset_table = (ut8 *)(data + be64toh (trailer->offset_table_offset));

	if (num_objects == 0) {
		eprintf ("number of objects must be larger than 0\n");
		return false;
	}

	if (offset_size == 0) {
		eprintf ("offset size in trailer must be larger than 0\n");
		return false;
	}

	if (ref_size == 0) {
		eprintf ("object reference size in trailer must be larger than 0\n");
		return false;
	}

	if (root_object >= num_objects) {
		eprintf ("root object index (%" PRIu64 ") must be smaller than number of objects (%" PRIu64 ")\n", root_object, num_objects);
		return false;
	}

	if (offset_table < start_data || offset_table >= end_data) {
		eprintf ("offset table offset points outside of valid range\n");
		return false;
	}

	if (UT64_MUL_OVFCHK (num_objects, offset_size)) {
		eprintf ("integer overflow when calculating offset table size\n");
		return false;
	}
	ut64 offset_table_size = num_objects * offset_size;
	if (offset_table_size > (ut64)(end_data - offset_table)) {
		eprintf ("offset table points outside of valid range\n");
		return false;
	}

	RBPlist bplist = {
		.data = (const char *)data,
		.size = data_len,
		.num_objects = num_objects,
		.ref_size = ref_size,
		.offset_size = offset_size,
		.offset_table = (const char *)offset_table,
		.pj = pj,
	};
	return parse_bin_node_at_index (&bplist, root_object);
}
