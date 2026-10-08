/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"

static inline ut64 get_max_offset(size_t addr_size) {
	switch (addr_size) {
	case 1: return UT8_MAX;
	case 2: return UT16_MAX;
	case 4: return UT32_MAX;
	case 8: return UT64_MAX;
	}
	return 0;
}

static inline RBinDwarfLocList *create_loc_list(ut64 offset) {
	RBinDwarfLocList *list = R_NEW0 (RBinDwarfLocList);
	list->list = r_list_new ();
	list->offset = offset;
	return list;
}

static inline RBinDwarfLocRange *create_loc_range(ut64 start, ut64 end, RBinDwarfBlock *block) {
	RBinDwarfLocRange *range = R_NEW0 (RBinDwarfLocRange);
	range->start = start;
	range->end = end;
	range->expression = block;
	return range;
}

static void parse_loc_raw(RBin *bin, HtUP /*<offset, List *<LocListEntry>*/ *loc_table, const ut8 *buf, size_t len, size_t addr_size) {
	const bool be = r_bin_is_big_endian (bin);
	/* GNU has their own extensions GNU locviews that we can't parse */
	const ut8 *const buf_start = buf;
	const ut8 *buf_end = buf + len;
	/* for recognizing Base address entry */
	const ut64 max_offset = get_max_offset (addr_size);

	ut64 address_base = 0; /* remember base of the loclist */
	ut64 list_offset = 0;

	RBinDwarfLocList *loc_list = NULL;
	RBinDwarfLocRange *range = NULL;
	while (buf && buf < buf_end) {
		/* Check if we have at least enough bytes to read two addresses */
		if (buf + 2 * addr_size > buf_end) {
			break;
		}
		ut64 start_addr = dwarf_read_address (bin, addr_size, &buf, buf_end);
		ut64 end_addr = dwarf_read_address (bin, addr_size, &buf, buf_end);

		if (start_addr == 0 && end_addr == 0) { /* end of list entry: 0, 0 */
			if (loc_list) {
				ht_up_insert (loc_table, loc_list->offset, loc_list);
				list_offset = buf - buf_start;
				loc_list = NULL;
			}
			address_base = 0;
			continue;
		}
		if (start_addr == max_offset && end_addr != max_offset) {
			/* base address, DWARF2 doesn't have this type of entry, these entries shouldn't
			be in the list, they are just informational entries for further parsing (address_base) */
			address_base = end_addr;
		} else { /* location list entry: */
			if (!loc_list) {
				loc_list = create_loc_list (list_offset);
			}
			/* Check if we have at least the 2-byte block length field */
			if (buf + 2 > buf_end) {
				break;
			}
			/* TODO in future parse expressions to better structure in dwarf.c and not in dwarf_process.c */
			RBinDwarfBlock *block = R_NEW0 (RBinDwarfBlock);
			block->length = READ16 (buf);
			if (block->length > 0) {
				size_t available = buf_end - buf;
				if (block->length <= available) {
					block->data = buf;
					buf += block->length;
				} else {
					/* Block extends past section end, truncate it */
					block->data = buf;
					block->length = available;
					buf = buf_end;
				}
			} else {
				block->data = NULL;
			}
			range = create_loc_range (start_addr + address_base, end_addr + address_base, block);
			r_list_append (loc_list->list, range);
			range = NULL;
		}
	}
	/* If the section ended without a terminating 0,0 entry, make sure to insert
	 * any pending loc_list into the lookup table so it can be freed later. */
	if (loc_list) {
		ht_up_insert (loc_table, loc_list->offset, loc_list);
		loc_list = NULL;
	}
}

#if 0
* @brief Parses out the .debug_loc section into a table that maps each list as
*        offset of a list -> LocationList
*
* @param bin
* @param addr_size machine address size used in executable (necessary for parsing)
* @return R_API*
#endif
R_API HtUP /*<offset, RBinDwarfLocList*/ *r_bin_dwarf_parse_loc(RBinFile *bf, int addr_size) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_LOC);
	if (!bf || !section) {
		return NULL;
	}
	/* The standarparse_loc_raw_frame, not sure why is that */
	const ut8 *buf = dwarf_get_section_bytes (bf, section);
	if (!buf) {
		return NULL;
	}
	/* set the endianity global [HOTFIX] */
	HtUP /*<offset, RBinDwarfLocList*/ *loc_table = ht_up_new0 ();
	if (!loc_table) {
		return NULL;
	}
	parse_loc_raw (bf->rbin, loc_table, buf, section->bytes.len, addr_size);
	return loc_table;
}

static int offset_comp(const void *a, const void *b) {
	const RBinDwarfLocList *f = a;
	const RBinDwarfLocList *s = b;
	ut64 first = f->offset;
	ut64 second = s->offset;
	if (first < second) {
		return -1;
	}
	if (first > second) {
		return 1;
	}
	return 0;
}

static bool sort_loclists(void *user, const ut64 key, const void *value) {
	RBinDwarfLocList *loc_list = (RBinDwarfLocList *)value;
	RList *sort_list = user;
	r_list_add_sorted (sort_list, loc_list, offset_comp);
	return true;
}

R_API R_OWNED char *r_bin_dwarf_print_loc(HtUP /*<offset, RBinDwarfLocList*/ *loc_table, int addr_size) {
	R_RETURN_VAL_IF_FAIL (loc_table, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "\nContents of the .debug_loc section:\n");
	RList /*<RBinDwarfLocList *>*/ *sort_list = r_list_new ();
	/* sort the table contents by offset and print sorted
	a bit ugly, but I wanted to decouple the parsing and printing */
	ht_up_foreach (loc_table, sort_loclists, sort_list);
	RListIter *i;
	RBinDwarfLocList *loc_list;
	r_list_foreach (sort_list, i, loc_list) {
		RListIter *j;
		RBinDwarfLocRange *range;
		ut64 base_offset = loc_list->offset;
		r_list_foreach (loc_list->list, j, range) {
			r_strbuf_appendf (sb, "0x%" PFMT64x " 0x%" PFMT64x " 0x%" PFMT64x "\n", base_offset, range->start, range->end);
			base_offset += addr_size * 2;
			if (range->expression) {
				base_offset += 2 + range->expression->length; /* 2 bytes for expr length */
			}
		}
		r_strbuf_appendf (sb, "0x%" PFMT64x " <End of list>\n", base_offset);
	}
	r_strbuf_append (sb, "\n");
	r_list_free (sort_list);
	return r_strbuf_drain (sb);
}

R_API R_OWNED char *r_bin_dwarf_print_loc_stream(RBinFile *bf, int addr_size) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_LOC);
	if (!section) {
		return NULL;
	}
	const ut8 *buf = dwarf_get_section_bytes (bf, section);
	if (!buf || section->bytes.len < 1) {
		return NULL;
	}
	RBin *bin = bf->rbin;
	const bool be = r_bin_is_big_endian (bin);
	const ut8 *const buf_start = buf;
	const ut8 *buf_end = buf + section->bytes.len;
	const ut64 max_offset = get_max_offset (addr_size);
	RStrBuf *sb = r_strbuf_new (NULL);
	ut64 address_base = 0;
	ut64 list_offset = 0;
	ut64 base_offset = 0;
	bool have_list = false;

	r_strbuf_append (sb, "\nContents of the .debug_loc section:\n");
	while (buf && buf < buf_end && !dwarf_is_breaked (bin)) {
		if (buf + 2 * addr_size > buf_end) {
			break;
		}
		ut64 start_addr = dwarf_read_address (bin, addr_size, &buf, buf_end);
		ut64 end_addr = dwarf_read_address (bin, addr_size, &buf, buf_end);
		if (start_addr == 0 && end_addr == 0) {
			if (have_list) {
				r_strbuf_appendf (sb, "0x%" PFMT64x " <End of list>\n", base_offset);
			}
			list_offset = buf - buf_start;
			address_base = 0;
			have_list = false;
			continue;
		}
		if (start_addr == max_offset && end_addr != max_offset) {
			address_base = end_addr;
			continue;
		}
		if (buf + 2 > buf_end) {
			break;
		}
		ut64 block_len = READ16 (buf);
		if (block_len > (ut64)(buf_end - buf)) {
			block_len = buf_end - buf;
		}
		buf += block_len;
		if (!have_list) {
			base_offset = list_offset;
			have_list = true;
		}
		r_strbuf_appendf (sb, "0x%" PFMT64x " 0x%" PFMT64x " 0x%" PFMT64x "\n",
			base_offset, start_addr + address_base, end_addr + address_base);
		base_offset += addr_size * 2 + 2 + block_len;
	}
	if (dwarf_is_breaked (bin)) {
		r_strbuf_append (sb, "\n");
		return r_strbuf_drain (sb);
	}
	if (have_list) {
		r_strbuf_appendf (sb, "0x%" PFMT64x " <End of list>\n", base_offset);
	}
	r_strbuf_append (sb, "\n");
	return r_strbuf_drain (sb);
}

static bool free_loc_list(void *user, const ut64 key, const void *value) {
	RBinDwarfLocList *loc_list = (RBinDwarfLocList *)value;
	if (loc_list && loc_list->list) {
		RBinDwarfLocRange *range;
		RListIter *iter;
		r_list_foreach (loc_list->list, iter, range) {
			if (range) {
				free (range->expression);
				free (range);
			}
		}
		r_list_free (loc_list->list);
	}
	free (loc_list);
	return true;
}

R_API void r_bin_dwarf_free_loc(HtUP /*<offset, RBinDwarfLocList*>*/ *loc_table) {
	if (loc_table) {
		ht_up_foreach (loc_table, free_loc_list, NULL);
		ht_up_free (loc_table);
	}
}
