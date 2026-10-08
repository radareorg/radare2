/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"

static int abbrev_cmp(const void *a, const void *b) {
	const RBinDwarfAbbrevDecl *first = a;
	const RBinDwarfAbbrevDecl *second = b;
	if (first->offset > second->offset) {
		return 1;
	}
	if (first->offset < second->offset) {
		return -1;
	}
	return 0;
}

static const ut8 *dwarf_read_sleb(const ut8 *buf, const ut8 *buf_end, st64 *value) {
	R_RETURN_VAL_IF_FAIL (buf && buf_end && value && buf < buf_end, NULL);
	size_t available = buf_end - buf;
	size_t i;
	for (i = 0; i < available && i < 10; i++) {
		ut8 byte = buf[i];
		if (!(byte & 0x80)) {
			if (i == 9 && byte != 0 && byte != 0x7f) {
				return NULL;
			}
			const ut8 *next = r_leb128 (buf, i + 1, value);
			return next == buf + i + 1? next: NULL;
		}
	}
	return NULL;
}

static void free_comp_dir_entry(HtUPKv *kv) {
	free (kv->value);
}

static RBinDwarfAbbrevDecl *abbrev_find(const RVecDwarfAbbrevDecl *decls, ut64 abbrev_offset) {
	RBinDwarfAbbrevDecl key = { .offset = abbrev_offset };
	return bsearch (&key, decls->_start, RVecDwarfAbbrevDecl_length (decls), sizeof (key), abbrev_cmp);
}

static bool init_debug_info(RBinDwarfDebugInfo *inf) {
	if (!inf) {
		return false;
	}
	inf->comp_units = RVecDwarfCompUnit_new ();
	if (!inf->comp_units) {
		return false;
	}

	return true;
}

static bool init_die(RArena *arena, RBinDwarfDie *die, ut64 abbr_code, size_t attr_count) {
	if (!die) {
		return false;
	}
	if (attr_count) {
		die->attr_values = RVecDwarfAttrValue_new ();
		if (!die->attr_values) {
			return false;
		}
		if (!RVecDwarfAttrValue_reserve (die->attr_values, attr_count)) {
			RVecDwarfAttrValue_free (die->attr_values);
			die->attr_values = NULL;
			return false;
		}
	} else {
		die->attr_values = NULL;
	}
	die->abbrev_code = abbr_code;
	return true;
}

static bool init_comp_unit(RBinDwarfCompUnit *cu) {
	if (!cu) {
		return false;
	}
	cu->dies = RVecDwarfDie_new ();
	if (!cu->dies) {
		return false;
	}
	return true;
}

static void attr_value_fini(RBinDwarfAttrValue *value) {
	if (!value) {
		return;
	}
	// Only DW_FORM_block2 allocates block.data with r_mem_dup.
	// Other block forms point into the section buffer.
	if (value->attr_form == DW_FORM_block2) {
		free ((void *)value->block.data);
	}
}

static void dwarf_die_fini(RBinDwarfDie *die) {
	if (!die || !die->attr_values) {
		return;
	}
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		attr_value_fini (value);
	}
	RVecDwarfAttrValue_free (die->attr_values);
	die->attr_values = NULL;
}

static void dwarf_comp_unit_fini(RBinDwarfCompUnit *unit) {
	if (!unit || !unit->dies) {
		return;
	}
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		dwarf_die_fini (die);
	}
	RVecDwarfDie_free (unit->dies);
	unit->dies = NULL;
}

R_API void r_bin_dwarf_free_debug_info(RBinDwarfDebugInfo *inf) {
	if (!inf) {
		return;
	}

	RBinDwarfCompUnit *unit;
	R_VEC_FOREACH (inf->comp_units, unit) {
		dwarf_comp_unit_fini (unit);
	}
	RVecDwarfCompUnit_free (inf->comp_units);

	ht_up_free (inf->lookup_table);
	free (inf);
}

static const ut8 *fill_block_data(const ut8 *buf, const ut8 *buf_end, RBinDwarfBlock *block) {
	const size_t available = buf_end - buf;
	if (available < block->length) {
		R_LOG_WARN ("not enough to fill block: have %d but need %d", available, block->length);
		block->length = 0;
		block->data = NULL;
		return NULL;
	}
	block->data = buf;
	return buf + block->length;
}

#if 0
* This function is quite incomplete and requires lot of work
* With parsing various new FORM values
* @brief Parses attribute value based on its definition
*        and stores it into `value`
*
* @param obuf
* @param obuf_len Buffer max capacity
* @param def Attribute definition
* @param value Parsed value storage
* @param hdr Current unit header
* @param debug_str Ptr to string section start
* @param debug_str_len Length of the string section
* @return const ut8* Updated buffer
#endif
static const ut8 *parse_attr_value(RBinFile *bf, const ut8 *obuf, int obuf_len, RBinDwarfAttrDef *def, RBinDwarfAttrValue *value, const RBinDwarfCompUnitHdr *hdr) {
	R_RETURN_VAL_IF_FAIL (bf && def && value && hdr && obuf, NULL);
	RBin *bin = bf->rbin;

	value->attr_form = def->attr_form;
	value->attr_name = def->attr_name;
	value->block.data = NULL;
	value->string.content = NULL;
	value->string.offset = 0;

	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + obuf_len;

	if (obuf_len < 1) {
		return NULL;
	}

	const bool be = r_bin_is_big_endian (bin);

	// https://www.dwarfstd.org/doc/DWARF4.pdf#page=161http://www.dwarfstd.org/doc/DWARF4.pdf#page=161&zoom=100,0,560zoom=100,0,560
	switch (def->attr_form) {
	case DW_FORM_addr:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = dwarf_read_index (buf, buf_end, be, hdr->address_size, &value->address);
		if (!buf) {
			R_LOG_WARN ("DWARF: Unexpected pointer size: %u", (unsigned)hdr->address_size);
			return NULL;
		}
		if (!dwarf_relocate_address (bf, value->address, &value->address)) {
			return NULL;
		}
		break;
	case DW_FORM_data1:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->uconstant);
		break;
	case DW_FORM_data2:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_index (buf, buf_end, be, 2, &value->uconstant);
		break;
	case DW_FORM_data4:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->uconstant);
		break;
	case DW_FORM_data8:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_index (buf, buf_end, be, 8, &value->uconstant);
		break;
	case DW_FORM_data16: // TODO Fix this, right now I just read the data, but I need to make storage for it
		value->kind = DW_AT_KIND_CONSTANT;
		if ((size_t)(buf_end - buf) < 16) {
			return NULL;
		}
		value->uconstant = r_read_ble64 (buf + 8, be);
		buf += 16;
		break;
	case DW_FORM_sdata:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_sleb (buf, buf_end, &value->sconstant);
		break;
	case DW_FORM_udata:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->uconstant);
		break;
	case DW_FORM_string:
		value->kind = DW_AT_KIND_STRING;
		size_t available = buf_end - buf;
		if (available < 1 || available > ST32_MAX) {
			return NULL;
		}
		size_t slen = r_str_nlen ((const char *)buf, (int)available);
		if (slen >= available) {
			return NULL;
		}
		if (slen > 0) {
			// go programs contain multibyte chars in the symbol names and strings we dont want to strip them here
			value->string.content = (const char *)buf;
		} else {
			value->string.content = NULL;
		}
		buf += slen + 1;
		break;
	case DW_FORM_block1:
		value->kind = DW_AT_KIND_BLOCK;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->block.length);
		if (!buf) {
			return NULL;
		}
		if (value->block.length > 0) {
			size_t available = buf_end - buf;
			if (value->block.length <= available) {
				value->block.data = buf;
				buf += value->block.length;
			} else {
				R_LOG_WARN ("not enough to fill block1: have %zu but need %zu", available, value->block.length);
				return NULL;
			}
		} else {
			value->block.data = NULL;
		}
		break;
	case DW_FORM_block2:
		value->kind = DW_AT_KIND_BLOCK;
		ut64 block2_length;
		buf = dwarf_read_index (buf, buf_end, be, 2, &block2_length);
		if (!buf || block2_length > SIZE_MAX) {
			return NULL;
		}
		size_t len = (size_t)block2_length;
		if (len > 0) {
			size_t len_buf = buf_end - buf;
			if (len > len_buf) {
				return NULL;
			}
			value->block.data = r_mem_dup (buf, len);
			if (!value->block.data) {
				return NULL;
			}
			buf += len;
			value->block.length = len;
		} else {
			value->block.length = 0;
		}
		break;
	case DW_FORM_block4:
		value->kind = DW_AT_KIND_BLOCK;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->block.length);
		if (!buf) {
			return NULL;
		}
		if (value->block.length > 0) {
			size_t available = buf_end - buf;
			if (value->block.length <= available) {
				value->block.data = buf;
				buf += value->block.length;
			} else {
				R_LOG_WARN ("not enough to fill block4: have %zu but need %zu", available, value->block.length);
				return NULL;
			}
		} else {
			value->block.data = NULL;
		}
		break;
	case DW_FORM_block: // variable length ULEB128
		value->kind = DW_AT_KIND_BLOCK;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->block.length);
		if (!buf) {
			return NULL;
		}
		if (value->block.length > 0) {
			size_t available = buf_end - buf;
			if (value->block.length <= available) {
				value->block.data = buf;
				buf += value->block.length;
			} else {
				R_LOG_WARN ("not enough to fill block: have %zu but need %zu", available, value->block.length);
				return NULL;
			}
		} else {
			value->block.data = NULL;
		}
		break;
	case DW_FORM_flag:
		value->kind = DW_AT_KIND_FLAG;
		ut64 flag;
		buf = dwarf_read_index (buf, buf_end, be, 1, &flag);
		if (!buf) {
			return NULL;
		}
		value->flag = (ut8)flag;
		break;
	// offset in .debug_str
	case DW_FORM_strp:
	case DW_FORM_line_strp:
		value->kind = DW_AT_KIND_STRING;
		buf = dwarf_read_index (buf, buf_end, be, hdr->is_64bit? 8: 4,
			&value->string.offset);
		if (!buf || value->string.offset > SIZE_MAX) {
			return NULL;
		}
		RBinSection *section = (def->attr_form == DW_FORM_strp)
			? dwarf_get_section (bf, DWARF_SN_STR)
			: dwarf_get_section (bf, DWARF_SN_LINE_STR);
		const char *str = section? dwarf_get_section_string (bf, section, (size_t)value->string.offset): NULL;
		value->string.content = str;
		break;
	// offset in .debug_info
	case DW_FORM_ref_addr:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, hdr->is_64bit? 8: 4, &value->reference);
		break;
	// This type of reference is an offset from the first byte of the compilation
	// header for the compilation unit containing the reference
	case DW_FORM_ref1:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_ref2:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 2, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_ref4:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_ref8:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 8, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_ref_udata:
		value->kind = DW_AT_KIND_REFERENCE;
		// uleb128 is enough to fit into ut64?
		buf = dwarf_read_uleb_index (buf, buf_end, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	// offset in a section other than .debug_info or .debug_str
	case DW_FORM_sec_offset:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, hdr->is_64bit? 8: 4, &value->reference);
		break;
	case DW_FORM_exprloc:
		value->kind = DW_AT_KIND_BLOCK;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->block.length);
		if (!buf) {
			return NULL;
		}
		buf = fill_block_data (buf, buf_end, &value->block);
		break;
	// this means that the flag is present, nothing is read
	case DW_FORM_flag_present:
		value->kind = DW_AT_KIND_FLAG;
		value->flag = true;
		break;
	case DW_FORM_ref_sig8:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 8, &value->reference);
		break;
	// Index into .debug_str_offsets. Resolve after the CU base attributes are known.
	case DW_FORM_strx:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->string.offset);
		break;
	case DW_FORM_strx1:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->string.offset);
		break;
	case DW_FORM_strx2:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 2, &value->string.offset);
		break;
	case DW_FORM_strx3:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 3, &value->string.offset);
		break;
	case DW_FORM_strx4:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->string.offset);
		break;
	case DW_FORM_implicit_const:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = def->special;
		break;
	/*  addrx* forms : The index is relative to the value of the
		DW_AT_addr_base attribute of the associated compilation unit.
	index into an array of addresses in the .debug_addr section.*/
	case DW_FORM_addrx:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->address);
		break;
	case DW_FORM_addrx1:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->address);
		break;
	case DW_FORM_addrx2:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 2, &value->address);
		break;
	case DW_FORM_addrx3:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 3, &value->address);
		break;
	case DW_FORM_addrx4:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->address);
		break;
	case DW_FORM_strp_sup: // offset in a section .debug_line_str
		value->kind = DW_AT_KIND_STRING;
		buf = dwarf_read_index (buf, buf_end, be, hdr->is_64bit? 8: 4,
			&value->string.offset);
		// if (debug_str && value->string.offset < debug_line_str_len) {
		// 	value->string.content =
		// 		strdupsts
		break;
	// offset in the supplementary object file
	case DW_FORM_ref_sup4:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->reference);
		break;
	case DW_FORM_ref_sup8:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 8, &value->reference);
		break;
	// An index into the .debug_loc
	case DW_FORM_loclistx:
		value->kind = DW_AT_KIND_LOCLIST_INDEX;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->reference);
		break;
		// An index into the .debug_rnglists
	case DW_FORM_rnglistx:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->address);
		break;
	case 0:
		value->uconstant = 0;
		return NULL;
		// TODO: handle DW_FORM_indirect
	default:
		R_LOG_WARN ("Unknown DW_FORM 0x%02" PFMT64x, def->attr_form);
		value->uconstant = 0;
		return NULL;
	}
	if (!buf || buf > buf_end) {
		return NULL;
	}
	return buf;
}

static void dwarf_metadata_set_comp_dir(RBinFile *bf, ut64 debug_line_offset, bool has_debug_line_offset, const char *comp_dir);

static void dwarf_comp_unit_save_comp_dir(RBinFile *bf, RBinDwarfCompUnit *unit) {
	R_RETURN_IF_FAIL (bf && unit && unit->dies);
	RBinDwarfDie *root = RVecDwarfDie_at (unit->dies, 0);
	if (!root || !root->attr_values) {
		return;
	}
	const char *comp_dir = NULL;
	ut64 debug_line_offset = 0;
	bool has_debug_line_offset = false;
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (root->attr_values, value) {
		if (value->attr_name == DW_AT_comp_dir && value->kind == DW_AT_KIND_STRING) {
			comp_dir = value->string.content;
		} else if (value->attr_name == DW_AT_stmt_list
			&& (value->kind == DW_AT_KIND_REFERENCE
				|| value->attr_form == DW_FORM_data4
				|| value->attr_form == DW_FORM_data8)) {
			debug_line_offset = value->reference;
			has_debug_line_offset = true;
		}
	}
	if (!comp_dir) {
		return;
	}
	dwarf_metadata_set_comp_dir (bf, debug_line_offset,
		has_debug_line_offset, comp_dir);
}

#if 0
* @brief
*
* @param buf Start of the DIE data
* @param buf_end
* @param abbrev Abbreviation of the DIE
* @param hdr Unit header
* @param die DIE to store the parsed info into
* @return const ut8* Updated buffer
#endif
static const ut8 *parse_die(RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfAbbrevDecl *abbrev, RBinDwarfCompUnitHdr *hdr, RBinDwarfDie *die) {
	if (!buf || !buf_end || buf > buf_end) {
		return NULL;
	}
	RBinDwarfAttrDef *def;
	R_VEC_FOREACH (abbrev->defs, def) {
		if (!def->attr_name && !def->attr_form) {
			break;
		}
		RBinDwarfAttrValue value = { 0 };
		const ut8 *nbuf = parse_attr_value (bf, buf, buf_end - buf, def, &value, hdr);
		if (!nbuf) {
			attr_value_fini (&value);
			return NULL;
		}
		buf = nbuf;

		if (die->attr_values) {
			RVecDwarfAttrValue_push_back (die->attr_values, &value);
		} else {
			attr_value_fini (&value);
		}
	}
	return buf;
}

#if 0
* @brief Reads throught comp_unit buffer and parses all its DIEntries
*
* @param sdb
* @param buf_start Start of the compilation unit data
* @param buf_end End of the compilation unit data
* @param unit Unit to store the newly parsed information
* @param abbrevs Parsed abbrev section info of *all* abbreviations
* @param first_abbr_idx index for first abbrev of the current comp unit in abbrev array
* @param be big endian flag
*
* @return const ut8* Update buffer
#endif
static const ut8 *parse_comp_unit(RBinFile *bf, const ut8 *buf_start, const ut8 *buf_end, RBinDwarfCompUnit *unit, const RVecDwarfAbbrevDecl *abbrevs, size_t first_abbr_idx) {
	const ut8 *buf = buf_start;
	size_t abbrevs_count = RVecDwarfAbbrevDecl_length (abbrevs);
	int child_depth = 0;
	bool has_root = false;
	while (buf && buf < buf_end && buf >= buf_start) {
		if (dwarf_is_breaked (bf->rbin)) {
			return NULL;
		}
		RBinDwarfDie die = { 0 };
		// add header size to the offset;
		die.offset = buf - buf_start + unit->hdr.header_size + unit->offset;
		die.offset += unit->hdr.is_64bit? 12: 4;

		// DIE starts with ULEB128 with the abbreviation code
		ut64 abbr_code = 0;
		buf = dwarf_read_uleb_index (buf, buf_end, &abbr_code);

		if (abbr_code > abbrevs_count || !buf) { // something invalid
			return NULL;
		}
		if (buf == buf_end && abbr_code) {
			return NULL;
		}

		// there can be "null" entries that have abbr_code == 0
		if (!abbr_code) {
			if (!has_root || child_depth <= 0) {
				return NULL;
			}
			RVecDwarfDie_push_back (unit->dies, &die);
			child_depth--;
			continue;
		}
		if (has_root && child_depth <= 0) {
			return NULL;
		}
		if (abbr_code > UT64_MAX - first_abbr_idx) {
			return NULL;
		}
		ut64 abbr_idx = first_abbr_idx + abbr_code;
		if (abbrevs_count < abbr_idx) {
			return NULL;
		}

		RBinDwarfAbbrevDecl *abbrev = RVecDwarfAbbrevDecl_at (abbrevs, abbr_idx - 1);
		if (!abbrev || !abbrev->defs) {
			return NULL;
		}

		size_t attr_count = RVecDwarfAttrDef_length (abbrev->defs);
		if (attr_count > 0) {
			RBinDwarfAttrDef *last = RVecDwarfAttrDef_at (abbrev->defs, attr_count - 1);
			if (last && !last->attr_name && !last->attr_form) {
				attr_count--;
			}
		}
		if (!init_die (bf->arena, &die, abbr_code, attr_count)) {
			return NULL; // error
		}
		die.tag = abbrev->tag;
		die.has_children = abbrev->has_children;

		buf = parse_die (bf, buf, buf_end, abbrev, &unit->hdr, &die);
		if (!buf) {
			dwarf_die_fini (&die);
			return NULL;
		}
		bool has_children = die.has_children;
		RVecDwarfDie_push_back (unit->dies, &die);
		has_root = true;
		if (has_children) {
			child_depth++;
		}
	}
	if (buf != buf_end || !has_root || child_depth != 0) {
		return NULL;
	}
	if (dwarf_resolve_comp_unit_indexes (bf, unit)
			== DWARF_INDEX_RESOLUTION_MALFORMED) {
		return NULL;
	}
	dwarf_comp_unit_save_comp_dir (bf, unit);
	return buf;
}

static bool dwarf_supported_address_size(ut8 address_size) {
	switch (address_size) {
	case 1:
	case 2:
	case 3:
	case 4:
	case 8:
		return true;
	}
	return false;
}

#if 0
* @brief Reads all information about compilation unit header
*
* @param buf Start of the buffer
* @param buf_end Upper bound of the buffer
* @param unit Unit to read information into
* @return ut8* Advanced position in a buffer
#endif
static const ut8 *info_comp_unit_read_hdr(RBin *bin, const ut8 *buf, const ut8 *buf_end, RBinDwarfCompUnitHdr *hdr) {
	// 32-bit vs 64-bit dwarf formats
	// https://www.dwarfstd.org/doc/Dwarf3.pdf section 7.4
	R_RETURN_VAL_IF_FAIL (bin && buf && buf_end && hdr && buf <= buf_end, NULL);
	bool be = r_bin_is_big_endian (bin);
	buf = dwarf_read_index (buf, buf_end, be, 4, &hdr->length);
	if (!buf) {
		return NULL;
	}
	if (hdr->length == (ut32)DWARF_INIT_LEN_64) { // then its 64bit
		buf = dwarf_read_index (buf, buf_end, be, 8, &hdr->length);
		if (!buf) {
			return NULL;
		}
		hdr->is_64bit = true;
	}
	const ut8 *tmp = buf; // to calculate header size
	ut64 value;
	buf = dwarf_read_index (buf, buf_end, be, 2, &value);
	if (!buf) {
		return NULL;
	}
	hdr->version = (ut16)value;
	if (hdr->version == 5) {
		buf = dwarf_read_index (buf, buf_end, be, 1, &value);
		if (!buf) {
			return NULL;
		}
		hdr->unit_type = (ut8)value;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value);
		if (!buf) {
			return NULL;
		}
		hdr->address_size = (ut8)value;
		ut8 offset_size = hdr->is_64bit? 8: 4;
		buf = dwarf_read_index (buf, buf_end, be, offset_size, &hdr->abbrev_offset);
		if (!buf) {
			return NULL;
		}

		if (hdr->unit_type == DW_UT_skeleton || hdr->unit_type == DW_UT_split_compile) {
			buf = dwarf_read_index (buf, buf_end, be, 8, &value);
			if (!buf) {
				return NULL;
			}
			hdr->dwo_id = value;
		} else if (hdr->unit_type == DW_UT_type || hdr->unit_type == DW_UT_split_type) {
			buf = dwarf_read_index (buf, buf_end, be, 8, &hdr->type_sig);
			if (!buf) {
				return NULL;
			}
			buf = dwarf_read_index (buf, buf_end, be, offset_size, &hdr->type_offset);
			if (!buf) {
				return NULL;
			}
		}
	} else {
		ut8 offset_size = hdr->is_64bit? 8: 4;
		buf = dwarf_read_index (buf, buf_end, be, offset_size, &hdr->abbrev_offset);
		if (!buf) {
			return NULL;
		}
		buf = dwarf_read_index (buf, buf_end, be, 1, &value);
		if (!buf) {
			return NULL;
		}
		hdr->address_size = (ut8)value;
	}
	hdr->header_size = buf - tmp; // header size excluding length field
	return buf;
}

static void dwarf_metadata_set_comp_dir(RBinFile *bf, ut64 debug_line_offset, bool has_debug_line_offset, const char *comp_dir) {
	if (!bf || !comp_dir) {
		return;
	}
	char *dir = strdup (comp_dir);
	if (!dir) {
		return;
	}
	if (has_debug_line_offset) {
		if (!bf->dwarf_metadata.comp_dirs) {
			bf->dwarf_metadata.comp_dirs = ht_up_new (NULL, free_comp_dir_entry, NULL);
			if (!bf->dwarf_metadata.comp_dirs) {
				free (dir);
				return;
			}
		}
		if (!ht_up_update (bf->dwarf_metadata.comp_dirs, debug_line_offset, dir)) {
			free (dir);
		}
		return;
	}
	free (bf->dwarf_metadata.comp_dir);
	bf->dwarf_metadata.comp_dir = dir;
}

typedef bool (*DwarfRootCallback)(RBinFile *bf, const RBinDwarfCompUnit *unit, void *user);

static bool dwarf_parse_root_die(RBinFile *bf, const ut8 *buf, const ut8 *unit_end, RBinDwarfCompUnit *unit, const RVecDwarfAbbrevDecl *decls, size_t first_abbr_idx) {
	R_RETURN_VAL_IF_FAIL (bf && buf && unit_end && unit && unit->dies && decls
		&& buf < unit_end, false);
	size_t abbrevs_count = RVecDwarfAbbrevDecl_length (decls);
	ut64 abbr_code = 0;
	const ut8 *attrs = dwarf_read_uleb_index (buf, unit_end, &abbr_code);
	if (!attrs || !abbr_code || abbr_code > UT64_MAX - first_abbr_idx) {
		return false;
	}
	ut64 abbr_idx = first_abbr_idx + abbr_code;
	if (!abbr_idx || abbr_idx > abbrevs_count) {
		return false;
	}
	RBinDwarfAbbrevDecl *abbrev = RVecDwarfAbbrevDecl_at (decls, abbr_idx - 1);
	if (!abbrev || (abbrev->tag != DW_TAG_compile_unit
			&& abbrev->tag != DW_TAG_partial_unit
			&& abbrev->tag != DW_TAG_type_unit
			&& abbrev->tag != DW_TAG_skeleton_unit)) {
		return false;
	}
	size_t attr_count = RVecDwarfAttrDef_length (abbrev->defs);
	if (attr_count) {
		RBinDwarfAttrDef *last = RVecDwarfAttrDef_at (abbrev->defs, attr_count - 1);
		if (last && !last->attr_name && !last->attr_form) {
			attr_count--;
		}
	}
	RBinDwarfDie die = { 0 };
	if (!init_die (bf->arena, &die, abbr_code, attr_count)) {
		return false;
	}
	die.offset = unit->offset + (unit->hdr.is_64bit? 12: 4)
		+ unit->hdr.header_size;
	die.tag = abbrev->tag;
	die.has_children = abbrev->has_children;
	if (!parse_die (bf, attrs, unit_end, abbrev, &unit->hdr, &die)) {
		dwarf_die_fini (&die);
		return false;
	}
	RVecDwarfDie_push_back (unit->dies, &die);
	if (dwarf_resolve_comp_unit_indexes (bf, unit)
		== DWARF_INDEX_RESOLUTION_MALFORMED) {
		return false;
	}
	dwarf_comp_unit_save_comp_dir (bf, unit);
	return true;
}

static bool dwarf_foreach_root(RBinFile *bf, RVecDwarfAbbrevDecl *decls, DwarfRootCallback callback, void *user) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && decls, false);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_INFO);
	const ut8 *data = section? dwarf_get_section_bytes (bf, section): NULL;
	if (!data || !section->bytes.len) {
		return false;
	}
	const ut8 *buf = data;
	const ut8 *end = data + section->bytes.len;
	while (buf < end && !dwarf_is_breaked (bf->rbin)) {
		if (dwarf_is_zero_padding (buf, end)) {
			return true;
		}
		RBinDwarfCompUnit unit = { 0 };
		if (!init_comp_unit (&unit)) {
			return false;
		}
		const ut8 *unit_start = buf;
		unit.offset = unit_start - data;
		unit.hdr.unit_offset = unit.offset;
		buf = info_comp_unit_read_hdr (bf->rbin, buf, end, &unit.hdr);
		size_t len_size = unit.hdr.is_64bit? 12: 4;
		size_t remaining = end - unit_start;
		if (!buf || remaining < len_size || unit.hdr.length < unit.hdr.header_size
			|| unit.hdr.length > remaining - len_size) {
			// The next unit boundary is unknown, so keep only the units visited so far.
			dwarf_comp_unit_fini (&unit);
			return true;
		}
		const ut8 *unit_end = unit_start + len_size + unit.hdr.length;
		if (!dwarf_supported_address_size (unit.hdr.address_size)) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		RBinDwarfAbbrevDecl *abbrev_start = abbrev_find (decls, unit.hdr.abbrev_offset);
		if (!abbrev_start || !dwarf_parse_root_die (bf, buf, unit_end, &unit,
				decls, abbrev_start - decls->_start)) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		if (callback && !callback (bf, &unit, user)) {
			dwarf_comp_unit_fini (&unit);
			return false;
		}
		dwarf_comp_unit_fini (&unit);
		buf = unit_end;
	}
	return buf == end && !dwarf_is_breaked (bf->rbin);
}

R_API bool r_bin_dwarf_parse_comp_dirs(RBinFile *bf, RVecDwarfAbbrevDecl *decls) {
	return dwarf_foreach_root (bf, decls, NULL, NULL);
}

static const char *attr_value_string(const RBinDwarfAttrValue *value) {
	if (!value || value->kind != DW_AT_KIND_STRING) {
		return NULL;
	}
	switch (value->attr_form) {
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_strp:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
	case DW_FORM_string:
		return value->string.content;
	default:
		return NULL;
	}
}

typedef struct {
	RList *files;
	HtPP *seen;
} DwarfSourceFilesContext;

static bool dwarf_collect_source_file(RBinFile *bf, const RBinDwarfCompUnit *unit, void *user) {
	(void)bf;
	DwarfSourceFilesContext *ctx = user;
	R_RETURN_VAL_IF_FAIL (ctx && ctx->files && ctx->seen && unit && unit->dies, false);
	RBinDwarfDie *root = RVecDwarfDie_at (unit->dies, 0);
	if (!root || !root->attr_values) {
		return true;
	}
	const char *comp_dir = NULL;
	const char *name = NULL;
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (root->attr_values, value) {
		const char *string_value = attr_value_string (value);
		if (value->attr_name == DW_AT_comp_dir && string_value) {
			comp_dir = string_value;
		} else if (value->attr_name == DW_AT_name && string_value) {
			name = string_value;
		}
	}
	if (!name) {
		return true;
	}
	char *path = (r_file_is_abspath (name) || !comp_dir)
		? strdup (name): r_str_newf ("%s/%s", comp_dir, name);
	dwarf_line_files_add (ctx->files, ctx->seen, path);
	free (path);
	return true;
}

R_API RList *r_bin_dwarf_parse_comp_unit_files(RBinFile *bf, RVecDwarfAbbrevDecl *decls) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && decls, NULL);
	RList *files = r_list_newf (free);
	HtPP *seen = ht_pp_new0 ();
	if (!files || !seen) {
		r_list_free (files);
		ht_pp_free (seen);
		return NULL;
	}
	DwarfSourceFilesContext ctx = {
		.files = files,
		.seen = seen,
	};
	if (!dwarf_foreach_root (bf, decls, dwarf_collect_source_file, &ctx)) {
		r_list_free (files);
		ht_pp_free (seen);
		return NULL;
	}
	ht_pp_free (seen);
	return files;
}

R_API R_OWNED char *r_bin_dwarf_print_info(RBinFile *bf, RVecDwarfAbbrevDecl *decls) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && decls, NULL);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_INFO);
	if (!section) {
		return NULL;
	}
	const ut8 *obuf = dwarf_get_section_bytes (bf, section);
	if (!obuf || section->bytes.len < 1 || section->bytes.len > (UT32_MAX >> 1)) {
		return NULL;
	}
	RBin *bin = bf->rbin;
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + section->bytes.len;
	RStrBuf *sb = r_strbuf_new (NULL);
	while (buf && buf < buf_end && !dwarf_is_breaked (bin)) {
		if (dwarf_is_zero_padding (buf, buf_end)) {
			buf = buf_end;
			break;
		}
		RBinDwarfCompUnit unit = { 0 };
		if (!init_comp_unit (&unit)) {
			goto cleanup;
		}
		const ut8 *unit_start = buf;
		unit.offset = unit_start - obuf;
		unit.hdr.unit_offset = unit.offset;
		buf = info_comp_unit_read_hdr (bin, buf, buf_end, &unit.hdr);
		if (!buf || buf > buf_end) {
			dwarf_comp_unit_fini (&unit);
			goto cleanup;
		}
		size_t len_size = unit.hdr.is_64bit? 12: 4;
		size_t remaining = buf_end - unit_start;
		if (remaining < len_size || unit.hdr.length < unit.hdr.header_size
			|| unit.hdr.length > remaining - len_size) {
			dwarf_comp_unit_fini (&unit);
			goto cleanup;
		}
		const ut8 *unit_end = unit_start + len_size + unit.hdr.length;
		if (!dwarf_supported_address_size (unit.hdr.address_size)) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		RBinDwarfAbbrevDecl *abbrev_start = abbrev_find (decls, unit.hdr.abbrev_offset);
		if (!abbrev_start) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		size_t first_abbr_idx = abbrev_start - decls->_start;
		if (!parse_comp_unit (bf, buf, unit_end, &unit, decls,
				first_abbr_idx)) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		dwarf_print_comp_unit (&unit, sb);
		dwarf_comp_unit_fini (&unit);
		buf = unit_end;
	}
	return r_strbuf_drain (sb);
cleanup:
	r_strbuf_free (sb);
	return NULL;
}

#if 0
* @brief Parses whole .debug_info section
*
* @param sdb Sdb to store line related information into
* @param da Parsed Abbreviations
* @param obuf .debug_info section buffer start
* @param len length of the section buffer
* @param be big endian flag
* @return R_API* parse_info_raw Parsed information
#endif
static RBinDwarfDebugInfo *parse_info_raw(RBinFile *bf, RVecDwarfAbbrevDecl *decls, const ut8 *obuf, size_t len) {
	R_RETURN_VAL_IF_FAIL (bf && decls && obuf, false);
	RBin *bin = bf->rbin;
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;
	RBinDwarfDebugInfo *info = R_NEW0 (RBinDwarfDebugInfo);
	if (!init_debug_info (info)) {
		goto cleanup;
	}

	while (buf < buf_end) {
		if (dwarf_is_zero_padding (buf, buf_end)) {
			break;
		}
		RBinDwarfCompUnit unit = { 0 };
		if (!init_comp_unit (&unit)) {
			goto cleanup;
		}
		const ut8 *unit_start = buf;
		unit.offset = buf - obuf;
		// small redundancy, because it was easiest solution at a time
		unit.hdr.unit_offset = buf - obuf;

		buf = info_comp_unit_read_hdr (bin, buf, buf_end, &unit.hdr);
		size_t len_size = unit.hdr.is_64bit? 12: 4;
		size_t remaining = buf_end - unit_start;
		if (!buf || remaining < len_size || unit.hdr.length < unit.hdr.header_size
			|| unit.hdr.length > remaining - len_size) {
			R_LOG_WARN ("Invalid DWARF compilation unit header at 0x%" PFMT64x, unit.offset);
			dwarf_comp_unit_fini (&unit);
			break;
		}
		const ut8 *unit_end = unit_start + len_size + unit.hdr.length;
		if (!dwarf_supported_address_size (unit.hdr.address_size)) {
			R_LOG_WARN ("Unsupported DWARF address size %u in compilation unit at 0x%" PFMT64x,
				(unsigned)unit.hdr.address_size, unit.offset);
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}

		// find abbrev start for current comp unit
		// we could also do naive, ((char *)da->decls) + abbrev_offset,
		// but this is more bulletproof to invalid DWARF
		RBinDwarfAbbrevDecl *abbrev_start = abbrev_find (decls, unit.hdr.abbrev_offset);
		if (!abbrev_start) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		// They point to the same array object, so should be def. behaviour
		size_t first_abbr_idx = abbrev_start - decls->_start;

		buf = parse_comp_unit (bf, buf, unit_end, &unit, decls, first_abbr_idx);
		if (!buf) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		buf = unit_end;

		RVecDwarfCompUnit_push_back (info->comp_units, &unit);
	}
	return info;
cleanup:
	r_bin_dwarf_free_debug_info (info);
	return NULL;
}

static const char *getstr(RBinDwarfAttrValue *val) {
	switch (val->attr_form) {
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_strp:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
	case DW_FORM_string:
		return val->string.content;
	}
	return NULL;
}

static ut64 getint(RBinDwarfAttrValue *val) {
	switch (val->attr_form) {
	case DW_FORM_addr:
	case DW_FORM_addrx:
	case DW_FORM_addrx1:
	case DW_FORM_addrx2:
	case DW_FORM_addrx3:
	case DW_FORM_addrx4:
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		return val->address;
	case DW_FORM_implicit_const:
		return val->uconstant;
	}
	return 0;
}

#if 0
* @brief Parses .debug_info section
*
* @param da Parsed abbreviations
* @param bin
* @return RBinDwarfDebugInfo* Parsed information, NULL if error
#endif

R_API RBinDwarfDebugInfo *r_bin_dwarf_parse_info(RBinFile *bf, RVecDwarfAbbrevDecl *da) {
	R_RETURN_VAL_IF_FAIL (da && bf, NULL);
	RBin *bin = bf->rbin;
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_INFO);

	if (!bin || !section) {
		return NULL;
	}
	/* Read and possibly decompress the .debug_info section */
	const ut8 *buf = dwarf_get_section_bytes (bf, section);
	if (!buf || section->size < 1 || section->size > (UT32_MAX >> 1)) {
		return NULL;
	}
	RBinDwarfDebugInfo *info = parse_info_raw (bf, da, buf, section->bytes.len);
	if (!info) {
		return NULL;
	}

	// TODO: load compilation units
	// TODO: only necessary when we have no srcline inf
	// TODO: add a command to enumerate the ranges for all the compilation units
	// TODO: idu? -> 0x00001600 0x0001840 entry.S
	RBinDwarfCompUnit *unit;
	R_VEC_FOREACH (info->comp_units, unit) {
		RBinDwarfDie *die;
		R_VEC_FOREACH (unit->dies, die) {
			const char *name = NULL;
			const char *path = NULL;
			ut64 low = 0;

			if (!die->attr_values) {
				continue;
			}
			RBinDwarfAttrValue *v;
			R_VEC_FOREACH (die->attr_values, v) {
				int n = v->attr_name;
				switch (n) {
				case DW_AT_name:
					name = getstr (v);
					break;
				case DW_AT_comp_dir:
					path = getstr (v);
					break;
				case DW_AT_low_pc:
					low = getint (v);
					break;
				case DW_AT_high_pc:
					// hig = getint (v);
					break;
				}
			}
			if (path && name) {
				char *abspath = (*name != '/')? r_str_newf ("%s/%s", path, name): strdup (name);
				// TODO: add compilation unit callback here
				bf->addrline.al_add_cu (&bf->addrline, low + 1, abspath, NULL, 0, 0);
				free (abspath);
			}
		}
	}

	// build hashtable after whole parsing because of possible relocations
	size_t dies_count = 0;
	R_VEC_FOREACH (info->comp_units, unit) {
		RBinDwarfDie *die;
		R_VEC_FOREACH (unit->dies, die) {
			dies_count += 1;
		}
	}

	info->lookup_table = ht_up_new_size (dies_count + dies_count / 3, NULL, NULL, NULL);
	R_VEC_FOREACH (info->comp_units, unit) {
		RBinDwarfDie *die;
		R_VEC_FOREACH (unit->dies, die) {
			ht_up_insert (info->lookup_table, die->offset, die); // optimization for further processing}
		}
	}

	return info;
}
