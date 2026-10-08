/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"

static bool dwarf_form_is_strx(ut64 form) {
	return form == DW_FORM_strx || (form >= DW_FORM_strx1 && form <= DW_FORM_strx4);
}

static bool dwarf_form_is_addrx(ut64 form) {
	return form == DW_FORM_addrx || (form >= DW_FORM_addrx1 && form <= DW_FORM_addrx4);
}

R_IPI bool dwarf_index_entry_offset(ut64 base, ut64 index, ut8 entry_size, size_t section_size, size_t *entry_offset) {
	R_RETURN_VAL_IF_FAIL (entry_offset, false);
	if (!entry_size || index > (UT64_MAX - base) / entry_size) {
		return false;
	}
	ut64 offset = base + index * entry_size;
	if (offset > SIZE_MAX || offset > section_size || entry_size > section_size - (size_t)offset) {
		return false;
	}
	*entry_offset = (size_t)offset;
	return true;
}

R_IPI bool dwarf_index_contribution_end(const ut8 *data, size_t size, bool be, ut64 base, bool is_64bit, bool is_address_table, ut8 address_size, size_t *contribution_end) {
	R_RETURN_VAL_IF_FAIL (data && contribution_end, false);
	const size_t header_size = is_64bit? 16: 8;
	if (base > SIZE_MAX || base < header_size || (size_t)base > size) {
		return false;
	}
	size_t header = (size_t)base - header_size;
	if (header > size || header_size > size - header) {
		return false;
	}
	ut64 length;
	size_t length_size;
	size_t fields_offset;
	if (is_64bit) {
		if (r_read_ble32 (data + header, be) != DWARF_INIT_LEN_64) {
			return false;
		}
		length = r_read_ble64 (data + header + 4, be);
		length_size = 12;
		fields_offset = header + 12;
	} else {
		length = r_read_ble32 (data + header, be);
		if (length == DWARF_INIT_LEN_64) {
			return false;
		}
		length_size = 4;
		fields_offset = header + 4;
	}
	if (length > SIZE_MAX || (size_t)length > size - header - length_size) {
		return false;
	}
	size_t end = header + length_size + (size_t)length;
	if (r_read_ble16 (data + fields_offset, be) != 5) {
		return false;
	}
	if (is_address_table) {
		if (data[fields_offset + 2] != address_size || data[fields_offset + 3] != 0) {
			return false;
		}
	} else if (r_read_ble16 (data + fields_offset + 2, be) != 0) {
		return false;
	}
	if ((size_t)base > end) {
		return false;
	}
	*contribution_end = end;
	return true;
}

static bool dwarf_string_offsets_contribution(const ut8 *data, size_t section_size, bool be, ut64 contribution_offset, ut64 contribution_size, ut64 *base, size_t *end, ut8 *entry_size) {
	R_RETURN_VAL_IF_FAIL (data && base && end && entry_size, false);
	if (contribution_offset > SIZE_MAX || contribution_size > SIZE_MAX
		|| contribution_offset > section_size
		|| contribution_size > section_size - (size_t)contribution_offset
		|| contribution_size < 4) {
		return false;
	}
	size_t start = (size_t)contribution_offset;
	size_t limit = start + (size_t)contribution_size;
	bool is_64bit = r_read_ble32 (data + start, be) == DWARF_INIT_LEN_64;
	*base = contribution_offset + (is_64bit? 16: 8);
	*entry_size = is_64bit? 8: 4;
	if (!dwarf_index_contribution_end (data, limit, be, *base,
			is_64bit, false, 0, end)) {
		return false;
	}
	return *end == limit || dwarf_is_zero_padding (data + *end, data + limit);
}

static bool dwarf_string_offsets_base(const ut8 *data, size_t section_size, bool be, ut64 base, size_t *end, ut8 *entry_size) {
	R_RETURN_VAL_IF_FAIL (data && end && entry_size, false);
	if (base > SIZE_MAX || base > section_size) {
		return false;
	}
	if (base >= 16 && r_read_ble32 (data + (size_t)base - 16, be) == DWARF_INIT_LEN_64
		&& dwarf_index_contribution_end (data, section_size, be, base,
			true, false, 0, end)) {
		*entry_size = 8;
		return true;
	}
	if (dwarf_index_contribution_end (data, section_size, be, base,
			false, false, 0, end)) {
		*entry_size = 4;
		return true;
	}
	return false;
}

R_IPI bool dwarf_address_base(const ut8 *data, size_t section_size, bool be,
		ut64 base, ut8 address_size, size_t *end) {
	R_RETURN_VAL_IF_FAIL (data && end, false);
	if (base > SIZE_MAX || base > section_size) {
		return false;
	}
	if (base >= 16 && r_read_ble32 (data + (size_t)base - 16, be) == DWARF_INIT_LEN_64
		&& dwarf_index_contribution_end (data, section_size, be, base,
			true, true, address_size, end)) {
		return true;
	}
	return dwarf_index_contribution_end (data, section_size, be, base,
		false, true, address_size, end);
}

// a DWARF 5 sec_offset location points into .debug_loclists, not .debug_loc
static inline bool dwarf_attr_is_loclist5(const RBinDwarfCompUnit *unit, const RBinDwarfAttrValue *value) {
	return unit->hdr.version >= 5 && value->attr_form == DW_FORM_sec_offset
		&& value->kind == DW_AT_KIND_REFERENCE
		&& (value->attr_name == DW_AT_location || value->attr_name == DW_AT_frame_base);
}

R_IPI bool dwarf_comp_unit_index_bases(const RBinDwarfCompUnit *unit, bool need_str, bool need_addr, bool need_loclists, ut64 *str_base, bool *has_str_base, ut64 *addr_base, bool *has_addr_base, ut64 *loclists_base, bool *has_loclists_base) {
	R_RETURN_VAL_IF_FAIL (unit && unit->dies && str_base && has_str_base
		&& addr_base && has_addr_base && loclists_base && has_loclists_base, false);
	*has_str_base = false;
	*has_addr_base = false;
	*has_loclists_base = false;
	if (!need_str && !need_addr && !need_loclists) {
		return true;
	}
	RBinDwarfDie *root = RVecDwarfDie_at (unit->dies, 0);
	if (!root || !root->attr_values || (root->tag != DW_TAG_compile_unit
			&& root->tag != DW_TAG_partial_unit && root->tag != DW_TAG_type_unit
			&& root->tag != DW_TAG_skeleton_unit)) {
		return false;
	}
	bool bad_loclists_base = false;
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (root->attr_values, value) {
		if (value->attr_name == DW_AT_str_offsets_base) {
			if (*has_str_base || value->attr_form != DW_FORM_sec_offset
				|| value->kind != DW_AT_KIND_REFERENCE) {
				return false;
			}
			*has_str_base = true;
			*str_base = value->reference;
		} else if (value->attr_name == DW_AT_addr_base) {
			if (*has_addr_base || value->attr_form != DW_FORM_sec_offset
				|| value->kind != DW_AT_KIND_REFERENCE) {
				return false;
			}
			*has_addr_base = true;
			*addr_base = value->reference;
		} else if (value->attr_name == DW_AT_loclists_base) {
			bad_loclists_base |= *has_loclists_base || value->attr_form != DW_FORM_sec_offset
				|| value->kind != DW_AT_KIND_REFERENCE;
			*has_loclists_base = true;
			*loclists_base = value->reference;
		}
	}
	// a bad loclists base costs the unit its location lists only
	*has_loclists_base &= !bad_loclists_base;
	return true;
}

static bool dwarf_is_split_unit(const RBinDwarfCompUnit *unit) {
	return unit && (unit->hdr.unit_type == DW_UT_split_compile
		|| unit->hdr.unit_type == DW_UT_split_type);
}

typedef struct {
	RBinFile *bf;
	RBinDwarfCompUnit *unit;
	bool be;
	bool has_str_base;
	bool has_addr_base;
	ut64 str_base;
	ut64 addr_base;
	DwarfIndexResolution str_status;
	RBinSection *str_offsets_section;
	RBinSection *str_section;
	const ut8 *str_offsets;
	ut8 str_offset_size;
	size_t str_offsets_end;
	DwarfIndexResolution addr_status;
	RBinSection *addr_section;
	const ut8 *addr;
	size_t addr_end;
	bool has_loclists_base;
	ut64 loclists_base;
	DwarfIndexResolution loclists_status;
	const ut8 *loclists;
	DwarfLoclistsContribution loclists_contribution;
} DwarfIndexResolver;

// DW_FORM_loclistx indexes the offset table at the unit's DW_AT_loclists_base
static void dwarf_index_resolver_init_loclists(DwarfIndexResolver *resolver) {
	RBinSection *section = dwarf_get_section (resolver->bf, DWARF_SN_LOCLISTS);
	resolver->loclists = section? dwarf_get_section_bytes (resolver->bf, section): NULL;
	resolver->loclists_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
	if (resolver->loclists && resolver->has_loclists_base
		&& dwarf_loclists_contribution_base (resolver->loclists, section->bytes.len, resolver->be,
			resolver->loclists_base, &resolver->loclists_contribution)) {
		resolver->loclists_status = DWARF_INDEX_RESOLUTION_OK;
	}
}

static DwarfIndexResolution dwarf_index_resolver_init_str(DwarfIndexResolver *resolver) {
	resolver->str_status = DWARF_INDEX_RESOLUTION_MALFORMED;
	resolver->str_offsets_section = dwarf_get_section (resolver->bf, DWARF_SN_STR_OFFSETS);
	resolver->str_section = dwarf_get_section (resolver->bf, DWARF_SN_STR);
	resolver->str_offsets = resolver->str_offsets_section
		? dwarf_get_section_bytes (resolver->bf, resolver->str_offsets_section): NULL;
	if (!resolver->str_offsets || !resolver->str_section
		|| !dwarf_get_section_bytes (resolver->bf, resolver->str_section)) {
		resolver->str_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
		return resolver->str_status;
	}
	if (resolver->has_str_base) {
		if (!dwarf_string_offsets_base (resolver->str_offsets,
				resolver->str_offsets_section->bytes.len, resolver->be,
				resolver->str_base, &resolver->str_offsets_end,
				&resolver->str_offset_size)) {
			return resolver->str_status;
		}
	} else if (!dwarf_is_split_unit (resolver->unit)) {
		return resolver->str_status;
	} else {
		if (!dwarf_string_offsets_contribution (resolver->str_offsets,
				resolver->str_offsets_section->bytes.len, resolver->be, 0,
				resolver->str_offsets_section->bytes.len, &resolver->str_base,
				&resolver->str_offsets_end, &resolver->str_offset_size)) {
			resolver->str_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
			return resolver->str_status;
		}
	}
	resolver->str_status = DWARF_INDEX_RESOLUTION_OK;
	return resolver->str_status;
}

static DwarfIndexResolution dwarf_index_resolver_init_addr(DwarfIndexResolver *resolver) {
	resolver->addr_status = DWARF_INDEX_RESOLUTION_MALFORMED;
	resolver->addr_section = dwarf_get_section (resolver->bf, DWARF_SN_ADDR);
	resolver->addr = resolver->addr_section
		? dwarf_get_section_bytes (resolver->bf, resolver->addr_section): NULL;
	if (!resolver->addr) {
		resolver->addr_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
		return resolver->addr_status;
	}
	if (!resolver->has_addr_base) {
		if (!dwarf_is_split_unit (resolver->unit)) {
			return resolver->addr_status;
		}
		resolver->addr_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
		return resolver->addr_status;
	}
	if (!dwarf_address_base (resolver->addr,
			resolver->addr_section->bytes.len, resolver->be,
			resolver->addr_base, resolver->unit->hdr.address_size,
			&resolver->addr_end)) {
		return resolver->addr_status;
	}
	resolver->addr_status = DWARF_INDEX_RESOLUTION_OK;
	return resolver->addr_status;
}

static DwarfIndexResolution dwarf_index_resolver_resolve_die(DwarfIndexResolver *resolver, RBinDwarfDie *die) {
	R_RETURN_VAL_IF_FAIL (resolver && resolver->bf && resolver->unit && die,
		DWARF_INDEX_RESOLUTION_MALFORMED);
	DwarfIndexResolution result = DWARF_INDEX_RESOLUTION_OK;
	if (!die->attr_values) {
		return result;
	}
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		size_t entry_offset;
		if (dwarf_form_is_strx (value->attr_form)
			&& value->kind == DW_AT_KIND_STRING_INDEX) {
			DwarfIndexResolution status = resolver->str_status;
			if (status == DWARF_INDEX_RESOLUTION_MALFORMED) {
				return status;
			}
			if (status == DWARF_INDEX_RESOLUTION_UNAVAILABLE) {
				result = status;
				continue;
			}
			if (!dwarf_index_entry_offset (resolver->str_base,
					value->string.offset, resolver->str_offset_size,
					resolver->str_offsets_end, &entry_offset)) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			ut64 string_offset = resolver->str_offset_size == 8
				? r_read_ble64 (resolver->str_offsets + entry_offset, resolver->be)
				: r_read_ble32 (resolver->str_offsets + entry_offset, resolver->be);
			if (string_offset > SIZE_MAX) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			const char *content = dwarf_get_section_string (resolver->bf,
				resolver->str_section, (size_t)string_offset);
			if (!content) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			value->string.offset = string_offset;
			value->string.content = content;
			value->kind = DW_AT_KIND_STRING;
		} else if (dwarf_form_is_addrx (value->attr_form)
			&& value->kind == DW_AT_KIND_ADDRESS_INDEX) {
			DwarfIndexResolution status = resolver->addr_status;
			if (status == DWARF_INDEX_RESOLUTION_MALFORMED) {
				return status;
			}
			if (status == DWARF_INDEX_RESOLUTION_UNAVAILABLE) {
				result = status;
				continue;
			}
			if (!dwarf_index_entry_offset (resolver->addr_base, value->address,
					resolver->unit->hdr.address_size, resolver->addr_end,
					&entry_offset)) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			ut64 address;
			if (!dwarf_read_index (resolver->addr + entry_offset,
					resolver->addr + resolver->addr_end, resolver->be,
					resolver->unit->hdr.address_size, &address)
				|| !dwarf_relocate_address (resolver->bf, address,
					&value->address)) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			value->kind = DW_AT_KIND_ADDRESS;
		} else if (value->kind == DW_AT_KIND_LOCLIST_INDEX) {
			if (resolver->loclists_status != DWARF_INDEX_RESOLUTION_OK) {
				result = resolver->loclists_status;
				continue;
			}
			const DwarfLoclistsContribution *c = &resolver->loclists_contribution;
			ut64 list_offset;
			// a bad list reference costs this location only, not the unit
			if (value->reference >= c->count
				|| !dwarf_index_entry_offset (c->base, value->reference, c->offset_size, c->end, &entry_offset)
				|| !dwarf_read_index (resolver->loclists + entry_offset, resolver->loclists + c->end,
					resolver->be, c->offset_size, &list_offset)
				|| list_offset < c->lists - c->base || list_offset >= c->end - c->base) {
				continue;
			}
			value->reference = c->base + list_offset;
			value->kind = DW_AT_KIND_LOCLISTPTR;
		} else if (dwarf_attr_is_loclist5 (resolver->unit, value)) {
			value->kind = DW_AT_KIND_LOCLISTPTR;
		}
	}
	return result;
}

R_IPI DwarfIndexResolution dwarf_resolve_comp_unit_indexes(RBinFile *bf, RBinDwarfCompUnit *unit) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && unit && unit->dies,
		DWARF_INDEX_RESOLUTION_MALFORMED);
	DwarfIndexResolver resolver = {
		.bf = bf,
		.unit = unit,
		.be = r_bin_is_big_endian (bf->rbin),
		.str_status = DWARF_INDEX_RESOLUTION_OK,
		.addr_status = DWARF_INDEX_RESOLUTION_OK,
	};
	bool need_str = false;
	bool need_addr = false;
	bool need_loclists = false;
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		if (!die->attr_values) {
			continue;
		}
		RBinDwarfAttrValue *value;
		R_VEC_FOREACH (die->attr_values, value) {
			need_str |= dwarf_form_is_strx (value->attr_form)
				&& value->kind == DW_AT_KIND_STRING_INDEX;
			need_addr |= dwarf_form_is_addrx (value->attr_form)
				&& value->kind == DW_AT_KIND_ADDRESS_INDEX;
			need_loclists |= value->kind == DW_AT_KIND_LOCLIST_INDEX
				|| dwarf_attr_is_loclist5 (unit, value);
		}
	}
	if (!need_str && !need_addr && !need_loclists) {
		return DWARF_INDEX_RESOLUTION_OK;
	}
	if (!dwarf_comp_unit_index_bases (unit, need_str, need_addr, need_loclists,
			&resolver.str_base, &resolver.has_str_base,
			&resolver.addr_base, &resolver.has_addr_base,
			&resolver.loclists_base, &resolver.has_loclists_base)) {
		return DWARF_INDEX_RESOLUTION_MALFORMED;
	}
	if (need_loclists) {
		dwarf_index_resolver_init_loclists (&resolver);
	}
	if (need_str && dwarf_index_resolver_init_str (&resolver)
			== DWARF_INDEX_RESOLUTION_MALFORMED) {
		return DWARF_INDEX_RESOLUTION_MALFORMED;
	}
	if (need_addr && dwarf_index_resolver_init_addr (&resolver)
			== DWARF_INDEX_RESOLUTION_MALFORMED) {
		return DWARF_INDEX_RESOLUTION_MALFORMED;
	}
	DwarfIndexResolution result = DWARF_INDEX_RESOLUTION_OK;
	R_VEC_FOREACH (unit->dies, die) {
		DwarfIndexResolution status = dwarf_index_resolver_resolve_die (&resolver, die);
		if (status == DWARF_INDEX_RESOLUTION_MALFORMED) {
			return status;
		}
		if (status == DWARF_INDEX_RESOLUTION_UNAVAILABLE) {
			result = status;
		}
	}
	return result;
}
