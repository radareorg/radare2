#include "base_types.h"
#include <sdb.h>
#include <r_anal.h>
#include <r_bin_dwarf.h>
#include <string.h>

static int die_tag_cmp(const void *a, const void *b) {
	const RBinDwarfDie *first = a;
	const RBinDwarfDie *second = b;

	if (first->offset > second->offset) {
		return 1;
	} else if (first->offset < second->offset) {
		return -1;
	} else {
		return 0;
	}
}

static inline bool is_type_tag(ut64 tag_code) {
	return (tag_code == DW_TAG_structure_type ||
		tag_code == DW_TAG_enumeration_type ||
		tag_code == DW_TAG_class_type ||
		tag_code == DW_TAG_union_type ||
		tag_code == DW_TAG_base_type ||
		tag_code == DW_TAG_typedef);
}

/**
 * @brief Finds index of a particular attribute of a DIE
 * 
 * @param die 
 * @param attr_name 
 * @return st32 Index, -1 if nothing found
 */
static st32 find_attr_idx(const RBinDwarfDie *die, st32 attr_name) {
	st32 i;
	r_return_val_if_fail (die, -1);
	for (i = 0; i < die->count; i++) {
		if (die->attr_values[i].attr_name == attr_name) {
			return i;
		}
	}
	return -1;
}

/**
 * @brief Prepends string before a last occurence of character c
 * 	      Used to replicate proper C declaration for function pointers
 * @param sb 
 * @param s 
 * @param c 
 * @return true Success
 * @return false Failure
 */
static bool strbuf_rev_prepend_char(RStrBuf *sb, const char *s, int c) {
	r_return_val_if_fail (sb && s, false);
	int l = strlen (s);
	// fast path if no chars to append
	if (l == 0) {
		return true;
	}
	int newlen = l + sb->len;
	char *ns = malloc (newlen + 1);
	bool ret = false;
	char *sb_str = sb->ptr ? sb->ptr : sb->buf;
	char *pivot = strrchr (sb_str, c);
	if (!pivot) {
		return false;
	}
	size_t idx = pivot - sb_str;
	if (ns) {
		memcpy (ns, sb_str, idx);
		memcpy (ns + idx, s, l);
		memcpy (ns + idx + l, sb_str + idx, sb->len - idx);
		ns[newlen] = 0;
		ret = r_strbuf_set (sb, ns);
		free (ns);
	}
	return ret;
}
/**
 * @brief Appends string after a first occurence of character c
 * 	      Used to replicate proper C declaration for function pointers
 * @param sb 
 * @param s 
 * @param c 
 * @return true Success
 * @return false Failure
 */
static bool strbuf_rev_append_char(RStrBuf *sb, const char *s, const char *needle) {
	r_return_val_if_fail (sb && s, false);
	int l = strlen (s);
	// fast path if no chars to append
	if (l == 0) {
		return true;
	}
	bool ret = false;
	char *sb_str = sb->ptr ? sb->ptr : sb->buf;
	char *pivot = strstr (sb_str, needle);
	if (!pivot) {
		return false;
	}
	pivot += strlen (needle);
	size_t idx = pivot - sb_str;
	int newlen = l + sb->len;
	char *ns = malloc (newlen + 1);
	if (ns) {
		memcpy (ns, sb_str, idx);
		memcpy (ns + idx, s, l);
		memcpy (ns + idx + l, sb_str + idx, sb->len - idx);
		ns[newlen] = 0;
		ret = r_strbuf_set (sb, ns);
		free (ns);
	}
	return ret;
}

/**
 * @brief Create a type name from it's unique offset
 * 
 * @param offset 
 * @return char* Name or NULL if error
 */
static char *create_type_name_from_offset(ut64 offset) {
	int offset_length = snprintf (NULL, 0, "type_0x%" PFMT64x, offset);
	char *str = malloc (offset_length + 1);
	snprintf (str, offset_length + 1, "type_0x%" PFMT64x, offset);
	return str;
}

/**
 * @brief Get the DIE name or create unique one from it's offset
 * 
 * @param die 
 * @return char* DIEs name or NULL if error
 */
static char *get_die_name(const RBinDwarfDie *die) {
	char *name = NULL;
	st32 name_attr_idx = find_attr_idx (die, DW_AT_name);

	if (name_attr_idx != -1 && die->attr_values[name_attr_idx].string.content) {
		name = strdup (die->attr_values[name_attr_idx].string.content);
	} else {
		name = create_type_name_from_offset (die->offset);
	}
	return name;
}

/**
 * @brief Get the DIE size in bits
 * 
 * @param die
 * @return ut64 size in bits or 0 if not found
 */
static ut64 get_die_size(const RBinDwarfDie *die) {
	ut64 size = 0;
	st32 byte_size_idx = find_attr_idx (die, DW_AT_byte_size);

	if (byte_size_idx != -1) {
		size = die->attr_values[byte_size_idx].data * CHAR_BIT;
	} else {
		st32 bit_size_idx = find_attr_idx (die, DW_AT_bit_size);

		if (bit_size_idx != -1) {
			size = die->attr_values[bit_size_idx].data;
		}
	}
	return size;
}

/**
 * @brief Parses array type entry into strbuf
 * 
 * @param all_dies Pointer to all DIEs
 * @param count of all DIEs
 * @param idx index of the current entry
 * @param strbuf strbuf to store the type into
 * @return st32 -1 if error else 0
 */
static st32 parse_array_type(const RBinDwarfDie *all_dies, ut64 count, ut64 idx, RStrBuf *strbuf) {

	r_return_val_if_fail (all_dies && strbuf, -1);
	const RBinDwarfDie *die = &all_dies[idx];

	if (die->has_children) {
		int child_depth = 1;
		const RBinDwarfDie *child_die = &all_dies[++idx];
		size_t j;
		for (j = idx; child_depth > 0 && j < count; j++) {
			child_die = &all_dies[j];
			// right now we skip non direct descendats of the structure
			// can be also DW_TAG_suprogram for class methods or tag for templates
			if (child_depth == 1 && child_die->tag == DW_TAG_subrange_type) {
				size_t i;
				for (i = 0; i < child_die->count; i++) {
					const RBinDwarfAttrValue *value = &child_die->attr_values[i];
					switch (value->attr_name) {
					case DW_AT_upper_bound:
					case DW_AT_count:
						r_strbuf_appendf (strbuf, "[%d]", value->data + 1);
						break;

					default:
						break;
					}
				}
			}
			if (child_die->has_children) {
				child_depth++;
			}
			// sibling list is terminated by null entry
			if (child_die->abbrev_code == 0) {
				child_depth--;
			}
		}
	}
	return 0;
}

/**
 * @brief Recursively parses type entry of a certain offset into strbuf
 *        saves type size into *size
 * 
 * @param all_dies Pointer to all DIEs
 * @param count of all DIEs
 * @param offset offset of the type entry
 * @param strbuf string to store the type into
 * @param size ptr to size of a type to fill up
 * @return st32 -1 if error else DW_TAG of the entry
 */
static st32 parse_type (const RBinDwarfDie *all_dies, const ut64 count,
	const ut64 offset, RStrBuf *strbuf, ut64 *size) {

	r_return_val_if_fail (all_dies && strbuf, -1);
	RBinDwarfDie key = { .offset = offset };
	RBinDwarfDie *die = bsearch (&key, all_dies, count, sizeof (key), die_tag_cmp);

	if (!die) {
		return -1;
	}
	st32 type_idx;
	st32 tag;
	char *name = NULL;

	// get size of first type DIE that has size
	if (*size == 0) {
		*size = get_die_size (die);
	}

	switch (die->tag) {
	// this should be recursive search for the type until you find base/user defined type
	case DW_TAG_pointer_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx == -1) {
			r_strbuf_append (strbuf, "void");
			r_strbuf_append (strbuf, " *");
		} else {
			tag = parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size);
			if (tag == DW_TAG_subroutine_type) {
				strbuf_rev_prepend_char (strbuf, "(*)", '(');
			} else if (tag == DW_TAG_pointer_type) {
				if (!strbuf_rev_append_char (strbuf, "*", "(*")) {
					strbuf_rev_prepend_char (strbuf, "*", '*');
				}
			} else {
				r_strbuf_append (strbuf, " *");
			}
		}
		break;
	// We won't parse them as a complete type, because that will already be done
	// so just a name now
	case DW_TAG_typedef:
	case DW_TAG_base_type:
	case DW_TAG_structure_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		name = get_die_name (die);
		r_strbuf_append (strbuf, name);
		free (name);
		break;
	case DW_TAG_subroutine_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx == -1) {
			r_strbuf_append (strbuf, "void");
		} else {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size);
		}
		r_strbuf_append (strbuf, " (");
		if (die->has_children) { // has parameters
		}
		r_strbuf_append (strbuf, ")");
		break;
	case DW_TAG_array_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size);
		}
		parse_array_type (all_dies, count, die - all_dies, strbuf);
		break;
	case DW_TAG_const_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size);
		}
		r_strbuf_append (strbuf, " const");
		break;
	case DW_TAG_volatile_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size);
		}
		r_strbuf_append (strbuf, " volatile");
		break;
	case DW_TAG_restrict_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size);
		}
		r_strbuf_append (strbuf, " restrict");
		break;
	case DW_TAG_rvalue_reference_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size);
		}
		r_strbuf_append (strbuf, " &&");
		break;
	case DW_TAG_reference_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size);
		}
		r_strbuf_append (strbuf, " &");
		break;
	default:
		break;
	}
	return (st32)die->tag;
}
// Data member has a DW_AT_name attribute!
/**
 * @brief Parses structured entry into *result RAnalStructMember
 * http://www.dwarfstd.org/doc/DWARF4.pdf#page=102&zoom=100,0,0
 * 
 * @param all_dies Pointer to all DIEs
 * @param count of all DIEs
 * @param idx index of the current entry
 * @param result ptr to result member to fill up
 * @return RAnalStructMember* ptr to parsed Member
 */
static RAnalStructMember *parse_struct_member (const RBinDwarfDie *all_dies,
	const ut64 all_dies_count, ut64 curr_die_idx, RAnalStructMember *result) {

	r_return_val_if_fail (all_dies && result, NULL);
	const RBinDwarfDie *die = &all_dies[curr_die_idx];

	char *name = NULL;
	char *type = NULL;
	ut64 offset = 0;
	ut64 size = 0;
	RStrBuf strbuf;
	r_strbuf_init (&strbuf);
	size_t i;
	for (i = 0; i < die->count; i++) {
		RBinDwarfAttrValue *value = &die->attr_values[i];
		switch (die->attr_values[i].attr_name) {
		case DW_AT_name:
			name = get_die_name (die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_type:
			parse_type (all_dies, all_dies_count, value->reference, &strbuf, &size);
			type = r_strbuf_drain_nofree (&strbuf);
			if (!type || !*type) {
				goto cleanup;
			}
			break;
		case DW_AT_data_member_location:
			/*
				2 cases, 1.: If val is integer, it offset in bytes from
				the beginning of containing entity. If containing entity has 
				a bit offset, member has that bit offset aswell
				2.: value is a location description 
				http://www.dwarfstd.org/doc/DWARF4.pdf#page=39&zoom=100,0,0
			*/
			offset = value->data;
			break;
		case DW_AT_accessibility: // private, public etc.
		case DW_AT_mutable: // flag is it is mutable
		case DW_AT_data_bit_offset:
			/* 
				int that specifies the number of bits from beginning
				of containing entity to the beginning of the data member
			*/
			break;
		// If the size of a data member is not the same as the
		//  size of the type given for the data member
		case DW_AT_byte_size:
			size = value->data * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = value->data;
			break;
		case DW_AT_containing_type:
		default:
			break;
		}
	}

	result->name = name;
	result->type = type;
	result->offset = offset;
	result->size = size;
	return result;
cleanup:
	free (name);
	free (type);
	return NULL;
}

/**
 * @brief  Parses enum entry into *result RAnalEnumCase
 * http://www.dwarfstd.org/doc/DWARF4.pdf#page=110&zoom=100,0,0
 * 
 * @param all_dies Pointer to all DIEs
 * @param count of all DIEs
 * @param idx index of the current entry
 * @param result ptr to result case to fill up
 * @return RAnalEnumCase* Ptr to parsed enum case
 */
static RAnalEnumCase *parse_enumerator(const RBinDwarfDie *all_dies,
	const ut64 count, ut64 idx, RAnalEnumCase *result) {

	r_return_val_if_fail (all_dies && result, NULL);
	const RBinDwarfDie *die = &all_dies[idx];

	char *name = NULL;
	int val = 0;
	size_t i;

	// Enumerator has DW_AT_name and DW_AT_const_value
	for (i = 0; i < die->count; i++) {
		RBinDwarfAttrValue *value = &die->attr_values[i];
		switch (die->attr_values[i].attr_name) {
		case DW_AT_name:
			name = get_die_name (die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_const_value:
			// ?? can be block, sdata, data, string w/e
			val = value->constant; // TODO solve the encoding, I don't know in which union member is it store
			break;
		default:
			break;
		}
	}

	result->name = name;
	result->val = (int)val;
	return result;
cleanup:
	free (name);
	return NULL;
}

/**
 * @brief  Parses a structured entry (structs, classes, unions) into 
 *         RAnalBaseType and saves it using r_anal_save_base_type ()
 * 
 * @param all_dies Pointer to all DIEs
 * @param count of all DIEs
 * @param idx index of the current entry
 */
// http://www.dwarfstd.org/doc/DWARF4.pdf#page=102&zoom=100,0,0
static void parse_structure_type(const RAnal *anal, const RBinDwarfDie *all_dies, 
	const ut64 count, ut64 idx) {

	r_return_if_fail (all_dies && anal);
	const RBinDwarfDie *die = &all_dies[idx];

	RAnalBaseTypeKind kind;
	if (die->tag == DW_TAG_union_type) {
		kind = R_ANAL_BASE_TYPE_KIND_UNION;
	} else {
		kind = R_ANAL_BASE_TYPE_KIND_STRUCT;
	}

	RAnalBaseType *base_type = r_anal_new_base_type (kind);
	if (!base_type) {
		return;
	}

	base_type->name = get_die_name (die);
	if (!base_type->name) {
		goto cleanup;
	}

	// if it is definition of previous declaration (TODO Fix, big ugly hotfix addition)
	st32 spec_attr_idx = find_attr_idx (die, DW_AT_specification);
	if (spec_attr_idx != -1) {
		RBinDwarfDie key = { .offset = die->attr_values[spec_attr_idx].reference };
		RBinDwarfDie *decl_die = bsearch (&key, all_dies, count, sizeof (key), die_tag_cmp);

		if (!die) {
			goto cleanup;
		}
		st32 name_attr_idx = find_attr_idx (decl_die, DW_AT_name);
		if (name_attr_idx != -1) {
			free (base_type->name);
			base_type->name = get_die_name (decl_die);
		}
	}

	base_type->size = get_die_size (die);

	r_vector_init (&base_type->struct_data.members,
		sizeof (RAnalStructMember), struct_type_member_free, NULL);
	RAnalStructMember member = { 0 };
	// Parse out all members, can this in someway be extracted to a function?
	if (die->has_children) {
		int child_depth = 1; // Direct children of the node
		size_t j;
		idx++; // Move to the first children node
		for (j = idx; child_depth > 0 && j < count; j++) {
			const RBinDwarfDie *child_die = &all_dies[j];
			// we take only direct descendats of the structure
			// can be also DW_TAG_suprogram for class methods or tag for templates
			if (child_depth == 1 && child_die->tag == DW_TAG_member) {
				RAnalStructMember *result = parse_struct_member (all_dies, count, j, &member);
				if (!result) {
					goto cleanup;
				} else {
					void *element = r_vector_push (&base_type->struct_data.members, &member);
					if (!element) {
						goto cleanup;
					}
				}
			}
			if (child_die->has_children) {
				child_depth++;
			}
			if (child_die->abbrev_code == 0) { // siblings terminator
				child_depth--;
			}
		}
	}
	r_anal_save_base_type (anal, base_type);
cleanup:
	r_anal_free_base_type (base_type);
}

/**
 * @brief Parses a enum entry into RAnalBaseType and saves it
 *        using r_anal_save_base_type ()
 * 
 * @param anal 
 * @param all_dies Pointer to all DIEs
 * @param count of all DIEs
 * @param idx index of the current entry
 */
static void parse_enum_type(const RAnal *anal, const RBinDwarfDie *all_dies,
	const ut64 count, ut64 idx) {

	r_return_if_fail (all_dies);
	const RBinDwarfDie *die = &all_dies[idx];

	RAnalBaseType *base_type = r_anal_new_base_type (R_ANAL_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return;
	}

	base_type->name = get_die_name (die);
	if (!base_type->name) {
		goto cleanup;
	}
	base_type->size = get_die_size (die);

	st32 type_attr_idx = find_attr_idx (die, DW_AT_type);
	if (type_attr_idx != -1) {
		RStrBuf strbuf;
		r_strbuf_init (&strbuf);
		parse_type (all_dies, count,
			die->attr_values[type_attr_idx].reference, &strbuf, &base_type->size);
		base_type->type = r_strbuf_drain_nofree (&strbuf);
	}

	r_vector_init (&base_type->enum_data.cases,
		sizeof (RAnalEnumCase), enum_type_case_free, NULL);
	RAnalEnumCase cas;
	if (die->has_children) {
		int child_depth = 1; // Direct children of the node
		size_t j;
		idx++; // Move to the first children node
		for (j = idx; child_depth > 0 && j < count; j++) {
			const RBinDwarfDie *child_die = &all_dies[j];
			// we take only direct descendats of the structure
			if (child_depth == 1 && child_die->tag == DW_TAG_enumerator) {
				RAnalEnumCase *result = parse_enumerator (all_dies, count, j, &cas);
				if (!result) {
					goto cleanup;
				} else {
					void *element = r_vector_push (&base_type->enum_data.cases, &cas);
					if (!element) {
						enum_type_case_free (result, NULL);
						goto cleanup;
					}
				}
			}
			if (child_die->has_children) {
				child_depth++;
			}
			// sibling list is terminated by null entry
			if (child_die->abbrev_code == 0) {
				child_depth--;
			}
		}
	}
	r_anal_save_base_type (anal, base_type);
cleanup:
	r_anal_free_base_type (base_type);
}

/**
 * @brief Parses a typedef entry into RAnalBaseType and saves it
 *        using r_anal_save_base_type ()
 * 
 * http://www.dwarfstd.org/doc/DWARF4.pdf#page=96&zoom=100,0,0
 * 
 * @param anal 
 * @param all_dies Pointer to all DIEs
 * @param count of all DIEs
 * @param idx index of the current entry
 */
static void parse_typedef(const RAnal *anal, const RBinDwarfDie *all_dies, 
	const ut64 count, ut64 idx) {

	r_return_if_fail (all_dies);
	const RBinDwarfDie *die = &all_dies[idx];

	char *name = NULL;
	char *type = NULL;
	ut64 size = 0;
	RStrBuf strbuf;
	r_strbuf_init (&strbuf);
	size_t i;

	for (i = 0; i < die->count; i++) {
		RBinDwarfAttrValue *value = &die->attr_values[i];
		switch (die->attr_values[i].attr_name) {
		case DW_AT_name:
			name = get_die_name (die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_type:
			parse_type (all_dies, count, value->reference, &strbuf, &size);
			type = r_strbuf_drain_nofree (&strbuf);
			if (!type) {
				goto cleanup;
			}
			break;
		default:
			break;
		}
	}
	if (!name) { // type has to have a name for now
		goto cleanup;
	}
	RAnalBaseType *base_type = r_anal_new_base_type (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		goto cleanup;
	}
	base_type->name = name;
	base_type->type = type;
	r_anal_save_base_type (anal, base_type);
	r_anal_free_base_type (base_type);
	r_strbuf_fini (&strbuf);
	return;
cleanup:
	free (name);
	free (type);
	r_strbuf_fini (&strbuf);
}

static void parse_atomic_type(const RAnal *anal, const RBinDwarfDie *all_dies, 
	const ut64 count, ut64 idx) {

	r_return_if_fail (all_dies);
	const RBinDwarfDie *die = &all_dies[idx];

	char *name = NULL;
	ut64 size = 0;
	size_t i;
	// TODO support endiannity and encoding in future?
	for (i = 0; i < die->count; i++) {
		RBinDwarfAttrValue *value = &die->attr_values[i];
		switch (die->attr_values[i].attr_name) {
		case DW_AT_name:
			if (!value->string.content) {
				name = create_type_name_from_offset (die->offset);
			} else {
				name = strdup (value->string.content);
			}
			if (!name) {
				return;
			}
			break;
		case DW_AT_byte_size:
			size = value->data * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = value->data;
			break;
		case DW_AT_encoding:
		default:
			break;
		}
	}
	if (!name) { // type has to have a name for now
		return;
	}
	RAnalBaseType *base_type = r_anal_new_base_type (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		return;
	}
	base_type->name = name;
	base_type->size = size;
	r_anal_save_base_type (anal, base_type);
	r_anal_free_base_type (base_type);
}

/**
 * @brief Delegates DIE to it's proper parsing method
 * 
 * @param anal 
 * @param all_dies Pointer to all DIEs
 * @param count of all DIEs
 * @param idx index of the current entry
 */
static void parse_type_entry(const RAnal *anal, const RBinDwarfDie *all_dies,
	const ut64 count, ut64 idx) {

	r_return_if_fail (all_dies);
	const RBinDwarfDie *die = &all_dies[idx];

	switch (die->tag) {
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		parse_structure_type (anal, all_dies, count, idx);
		break;
	case DW_TAG_enumeration_type:
		parse_enum_type (anal, all_dies, count, idx);
		break;
	case DW_TAG_typedef:
		parse_typedef (anal, all_dies, count, idx);
		break;
	case DW_TAG_base_type:
		parse_atomic_type (anal, all_dies, count, idx);
		break;
	case DW_TAG_subroutine_type: // one day TODO ?
	default:
		break;
	}
}

/**
 * @brief Parses type information out of DWARF entries
 *        and stores them to the sdb
 * 
 * @param info 
 * @param anal 
 */
R_API void r_anal_parse_dwarf_types(const RAnal *anal, const RBinDwarfDebugInfo *info) {
    size_t i, j;
	r_return_if_fail (info && anal);
	for (i = 0; i < info->count; i++) {
		RBinDwarfCompUnit *unit = &info->comp_units[i];
		for (j = 0; j < unit->count; j++) {
			RBinDwarfDie *curr_die = &unit->dies[j];
			if (is_type_tag (curr_die->tag)) {
				parse_type_entry (anal, unit->dies, unit->count, j);
			}
		}
	}
}
