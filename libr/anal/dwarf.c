#include "base_types.h"
#include <sdb.h>
#include <r_anal.h>
#include <r_bin_dwarf.h>
#include <string.h>

typedef struct dwarf_function_t {
	ut64 addr;
	const char *name;
	const char *signature;
	bool is_external;
	bool is_method;
	bool is_virtual;
	bool is_trampoline; // intermediary in making call to another func
	ut8 access; // public = 1, protected = 2, private = 3, if not set assume private
	ut64 vtable_addr; // location description
	ut64 call_conv; // normal || program || nocall
} DwarfFunction;

typedef enum dwarf_location_kind {
	UNKNOWN = 0,
	GLOBAL = 1,
	STACK = 2,
	REGISTER = 3,
} DwarfVarLocationKind;
typedef struct dwarf_var_location_t {
	DwarfVarLocationKind kind;
} DwarfVarLocation;

static inline bool is_type_tag(ut64 tag_code) {
	return (tag_code == DW_TAG_structure_type ||
		tag_code == DW_TAG_enumeration_type ||
		tag_code == DW_TAG_class_type ||
		tag_code == DW_TAG_subprogram ||
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
	const ut64 offset, RStrBuf *strbuf, ut64 *size, HtUP *die_map) {

	r_return_val_if_fail (all_dies && strbuf && die_map, -1);
	RBinDwarfDie *die = ht_up_find (die_map, offset, NULL);
	if (!die) {
		return -1;
	}

	st32 type_idx;
	st32 tag;
	char *name = NULL;
	// get size of first type DIE that has size
	if (size && *size == 0) {
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
			tag = parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size, die_map);
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
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size, die_map);
		}
		r_strbuf_append (strbuf, " (");
		if (die->has_children) { // has parameters
		}
		r_strbuf_append (strbuf, ")");
		break;
	case DW_TAG_array_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size, die_map);
		}
		parse_array_type (all_dies, count, die - all_dies, strbuf);
		break;
	case DW_TAG_const_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size, die_map);
		}
		r_strbuf_append (strbuf, " const");
		break;
	case DW_TAG_volatile_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size, die_map);
		}
		r_strbuf_append (strbuf, " volatile");
		break;
	case DW_TAG_restrict_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size, die_map);
		}
		r_strbuf_append (strbuf, " restrict");
		break;
	case DW_TAG_rvalue_reference_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size, die_map);
		}
		r_strbuf_append (strbuf, " &&");
		break;
	case DW_TAG_reference_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (all_dies, count, die->attr_values[type_idx].reference, strbuf, size, die_map);
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
	const ut64 all_dies_count, ut64 curr_die_idx, RAnalStructMember *result, HtUP *die_map) {

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
			parse_type (all_dies, all_dies_count, value->reference, &strbuf, &size, die_map);
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
	const ut64 count, ut64 idx, HtUP *die_map) {

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
		RBinDwarfDie *decl_die = ht_up_find (die_map, die->attr_values[spec_attr_idx].reference, NULL);
		if (!decl_die) {
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
				RAnalStructMember *result = parse_struct_member (all_dies, count, j, &member, die_map);
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
	const ut64 count, ut64 idx, HtUP *die_map) {

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
			die->attr_values[type_attr_idx].reference, &strbuf, &base_type->size, die_map);
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
	const ut64 count, ut64 idx, HtUP *die_map) {

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
			parse_type (all_dies, count, value->reference, &strbuf, &size, die_map);
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

static const char *get_specification_die_name(const RBinDwarfDie *die) {
	st32 linkage_name_attr_idx = find_attr_idx (die, DW_AT_linkage_name);
	if (linkage_name_attr_idx != -1 && die->attr_values[linkage_name_attr_idx].string.content) {
		return die->attr_values[linkage_name_attr_idx].string.content;
	}
	st32 name_attr_idx = find_attr_idx (die, DW_AT_name);
	if (name_attr_idx != -1 && die->attr_values[name_attr_idx].string.content) {
		return die->attr_values[name_attr_idx].string.content;
	}
	return NULL;
}

/**
 * @brief Saves the return type from specification DIE
 * 
 * @param all_dies 
 * @param count 
 * @param die 
 * @param ret_type 
 */
static void get_spec_die_type(const RBinDwarfDie *all_dies, ut64 count, RBinDwarfDie *die, RStrBuf *ret_type, HtUP *die_map) {
	st32 attr_idx = find_attr_idx (die, DW_AT_type);
	if (attr_idx != -1) {
		ut64 size = 0;
		parse_type (all_dies, count, die->attr_values[attr_idx].reference, ret_type, &size, die_map);
	}
}

static void parse_abstract_origin(const RBinDwarfDie *all_dies, ut64 count, ut64 offset, RStrBuf *type, const char **name, HtUP *die_map) {
	RBinDwarfDie *die = ht_up_find (die_map, offset, NULL);
	if (die) {
		size_t i;
		ut64 size = 0;
		bool has_linkage_name = false;
		for (i = 0; i < die->count; i++) {
			const RBinDwarfAttrValue *val = &die->attr_values[i];
			switch (val->attr_name) {
			case DW_AT_name:
				if (!has_linkage_name) {
					*name = val->string.content;
				}
				break;
			case DW_AT_linkage_name:
			case DW_AT_MIPS_linkage_name:
				*name = val->string.content;
				has_linkage_name = true;
				break;
			case DW_AT_type:
				parse_type (all_dies, count, val->reference, type, &size, die_map);
				break;
			default:
				break;
			}
		}
	}
}

static void parse_dwarf_location (const RBinDwarfAttrValue *val) {
	// reg5 - val is in register 5
	// fbreg <leb> - offset from frame base
	// regx <leb> - contents is in register X
	// addr <addr> - contents is in at addr
	// breg <addr> - contents is in at addr
}

static st32 parse_function_args(const RBinDwarfDie *all_dies, ut64 count, 
	ut64 idx, RStrBuf *args, HtUP *die_map) {

	r_return_val_if_fail (all_dies && args, -1);
	const RBinDwarfDie *die = &all_dies[idx];

	if (die->has_children) {
		int child_depth = 1;
		const RBinDwarfDie *child_die = &all_dies[++idx];
		size_t j;
		const char *name = NULL;
		bool has_linkage_name = false;
		for (j = idx; child_depth > 0 && j < count; j++) {
			child_die = &all_dies[j];
			RStrBuf type;
			r_strbuf_init (&type);
			// right now we skip non direct descendants of the structure
			// TODO maybe add parsing of possible thrown exception DW_TAG_thrown_type
			if (child_depth == 1 && child_die->tag == DW_TAG_formal_parameter) {
				size_t i;
				for (i = 0; i < child_die->count; i++) {
					const RBinDwarfAttrValue *val = &child_die->attr_values[i];
					switch (val->attr_name) {
					case DW_AT_name:
						if (!has_linkage_name) {
							name = val->string.content;
						}
						break;
					case DW_AT_linkage_name:
					case DW_AT_MIPS_linkage_name:
						name = val->string.content;
						has_linkage_name = true;
						break;
					case DW_AT_type:
						parse_type (all_dies, count, val->reference, &type, NULL, die_map);
						break;
					// abstract origin is supposed to have omitted information
					case DW_AT_abstract_origin:
						parse_abstract_origin (all_dies, count, val->reference, &type, &name, die_map);
						break;
					default:
						break;
					}
				}
				r_warn_if_fail (type.len && name);
				r_strbuf_appendf (args, "%s %s,", r_strbuf_get (&type), name);
				r_strbuf_fini (&type);
			} else if (child_depth == 1 && child_die->tag == DW_TAG_unspecified_parameters) {
				r_strbuf_appendf (args, "va_args ...,");
			} else if (child_depth == 1 && child_die->tag == DW_TAG_variable) {
				size_t i;
				for (i = 0; i < child_die->count; i++) {
					const RBinDwarfAttrValue *val = &child_die->attr_values[i];
					switch (val->attr_name) {
					case DW_AT_name:
						if (!has_linkage_name) {
							name = val->string.content;
						}
						break;
					case DW_AT_linkage_name:
					case DW_AT_MIPS_linkage_name:
						name = val->string.content;
						has_linkage_name = true;
						break;
					case DW_AT_type:
						parse_type (all_dies, count, val->reference, &type, NULL, die_map);
						break;
					// abstract origin is supposed to have omitted information
					case DW_AT_abstract_origin:
						parse_abstract_origin (all_dies, count, val->reference, &type, &name, die_map);
						break;
					case DW_AT_location:
						if (val->kind == DW_AT_KIND_BLOCK) {
							parse_dwarf_location (val);
						}
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
		// if no params
		if (args->len > 0) {
			r_strbuf_slice (args, 0, args->len - 1);
		}
	}
	return 0;
}

static void sdb_save_dwarf_function(DwarfFunction *fcn, Sdb *sdb) {
	sdb_set (sdb, fcn->name, "func", 0);
	char *addr_key = r_str_newf ("func.%s.addr", fcn->name);
	char *addr_val = r_str_newf ("0x%" PFMT64x "", fcn->addr);
	sdb_set (sdb, addr_key, addr_val, 0);
	char *sig_key = r_str_newf ("func.%s.sig", fcn->name);
	sdb_set (sdb, sig_key, fcn->signature, 0);
	free (addr_key);
	free (addr_val);
	free (sig_key);
}

/**
 * @brief Parse function,it's arguments and
 *        save the information into the Sdb
 * 
 * @param anal 
 * @param all_dies 
 * @param count 
 * @param idx 
 * @param sdb 
 */
static void parse_function(const RAnal *anal, const RBinDwarfDie *all_dies, 
	const ut64 count, ut64 idx, Sdb *sdb, HtUP *die_map) {

	r_return_if_fail (all_dies && sdb && die_map);
	const RBinDwarfDie *die = &all_dies[idx];

	DwarfFunction fcn = { 0 };
	bool has_linkage_name = false;
	RStrBuf ret_type;
	r_strbuf_init (&ret_type);

	size_t i;
	for (i = 0; i < die->count; i++) {
		RBinDwarfAttrValue *val = &die->attr_values[i];
		switch (die->attr_values[i].attr_name) {
		case DW_AT_declaration: // just a declaration, skip
			return;
		// Prefer the linkage name
		case DW_AT_name:
			if (!has_linkage_name) {
				fcn.name = val->string.content;
			}
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			fcn.name = val->string.content;
			has_linkage_name = true;
			break;
		case DW_AT_low_pc:
		case DW_AT_entry_pc:
			fcn.addr  = val->address;
			break;
		case DW_AT_specification: // reference to declaration DIE with more info
		{
			RBinDwarfDie *spec_die = ht_up_find (die_map, val->reference, NULL);
			if (spec_die) {
				fcn.name = get_specification_die_name (spec_die); // I assume that if specification has a name, this DIE hasn't
				get_spec_die_type (all_dies, count, spec_die, &ret_type, die_map);
			}
		} break;
		case DW_AT_type:
			parse_type (all_dies, count, val->reference, &ret_type, NULL, die_map);
			break;
		case DW_AT_virtuality:
			fcn.is_method = true; // method specific attr
			fcn.is_virtual = true;
			break;
		case DW_AT_object_pointer:
			fcn.is_method = true;
			break;
		case DW_AT_vtable_elem_location:
			fcn.is_method = true;
			fcn.vtable_addr = 0; // TODO, how this location description work
			break;
		case DW_AT_accessibility:
			fcn.is_method = true;
			fcn.access = (ut8) val->constant;
			break;
		case DW_AT_external:
			fcn.is_external = true;
			break;
		case DW_AT_trampoline:
			fcn.is_trampoline = true;
			break;
		case DW_AT_ranges: // TODO, might be useful info
		case DW_AT_high_pc:
		default:
			break;
		}
	}
	if (!fcn.name || !fcn.addr) { // we need a name, faddr
		goto cleanup;
	}
	RStrBuf args;
	r_strbuf_init (&args);
	parse_function_args (all_dies, count, idx, &args, die_map);

	if (ret_type.len == 0) { // DW_AT_type is omitted in case of `void` ret type
		r_strbuf_append (&ret_type, "void");
	}
	fcn.signature = r_str_newf ("%s (%s);", r_strbuf_get (&ret_type), r_strbuf_get (&args));
	// XXX function can have a mangled name, appears demangled in afl or pdf
	sdb_save_dwarf_function (&fcn, sdb);

	free ((char *)fcn.signature);
	r_strbuf_fini (&args);
cleanup:
	r_strbuf_fini (&ret_type);
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
	const ut64 count, ut64 idx, HtUP *die_map, Sdb *dwarf_sdb) {

	r_return_if_fail (anal && all_dies);

	const RBinDwarfDie *die = &all_dies[idx];
	switch (die->tag) {
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		parse_structure_type (anal, all_dies, count, idx, die_map);
		break;
	case DW_TAG_enumeration_type:
		parse_enum_type (anal, all_dies, count, idx, die_map);
		break;
	case DW_TAG_typedef:
		parse_typedef (anal, all_dies, count, idx, die_map);
		break;
	case DW_TAG_base_type:
		parse_atomic_type (anal, all_dies, count, idx);
		break;
	case DW_TAG_subprogram:
		parse_function (anal, all_dies, count, idx, dwarf_sdb, die_map);
		break;
	default:
		break;
	}
}

/**
 * @brief Parses type and function information out of DWARF entries
 *        and stores them to the sdb for further use
 * 
 * @param info 
 * @param anal 
 */
R_API void r_anal_process_dwarf_info(const RAnal *anal, const RBinDwarfDebugInfo *info) {
	r_return_if_fail (info && anal);
	Sdb *dwarf_sdb =  sdb_ns (anal->sdb, "dwarf", 1);
    size_t i, j;
	for (i = 0; i < info->count; i++) {
		RBinDwarfCompUnit *unit = &info->comp_units[i];
		for (j = 0; j < unit->count; j++) {
			RBinDwarfDie *curr_die = &unit->dies[j];
			if (is_type_tag (curr_die->tag)) {
				parse_type_entry (anal, unit->dies, unit->count, j, info->lookup_table, dwarf_sdb);
			}
		}
	}
}

bool filter_sdb_function_names(void *user, const char *k, const char *v) {
	(void) user;
	(void) k;
	return !strcmp (v, "func");
}

/**
 * @brief Use parsed DWARF function info from Sdb in the anal functions
 *  XXX right now we only save parsed name, we can't use signature now
 * @param anal 
 * @param dwarf_sdb 
 * @return R_API 
 */
R_API void r_anal_integrate_dwarf_functions(RAnal *anal, Sdb *dwarf_sdb) {
	r_return_if_fail (anal && dwarf_sdb);

	// get all entries with value == func
	SdbList *sdb_list = sdb_foreach_list_filter (dwarf_sdb, filter_sdb_function_names, false);
	SdbListIter *it;
	SdbKv *kv;
	// iterate all function entries
	ls_foreach (sdb_list, it, kv) {
		char *func_name = kv->base.key;
		char *addr_key = r_str_newf ("func.%s.addr", func_name);
		ut64 faddr = sdb_num_get (dwarf_sdb, addr_key, 0);
		R_FREE (addr_key);

		// if the function is analyzed so we can edit
		RAnalFunction *func = r_anal_get_function_at (anal, faddr);
		if (func) {
			r_anal_function_rename (func, func_name);
			// TODO apply signatures when r2 will use tree-sitter parser
			// tmp = sdb_fmt ("func.%s.sig", func_name);
			// char *fcnstr = sdb_get (dwarf_sdb, tmp, 0);
			// r_anal_str_to_fcn (anal, func, fcnstr);
		}
	}
	ls_free (sdb_list);
} 