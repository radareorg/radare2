/* radare - LGPL - Copyright 2012-2025 - pancake, houndthe */

#include <ctype.h>
#include <errno.h>
#include <r_anal.h>
#include <r_anal_priv.h>
#include <r_bin_dwarf.h>

typedef struct dwarf_parse_context_t {
	const RAnal *anal;
	const RBinDwarfDie *all_dies;
	const ut64 count;
	Sdb *sdb;
	HtUP/*<ut64 offset, DwarfDie *die>*/ *die_map;
	HtUU/*<ut64 offset, size_t index>*/ *cu_die_indices;
	HtUP/*<offset, RBinDwarfLocList*>*/  *locations;
	const char *lang; // for demangling
	RArena *arena;
	HtUP *exact_formal_records;
	HtUP *exact_function_links;
	HtUP *exact_frame_pointer_proofs;
	bool *exact_formal_records_ok;
	bool tree_exact;
} Context;

typedef struct dwarf_function_t {
	ut64 addr;
	const char *name;
	const char *type_name;
	char *signature;
	bool is_external;
	bool is_method;
	bool is_virtual;
	bool is_trampoline; // intermediary in making call to another func
	ut8 access; // public = 1, protected = 2, private = 3, if not set assume private
	ut64 vtable_addr; // location description
	ut64 call_conv; // normal || program || nocall
} Function;

typedef enum dwarf_location_kind {
	LOCATION_UNKNOWN = 0,
	LOCATION_GLOBAL = 1,
	LOCATION_BP = 2,
	LOCATION_SP = 3,
	LOCATION_REGISTER = 4,
} VariableLocationKind;

typedef struct dwarf_var_location_t {
	VariableLocationKind kind;
	ut64 address;
	ut64 reg_num;
	st64 offset;
	const char *reg_name; /* string literal */
	bool exact;
} VariableLocation;

typedef enum dwarf_variable_kind_t {
	VARIABLE_KIND_INVALID = 0,
	VARIABLE_KIND_FORMAL_PARAMETER = 1,
	VARIABLE_KIND_LOCAL = 2,
} VariableKind;

typedef struct dwarf_variable_t {
	VariableLocation *location;
	char *name;
	char *type;
	VariableKind kind;
	int formal_index;
	bool is_result;
} Variable;

static void variable_free(Variable *var) {
	if (var) {
		free (var->name);
		free (var->location);
		free (var->type);
		free (var);
	}
}

/* return -1 if attr isn't found */
static inline st32 find_attr_idx(const RBinDwarfDie *die, st32 attr_name) {
	R_RETURN_VAL_IF_FAIL (die, -1);
	if (!die->attr_values) {
		return -1;
	}

	R_VEC_FOREACH_I (die->attr_values, i) {
		RBinDwarfAttrValue *value = RVecDwarfAttrValue_at(die->attr_values, i);
		if (value->attr_name == attr_name) {
			return i;
		}
	}
	return -1;
}

/* return NULL if attr isn't found */
static RBinDwarfAttrValue *find_attr(const RBinDwarfDie *die, st32 attr_name) {
	R_RETURN_VAL_IF_FAIL (die, NULL);
	if (!die->attr_values) {
		return NULL;
	}

	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		if (value->attr_name == attr_name) {
			return value;
		}
	}
	return NULL;
}

/**
 * @brief Pasted from r_strbuf_*
 *        Prepends string before a last occurence of character c
 * 	      Used to replicate proper C declaration for function pointers
 * @param sb
 * @param s
 * @param c
 */
static bool strbuf_rev_prepend_char(RStrBuf *sb, const char *s, int c) {
	R_RETURN_VAL_IF_FAIL (sb && s, false);
	size_t l = strlen (s);
	// fast path if no chars to append
	if (l == 0) {
		return true;
	}
	size_t newlen = l + sb->len;
	char *ns = malloc (newlen + 1);
	if (!ns) {
		return false;
	}
	bool ret = false;
	char *sb_str = sb->ptr ? sb->ptr : sb->buf;
	char *pivot = strrchr (sb_str, c);
	if (pivot) {
		size_t idx = pivot - sb_str;
		memcpy (ns, sb_str, idx);
		memcpy (ns + idx, s, l);
		memcpy (ns + idx + l, sb_str + idx, sb->len - idx);
		ns[newlen] = 0;
		ret = r_strbuf_set (sb, ns);
	}
	free (ns);
	return ret;
}
/**
 * @brief Pasted from r_strbuf_*
 * 	      Appends string after a first occurence of character c
 * 	      Used to replicate proper C declaration for function pointers
 * @param sb
 * @param s
 * @param needle
 */
static bool strbuf_rev_append_char(RStrBuf *sb, const char *s, const char *needle) {
	R_RETURN_VAL_IF_FAIL (sb && s, false);
	size_t l = strlen (s);
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
	size_t newlen = l + sb->len;
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

static inline char *create_type_name_from_offset(RArena *arena, ut64 offset) {
	return r_arena_push_strf (arena, "type_0x%" PFMT64x, offset);
}

static RBinDwarfAttrValue *get_die_attr(const RBinDwarfDie *die, int attr_name) {
	st32 idx = find_attr_idx (die, attr_name);
	if (idx == -1) {
		return NULL;
	}
	return RVecDwarfAttrValue_at (die->attr_values, idx);
}

/**
 * @brief Get the DIE name or create unique one from it's offset
 *
 * @param die
 * @return char* DIEs name or NULL if error
 */
static const char *get_die_name(RArena *arena, const RBinDwarfDie *die) {
	RBinDwarfAttrValue *av = get_die_attr(die, DW_AT_name);
	if (av && av->kind == DW_AT_KIND_STRING && av->string.content) {
		return av->string.content;
	}
	return create_type_name_from_offset (arena, die->offset);
}

/**
 * @brief Get the DIE size in bits
 *
 * @param die
 * @return ut64 size in bits or 0 if not found
 */
static ut64 get_die_size(const RBinDwarfDie *die) {
	ut64 size = 0;
	RBinDwarfAttrValue *av = get_die_attr (die, DW_AT_byte_size);

	if (av) {
		size = av->uconstant * CHAR_BIT;
	} else {
		av = get_die_attr (die, DW_AT_bit_size);

		if (av) {
			size = av->uconstant;
		}
	}
	return size;
}

/**
 * @brief Parses array type entry signature into strbuf
 *
 * @param ctx
 * @param idx index of the current entry
 * @param strbuf strbuf to store the type into
 * @return st32 -1 if error else 0
 */
static void parse_array_type(Context *ctx, int idx, RStrBuf *strbuf) {
	if (idx < 0 || idx >= ctx->count) {
		return;
	}
	const RBinDwarfDie *die = &ctx->all_dies[idx++];

	if (die->has_children) {
		int child_depth = 1;
		size_t j;
		for (j = idx; child_depth > 0 && j < ctx->count; j++) {
			const RBinDwarfDie *child_die = &ctx->all_dies[j];
			// right now we skip non direct descendats of the structure
			// can be also DW_TAG_suprogram for class methods or tag for templates
			if (child_depth == 1 && child_die->tag == DW_TAG_subrange_type && child_die->attr_values) {
				RBinDwarfAttrValue *value;
				R_VEC_FOREACH(child_die->attr_values, value) {
					switch (value->attr_name) {
					case DW_AT_upper_bound:
						// The last index, so the extent is one more than it.
						r_strbuf_appendf (strbuf, "[%" PFMT64d "]", value->uconstant + 1);
						break;
					case DW_AT_count:
						// Already the extent. Adding one to it as well made every
						// clang-built array import one element too large, so
						// `int32_t r[8]` came back as `int32_t[9]`.
						r_strbuf_appendf (strbuf, "[%" PFMT64d "]", value->uconstant);
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
}

/**
 * @brief Recursively parses type entry of a certain offset into strbuf
 *        saves type size into *size
 *
 * @param ctx
 * @param offset offset of the type entry
 * @param strbuf string to store the type into
 * @param size ptr to size of a type to fill up (can be NULL if unwanted)
 * @return st32 -1 if error else DW_TAG of the entry
 *
 * TODO make cache for type entries, one type is usually referenced
 * multiple times which means it's parsed multiple times instead of once
 */
static st32 parse_type(Context *ctx, const ut64 offset, RStrBuf *strbuf, ut64 *size, HtUP **visited) {
	R_RETURN_VAL_IF_FAIL (strbuf, -1);
	RBinDwarfDie *die = ht_up_find (ctx->die_map, offset, NULL);
	if (!die || !die->attr_values) {
		return -1;
	}
	bool root = false;

	if (!visited) {
		root = true;
		SetU *su = set_u_new ();
		visited = malloc (sizeof (void*));
		*visited = su;
	}
	if (visited && set_u_contains (*visited, offset)) {
		R_LOG_WARN ("anal.dwarf.parse_type: infinite recursion detected");
		if (root) {
			set_u_free (*visited);
			free (visited);
		}
		return -1;
	}
	set_u_add (*visited, offset);

	st32 type_idx;
	st32 tag;
	const char *name = NULL;
	// get size of first type DIE that has size
	if (size && *size == 0) {
		*size = get_die_size (die);
	}
	RBinDwarfAttrValue *attr_values = die->attr_values->_start;
	switch (die->tag) {
	// this should be recursive search for the type until you find base/user defined type
	case DW_TAG_pointer_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx == -1) {
			r_strbuf_append (strbuf, "void");
			r_strbuf_append (strbuf, " *");
		} else {
			tag = parse_type (ctx, attr_values[type_idx].reference, strbuf, size, visited);
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
		name = get_die_name (ctx->arena, die);
		if (name) {
			r_strbuf_append (strbuf, name);
		}
		break;
	case DW_TAG_subroutine_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx == -1) {
			r_strbuf_append (strbuf, "void");
		} else {
			parse_type (ctx, attr_values[type_idx].reference, strbuf, size, visited);
		}
		r_strbuf_append (strbuf, " (");
		if (die->has_children) { // has parameters
		}
		r_strbuf_append (strbuf, ")");
		break;
	case DW_TAG_array_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (ctx, attr_values[type_idx].reference, strbuf, size, visited);
		}
		parse_array_type (ctx, die - ctx->all_dies, strbuf);
		break;
	case DW_TAG_const_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (ctx, attr_values[type_idx].reference, strbuf, size, visited);
		}
		r_strbuf_append (strbuf, " const");
		break;
	case DW_TAG_volatile_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (ctx, attr_values[type_idx].reference, strbuf, size, visited);
		}
		r_strbuf_append (strbuf, " volatile");
		break;
	case DW_TAG_restrict_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (ctx, attr_values[type_idx].reference, strbuf, size, visited);
		}
		r_strbuf_append (strbuf, " restrict");
		break;
	case DW_TAG_rvalue_reference_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (ctx, attr_values[type_idx].reference, strbuf, size, visited);
		}
		r_strbuf_append (strbuf, " &&");
		break;
	case DW_TAG_reference_type:
		type_idx = find_attr_idx (die, DW_AT_type);
		if (type_idx != -1) {
			parse_type (ctx, attr_values[type_idx].reference, strbuf, size, visited);
		}
		r_strbuf_append (strbuf, " &");
		break;
	default:
		break;
	}
	if (root) {
		set_u_free (*visited);
		free (visited);
	}
	return (st32)die->tag;
}

/**
 * @brief Parses structured entry into *result RAnalStructMember
 * https://www.dwarfstd.org/doc/DWARF4.pdf#page=102&zoom=100,0,0
 *
 * @param ctx
 * @param idx index of the current entry
 * @param result ptr to result member to fill up
 * @return RAnalStructMember* ptr to parsed Member
 */
static RAnalStructMember *parse_struct_member(Context *ctx, ut64 idx, RAnalStructMember *result) {
	R_RETURN_VAL_IF_FAIL (result, NULL);
	const RBinDwarfDie *die = &ctx->all_dies[idx];
	if (!die->attr_values) {
		return NULL;
	}

	const char *name = NULL;
	char *type = NULL;
	ut64 offset = 0;
	ut64 size = 0;
	RStrBuf strbuf;
	r_strbuf_init (&strbuf);

	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		switch (value->attr_name) {
		case DW_AT_name:
			name = get_die_name (ctx->arena, die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_type:
			parse_type (ctx, value->reference, &strbuf, &size, NULL);
			free (type);
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
				https://www.dwarfstd.org/doc/DWARF4.pdf#page=39&zoom=100,0,0
			*/
			offset = value->uconstant;
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
			size = value->uconstant * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = value->uconstant;
			break;
		case DW_AT_containing_type:
		default:
			break;
		}
	}

	if (!name || !type) {
		goto cleanup;
	}

	result->name = strdup (name);
	result->type = strdup (type);
	free (type);
	r_strbuf_fini (&strbuf);
	result->offset = offset;
	result->bitsize = size;
	return result;
cleanup:
	free (type);
	r_strbuf_fini (&strbuf);
	return NULL;
}

/**
 * @brief  Parses enum entry into *result RAnalEnumCase
 * https://www.dwarfstd.org/doc/DWARF4.pdf#page=110&zoom=100,0,0
 *
 * @param ctx
 * @param idx index of the current entry
 * @param result ptr to result case to fill up
 * @return RAnalEnumCase* Ptr to parsed enum case
 */
static RAnalEnumCase *parse_enumerator(Context *ctx, ut64 idx, RAnalEnumCase *result) {
	const RBinDwarfDie *die = &ctx->all_dies[idx];
	if (!die->attr_values) {
		return NULL;
	}

	const char *name = NULL;
	int val = 0;

	// Enumerator has DW_AT_name and DW_AT_const_value
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH(die->attr_values, value) {
		switch (value->attr_name) {
		case DW_AT_name:
			name = get_die_name (ctx->arena, die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_const_value:
			// ?? can be block, sdata, data, string w/e
			val = value->uconstant; // TODO solve the encoding, I don't know in which union member is it store
			break;
		default:
			break;
		}
	}

	if (!name) {
		goto cleanup;
	}

	if (result->name != name) {
		result->name = strdup (name);
	}
	result->val = (int)val;
	return result;
cleanup:
	return NULL;
}

/**
 * @brief  Parses a structured entry (structs, classes, unions) into
 *         RAnalBaseType and saves it using r_anal_save_base_type ()
 *
 * @param ctx
 * @param idx index of the current entry
 */
// https://www.dwarfstd.org/doc/DWARF4.pdf#page=102&zoom=100,0,0
static void parse_structure_type(Context *ctx, ut64 idx) {
	const RBinDwarfDie *die = &ctx->all_dies[idx];

	if (find_attr_idx (die, DW_AT_declaration) != -1) {
		return;
	}

	RAnalBaseTypeKind kind;
	if (die->tag == DW_TAG_union_type) {
		kind = R_ANAL_BASE_TYPE_KIND_UNION;
	} else {
		kind = R_ANAL_BASE_TYPE_KIND_STRUCT;
	}

	RAnalBaseType *base_type = r_anal_base_type_new (kind);
	if (!base_type) {
		return;
	}

	const char *name = get_die_name (ctx->arena, die);
	if (!name) {
		goto cleanup;
	}
	base_type->name = strdup (name);

	// if it is definition of previous declaration (TODO Fix, big ugly hotfix addition)
	st32 spec_attr_idx = find_attr_idx (die, DW_AT_specification);
	if (spec_attr_idx != -1) {
		RBinDwarfDie *decl_die = ht_up_find (ctx->die_map, RVecDwarfAttrValue_at(die->attr_values, spec_attr_idx)->reference, NULL);
		if (!decl_die) {
			goto cleanup;
		}
		st32 name_attr_idx = find_attr_idx (decl_die, DW_AT_name);
		if (name_attr_idx != -1) {
			free (base_type->name);
			base_type->name = strdup (get_die_name (ctx->arena, decl_die));
		}
	}

	base_type->size = get_die_size (die);

	RAnalStructMember member = {0};
	// Parse out all members, can this in someway be extracted to a function?
	if (die->has_children) {
		int child_depth = 1; // Direct children of the node
		size_t j;
		idx++; // Move to the first children node
		for (j = idx; child_depth > 0 && j < ctx->count; j++) {
			const RBinDwarfDie *child_die = &ctx->all_dies[j];
			// we take only direct descendats of the structure
			// can be also DW_TAG_suprogram for class methods or tag for templates
			if (child_depth == 1 && child_die->tag == DW_TAG_member) {
				RAnalStructMember *result = parse_struct_member (ctx, j, &member);
				if (!result) {
					goto cleanup;
				}
				RAnalTypeMember *slot = RVecAnalTypeMember_emplace_back (r_anal_base_type_members (base_type));
				if (!slot) {
					anal_type_member_fini (&member);
					goto cleanup;
				}
				*slot = member;
			}
			if (child_die->has_children) {
				child_depth++;
			}
			if (child_die->abbrev_code == 0) { // siblings terminator
				child_depth--;
			}
		}
	}
	r_anal_save_base_type (ctx->anal, base_type);
cleanup:
	r_anal_base_type_free (base_type);
}

/**
 * @brief Parses a enum entry into RAnalBaseType and saves it
 *        int Sdb using r_anal_save_base_type ()
 *
 * @param ctx
 * @param idx index of the current entry
 */
static void parse_enum_type(Context *ctx, ut64 idx) {
	const RBinDwarfDie *die = &ctx->all_dies[idx];

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return;
	}

	const char *name = get_die_name (ctx->arena, die);
	if (!name) {
		goto cleanup;
	}
	base_type->name = strdup (name);
	base_type->size = get_die_size (die);

	RBinDwarfAttrValue *attr = get_die_attr (die, DW_AT_type);
	if (attr) {
		RStrBuf strbuf;
		r_strbuf_init (&strbuf);
		parse_type (ctx, attr->reference, &strbuf, &base_type->size, NULL);
		base_type->type = r_strbuf_drain_nofree (&strbuf);
	}

	RAnalEnumCase cas = {0};
	if (die->has_children) {
		int child_depth = 1; // Direct children of the node
		size_t j;
		idx++; // Move to the first children node
		for (j = idx; child_depth > 0 && j < ctx->count; j++) {
			const RBinDwarfDie *child_die = &ctx->all_dies[j];
			// we take only direct descendats of the structure
			if (child_depth == 1 && child_die->tag == DW_TAG_enumerator) {
				RAnalEnumCase *result = parse_enumerator (ctx, j, &cas);
				if (!result) {
					goto cleanup;
				}
				RAnalEnumCase *slot = RVecAnalEnumCase_emplace_back (&base_type->enum_data.cases);
				*slot = cas;
				cas.name = NULL;
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
	r_anal_save_base_type (ctx->anal, base_type);
cleanup:
	r_anal_base_type_free (base_type);
}

/**
 * @brief Parses a typedef entry into RAnalBaseType and saves it
 *        using r_anal_save_base_type ()
 *
 * https://www.dwarfstd.org/doc/DWARF4.pdf#page=96&zoom=100,0,0
 *
 * @param ctx
 * @param idx index of the current entry
 */
static void parse_typedef(Context *ctx, ut64 idx) {
	const RBinDwarfDie *die = &ctx->all_dies[idx];
	if (!die->attr_values) {
		return;
	}

	const char *name = NULL;
	const char *type = NULL;
	ut64 size = 0;
	RStrBuf strbuf;
	r_strbuf_init (&strbuf);

	RBinDwarfAttrValue *value;
	R_VEC_FOREACH(die->attr_values, value) {
		switch (value->attr_name) {
		case DW_AT_name:
			name = get_die_name (ctx->arena, die);
			if (!name) {
				goto cleanup;
			}
			break;
		case DW_AT_type:
			parse_type (ctx, value->reference, &strbuf, &size, NULL);
			type = r_strbuf_drain_nofree (&strbuf);
			if (!type) {
				goto cleanup;
			}
			break;
		default:
			break;
		}
	}
	if (!name || !type) { // type has to have a name for now
		goto cleanup;
	}
	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		goto cleanup;
	}
	base_type->name = strdup (name);
	base_type->type = strdup (type);
	r_anal_save_base_type (ctx->anal, base_type);
	r_anal_base_type_free (base_type);
	r_strbuf_fini (&strbuf);
	R_FREE (type);
	return;
cleanup:
	R_FREE (type);
	r_strbuf_fini (&strbuf);
}

static void parse_atomic_type(Context *ctx, ut64 idx) {
	const RBinDwarfDie *die = &ctx->all_dies[idx];
	if (!die->attr_values) {
		return;
	}

	const char *name = NULL;
	ut64 size = 0;
	// TODO support endiannity and encoding in future?
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH(die->attr_values, value) {
		switch (value->attr_name) {
		case DW_AT_name:
			if (value->kind == DW_AT_KIND_STRING) {
				if (!value->string.content) {
					name = create_type_name_from_offset (ctx->arena, die->offset);
				} else {
					name = value->string.content;
				}
			}
			if (!name) {
				return;
			}
			break;
		case DW_AT_byte_size:
			size = value->uconstant * CHAR_BIT;
			break;
		case DW_AT_bit_size:
			size = value->uconstant;
			break;
		case DW_AT_encoding:
		default:
			break;
		}
	}
	if (!name) { // type has to have a name for now
		return;
	}
	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		return;
	}
	base_type->name = strdup (name);
	base_type->size = size;
	r_anal_save_base_type (ctx->anal, base_type);
	r_anal_base_type_free (base_type);
}

/* For some languages linkage name is more informative like C++,
 * but for Rust it's rubbish and the normal name is fine */
static bool prefer_linkage_name(const char *lang) {
	if (!lang || !strcmp (lang, "rust") || !strcmp (lang, "ada")) {
		return false;
	}
	return true;
}

typedef struct dwarf_exact_decl_t {
	const char *name;
	const char *linkage_name;
	const char *standard_linkage_name;
	ut64 type_ref;
	bool has_type;
	bool prototyped;
	bool has_prototyped;
	bool has_code_location;
} DwarfExactDecl;

#define DWARF_EXACT_REFERENCE_LIMIT 256

static bool dwarf_die_index_in_current_cu(Context *ctx, const RBinDwarfDie *die, R_OUT size_t *index);

static bool dwarf_exact_string_merge(const char **dst, const char *src) {
	if (!*dst) {
		*dst = src;
		return true;
	}
	return !strcmp (*dst, src);
}

static bool dwarf_exact_type_merge(DwarfExactDecl *decl, ut64 type_ref) {
	if (!decl->has_type) {
		decl->type_ref = type_ref;
		decl->has_type = true;
		return true;
	}
	return decl->type_ref == type_ref;
}

static bool dwarf_exact_prototyped_merge(DwarfExactDecl *decl, bool prototyped) {
	if (!decl->has_prototyped) {
		decl->prototyped = prototyped;
		decl->has_prototyped = true;
		return true;
	}
	return decl->prototyped == prototyped;
}

static bool dwarf_merge_exact_decl_die(const RBinDwarfDie *die, DwarfExactDecl *decl) {
	const RBinDwarfAttrValue *value;
	size_t name_count = 0;
	size_t linkage_name_count = 0;
	size_t type_count = 0;
	size_t prototyped_count = 0;
	size_t declaration_count = 0;
	R_VEC_FOREACH (die->attr_values, value) {
		switch (value->attr_name) {
		case DW_AT_name:
			name_count++;
			if (value->kind != DW_AT_KIND_STRING || R_STR_ISEMPTY (value->string.content)
				|| !dwarf_exact_string_merge (&decl->name, value->string.content)) {
				return false;
			}
			break;
		case DW_AT_linkage_name:
			linkage_name_count++;
			if (value->kind != DW_AT_KIND_STRING || R_STR_ISEMPTY (value->string.content)
				|| !dwarf_exact_string_merge (&decl->linkage_name, value->string.content)) {
				return false;
			}
			decl->standard_linkage_name = value->string.content;
			break;
		case DW_AT_MIPS_linkage_name:
			linkage_name_count++;
			if (value->kind != DW_AT_KIND_STRING || R_STR_ISEMPTY (value->string.content)
				|| !dwarf_exact_string_merge (&decl->linkage_name, value->string.content)) {
				return false;
			}
			break;
		case DW_AT_type:
			type_count++;
			if (value->kind != DW_AT_KIND_REFERENCE
				|| !dwarf_exact_type_merge (decl, value->reference)) {
				return false;
			}
			break;
		case DW_AT_prototyped:
			prototyped_count++;
			if (value->kind != DW_AT_KIND_FLAG
				|| !dwarf_exact_prototyped_merge (decl, value->flag)) {
				return false;
			}
			break;
		case DW_AT_low_pc:
		case DW_AT_entry_pc:
		case DW_AT_high_pc:
		case DW_AT_ranges:
			decl->has_code_location = true;
			break;
		case DW_AT_declaration:
			if (value->kind != DW_AT_KIND_FLAG) {
				return false;
			}
			declaration_count++;
			break;
		default:
			break;
		}
	}
	return name_count <= 1 && linkage_name_count <= 1 && type_count <= 1
		&& prototyped_count <= 1 && declaration_count <= 1;
}

static bool dwarf_collect_exact_decl(Context *ctx, const RBinDwarfDie *die, ut64 expected_tag, bool current_cu_only, DwarfExactDecl *decl, R_OUT const RBinDwarfDie **terminal) {
	if (terminal) {
		*terminal = NULL;
	}
	const RBinDwarfDie *chain[DWARF_EXACT_REFERENCE_LIMIT];
	size_t chain_count = 0;
	SetU *visited = set_u_new ();
	if (!visited) {
		return false;
	}
	bool exact = false;
	for (;;) {
		size_t die_index;
		if (!die || !die->attr_values || die->tag != expected_tag
			|| chain_count >= DWARF_EXACT_REFERENCE_LIMIT
			|| chain_count >= ctx->count || set_u_contains (visited, die->offset)
			|| (current_cu_only
				&& !dwarf_die_index_in_current_cu (ctx, die, &die_index))) {
			goto beach;
		}
		set_u_add (visited, die->offset);
		chain[chain_count++] = die;
		const RBinDwarfAttrValue *origin = NULL;
		size_t origin_count = 0;
		const RBinDwarfAttrValue *value;
		R_VEC_FOREACH (die->attr_values, value) {
			if (value->attr_name == DW_AT_specification || value->attr_name == DW_AT_abstract_origin) {
				origin_count++;
				if (value->kind != DW_AT_KIND_REFERENCE) {
					goto beach;
				}
				origin = value;
			}
		}
		if (origin_count > 1) {
			goto beach;
		}
		if (!origin) {
			break;
		}
		die = ht_up_find (ctx->die_map, origin->reference, NULL);
	}
	const RBinDwarfDie *terminal_die = die;
	while (chain_count > 0) {
		if (!dwarf_merge_exact_decl_die (chain[--chain_count], decl)) {
			goto beach;
		}
	}
	if (terminal) {
		*terminal = terminal_die;
	}
	exact = true;
beach:
	set_u_free (visited);
	return exact;
}

typedef enum dwarf_direct_signature_result_t {
	DWARF_DIRECT_SIGNATURE_ERROR = -1,
	DWARF_DIRECT_SIGNATURE_END = 0,
	DWARF_DIRECT_SIGNATURE_CHILD = 1,
} DwarfDirectSignatureResult;

typedef struct dwarf_direct_signature_iter_t {
	Context *ctx;
	size_t next;
	int depth;
} DwarfDirectSignatureIter;

static bool dwarf_die_index_in_current_cu(Context *ctx, const RBinDwarfDie *die, R_OUT size_t *index) {
	if (!ctx || !ctx->cu_die_indices || !die || !index) {
		return false;
	}
	bool found = false;
	const ut64 die_index = ht_uu_find (
		ctx->cu_die_indices, die->offset, &found);
	if (!found || die_index >= ctx->count
		|| &ctx->all_dies[die_index] != die) {
		return false;
	}
	*index = (size_t)die_index;
	return true;
}

static HtUU *dwarf_cu_die_indices_new(const RBinDwarfDie *dies, size_t count) {
	if (!dies || !count) {
		return NULL;
	}
	HtUU *indices = ht_uu_new0 ();
	if (!indices) {
		return NULL;
	}
	size_t i;
	for (i = 0; i < count; i++) {
		bool found = false;
		ht_uu_find (indices, dies[i].offset, &found);
		if (found || !ht_uu_insert (indices, dies[i].offset, (ut64)i)) {
			ht_uu_free (indices);
			return NULL;
		}
	}
	return indices;
}

static bool dwarf_cu_tree_is_exact(const RBinDwarfDie *dies, size_t count) {
	if (!dies || !count) {
		return false;
	}
	size_t depth = 0;
	size_t i;
	for (i = 0; i < count; i++) {
		const RBinDwarfDie *die = &dies[i];
		if (!die->abbrev_code) {
			if (!depth || die->tag || die->has_children) {
				return false;
			}
			depth--;
			continue;
		}
		if (i > 0 && !depth) {
			return false;
		}
		if (die->has_children) {
			if (depth >= count) {
				return false;
			}
			depth++;
		}
	}
	return depth == 0;
}

static bool dwarf_direct_signature_iter_init(Context *ctx, const RBinDwarfDie *parent, R_OUT DwarfDirectSignatureIter *iter) {
	size_t index;
	if (!iter || !ctx->tree_exact
		|| !dwarf_die_index_in_current_cu (ctx, parent, &index)) {
		return false;
	}
	iter->ctx = ctx;
	iter->next = index + 1;
	iter->depth = parent->has_children? 1: 0;
	return true;
}

static DwarfDirectSignatureResult dwarf_direct_signature_next(DwarfDirectSignatureIter *iter, R_OUT const RBinDwarfDie **child) {
	if (!iter || !iter->ctx || !child) {
		return DWARF_DIRECT_SIGNATURE_ERROR;
	}
	*child = NULL;
	while (iter->depth > 0) {
		if (iter->next >= iter->ctx->count) {
			return DWARF_DIRECT_SIGNATURE_ERROR;
		}
		const RBinDwarfDie *die = &iter->ctx->all_dies[iter->next++];
		const bool direct = iter->depth == 1;
		const bool signature_child = direct
			&& (die->tag == DW_TAG_formal_parameter
				|| die->tag == DW_TAG_unspecified_parameters);
		if (signature_child && (die->abbrev_code == 0 || die->has_children)) {
			return DWARF_DIRECT_SIGNATURE_ERROR;
		}
		if (die->has_children) {
			iter->depth++;
		}
		if (die->abbrev_code == 0) {
			iter->depth--;
		}
		if (signature_child) {
			*child = die;
			return DWARF_DIRECT_SIGNATURE_CHILD;
		}
	}
	return DWARF_DIRECT_SIGNATURE_END;
}

static const RBinDwarfDie *dwarf_exact_direct_abstract_origin(Context *ctx, const RBinDwarfDie *die) {
	if (!ctx || !die || !die->attr_values) {
		return NULL;
	}
	const RBinDwarfAttrValue *origin = NULL;
	size_t origin_count = 0;
	const RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		if (value->attr_name == DW_AT_specification
			|| value->attr_name == DW_AT_abstract_origin) {
			origin_count++;
			if (value->attr_name != DW_AT_abstract_origin
				|| value->kind != DW_AT_KIND_REFERENCE) {
				return NULL;
			}
			origin = value;
		}
	}
	if (origin_count != 1) {
		return NULL;
	}
	RBinDwarfDie *origin_die = ht_up_find (
		ctx->die_map, origin->reference, NULL);
	size_t origin_index;
	return origin_die && origin_die->tag == DW_TAG_subprogram
		&& dwarf_die_index_in_current_cu (ctx, origin_die, &origin_index)
		? origin_die: NULL;
}

static const char *dwarf_itanium_special_member_code(const char *name) {
	if (!r_str_startswith (name, "_ZN")) {
		return NULL;
	}
	const char *cursor = name + 3;
	const char *end = name + strlen (name);
	bool has_component = false;
	while (isdigit ((ut8)*cursor)) {
		if (*cursor == '0') {
			return NULL;
		}
		size_t length = 0;
		do {
			const size_t digit = (size_t)(*cursor++ - '0');
			if (length > (SIZE_MAX - digit) / 10) {
				return NULL;
			}
			length = length * 10 + digit;
		} while (isdigit ((ut8)*cursor));
		if (!length || length > (size_t)(end - cursor)) {
			return NULL;
		}
		cursor += length;
		has_component = true;
	}
	if (!has_component || (cursor[0] != 'C' && cursor[0] != 'D')
		|| !cursor[1] || !cursor[2]) {
		return NULL;
	}
	return cursor;
}

static bool dwarf_itanium_instance_linkage_matches(const char *abstract_name, const char *concrete_name) {
	const char *abstract_code = dwarf_itanium_special_member_code (abstract_name);
	const char *concrete_code = dwarf_itanium_special_member_code (concrete_name);
	if (!abstract_code || !concrete_code
		|| abstract_code - abstract_name != concrete_code - concrete_name
		|| strncmp (abstract_name, concrete_name,
			(size_t)(abstract_code - abstract_name))
		|| abstract_code[0] != concrete_code[0]
		|| abstract_code[1] != '4'
		|| strcmp (abstract_code + 2, concrete_code + 2)) {
		return false;
	}
	return abstract_code[0] == 'C'
		? concrete_code[1] >= '1' && concrete_code[1] <= '3'
		: concrete_code[1] >= '0' && concrete_code[1] <= '2';
}

static bool dwarf_exact_concrete_linkage_merge(DwarfExactDecl *decl,
		const char *concrete_linkage_name, const char *concrete_standard_linkage_name) {
	if (decl->linkage_name && strcmp (decl->linkage_name, concrete_linkage_name)
		&& !dwarf_itanium_instance_linkage_matches (
			decl->linkage_name, concrete_linkage_name)) {
		return false;
	}
	decl->linkage_name = concrete_linkage_name;
	decl->standard_linkage_name = concrete_standard_linkage_name;
	return true;
}

static bool dwarf_merge_exact_concrete_prototype(const RBinDwarfDie *die, DwarfExactDecl *decl) {
	if (!die || !die->attr_values || !decl) {
		return false;
	}
	size_t type_count = 0;
	size_t prototyped_count = 0;
	size_t name_count = 0;
	size_t linkage_name_count = 0;
	const char *concrete_name = NULL;
	const char *concrete_linkage_name = NULL;
	const char *concrete_standard_linkage_name = NULL;
	const RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		switch (value->attr_name) {
		case DW_AT_name:
			name_count++;
			if (value->kind != DW_AT_KIND_STRING || R_STR_ISEMPTY (value->string.content)) {
				return false;
			}
			concrete_name = value->string.content;
			break;
		case DW_AT_linkage_name:
			linkage_name_count++;
			if (value->kind != DW_AT_KIND_STRING || R_STR_ISEMPTY (value->string.content)) {
				return false;
			}
			concrete_linkage_name = value->string.content;
			concrete_standard_linkage_name = value->string.content;
			break;
		case DW_AT_MIPS_linkage_name:
			linkage_name_count++;
			if (value->kind != DW_AT_KIND_STRING || R_STR_ISEMPTY (value->string.content)) {
				return false;
			}
			concrete_linkage_name = value->string.content;
			break;
		case DW_AT_type:
			type_count++;
			if (value->kind != DW_AT_KIND_REFERENCE
				|| !dwarf_exact_type_merge (decl, value->reference)) {
				return false;
			}
			break;
		case DW_AT_prototyped:
			prototyped_count++;
			if (value->kind != DW_AT_KIND_FLAG
				|| !dwarf_exact_prototyped_merge (decl, value->flag)) {
				return false;
			}
			break;
		default:
			break;
		}
	}
	if (name_count > 1 || linkage_name_count > 1
		|| type_count > 1 || prototyped_count > 1) {
		return false;
	}
	if (concrete_name && !dwarf_exact_string_merge (&decl->name, concrete_name)) {
		return false;
	}
	if (concrete_linkage_name
		&& !dwarf_exact_concrete_linkage_merge (decl,
			concrete_linkage_name, concrete_standard_linkage_name)) {
		return false;
	}
	return true;
}

static bool dwarf_exact_abstract_formals_biject(Context *ctx,
		const RBinDwarfDie *concrete, const RBinDwarfDie *abstract_origin) {
	DwarfDirectSignatureIter concrete_iter;
	DwarfDirectSignatureIter abstract_iter;
	if (!dwarf_direct_signature_iter_init (ctx, concrete, &concrete_iter)
		|| !dwarf_direct_signature_iter_init (ctx, abstract_origin, &abstract_iter)) {
		return false;
	}
	for (;;) {
		const RBinDwarfDie *concrete_child;
		const RBinDwarfDie *abstract_child;
		const DwarfDirectSignatureResult concrete_result =
			dwarf_direct_signature_next (&concrete_iter, &concrete_child);
		const DwarfDirectSignatureResult abstract_result =
			dwarf_direct_signature_next (&abstract_iter, &abstract_child);
		if (concrete_result != abstract_result
			|| concrete_result == DWARF_DIRECT_SIGNATURE_ERROR) {
			return false;
		}
		if (concrete_result == DWARF_DIRECT_SIGNATURE_END) {
			return true;
		}
		if (concrete_child->tag != abstract_child->tag) {
			return false;
		}
		if (concrete_child->tag == DW_TAG_formal_parameter) {
			DwarfExactDecl formal_decl = { 0 };
			const RBinDwarfDie *formal_terminal = NULL;
			if (!dwarf_collect_exact_decl (ctx, concrete_child,
					DW_TAG_formal_parameter, true, &formal_decl, &formal_terminal)
				|| formal_terminal != abstract_child) {
				return false;
			}
		}
	}
}

static bool dwarf_exact_type_attr(const RBinDwarfDie *die, const RBinDwarfAttrValue **type_attr) {
	*type_attr = NULL;
	if (!die || !die->attr_values) {
		return false;
	}
	size_t count = 0;
	const RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		if (value->attr_name == DW_AT_type) {
			count++;
			if (value->kind != DW_AT_KIND_REFERENCE) {
				return false;
			}
			*type_attr = value;
		}
	}
	return count <= 1;
}

static bool dwarf_exact_named_type(const RBinDwarfDie *die) {
	size_t count = 0;
	const RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		if (value->attr_name == DW_AT_name) {
			count++;
			if (value->kind != DW_AT_KIND_STRING || R_STR_ISEMPTY (value->string.content)) {
				return false;
			}
		}
	}
	return count == 1;
}

static bool dwarf_type_reference_is_exact(Context *ctx, ut64 offset) {
	SetU *visited = set_u_new ();
	if (!visited) {
		return false;
	}
	bool exact = false;
	bool named_typedef = false;
	size_t depth;
	for (depth = 0; depth < DWARF_EXACT_REFERENCE_LIMIT && depth < ctx->count; depth++) {
		if (set_u_contains (visited, offset)) {
			break;
		}
		set_u_add (visited, offset);
		RBinDwarfDie *die = ht_up_find (ctx->die_map, offset, NULL);
		if (!die || !die->attr_values) {
			break;
		}
		const RBinDwarfAttrValue *type_attr = NULL;
		if (!dwarf_exact_type_attr (die, &type_attr)) {
			break;
		}
		switch (die->tag) {
		case DW_TAG_base_type:
			exact = !type_attr && dwarf_exact_named_type (die);
			goto beach;
		case DW_TAG_structure_type:
		case DW_TAG_enumeration_type:
		case DW_TAG_union_type:
		case DW_TAG_class_type:
			exact = !type_attr
				&& (named_typedef || dwarf_exact_named_type (die));
			goto beach;
		case DW_TAG_typedef:
			if (!type_attr || !dwarf_exact_named_type (die)) {
				goto beach;
			}
			named_typedef = true;
			offset = type_attr->reference;
			break;
		case DW_TAG_pointer_type:
			if (!type_attr) {
				exact = true;
				goto beach;
			}
			offset = type_attr->reference;
			break;
		case DW_TAG_const_type:
		case DW_TAG_volatile_type:
		case DW_TAG_restrict_type:
		case DW_TAG_rvalue_reference_type:
		case DW_TAG_reference_type:
			if (!type_attr) {
				goto beach;
			}
			offset = type_attr->reference;
			break;
		default:
			goto beach;
		}
	}
beach:
	set_u_free (visited);
	return exact;
}

static bool dwarf_render_exact_type(Context *ctx, ut64 offset, RStrBuf *type) {
	bool exact = dwarf_type_reference_is_exact (ctx, offset);
	if (!exact || parse_type (ctx, offset, type, NULL, NULL) < 0) {
		return false;
	}
	const char *rendered = r_strbuf_get (type);
	if (R_STR_ISEMPTY (rendered)) {
		return false;
	}
	for (; *rendered; rendered++) {
		if (isalnum ((ut8)*rendered) || *rendered == '_') {
			return true;
		}
	}
	return false;
}

static const char *dwarf_exact_decl_name(Context *ctx, const DwarfExactDecl *decl) {
	if (prefer_linkage_name (ctx->lang) && decl->linkage_name) {
		return decl->linkage_name;
	}
	return decl->name? decl->name: decl->linkage_name;
}

static bool dwarf_origin_names(Context *ctx, const RBinDwarfAttrValue *origin, const char **name, const char **linkage_name, const char **standard_linkage_name) {
	*name = NULL;
	*linkage_name = NULL;
	*standard_linkage_name = NULL;
	if (!origin || origin->kind != DW_AT_KIND_REFERENCE) {
		return false;
	}
	RBinDwarfDie *origin_die = ht_up_find (ctx->die_map, origin->reference, NULL);
	if (!origin_die || !origin_die->attr_values) {
		return false;
	}
	const RBinDwarfAttrValue *value;
	R_VEC_FOREACH (origin_die->attr_values, value) {
		if ((value->attr_name == DW_AT_linkage_name || value->attr_name == DW_AT_MIPS_linkage_name)
			&& value->kind == DW_AT_KIND_STRING && R_STR_ISNOTEMPTY (value->string.content)) {
			*linkage_name = value->string.content;
			if (value->attr_name == DW_AT_linkage_name) {
				*standard_linkage_name = value->string.content;
			}
		}
		if (value->attr_name == DW_AT_name && value->kind == DW_AT_KIND_STRING
			&& R_STR_ISNOTEMPTY (value->string.content)) {
			*name = value->string.content;
		}
	}
	return *name || *linkage_name;
}

/* x86_64 https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf */
		// https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf
static const char *map_dwarf_reg_to_x86_64_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0: return "rax";
	case 1: return "rdx";
	case 2: return "rcx";
	case 3: return "rbx";
	case 4: return "rsi";
	case 5: return "rdi";
	case 6:
		*kind = LOCATION_BP;
		return "rbp";
	case 7:
		*kind = LOCATION_SP;
		return "rsp";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 16: return "reserved"; // return address
	case 17: return "xmm0";
	case 18: return "xmm1";
	case 19: return "xmm2";
	case 20: return "xmm3";
	case 21: return "xmm4";
	case 22: return "xmm5";
	case 23: return "xmm6";
	case 24: return "xmm7";
	case 25: return "xmm8";
	case 26: return "xmm9";
	case 27: return "xmm10";
	case 28: return "xmm11";
	case 29: return "xmm12";
	case 30: return "xmm13";
	case 31: return "xmm14";
	case 32: return "xmm15";

	case 33: return "st0";
	case 34: return "st1";
	case 35: return "st2";
	case 36: return "st3";
	case 37: return "st4";
	case 38: return "st5";
	case 39: return "st6";
	case 40: return "st7";

	case 41: return "mm4";
	case 42: return "mm5";
	case 43: return "mm6";
	case 44: return "mm7";
	case 45: return "mm8";
	case 46: return "mm9";
	case 47: return "mm10";
	case 48: return "mm11";

	case 49: return "rflags";
	case 50: return "es";
	case 51: return "cs";
	case 52: return "ss";
	case 53: return "ds";
	case 54: return "fs";
	case 55: return "gs";

	case 58: return "fs.base";
	case 59: return "gs.base";

	case 62: return "tr";
	case 63: return "ldtr";
	case 64: return "mxcsr";
	case 65: return "fcw";
	case 66: return "fsw";

	case 67: return "xmm16";
	case 68: return "xmm17";
	case 69: return "xmm18";
	case 70: return "xmm19";
	case 71: return "xmm20";
	case 72: return "xmm21";
	case 73: return "xmm22";
	case 74: return "xmm23";
	case 75: return "xmm24";
	case 76: return "xmm25";
	case 77: return "xmm26";
	case 78: return "xmm27";
	case 79: return "xmm28";
	case 80: return "xmm29";
	case 81: return "xmm30";
	case 82: return "xmm31";

	case 118: return "k0";
	case 119: return "k1";
	case 120: return "k2";
	case 121: return "k3";
	case 122: return "k4";
	case 123: return "k5";
	case 124: return "k6";
	case 125: return "k7";

	default:
		*kind = LOCATION_UNKNOWN;
		return "unsupported_reg";
	}
}

static const char *map_dwarf_reg_to_arm64_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0: return "x0";
	case 1: return "x1";
	case 2: return "x2";
	case 3: return "x3";
	case 4: return "x4";
	case 5: return "x5";
	case 6: return "x6";
	case 7: return "x7";
	case 8: return "x8";
	case 9: return "x9";
	case 10: return "x10";
	case 11: return "x11";
	case 12: return "x12";
	case 13: return "x13";
	case 14: return "x14";
	case 15: return "x15";
	case 16: return "x16";
	case 17: return "x17";
	case 18: return "x18";
	case 19: return "x19";
	case 20: return "x20";
	case 21: return "x21";
	case 22: return "x22";
	case 23: return "x23";
	case 24: return "x24";
	case 25: return "x25";
	case 26: return "x26";
	case 27: return "x27";
	case 28: return "x28";
	case 29:
		*kind = LOCATION_BP;
		return "x29";
	case 30: return "x30";
	case 31:
		*kind = LOCATION_SP;
		return "sp";
	case 32: return "pc";
	case 33: return "elr_mode";
	case 34: return "rasign_state";
	case 35: return "tpidrr0_el0";
	case 36: return "tpidr_el0";
	case 37: return "tpidr_el1";
	case 38: return "tpidr_el2";
	case 39: return "tpidr_el3";
	}
#if 0
ARM64 - dwarf register mapping
0–30	X0–X30	64-bit general registers (Note 1)
31	SP	64-bit stack pointer
32	PC	64-bit program counter (Note 9)
33	ELR_mode	The current mode exception link register
34	RA_SIGN_STATE	Return address signed state pseudo-register (Note 8)
35	TPIDRRO_ELO	EL0 Read-Only Software Thread ID register
36	TPIDR_ELO	EL0 Read/Write Software Thread ID register
37	TPIDR_EL1	EL1 Software Thread ID register
38	TPIDR_EL2	EL2 Software Thread ID register
39	TPIDR_EL3	EL3 Software Thread ID register
40-45	Reserved	-
46	VG (Beta)	64-bit SVE vector granule pseudo-register (Note 2, Note 3)
47	FFR (Beta)	VG × 8-bit SVE first fault register (Note 4)
48-63	P0-P15 (Beta)	VG × 8-bit SVE predicate registers (Note 4)
64-95	V0-V31	128-bit FP/Advanced SIMD registers (Note 5, Note 7)
96-127	Z0-Z31 (Beta)	VG × 64-bit SVE vector registers (Note 6, Note 7)
#endif
	*kind = LOCATION_UNKNOWN;
	return "unk"; // please complete the list :___
}

static const char *map_dwarf_reg_to_v850_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0: return "r0"; // wired to ground so it may shift
	case 1: return "r1";
	case 2: return "r2";
	case 3: return "r3";
	case 4: return "r4";
	case 5: return "r5";
	case 6: return "r6";
	case 7: return "r7";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 16: return "r16";
	case 17: return "r17";
	case 18: return "r18";
	case 19: return "r19";
	case 20: return "r20";
	case 21: return "r21";
	case 22: return "r22";
	case 23: return "r23";
	case 24: return "r24";
	case 25: return "r25";
	case 26: return "r26";
	case 27: return "r27";
	case 28: return "r28";
	case 29: return "r29";
	case 30: return "r30";
	case 31: return "r31";
	case 32: return "pc"; // uhm
	default:
		R_LOG_WARN ("Unhandled dwarf register reference number %d", (int)reg_num);
		*kind = LOCATION_UNKNOWN;
		return "unsupported_reg";
	}
}

/* x86 https://01.org/sites/default/files/file_attach/intel386-psabi-1.0.pdf */
static const char *map_dwarf_reg_to_x86_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0: return "eax";
	case 1: return "edx";
	case 2: return "ecx";
	case 3: return "ebx";
	case 4:
		*kind = LOCATION_SP;
		return "esp";
	case 5:
		*kind = LOCATION_BP;
		return "ebp";
	case 6: return "esi";
	case 7: return "edi";
	case 8: return "eip"; // return address register, should not be used
	case 9: return "eflags";

	case 10: return "reserved";
	case 11: return "st0";
	case 12: return "st1";
	case 13: return "st2";
	case 14: return "st3";
	case 15: return "st4";
	case 16: return "st5";
	case 17: return "st6";
	case 18: return "st7";

	case 19: return "reserved";
	case 20: return "reserved";

	case 21: return "xmm0";
	case 22: return "xmm1";
	case 23: return "xmm2";
	case 24: return "xmm3";
	case 25: return "xmm4";
	case 26: return "xmm5";
	case 27: return "xmm6";
	case 28: return "xmm7";

	case 29: return "mm0";
	case 30: return "mm1";
	case 31: return "mm2";
	case 32: return "mm3";
	case 33: return "mm4";
	case 34: return "mm5";
	case 35: return "mm6";
	case 36: return "mm7";

	case 40: return "es";
	case 41: return "cs";
	case 42: return "ss";
	case 43: return "ds";
	case 44: return "fs";
	case 45: return "gs";

	case 48: return "tr";
	case 49: return "ldtr";

	default:
		R_LOG_WARN ("Unhandled dwarf register reference number %d", (int)reg_num);
		*kind = LOCATION_UNKNOWN;
		return "unsupported_reg";
	}
}

/* https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.html#DW-REG */
static const char *map_dwarf_reg_to_ppc64_reg(ut64 reg_num, VariableLocationKind *kind) {
	*kind = LOCATION_REGISTER;
	switch (reg_num) {
	case 0: return "r0";
	case 1:
		*kind = LOCATION_SP;
		return "r1";
	case 2: return "r2";
	case 3: return "r3";
	case 4: return "r4";
	case 5: return "r5";
	case 6: return "r6";
	case 7: return "r7";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 16: return "r16";
	case 17: return "r17";
	case 18: return "r18";
	case 19: return "r19";
	case 20: return "r20";
	case 21: return "r21";
	case 22: return "r22";
	case 23: return "r23";
	case 24: return "r24";
	case 25: return "r25";
	case 26: return "r26";
	case 27: return "r27";
	case 28: return "r28";
	case 29: return "r29";
	case 30: return "r30";
	case 31: return "r31";
	default:
		R_WARN_IF_REACHED ();
		*kind = LOCATION_UNKNOWN;
		return "unsupported_reg";
	}
}

/* returns string literal register name!
 * TODO add more arches                 */
static const char *get_dwarf_reg_name(const char *arch, int reg_num, VariableLocationKind *kind, int bits) {
	R_LOG_DEBUG ("get_dwarf_reg_name %s %d", arch, bits);
	if (arch) {
		if (!strcmp (arch, "x86")) {
			if (bits == 64) {
				return map_dwarf_reg_to_x86_64_reg (reg_num, kind);
			}
			return map_dwarf_reg_to_x86_reg (reg_num, kind);
		}
		if (!strcmp (arch, "arm") && bits == 64) {
			return map_dwarf_reg_to_arm64_reg (reg_num, kind);
		}
		if (!strcmp (arch, "v850")) {
			return map_dwarf_reg_to_v850_reg (reg_num, kind);
		}
		if (!strcmp (arch, "ppc") && bits == 64) {
			return map_dwarf_reg_to_ppc64_reg (reg_num, kind);
		}
	}
	// this can be very anoying as its printed over 9000 times
	R_LOG_DEBUG ("get_dwarf_reg_name: unsupported arch: '%s' with %d bits", arch, bits);
	*kind = LOCATION_UNKNOWN;
	return "unsupported_reg";
}

typedef struct dwarf_frame_pointer_rebind_item_t {
	RAnalDwarfFramePointerProof *proof;
	char *reg_name;
	ut64 offset;
	ut32 size;
} DwarfFramePointerRebindItem;

typedef struct dwarf_frame_pointer_rebind_t {
	RAnal *anal;
	DwarfFramePointerRebindItem *items;
	size_t count;
	size_t capacity;
	bool ok;
} DwarfFramePointerRebind;

static bool dwarf_frame_pointer_rebind_prepare_cb(void *user, ut64 function_addr, const void *value) {
	DwarfFramePointerRebind *rebind = (DwarfFramePointerRebind *)user;
	RAnalDwarfFramePointerProof *proof = (RAnalDwarfFramePointerProof *)value;
	RAnalPriv *priv = R_ANAL_PRIV (rebind->anal);
	HtUP *authorities = priv->dwarf_function_link_authority;
	RAnalDwarfFunctionLinkAuthority *authority = authorities
		? ht_up_find (authorities, function_addr, NULL): NULL;
	const char *linked = r_anal_function_type_link_at (rebind->anal, function_addr);
	if (!proof || rebind->count >= rebind->capacity
		|| proof->generation != priv->dwarf_function_link_generation
		|| !authority
		|| authority->generation != priv->dwarf_function_link_generation
		|| authority->state != R_ANAL_DWARF_FUNCTION_LINK_OWNED
		|| R_STR_ISEMPTY (proof->type_name)
		|| strcmp (r_str_get (authority->type_name), proof->type_name)
		|| !linked || strcmp (linked, proof->type_name)
		|| !rebind->anal->config || !rebind->anal->reg
		|| R_STR_ISEMPTY (proof->arch) || R_STR_ISEMPTY (proof->reg_name)
		|| strcmp (proof->arch, rebind->anal->config->arch)
		|| proof->bits != rebind->anal->config->bits
		|| proof->dwarf_reg_num < 0 || proof->dwarf_reg_num > 31) {
		rebind->ok = false;
		return false;
	}
	VariableLocationKind kind = LOCATION_UNKNOWN;
	const char *reg_name = get_dwarf_reg_name (rebind->anal->config->arch,
		proof->dwarf_reg_num, &kind, rebind->anal->config->bits);
	if (kind != LOCATION_BP || R_STR_ISEMPTY (reg_name)) {
		rebind->ok = false;
		return false;
	}
	RRegItem *reg = r_reg_get (rebind->anal->reg, reg_name, -1);
	const bool exact = reg && R_STR_ISNOTEMPTY (reg->name)
		&& !strcmp (reg->name, reg_name)
		&& reg->offset >= 0 && !(reg->offset % 8)
		&& reg->size > 0 && !(reg->size % 8)
		&& reg->size == rebind->anal->config->bits
		&& reg->size / 8 <= UT32_MAX;
	if (!exact) {
		r_unref (reg);
		rebind->ok = false;
		return false;
	}
	char *name_copy = strdup (reg_name);
	if (!name_copy) {
		r_unref (reg);
		rebind->ok = false;
		return false;
	}
	DwarfFramePointerRebindItem *item = &rebind->items[rebind->count++];
	item->proof = proof;
	item->reg_name = name_copy;
	item->offset = (ut64)(reg->offset / 8);
	item->size = (ut32)(reg->size / 8);
	r_unref (reg);
	return true;
}

R_IPI bool r_anal_dwarf_frame_pointer_proofs_rebind_current(RAnal *anal) {
	if (!anal || !anal->priv || !anal->lock) {
		return false;
	}
	r_th_lock_enter (anal->lock);
	HtUP *proofs = R_ANAL_PRIV (anal)->dwarf_frame_pointer_proofs;
	if (!proofs || !proofs->count) {
		r_th_lock_leave (anal->lock);
		return true;
	}
	size_t allocation_size;
	if (r_mul_overflow_size_t (proofs->count,
			sizeof (DwarfFramePointerRebindItem), &allocation_size)) {
		r_th_lock_leave (anal->lock);
		return false;
	}
	DwarfFramePointerRebindItem *items = calloc (1, allocation_size);
	if (!items) {
		r_th_lock_leave (anal->lock);
		return false;
	}
	DwarfFramePointerRebind rebind = {
		.anal = anal,
		.items = items,
		.capacity = proofs->count,
		.ok = true,
	};
	ht_up_foreach (proofs, dwarf_frame_pointer_rebind_prepare_cb, &rebind);
	bool changed = false;
	if (rebind.ok && rebind.count == rebind.capacity) {
		size_t i;
		for (i = 0; i < rebind.count; i++) {
			DwarfFramePointerRebindItem *item = &items[i];
			RAnalDwarfFramePointerProof *proof = item->proof;
			if (strcmp (proof->reg_name, item->reg_name)
				|| proof->offset != item->offset || proof->size != item->size) {
				free (proof->reg_name);
				proof->reg_name = item->reg_name;
				item->reg_name = NULL;
				proof->offset = item->offset;
				proof->size = item->size;
				changed = true;
			}
		}
		if (changed) {
			r_anal_types_bump_dirty_epoch (anal);
		}
	}
	size_t i;
	for (i = 0; i < rebind.count; i++) {
		free (items[i].reg_name);
	}
	free (items);
	r_th_lock_leave (anal->lock);
	return rebind.ok && rebind.count == rebind.capacity;
}

static RBinDwarfLocRange *find_largest_loc_range(RList *loc_list) {
	RBinDwarfLocRange *largest = NULL;
	ut64 max_range_size = 0;
	RListIter *iter;
	RBinDwarfLocRange *range;
	r_list_foreach (loc_list, iter, range) {
		ut64 diff = range->end - range->start;
		if (diff > max_range_size) {
			max_range_size = diff ;
			largest = range;
		}
	}
	return largest;
}

typedef struct dwarf_exact_stack_location_t {
	VariableLocationKind kind;
	st64 offset;
} DwarfExactStackLocation;

static size_t dwarf_read_canonical_uleb64(const ut8 *data, const ut8 *end, R_OUT ut64 *value) {
	if (!data || !end || !value || data >= end) {
		return 0;
	}
	const size_t length = read_u64_leb128 (data, end, value);
	if (!length || (length > 1 && data[length - 1] == 0)
		|| (length == 10 && data[9] > 1)) {
		return 0;
	}
	return length;
}

/* Certifying input is intentionally narrower than the advisory DWARF
 * location parser below. A stack home must be one complete fbreg expression
 * whose frame base is one direct register expression. Loclists, direct breg
 * expressions, register values, address expressions, and compound expressions
 * remain advisory until a shared bounded decoder supports them. */
static bool dwarf_exact_stack_location_parse(Context *ctx,
		const RBinDwarfAttrValue *loc, const RBinDwarfAttrValue *frame_base,
		R_OUT DwarfExactStackLocation *result) {
	if (!ctx || !ctx->anal || !loc || !result
		|| loc->kind != DW_AT_KIND_BLOCK
		|| !loc->block.data || loc->block.length < 2) {
		return false;
	}
	const ut8 location_op = loc->block.data[0];
	const ut8 *operand = loc->block.data + 1;
	const ut8 *end = loc->block.data + loc->block.length;
	if (location_op != DW_OP_fbreg || !frame_base
		|| frame_base->kind != DW_AT_KIND_BLOCK
		|| !frame_base->block.data || frame_base->block.length != 1) {
		return false;
	}
	const ut8 frame_op = frame_base->block.data[0];
	if (frame_op < DW_OP_reg0 || frame_op > DW_OP_reg31) {
		return false;
	}
	const ut64 reg_num = frame_op - DW_OP_reg0;
	VariableLocationKind kind = LOCATION_UNKNOWN;
	(void)get_dwarf_reg_name (ctx->anal->config->arch, reg_num, &kind,
		ctx->anal->config->bits);
	if (kind != LOCATION_BP && kind != LOCATION_SP) {
		return false;
	}
	st64 offset = 0;
	const size_t length = read_i64_leb128 (operand, end, &offset);
	if (!length || operand + length != end) {
		return false;
	}
	if (length > 1) {
		const ut8 last = operand[length - 1];
		const ut8 previous = operand[length - 2];
		if ((last == 0 && !(previous & 0x40))
			|| (last == 0x7f && (previous & 0x40))) {
			return false;
		}
	}
	const ut8 *decoded_end = operand;
	offset = r_sleb128 (&decoded_end, end);
	if (decoded_end != end) {
		return false;
	}
	result->kind = kind;
	result->offset = offset;
	return true;
}

static bool dwarf_location_matches_exact_stack(Context *ctx,
		const RBinDwarfAttrValue *loc, const RBinDwarfAttrValue *frame_base,
		const VariableLocation *location) {
	DwarfExactStackLocation exact = {0};
	const bool parsed = dwarf_exact_stack_location_parse (
		ctx, loc, frame_base, &exact);
	return location && parsed
		&& location->kind == exact.kind && location->offset == exact.offset;
}

/* TODO move a lot of the parsing here into dwarf.c and do only processing here */
static VariableLocation *parse_dwarf_location(Context *ctx, const RBinDwarfAttrValue *loc, const RBinDwarfAttrValue *frame_base) {
	/* reg5 - val is in register 5
	fbreg <leb> - offset from frame base
	regx <leb> - contents is in register X
	addr <addr> - contents is in at addr
	bregXX <leb> - contents is at offset from specified register
	- we now support 3 options: SP, BP and register based arguments */

	/* Loclist offset is usually CONSTANT or REFERENCE at older DWARF versions, new one has LocListPtr for that */
	if (loc->kind != DW_AT_KIND_BLOCK && loc->kind != DW_AT_KIND_LOCLISTPTR && loc->kind != DW_AT_KIND_REFERENCE && loc->kind != DW_AT_KIND_CONSTANT) {
		return NULL;
	}
	RBinDwarfBlock block;
	if (loc->kind == DW_AT_KIND_LOCLISTPTR || loc->kind == DW_AT_KIND_REFERENCE || loc->kind == DW_AT_KIND_CONSTANT) {
		ut64 offset = loc->reference;
		RBinDwarfLocList *range_list = ht_up_find (ctx->locations, offset, NULL);
		if (!range_list) { /* for some reason offset isn't there, wrong parsing or malformed dwarf */
			return NULL;
		}
		/* use the largest range as a variable */
		RBinDwarfLocRange *range = find_largest_loc_range (range_list->list);
		if (!range) {
			return NULL;
		}
		/* Very rough and sloppy, refactor this hacked up stuff */
		block = *range->expression;
		// range->expression... etc
	} else {
		block = loc->block;
	}
	VariableLocationKind kind = LOCATION_UNKNOWN;
	st64 offset = 0;
	ut64 address = 0;
	ut64 reg_num = -1;
	const char *reg_name = NULL; /* literal */
	const char *arch = ctx->anal->config->arch;
	const int bits = ctx->anal->config->bits;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (ctx->anal->config);
	size_t i;
	for (i = 0; i < block.length; i++) {
		switch (block.data[i]) {
		case DW_OP_fbreg: {
			/* TODO sometimes CFA is referenced, but we don't parse that yet
			   just an offset involving framebase of a function*/
			if (i == block.length - 1) {
				return NULL;
			}
			i++;
			const ut8 *dump = block.data + i;
			if (loc->block.length > block.length) {
				return NULL;
			}
			offset = r_sleb128 (&dump, block.data + loc->block.length);
			if (frame_base) {
				/* recursive parsing, but frame_base should be only one, but someone
				   could make malicious resource exhaustion attack, so a depth counter might be cool? */
				VariableLocation *location = parse_dwarf_location (ctx, frame_base, NULL);
				if (location) {
					st64 combined;
					if (r_add_overflow (location->offset, offset, &combined)) {
						free (location);
						return NULL;
					}
					location->offset = combined;
					location->exact = dwarf_location_matches_exact_stack (
						ctx, loc, frame_base, location);
					return location;
				}
			} else {
				/* Might happen if frame_base has a frame_base reference? I don't think it can tho */
			}
			return NULL;
		}
		case DW_OP_reg0:
		case DW_OP_reg1:
		case DW_OP_reg2:
		case DW_OP_reg3:
		case DW_OP_reg4:
		case DW_OP_reg5:
		case DW_OP_reg6:
		case DW_OP_reg7:
		case DW_OP_reg8:
		case DW_OP_reg9:
		case DW_OP_reg10:
		case DW_OP_reg11:
		case DW_OP_reg12:
		case DW_OP_reg13:
		case DW_OP_reg14:
		case DW_OP_reg15:
		case DW_OP_reg16:
		case DW_OP_reg17:
		case DW_OP_reg18:
		case DW_OP_reg19:
		case DW_OP_reg20:
		case DW_OP_reg21:
		case DW_OP_reg22:
		case DW_OP_reg23:
		case DW_OP_reg24:
		case DW_OP_reg25:
		case DW_OP_reg26:
		case DW_OP_reg27:
		case DW_OP_reg28:
		case DW_OP_reg29:
		case DW_OP_reg30:
		case DW_OP_reg31: {
			/* Will mostly be used for SP based arguments */
			/* TODO I need to find binaries that uses this so I can test it out*/
			reg_num = block.data[i] - DW_OP_reg0; // get the reg number
			reg_name = get_dwarf_reg_name (arch, reg_num, &kind, bits);
			break;
		}
		case DW_OP_breg0:
		case DW_OP_breg1:
		case DW_OP_breg2:
		case DW_OP_breg3:
		case DW_OP_breg4:
		case DW_OP_breg5:
		case DW_OP_breg6:
		case DW_OP_breg7:
		case DW_OP_breg8:
		case DW_OP_breg9:
		case DW_OP_breg10:
		case DW_OP_breg11:
		case DW_OP_breg12:
		case DW_OP_breg13:
		case DW_OP_breg14:
		case DW_OP_breg15:
		case DW_OP_breg16:
		case DW_OP_breg17:
		case DW_OP_breg18:
		case DW_OP_breg19:
		case DW_OP_breg20:
		case DW_OP_breg21:
		case DW_OP_breg22:
		case DW_OP_breg23:
		case DW_OP_breg24:
		case DW_OP_breg25:
		case DW_OP_breg26:
		case DW_OP_breg27:
		case DW_OP_breg28:
		case DW_OP_breg29:
		case DW_OP_breg30:
		case DW_OP_breg31: {
			if (i == block.length - 1) {
				return NULL;
			}
			/* The single operand of the DW_OP_bregn operations provides
			signed LEB128 offset from the specified register.  */
			reg_num = block.data[i] - DW_OP_breg0; // get the reg number
			const ut8 *buffer = &block.data[++i];
			offset = r_sleb128 (&buffer, &block.data[block.length]);
			/* TODO do a proper expression parsing, move by the amount of bytes sleb reads */
			i += buffer - &block.data[0];
			reg_name = get_dwarf_reg_name (arch, reg_num, &kind, bits);
			break;
		}
		case DW_OP_bregx: {
			if (i == block.length - 1) {
				return NULL;
			}
			/* 2 operands, reg_number, offset*/
			/* I need to find binaries that uses this so I can test it out*/
			const ut8 *buffer = &block.data[++i];
			const ut8 *buf_end = &block.data[block.length];
			const size_t reg_length = dwarf_read_canonical_uleb64 (
				buffer, buf_end, &reg_num);
			if (!reg_length || buffer + reg_length >= buf_end
				|| reg_num > INT_MAX) {
				return NULL;
			}
			buffer += reg_length;
			offset = r_sleb128 (&buffer, buf_end);
			reg_name = get_dwarf_reg_name (arch, reg_num, &kind, bits);
			break;
		}
		case DW_OP_addr: {
			/* The DW_OP_addr operation has a single operand that encodes a machine address and whose
			size is the size of an address on the target machine.  */
			const int addr_size = bits / 8;
			const ut8 *dump = &block.data[++i];
			/* malformed, not enough bytes to represent address */
			if (block.length - i < addr_size) {
				return NULL;
			}
			switch (addr_size) {
			case 1:
				address = r_read_ble8 (dump);
				break;
			case 2:
				address = r_read_ble16 (dump, be);
				break;
			case 4:
				address = r_read_ble32 (dump, be);
				break;
			case 8:
				address = r_read_ble64 (dump, be);
				break;
			default:
				R_WARN_IF_REACHED (); /* weird addr_size */
				return NULL;
			}
			kind = LOCATION_GLOBAL; // address
			break;
		}
		case DW_OP_call_frame_cfa: {
			// REMOVE XXX
			kind = LOCATION_BP;
			offset += 16;
			break;
		}
		default:
			break;
		}
	}
	if (kind == LOCATION_UNKNOWN) {
		return NULL;
	}
	VariableLocation *location = R_NEW0 (VariableLocation);
	if (location) {
		location->reg_name = reg_name;
		location->reg_num = reg_num;
		location->kind = kind;
		location->offset = offset;
		location->address = address;
		location->exact = dwarf_location_matches_exact_stack (
			ctx, loc, frame_base, location);
	}
	return location;
}

static bool parse_function_args_and_vars(Context *ctx, ut64 idx, RStrBuf *args, RList/*<Variable*>*/ *variables, bool *has_unspecified_parameters, bool *decl_corrupt) {
	const RBinDwarfDie *die = &ctx->all_dies[idx++];
	bool complete = true;

	if (die->has_children) {
		int child_depth = 1;
		int arg_number = 1;
		size_t unspecified_count = 0;
		// cache frame_base once instead of looking it up per-variable
		const RBinDwarfAttrValue *frame_base = find_attr (die, DW_AT_frame_base);
		size_t j;
		for (j = idx; child_depth > 0 && j < ctx->count; j++) {
			const RBinDwarfDie *child_die = &ctx->all_dies[j];
			RStrBuf type;
			r_strbuf_init (&type);
			if (child_die->tag == DW_TAG_formal_parameter || child_die->tag == DW_TAG_variable) {
				Variable *var = R_NEW0 (Variable);
				const char *name = NULL;
				DwarfExactDecl decl = { 0 };
				bool decl_complete = dwarf_collect_exact_decl (
					ctx, child_die, child_die->tag, false, &decl, NULL);
				if (child_die->tag == DW_TAG_formal_parameter && child_depth == 1
					&& unspecified_count > 0) {
					decl_complete = false;
				}
				if (decl_complete) {
					name = dwarf_exact_decl_name (ctx, &decl);
					if (decl.has_type) {
						if (child_die->tag == DW_TAG_formal_parameter && child_depth == 1) {
							decl_complete = dwarf_render_exact_type (ctx, decl.type_ref, &type);
						} else {
							parse_type (ctx, decl.type_ref, &type, NULL, NULL);
						}
					} else if (child_die->tag == DW_TAG_formal_parameter && child_depth == 1) {
						decl_complete = false;
					}
				}
				if (!decl_complete && child_die->attr_values) {
					const RBinDwarfAttrValue *value;
					R_VEC_FOREACH (child_die->attr_values, value) {
						if (value->attr_name == DW_AT_name && value->kind == DW_AT_KIND_STRING
							&& R_STR_ISNOTEMPTY (value->string.content)) {
							name = value->string.content;
						} else if (value->attr_name == DW_AT_type
							&& value->kind == DW_AT_KIND_REFERENCE && !type.len) {
							parse_type (ctx, value->reference, &type, NULL, NULL);
						}
					}
				}
				if (child_die->attr_values) {
					const RBinDwarfAttrValue *value;
					R_VEC_FOREACH (child_die->attr_values, value) {
						if (value->attr_name == DW_AT_location) {
							var->location = parse_dwarf_location (ctx, value, frame_base);
						} else if (value->attr_name == DW_AT_variable_parameter
							&& value->flag) {
							// go marks a result slot as a formal parameter with this flag set
							var->is_result = true;
						}
					}
				}
				if (child_die->tag == DW_TAG_formal_parameter && child_depth == 1) {
					complete &= decl_complete;
					var->formal_index = arg_number - 1;
					if (decl_corrupt && !type.len
						&& get_die_attr (child_die, DW_AT_type)) {
						// a type attribute is present but unreadable
						*decl_corrupt = true;
					}
					/* arguments sometimes have only type, create generic argX */
					if (type.len) {
						var->kind = VARIABLE_KIND_FORMAL_PARAMETER;
						if (name) {
							var->name = strdup (name);
						} else {
							var->name = r_str_newf ("arg%d", arg_number);
						}
						r_strbuf_appendf (args, "%s %s,", r_strbuf_get (&type), var->name);
						var->type = strdup (r_strbuf_get (&type));
						r_list_append (variables, var);
					} else {
						complete = false;
						variable_free (var);
					}
					arg_number++;
				} else { /* DW_TAG_variable */
					if (name && type.len) {
						var->kind = VARIABLE_KIND_LOCAL;
						var->name = strdup (name);
						var->type = strdup (r_strbuf_get (&type));
						r_list_append (variables, var);
					} else {
						variable_free (var);
					}
				}
			} else if (child_depth == 1 && child_die->tag == DW_TAG_unspecified_parameters) {
				unspecified_count++;
				complete &= unspecified_count == 1 && !child_die->has_children;
				if (has_unspecified_parameters) {
					*has_unspecified_parameters = true;
				}
				r_strbuf_append (args, "va_args ...,");
			}
			if (child_die->has_children) {
				child_depth++;
			}
			if (child_die->abbrev_code == 0) { /* sibling list is terminated by null entry */
				child_depth--;
			}
			r_strbuf_fini (&type);
		}
		complete &= child_depth == 0;
		if (args->len > 0) {
			r_strbuf_slice (args, 0, args->len - 1);
		}
	}
	return complete;
}

static char *sanitize_c_identifier(const char *name) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	const size_t len = strlen (name);
	char *out = malloc (len + 2);
	if (!out) {
		return NULL;
	}
	size_t j = 0;
	size_t i;
	for (i = 0; i < len; i++) {
		const ut8 ch = (ut8)name[i];
		const bool valid = (i == 0)? (isalpha (ch) || ch == '_'): (isalnum (ch) || ch == '_');
		if (valid) {
			out[j++] = (char)ch;
		} else if (j == 0 || out[j - 1] != '_') {
			out[j++] = '_';
		}
	}
	if (j == 0) {
		out[j++] = '_';
	}
	out[j] = 0;
	return out;
}

static char *sdb_variable_data(const Variable *var) {
	if (!var || !var->location || !var->type) {
		return NULL;
	}
	switch (var->location->kind) {
	case LOCATION_BP:
		return r_str_newf ("b,%" PFMT64d ",%s", var->location->offset, var->type);
	case LOCATION_SP:
		return r_str_newf ("s,%" PFMT64d ",%s", var->location->offset, var->type);
	case LOCATION_GLOBAL:
		return r_str_newf ("g,%" PFMT64u ",%s", var->location->address, var->type);
	case LOCATION_REGISTER:
		return r_str_newf ("r,%s,%s", var->location->reg_name, var->type);
	default:
		break;
	}
	return NULL;
}

#define DWARF_EXACT_FORMAL_RECORD_V1 "dwarf-stack-home-v1"

static char *dwarf_exact_formal_record(const Variable *var, R_OUT bool *eligible) {
	R_RETURN_VAL_IF_FAIL (eligible, NULL);
	*eligible = var && var->kind == VARIABLE_KIND_FORMAL_PARAMETER
		&& var->formal_index >= 0 && var->location && var->location->exact
		&& (var->location->kind == LOCATION_BP
			|| var->location->kind == LOCATION_SP)
		&& R_STR_ISNOTEMPTY (var->name) && R_STR_ISNOTEMPTY (var->type)
		&& strlen (var->name) <= INT_MAX && strlen (var->type) <= INT_MAX;
	if (!*eligible) {
		return NULL;
	}
	char *name = r_base64_encode_dyn ((const ut8 *)var->name,
		(int)strlen (var->name));
	char *type = r_base64_encode_dyn ((const ut8 *)var->type,
		(int)strlen (var->type));
	char *record = NULL;
	if (name && type) {
		record = r_str_newf (DWARF_EXACT_FORMAL_RECORD_V1 ",%d,%c,%" PFMT64d ",%s,%s",
			var->formal_index,
			var->location->kind == LOCATION_BP? 'b': 's',
			var->location->offset, name, type);
	}
	free (name);
	free (type);
	return record;
}

static bool dwarf_sdb_set_checked(Sdb *sdb, const char *key, const char *value) {
	R_RETURN_VAL_IF_FAIL (sdb && key && value, false);
	if (sdb_set (sdb, key, value, 0)) {
		return true;
	}
	const char *current = sdb_const_get (sdb, key, NULL);
	return current && !strcmp (current, value);
}

static bool dwarf_sdb_setf_checked(Sdb *sdb, const char *value, const char *fmt, ...) {
	R_RETURN_VAL_IF_FAIL (sdb && value && fmt, false);
	char key[SDB_MAX_KEY];
	va_list ap;
	va_start (ap, fmt);
	const int length = vsnprintf (key, sizeof (key), fmt, ap);
	va_end (ap);
	return length >= 0 && (size_t)length < sizeof (key)
		&& dwarf_sdb_set_checked (sdb, key, value);
}

static bool dwarf_sdb_no_key_matches(void *user, const char *key, const char *value) {
	const char *pattern = (const char *)user;
	return R_STR_ISEMPTY (value) || !sdb_match (key, pattern);
}

static bool dwarf_sdb_unset_like_checked(Sdb *sdb, const char *pattern) {
	R_RETURN_VAL_IF_FAIL (sdb && pattern, false);
	return sdb_unset_like (sdb, pattern)
		&& sdb_foreach (sdb, dwarf_sdb_no_key_matches, (void *)pattern);
}

typedef struct dwarf_exact_function_link_t {
	char *type_name;
	bool inserted;
} DwarfExactFunctionLink;

static void dwarf_exact_function_link_kv_free(HtUPKv *kv) {
	if (kv) {
		DwarfExactFunctionLink *link = kv->value;
		if (link) {
			free (link->type_name);
			free (link);
		}
	}
}

static HtUP *dwarf_exact_function_links_new(void) {
	return ht_up_new (NULL, dwarf_exact_function_link_kv_free, NULL);
}

static bool dwarf_function_type_link_stage(Context *ctx, const char *type_name, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (ctx && ctx->exact_function_links && type_name, false);
	DwarfExactFunctionLink *staged = ht_up_find (
		ctx->exact_function_links, addr, NULL);
	if (staged) {
		// two declarations claim one address; the first candidate wins
		return true;
	}
	DwarfExactFunctionLink *link = R_NEW0 (DwarfExactFunctionLink);
	link->type_name = strdup (type_name);
	if (!link->type_name
		|| !ht_up_insert (ctx->exact_function_links, addr, link)) {
		free (link->type_name);
		free (link);
		return false;
	}
	return true;
}

static bool dwarf_function_frame_pointer_stage(Context *ctx, const RBinDwarfDie *die, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (ctx && ctx->anal && ctx->exact_function_links
		&& ctx->exact_frame_pointer_proofs && die && die->attr_values, false);
	DwarfExactFunctionLink *link = ht_up_find (
		ctx->exact_function_links, addr, NULL);
	if (!link) {
		return true;
	}
	const RBinDwarfAttrValue *frame_base = NULL;
	size_t frame_base_count = 0;
	const RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		if (value->attr_name == DW_AT_frame_base) {
			frame_base = value;
			frame_base_count++;
		}
	}
	if (frame_base_count != 1 || frame_base->kind != DW_AT_KIND_BLOCK
		|| !frame_base->block.data || frame_base->block.length != 1) {
		return true;
	}
	const ut8 op = frame_base->block.data[0];
	if (op < DW_OP_reg0 || op > DW_OP_reg31) {
		return true;
	}
	RAnal *anal = (RAnal *)ctx->anal;
	if (!anal->config || !anal->reg || R_STR_ISEMPTY (anal->config->arch)
		|| anal->config->bits <= 0) {
		return true;
	}
	VariableLocationKind kind = LOCATION_UNKNOWN;
	const char *reg_name = get_dwarf_reg_name (anal->config->arch,
		op - DW_OP_reg0, &kind, anal->config->bits);
	if (kind != LOCATION_BP || R_STR_ISEMPTY (reg_name)) {
		return true;
	}
	RRegItem *reg = r_reg_get (anal->reg, reg_name, -1);
	const bool exact = reg && R_STR_ISNOTEMPTY (reg->name)
		&& !strcmp (reg->name, reg_name)
		&& reg->offset >= 0 && !(reg->offset % 8)
		&& reg->size > 0 && !(reg->size % 8)
		&& reg->size == anal->config->bits
		&& reg->size / 8 <= UT32_MAX;
	bool staged = true;
	if (exact) {
		staged = r_anal_dwarf_frame_pointer_proof_add (
			ctx->exact_frame_pointer_proofs, addr, link->type_name,
			anal->config->arch, anal->config->bits, op - DW_OP_reg0, reg_name,
			(ut64)(reg->offset / 8), (ut32)(reg->size / 8));
	}
	r_unref (reg);
	return staged;
}

typedef struct dwarf_function_link_transaction_t {
	RAnal *anal;
	bool ok;
} DwarfFunctionLinkTransaction;

static bool dwarf_function_link_install_cb(void *user, ut64 addr, const void *value) {
	DwarfFunctionLinkTransaction *transaction =
		(DwarfFunctionLinkTransaction *)user;
	DwarfExactFunctionLink *link = (DwarfExactFunctionLink *)value;
	const char *current = r_anal_function_type_link_at (transaction->anal, addr);
	if (current) {
		if (strcmp (current, link->type_name)) {
			// a coherent foreign link is the user's and wins; an incoherent
			// one is tampering and refuses the whole generation
			if (r_type_func_ret (transaction->anal->sdb_types, current)) {
				return true;
			}
			transaction->ok = false;
			return false;
		}
		r_anal_dwarf_function_link_mark_unowned (transaction->anal, addr);
		return true;
	}
	if (!r_anal_dwarf_function_link_mark_poisoned (
			transaction->anal, addr, link->type_name)
		|| !r_anal_dwarf_function_link_poisoned_matches (
			transaction->anal, addr, link->type_name)
		|| !r_anal_function_type_link_set_owned (
			transaction->anal, link->type_name, addr)) {
		transaction->ok = false;
		return false;
	}
	link->inserted = true;
	return true;
}

static bool dwarf_function_link_prepare_rollback_cb(void *user, ut64 addr, const void *value) {
	DwarfFunctionLinkTransaction *transaction =
		(DwarfFunctionLinkTransaction *)user;
	const DwarfExactFunctionLink *link = value;
	if (link->inserted
		&& !r_anal_dwarf_function_link_mark_poisoned (
			transaction->anal, addr, link->type_name)) {
		transaction->ok = false;
	}
	return true;
}

static bool dwarf_function_links_rollback(RAnal *anal, HtUP *links) {
	DwarfFunctionLinkTransaction rollback = {
		.anal = anal,
		.ok = true,
	};
	ht_up_foreach (links, dwarf_function_link_prepare_rollback_cb, &rollback);
	const bool revoked = r_anal_dwarf_function_links_revoke_owned (anal);
	return rollback.ok && revoked;
}

static bool dwarf_function_link_validate_cb(void *user, ut64 addr, const void *value) {
	DwarfFunctionLinkTransaction *transaction =
		(DwarfFunctionLinkTransaction *)user;
	const DwarfExactFunctionLink *link = value;
	if (link->inserted
		&& !r_anal_dwarf_function_link_poisoned_matches (
			transaction->anal, addr, link->type_name)) {
		transaction->ok = false;
		return false;
	}
	return true;
}

static bool dwarf_function_link_publish_cb(void *user, ut64 addr, const void *value) {
	DwarfFunctionLinkTransaction *transaction =
		(DwarfFunctionLinkTransaction *)user;
	const DwarfExactFunctionLink *link = value;
	if (link->inserted
		&& !r_anal_dwarf_function_link_publish_owned (
			transaction->anal, addr, link->type_name)) {
		transaction->ok = false;
		return false;
	}
	return true;
}

static bool dwarf_function_links_publish(RAnal *anal, HtUP *links) {
	R_RETURN_VAL_IF_FAIL (anal && links, false);
	DwarfFunctionLinkTransaction transaction = {
		.anal = anal,
		.ok = true,
	};
	ht_up_foreach (links, dwarf_function_link_install_cb, &transaction);
	if (transaction.ok) {
		ht_up_foreach (links, dwarf_function_link_validate_cb, &transaction);
	}
	if (transaction.ok) {
		ht_up_foreach (links, dwarf_function_link_publish_cb, &transaction);
	}
	if (!transaction.ok) {
		const bool rolled_back = dwarf_function_links_rollback (anal, links);
		if (!rolled_back) {
			R_LOG_ERROR ("Failed to revoke poisoned DWARF function links");
		}
		return false;
	}
	return true;
}

static bool import_dwarf_function_fallback(RAnal *anal, const char *typed_name, const char *ret_type, RList/*<Variable*>*/ *variables, bool has_unspecified_parameters) {
	R_RETURN_VAL_IF_FAIL (anal && typed_name && ret_type && variables, false);
	Sdb *types = anal->sdb_types;
	if (r_type_func_exist (types, typed_name)) {
		return true;
	}
	bool success = dwarf_sdb_set_checked (types, typed_name, "func")
		&& dwarf_sdb_setf_checked (types, ret_type, "func.%s.ret", typed_name);

	const char *default_cc = r_anal_cc_default (anal);
	success &= dwarf_sdb_setf_checked (types, default_cc? default_cc: "cdecl",
		"func.%s.cc", typed_name);

	RStrBuf argnames;
	r_strbuf_init (&argnames);
	int arg_index = 0;
	RListIter *iter;
	Variable *var;
	r_list_foreach (variables, iter, var) {
		if (var->kind != VARIABLE_KIND_FORMAL_PARAMETER || !var->type) {
			continue;
		}
		char *arg_name = var->name? strdup (var->name): r_str_newf ("arg%d", arg_index);
		char *arg_val = arg_name? r_str_newf ("%s,%s", var->type, arg_name): NULL;
		success &= arg_val
			&& dwarf_sdb_setf_checked (types, arg_val,
				"func.%s.arg.%d", typed_name, arg_index)
			&& r_strbuf_appendf (&argnames, "%s%s", arg_index? ",": "", arg_name);
		free (arg_name);
		free (arg_val);
		arg_index++;
	}
	if (has_unspecified_parameters) {
		// canonical types.sdb.txt form: empty type, "..." as the name
		success &= dwarf_sdb_setf_checked (types, ",...",
			"func.%s.arg.%d", typed_name, arg_index)
			&& r_strbuf_appendf (&argnames, "%s...", arg_index? ",": "");
		arg_index++;
	}
	r_strf_buffer (16);
	success &= dwarf_sdb_setf_checked (types, r_strf ("%d", arg_index),
		"func.%s.args", typed_name)
		&& dwarf_sdb_setf_checked (types, r_strbuf_get (&argnames),
			"func.%s", typed_name);
	r_strbuf_fini (&argnames);
	return success;
}

static bool dwarf_function_type_matches(RAnal *anal, const char *typed_name, const char *ret_type, RList/*<Variable*>*/ *variables, bool has_unspecified_parameters) {
	R_RETURN_VAL_IF_FAIL (anal && anal->sdb_types && typed_name && ret_type && variables, false);
	const char *kind = sdb_const_get (anal->sdb_types, typed_name, 0);
	const char *actual_ret = r_type_func_ret (anal->sdb_types, typed_name);
	if (!kind || strcmp (kind, "func") || !actual_ret || strcmp (actual_ret, ret_type)) {
		return false;
	}
	int formal_count = 0;
	RListIter *iter;
	Variable *var;
	r_list_foreach (variables, iter, var) {
		if (var->kind == VARIABLE_KIND_FORMAL_PARAMETER) {
			if (!var->type) {
				return false;
			}
			formal_count++;
		}
	}
	int actual_count = r_type_func_args_count (anal->sdb_types, typed_name);
	if (actual_count != formal_count + (has_unspecified_parameters? 1: 0)
		|| r_type_func_is_variadic (anal->sdb_types, typed_name) != has_unspecified_parameters) {
		return false;
	}
	int arg_index = 0;
	r_list_foreach (variables, iter, var) {
		if (var->kind != VARIABLE_KIND_FORMAL_PARAMETER) {
			continue;
		}
		char *actual_type = r_type_func_args_type (anal->sdb_types, typed_name, arg_index++);
		bool matches = actual_type && !strcmp (actual_type, var->type);
		free (actual_type);
		if (!matches) {
			return false;
		}
	}
	return true;
}

// Rebuild a csig from the registered record; textual equality with the prior
// import's csig means the record is still the one this importer wrote
static bool dwarf_record_is_ours(Context *ctx, const char *sname, const char *typed_name) {
	RAnal *anal = (RAnal *)ctx->anal;
	const char *prior = sdb_const_getf (ctx->sdb, NULL, "fcn.%s.csig", sname);
	if (!prior) {
		return false;
	}
	Sdb *types = anal->sdb_types;
	const char *ret = r_type_func_ret (types, typed_name);
	if (!ret) {
		return false;
	}
	RStrBuf rebuilt;
	r_strbuf_init (&rebuilt);
	r_strbuf_appendf (&rebuilt, "%s %s(", ret, typed_name);
	const int count = r_type_func_args_count (types, typed_name);
	int i;
	for (i = 0; i < count; i++) {
		char *arg_type = r_type_func_args_type (types, typed_name, i);
		const char *arg_name = r_type_func_args_name (types, typed_name, i);
		if (!arg_type) {
			r_strbuf_fini (&rebuilt);
			return false;
		}
		if (R_STR_ISEMPTY (arg_type) && arg_name && !strcmp (arg_name, "...")) {
			r_strbuf_appendf (&rebuilt, "%s...", i? ",": "");
		} else {
			r_strbuf_appendf (&rebuilt, "%s%s %s", i? ",": "",
				arg_type, r_str_get (arg_name));
		}
		free (arg_type);
	}
	r_strbuf_append (&rebuilt, ");");
	const bool ours = !strcmp (r_strbuf_get (&rebuilt), prior);
	r_strbuf_fini (&rebuilt);
	return ours;
}

// The typed name is sticky across reimports of the same function; a fresh
// import probes for a name that is either unclaimed or already matching
static char *dwarf_function_typed_name(Context *ctx, const char *sname, Function *dwarf_fcn, const char *ret_type, RList/*<Variable*>*/ *variables, bool has_unspecified_parameters) {
	RAnal *anal = (RAnal *)ctx->anal;
	Sdb *types = anal->sdb_types;
	const char *previous_name = sdb_const_getf (ctx->sdb, NULL, "fcn.%s.name", sname);
	const char *previous = sdb_const_getf (ctx->sdb, NULL, "fcn.%s.typed_name", sname);
	if (previous_name && !strcmp (previous_name, dwarf_fcn->name)
		&& previous && r_type_kind (types, previous) == R_TYPE_FUNCTION
		&& sdb_num_getf (ctx->sdb, NULL, "fcn.%s.addr", sname) == dwarf_fcn->addr) {
		return strdup (previous);
	}
	char *name = sanitize_c_identifier (dwarf_fcn->name);
	if (!name || !sdb_const_get (types, name, 0)
		|| dwarf_function_type_matches (anal, name, ret_type,
			variables, has_unspecified_parameters)) {
		return name;
	}
	char *candidate = r_str_newf ("%s_%" PFMT64x, name, dwarf_fcn->addr);
	int suffix = 2;
	while (candidate && sdb_const_get (types, candidate, 0)
		&& !dwarf_function_type_matches (anal, candidate, ret_type,
			variables, has_unspecified_parameters)) {
		free (candidate);
		candidate = r_str_newf ("%s_%" PFMT64x "_%d", name, dwarf_fcn->addr, suffix++);
	}
	free (name);
	return candidate;
}

static bool import_dwarf_function_type(Context *ctx, const char *sname, Function *dwarf_fcn, const char *ret_type, RList/*<Variable*>*/ *variables, bool has_unspecified_parameters, bool link_complete) {
	R_RETURN_VAL_IF_FAIL (ctx && ctx->anal && sname && dwarf_fcn && ret_type && variables, false);
	RAnal *anal = (RAnal *)ctx->anal;
	r_anal_types_ensure_loaded (anal);
	char *typed_name = dwarf_function_typed_name (ctx, sname, dwarf_fcn,
		ret_type, variables, has_unspecified_parameters);
	if (!typed_name) {
		return false;
	}
	// A sticky record the user rewrote is preserved untouched and unlinked;
	// one this importer wrote is repaired to the current DWARF shape below
	const char *sticky_kind = sdb_const_get (anal->sdb_types, typed_name, 0);
	const bool preserve_existing = sticky_kind && !strcmp (sticky_kind, "func")
		&& !dwarf_function_type_matches (anal, typed_name, ret_type,
			variables, has_unspecified_parameters)
		&& !dwarf_record_is_ours (ctx, sname, typed_name);
	bool success = dwarf_sdb_setf_checked (ctx->sdb, typed_name,
		"fcn.%s.typed_name", sname);

	RStrBuf args_buf;
	r_strbuf_init (&args_buf);
	RListIter *iter;
	Variable *var;
	r_list_foreach (variables, iter, var) {
		if (var->kind != VARIABLE_KIND_FORMAL_PARAMETER || !var->type) {
			continue;
		}
		const char *arg_name = var->name? var->name: "arg";
		success &= r_strbuf_appendf (&args_buf, "%s %s,", var->type, arg_name);
	}
	if (has_unspecified_parameters) {
		success &= r_strbuf_append (&args_buf, "...,");
	}
	if (args_buf.len > 0) {
		r_strbuf_slice (&args_buf, 0, args_buf.len - 1);
	}
	char *csig = r_str_newf ("%s %s(%s);", ret_type, typed_name, r_strbuf_get (&args_buf));
	r_strbuf_fini (&args_buf);
	if (!csig) {
		free (typed_name);
		return false;
	}
	success &= dwarf_sdb_setf_checked (ctx->sdb, csig, "fcn.%s.csig", sname);

	bool type_existed = r_type_func_exist (anal->sdb_types, typed_name);
	if (type_existed && !preserve_existing
		&& !dwarf_function_type_matches (anal, typed_name, ret_type,
			variables, has_unspecified_parameters)) {
		// our stale record from an earlier import; rewrite the exact shape
		type_existed = !(r_anal_function_del_signature (anal, typed_name)
			&& import_dwarf_function_fallback (anal, typed_name,
				ret_type, variables, has_unspecified_parameters));
	} else if (!type_existed && !preserve_existing) {
		/* Only attempt C parsing for C-like languages.  Non-C languages
		   (Rust, Go, D, etc.) produce type names that are not valid C and
		   would choke the parser.  Use the fallback which writes the same
		   sdb entries directly. */
		const char *lang = ctx->lang;
		bool is_c_like = !lang || !strcmp (lang, "cxx") || !strcmp (lang, "objc");
		bool imported = false;
		if (is_c_like) {
			char *errmsg = NULL;
			imported = r_anal_import_c_decls (anal, csig, &errmsg);
			if (!imported && errmsg) {
				R_LOG_DEBUG ("DWARF type import fallback for %s: %s", typed_name, errmsg);
			}
			free (errmsg);
		}
			if (!imported) {
				success &= import_dwarf_function_fallback (anal, typed_name,
					ret_type, variables, has_unspecified_parameters);
			} else if (!dwarf_function_type_matches (anal,
				typed_name, ret_type, variables, has_unspecified_parameters)) {
				// the C parser normalized this new record, so restore the exact DWARF shape
				success &= r_anal_function_del_signature (anal, typed_name)
					&& import_dwarf_function_fallback (anal, typed_name, ret_type,
						variables, has_unspecified_parameters);
			}
		}
	if (success && !preserve_existing && link_complete
		&& dwarf_function_type_matches (anal,
		typed_name, ret_type, variables, has_unspecified_parameters)) {
		success = dwarf_function_type_link_stage (ctx, typed_name, dwarf_fcn->addr);
	}
	free (typed_name);
	free (csig);
	return success;
}

// the cc argslot tables describe integer slots only, so a float formal would be
// handed an integer register it never occupies, colliding with a located arg
static bool dwarf_type_is_fp(const char *type) {
	if (R_STR_ISEMPTY (type) || strchr (type, '*') || strchr (type, '[')) {
		return false;
	}
	while (r_str_startswith (type, "const ") || r_str_startswith (type, "volatile ")) {
		type = strchr (type, ' ') + 1;
	}
	const char *const names[] = {
		"float", "double", "long double", "_Float16", "__float128",
		"f32", "f64", "float32", "float64",
		"complex64", "complex128", NULL
	};
	int i;
	for (i = 0; names[i]; i++) {
		if (!strcmp (type, names[i])) {
			return true;
		}
	}
	return false;
}

static bool dwarf_function_address_is_valid(Context *ctx, ut64 address) {
	R_RETURN_VAL_IF_FAIL (ctx && ctx->anal, false);
	if (address) {
		return true;
	}
	const RIOBind *iob = &ctx->anal->iob;
	return !iob->io || !iob->is_valid_offset
		|| iob->is_valid_offset (iob->io, address, R_PERM_X);
}

static char *dwarf_function_sname(Sdb *sdb, const char *real_name, ut64 address) {
	R_RETURN_VAL_IF_FAIL (sdb && real_name, NULL);
	char *sname = r_str_sanitize_sdb_key (real_name);
	if (!sname) {
		return NULL;
	}
	const char *kind = sdb_const_get (sdb, sname, 0);
	const char *existing_value = sdb_const_getf (sdb, NULL, "fcn.%s.addr", sname);
	if (!kind || strcmp (kind, "fcn") || !existing_value) {
		return sname;
	}
	ut64 existing_address = sdb_num_getf (sdb, NULL, "fcn.%s.addr", sname);
	if (existing_address == address) {
		return sname;
	}
	char *unique = r_str_newf ("%s_0x%08" PFMT64x, sname, address);
	free (sname);
	return unique;
}

/* A formal parameter can carry a type and a name but no DW_AT_location, which
 * happens routinely at -O2 when the parameter is never spilled. The prototype
 * still lists it, so dropping it here left the recovered signature and the
 * placed arguments disagreeing on arity: safe_array_access(int*, int, int) kept
 * a three-parameter prototype while only two arguments were ever placed.
 *
 * The calling convention already answers where the caller left parameter N on
 * entry, so use it rather than discarding the parameter. This is entry-state
 * storage, which is exactly what an interface describes; it is not claimed as
 * exact DWARF evidence, because dwarf_exact_formal_record() requires a real
 * location and so stays ineligible for these. */
static char *dwarf_formal_convention_meta(Context *ctx, int argno, int argc, bool is_fp, const char *type) {
	if (!ctx || !ctx->anal || argno < 0 || R_STR_ISEMPTY (type)) {
		return NULL;
	}
	RAnal *anal = (RAnal *)ctx->anal;
	const char *cc = r_anal_cc_default (anal);
	if (R_STR_ISEMPTY (cc)) {
		return NULL;
	}
	if (is_fp) {
		// a convention with no floating-point argument registers cannot answer for one
		const char *loc = r_anal_cc_fparg (anal, cc, argno);
		if (R_STR_ISEMPTY (loc)) {
			return NULL;
		}
		const char *reg = r_anal_cc_location_first (anal, loc);
		return R_STR_ISEMPTY (reg)? NULL: r_str_newf ("r,%s,%s", reg, type);
	}
	RAnalCCArgSlot slot = { 0 };
	if (!r_anal_cc_argslot (anal, cc, argno, argc, false, &slot)
		|| R_STR_ISEMPTY (slot.reg)) {
		return NULL;
	}
	return r_str_newf ("r,%s,%s", slot.reg, type);
}

static bool sdb_save_dwarf_function(Context *ctx, Function *dwarf_fcn, const char *ret_type, RList/*<Variable*>*/ *variables, bool has_unspecified_parameters, bool prototype_complete, bool link_complete) {
	Sdb *sdb = ctx->sdb;
	// go emits synthetic type-equality helpers whose whole struct is the name
	if (strlen (dwarf_fcn->name) > 192) {
		R_LOG_DEBUG ("Skipping DWARF function with an oversized name at 0x%08" PFMT64x, dwarf_fcn->addr);
		return true;
	}
	char *real_name = strdup (dwarf_fcn->name);
	if (!real_name) {
		return false;
	}
	r_str_ansi_strip (real_name);
	char *sname = dwarf_function_sname (sdb, real_name, dwarf_fcn->addr);
	if (!sname) {
		free (real_name);
		return false;
	}
	bool success = dwarf_sdb_set_checked (sdb, sname, "fcn");

	char *addr_val = r_str_newf ("0x%" PFMT64x, dwarf_fcn->addr);
	success &= addr_val
		&& dwarf_sdb_setf_checked (sdb, addr_val, "fcn.%s.addr", sname);
	free (addr_val);

	/* so we can have name without sanitization */
	success &= dwarf_sdb_setf_checked (sdb, real_name, "fcn.%s.name", sname);

	char *signature = strdup (dwarf_fcn->signature);
	if (signature) {
		r_str_ansi_strip (signature);
	}
	success &= signature
		&& dwarf_sdb_setf_checked (sdb, signature, "fcn.%s.sig", sname);
	free (signature);
	const bool authority_header_saved = success;
	const bool authority_imported = import_dwarf_function_type (
		ctx, sname, dwarf_fcn, ret_type, variables,
		has_unspecified_parameters, link_complete);
	bool exact_authority_ok = true;
	bool has_exact_records = false;

	RStrBuf vars_buf;
	RStrBuf args_buf;
	r_strbuf_init (&vars_buf);
	r_strbuf_init (&args_buf);
	char *arg_prefix = r_str_newf ("^fcn.%s.arg.", sname);
	if (arg_prefix) {
		success &= dwarf_sdb_unset_like_checked (sdb, arg_prefix);
	} else {
		success = false;
	}
	free (arg_prefix);
	// the abi position of a formal counts every parameter the caller passes,
	// while arg_index below must stay dense: apply_debug_info stops reading at
	// the first missing fcn.%s.arg.%d key. a skipped formal separates the two
	int formal_count = 0;
	{
		RListIter *count_iter;
		Variable *count_var;
		r_list_foreach (variables, count_iter, count_var) {
			if (count_var->kind == VARIABLE_KIND_FORMAL_PARAMETER
				&& !count_var->is_result) {
				formal_count++;
			}
		}
	}
	int arg_index = 0;
	int formal_index = 0;
	// each register class advances on its own, so a float never consumes an integer slot
	int int_formal_index = 0;
	int fp_formal_index = 0;
	RListIter *iter;
	Variable *var;
	r_list_foreach (variables, iter, var) {
		const bool is_formal = var->kind == VARIABLE_KIND_FORMAL_PARAMETER
			&& !var->is_result;
		const bool is_fp_formal = is_formal && dwarf_type_is_fp (var->type);
		const int argno = is_fp_formal? fp_formal_index: int_formal_index;
		if (is_formal) {
			formal_index++;
			if (is_fp_formal) {
				fp_formal_index++;
			} else {
				int_formal_index++;
			}
		}
		char *meta = sdb_variable_data (var);
		if (!meta && is_formal && !var->location) {
			meta = dwarf_formal_convention_meta (ctx, argno, formal_count,
				is_fp_formal, var->type);
		}
		if (!meta || !var->name) {
			free (meta);
			continue;
		}
		if (var->kind == VARIABLE_KIND_FORMAL_PARAMETER) {
			bool exact_eligible = false;
			char *arg_val = dwarf_exact_formal_record (var, &exact_eligible);
			exact_eligible &= prototype_complete && authority_imported;
			if (!exact_eligible) {
				free (arg_val);
				arg_val = NULL;
			}
			const bool exact_record = exact_eligible && arg_val != NULL;
			has_exact_records |= exact_eligible;
			if (exact_eligible && (!arg_val || var->formal_index != arg_index)) {
				exact_authority_ok = false;
			}
			if (!arg_val) {
				arg_val = r_str_newf ("%s,%s", var->name, meta);
			}
			const bool arg_saved = arg_val && dwarf_sdb_setf_checked (sdb, arg_val,
				"fcn.%s.arg.%d", sname, arg_index);
			success &= arg_saved
				&& r_strbuf_appendf (&args_buf, "%s,", var->name);
			if (arg_saved && exact_record
				&& !r_anal_dwarf_exact_formal_record_add (
					ctx->exact_formal_records, dwarf_fcn->addr,
					arg_index, arg_val)) {
				exact_authority_ok = false;
			}
			if (exact_record && !arg_saved) {
				exact_authority_ok = false;
			}
			free (arg_val);
			arg_index++;
		} else if (var->kind == VARIABLE_KIND_LOCAL) {
			success &= dwarf_sdb_setf_checked (sdb, meta,
				"fcn.%s.var.%s", sname, var->name)
				&& r_strbuf_appendf (&vars_buf, "%s,", var->name);
		}
		free (meta);
	}
	if (vars_buf.len > 0) {
		r_strbuf_slice (&vars_buf, 0, vars_buf.len - 1);
	}
	if (args_buf.len > 0) {
		r_strbuf_slice (&args_buf, 0, args_buf.len - 1);
	}
	success &= dwarf_sdb_setf_checked (sdb, r_strbuf_get (&vars_buf),
		"fcn.%s.vars", sname)
		&& dwarf_sdb_setf_checked (sdb, r_strbuf_get (&args_buf),
			"fcn.%s.args", sname);
	r_strbuf_fini (&vars_buf);
	r_strbuf_fini (&args_buf);
	free (real_name);
	free (sname);
	return success && (!has_exact_records
		|| (authority_header_saved && exact_authority_ok));
}

/**
 * @brief Parse function,it's arguments, variables and
 *        save the information into the Sdb
 *
 * @param ctx
 * @param idx Current entry index
 */
static void parse_function(Context *ctx, ut64 idx) {
	const RBinDwarfDie *die = &ctx->all_dies[idx];
	if (!die->attr_values) {
		return;
	}

	Function fcn = {0};
	bool get_linkage_name = prefer_linkage_name (ctx->lang);
	const char *direct_name = NULL;
	const char *direct_linkage_name = NULL;
	const char *origin_name = NULL;
	const char *origin_linkage_name = NULL;
	const char *origin_standard_linkage_name = NULL;
	bool has_address = false;
	bool address_exact = true;
	size_t address_count = 0;
	bool has_origin = false;
	bool has_return_type = false;
	ut64 fallback_type_ref = 0;
	RStrBuf ret_type;
	r_strbuf_init (&ret_type);
	const RBinDwarfDie *abstract_origin = dwarf_exact_direct_abstract_origin (
		ctx, die);
	DwarfExactDecl decl = { 0 };
	const RBinDwarfDie *decl_terminal = NULL;
	bool exact_decl = dwarf_collect_exact_decl (
		ctx, abstract_origin? abstract_origin: die,
		DW_TAG_subprogram, abstract_origin != NULL, &decl, &decl_terminal);
	if (exact_decl && abstract_origin) {
		exact_decl = decl_terminal && !decl.has_code_location
			&& dwarf_merge_exact_concrete_prototype (die, &decl)
			&& dwarf_exact_abstract_formals_biject (
				ctx, die, abstract_origin);
	}
	bool prototype_complete = exact_decl && ctx->tree_exact;
	/* For rust binaries prefer regular name not linkage TODO */
	RBinDwarfAttrValue *val;
	R_VEC_FOREACH (die->attr_values, val) {
		switch (val->attr_name) {
		case DW_AT_name:
			if (val->kind == DW_AT_KIND_STRING && R_STR_ISNOTEMPTY (val->string.content)) {
				direct_name = val->string.content;
			}
			break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			if (val->kind == DW_AT_KIND_STRING && R_STR_ISNOTEMPTY (val->string.content)) {
				direct_linkage_name = val->string.content;
			}
			break;
		case DW_AT_low_pc:
		case DW_AT_entry_pc:
			address_count++;
			if (val->kind == DW_AT_KIND_ADDRESS) {
				fcn.addr = val->address;
				has_address = true;
			} else {
				address_exact = false;
			}
			break;
		case DW_AT_specification:
		case DW_AT_abstract_origin:
			has_origin = true;
			(void)dwarf_origin_names (ctx, val, &origin_name, &origin_linkage_name,
				&origin_standard_linkage_name);
			break;
		case DW_AT_type:
			if (!prototype_complete && val->kind == DW_AT_KIND_REFERENCE && !has_return_type) {
				fallback_type_ref = val->reference;
				has_return_type = true;
			}
			break;
		case DW_AT_virtuality:
			fcn.is_method = true; /* method specific attr */
			fcn.is_virtual = true;
			break;
		case DW_AT_object_pointer:
			fcn.is_method = true;
			break;
		case DW_AT_vtable_elem_location:
			fcn.is_method = true;
			fcn.vtable_addr = 0; /* TODO we might use this information */
			break;
		case DW_AT_accessibility:
			fcn.is_method = true;
			if (val->kind == DW_AT_KIND_CONSTANT) {
				fcn.access = (ut8)val->uconstant;
			}
			break;
		case DW_AT_external:
			fcn.is_external = true;
			break;
		case DW_AT_prototyped:
			if (val->kind != DW_AT_KIND_FLAG) {
				prototype_complete = false;
			}
			break;
		case DW_AT_declaration:
			if (val->kind != DW_AT_KIND_FLAG || val->flag) {
				goto cleanup;
			}
			break;
		case DW_AT_trampoline:
			fcn.is_trampoline = true;
			break;
		case DW_AT_ranges:
			address_exact = false;
			break;
		case DW_AT_high_pc:
		default:
			break;
		}
	}
	if (exact_decl) {
		fcn.type_name = dwarf_exact_decl_name (ctx, &decl);
		fcn.name = abstract_origin? fcn.type_name
			: (has_origin
				? (origin_standard_linkage_name? origin_standard_linkage_name
					: (origin_name? origin_name: (decl.name? decl.name: decl.linkage_name)))
				: fcn.type_name);
	} else {
		const char *name = origin_name? origin_name: direct_name;
		const char *linkage_name = origin_linkage_name? origin_linkage_name: direct_linkage_name;
		fcn.type_name = get_linkage_name && linkage_name? linkage_name: (name? name: linkage_name);
		fcn.name = has_origin
			? (origin_standard_linkage_name? origin_standard_linkage_name
				: (name? name: linkage_name))
			: fcn.type_name;
	}
	address_exact &= address_count == 1;
	prototype_complete &= address_exact
		&& (!has_origin || abstract_origin) && fcn.name
		&& decl.has_prototyped && decl.prototyped;
	bool return_type_exact = true;
	if (decl.has_type) {
		has_return_type = true;
		return_type_exact = dwarf_render_exact_type (ctx, decl.type_ref, &ret_type);
		prototype_complete &= return_type_exact;
		if (!return_type_exact && !ret_type.len) {
			parse_type (ctx, decl.type_ref, &ret_type, NULL, NULL);
		}
	} else if (has_return_type) {
		parse_type (ctx, fallback_type_ref, &ret_type, NULL, NULL);
	}

	if (!fcn.name || !has_address || !dwarf_function_address_is_valid (ctx, fcn.addr)) {
		/* We need a name and a low_pc/entry_pc in executable address space. */
		goto cleanup;
	}

	RStrBuf args;
	r_strbuf_init (&args);
	/* TODO do the same for arguments in future so we can use their location */
	RList/*<Variable*>*/  *variables = r_list_new ();
	bool has_unspecified_parameters = false;
	bool decl_corrupt = has_origin && !exact_decl;
	const bool args_complete = parse_function_args_and_vars (
		ctx, idx, &args, variables, &has_unspecified_parameters, &decl_corrupt);
	prototype_complete &= args_complete;
	// identity: the declaration parsed whole and names one address; unlike the
	// exact authority above it does not require locations or a whole-exact CU
	bool link_complete = exact_decl && !decl_corrupt && args_complete
		&& address_exact && address_count == 1 && return_type_exact;


	if (ret_type.len == 0) { /* DW_AT_type is omitted in case of `void` ret type */
		prototype_complete &= !has_return_type;
		link_complete &= !has_return_type;
		r_strbuf_append (&ret_type, "void");
	}

	R_WARN_IF_FAIL (ctx->lang);
	const char *raw_name = fcn.name;
	const char *raw_type_name = fcn.type_name? fcn.type_name: raw_name;
	char *demangled_name = NULL;
	char *demangled_type_name = NULL;
	if (ctx->anal->binb.demangle) {
		demangled_name = ctx->anal->binb.demangle (NULL, ctx->lang, raw_name, fcn.addr, false);
		if (demangled_name) {
			fcn.name = demangled_name;
		}
		if (raw_type_name == raw_name) {
			fcn.type_name = fcn.name;
		} else {
			demangled_type_name = ctx->anal->binb.demangle (NULL, ctx->lang,
				raw_type_name, fcn.addr, false);
			fcn.type_name = demangled_type_name? demangled_type_name: raw_type_name;
		}
	}
	fcn.signature = r_str_newf ("%s %s(%s);", r_strbuf_get (&ret_type), fcn.name, r_strbuf_get (&args));
	const bool function_saved = sdb_save_dwarf_function (ctx, &fcn,
		r_strbuf_get (&ret_type), variables, has_unspecified_parameters,
		prototype_complete, link_complete);
	if (ctx->exact_formal_records_ok
		&& (!function_saved || (prototype_complete
			&& !dwarf_function_frame_pointer_stage (ctx, die, fcn.addr)))) {
		*ctx->exact_formal_records_ok = false;
	}

	/* Free the demangled name and signature */
	free (demangled_name);
	free (demangled_type_name);
	free (fcn.signature);

	RListIter *iter;
	Variable *var;
	r_list_foreach (variables, iter, var) {
		variable_free (var);
	}
	r_list_free (variables);
	r_strbuf_fini (&args);
cleanup:
	r_strbuf_fini (&ret_type);
}

/**
 * @brief Get's language from comp unit for demangling
 *
 * @param die
 * @return char* string literal language represantation for demangling BinDemangle
 */
static const char *parse_comp_unit_lang(const RBinDwarfDie *die) {
	R_RETURN_VAL_IF_FAIL (die, NULL);

	RBinDwarfAttrValue *val = get_die_attr(die, DW_AT_language);
	const char *lang = "cxx"; // default fallback
	if (!val) {
		/* What to do now, it should have  one?, just assume C++ */
		return lang;
	}
	R_WARN_IF_FAIL (val->kind == DW_AT_KIND_CONSTANT);

	switch (val->uconstant) {
	case DW_LANG_Java:
		return "java";
	case DW_LANG_ObjC:
	/* subideal, TODO research if dwarf gives me enough info to properly separate C++ and ObjC mangling */
	case DW_LANG_ObjC_plus_plus:
		return "objc";
	case DW_LANG_D:
		return "dlang";
	case DW_LANG_Rust:
		return "rust";
	case DW_LANG_C_plus_plus:
	case DW_LANG_C_plus_plus_14:
	/* no demangling available */
	case DW_LANG_Ada83:
	case DW_LANG_Cobol74:
	case DW_LANG_Cobol85:
	case DW_LANG_Fortran77:
	case DW_LANG_Fortran90:
	case DW_LANG_Pascal83:
	case DW_LANG_Modula2:
	case DW_LANG_Ada95:
	case DW_LANG_Fortran95:
	case DW_LANG_PLI:
	case DW_LANG_Python:
	case DW_LANG_Swift:
	case DW_LANG_Julia:
	case DW_LANG_Dylan:
	case DW_LANG_Fortran03:
	case DW_LANG_Fortran08:
	case DW_LANG_UPC:
	case DW_LANG_C:
	case DW_LANG_C89:
	case DW_LANG_C99:
	case DW_LANG_C11:
	default:
		return lang;
	}
	return lang;
}

/**
 * @brief Delegates DIE to it's proper parsing method
 *
 * @param ctx
 * @param idx index of the current entry
 */
static void parse_type_entry(Context *ctx, ut64 idx) {
	R_RETURN_IF_FAIL (ctx);

	const RBinDwarfDie *die = &ctx->all_dies[idx];
	if (!die->attr_values) {
		return;
	}
	switch (die->tag) {
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_class_type:
		parse_structure_type (ctx, idx);
		break;
	case DW_TAG_enumeration_type:
		parse_enum_type (ctx, idx);
		break;
	case DW_TAG_typedef:
		parse_typedef (ctx, idx);
		break;
	case DW_TAG_base_type:
		parse_atomic_type (ctx, idx);
		break;
	case DW_TAG_subprogram:
		parse_function (ctx, idx);
		break;
	case DW_TAG_compile_unit:
		/* used for name demangling */
		ctx->lang = parse_comp_unit_lang (die);
	default:
		break;
	}
}

/**
 * @brief Parses type and function information out of DWARF entries
 *        and stores them to the sdb for further use
 *
 * @param anal
 * @param ctx
 */
R_API void r_anal_dwarf_process_info(const RAnal *anal, RAnalDwarfContext *ctx) {
	R_RETURN_IF_FAIL (ctx && anal);
	RAnal *mutable_anal = (RAnal *)anal;
	r_th_lock_enter (mutable_anal->lock);
	r_anal_dwarf_exact_formal_authority_reset (mutable_anal);
	HtUP *exact_formal_records = r_anal_dwarf_exact_formal_records_new ();
	HtUP *exact_function_links = dwarf_exact_function_links_new ();
	HtUP *exact_frame_pointer_proofs =
		r_anal_dwarf_frame_pointer_proofs_new ();
	bool exact_formal_records_ok = exact_formal_records && exact_function_links
		&& exact_frame_pointer_proofs;
	Sdb *dwarf_sdb = sdb_ns (anal->sdb, "dwarf", 1);
	if (!dwarf_sdb) {
		exact_formal_records_ok = false;
		goto beach;
	}
	exact_formal_records_ok &= r_anal_dwarf_function_links_revoke_owned (
		mutable_anal);
	if (!ctx->info) {
		exact_formal_records_ok = false;
		goto beach;
	}

	const RBinDwarfDebugInfo *info = ctx->info;
	const RBinDwarfCompUnit *unit;
	RArena *arena = r_arena_new ();
	if (!arena) {
		exact_formal_records_ok = false;
		goto beach;
	}
	R_VEC_FOREACH (info->comp_units, unit) {
		const size_t die_count = RVecDwarfDie_length (unit->dies);
		HtUU *cu_die_indices = dwarf_cu_die_indices_new (
			unit->dies->_start, die_count);
		Context dw_context = { // context per unit?
			.anal = anal,
			.all_dies = unit->dies->_start,
			.count = die_count,
			.die_map = info->lookup_table,
			.cu_die_indices = cu_die_indices,
			.sdb = dwarf_sdb,
			.locations = ctx->loc,
			.lang = NULL,
			.arena = arena,
			.exact_formal_records = exact_formal_records,
			.exact_function_links = exact_function_links,
			.exact_frame_pointer_proofs = exact_frame_pointer_proofs,
			.exact_formal_records_ok = &exact_formal_records_ok,
			.tree_exact = cu_die_indices
				&& dwarf_cu_tree_is_exact (unit->dies->_start, die_count),
		};
		R_VEC_FOREACH_I (unit->dies, j) {
			parse_type_entry (&dw_context, j);
		}
		ht_uu_free (cu_die_indices);
	}
	r_arena_free (arena);
beach:
	if (exact_formal_records_ok) {
		exact_formal_records_ok = dwarf_function_links_publish (
			mutable_anal, exact_function_links);
	}
	if (exact_formal_records_ok) {
		exact_formal_records_ok = r_anal_dwarf_frame_pointer_proofs_publish (
			mutable_anal, exact_frame_pointer_proofs);
		if (exact_formal_records_ok) {
			exact_frame_pointer_proofs = NULL;
		} else if (!dwarf_function_links_rollback (
				mutable_anal, exact_function_links)) {
			R_LOG_ERROR ("Failed to revoke DWARF function links after frame-pointer proof refusal");
		}
	}
	if (exact_formal_records_ok) {
		r_anal_dwarf_exact_formal_records_publish (
			mutable_anal, exact_formal_records);
		exact_formal_records = NULL;
	}
	r_anal_dwarf_exact_formal_records_free (exact_formal_records);
	ht_up_free (exact_function_links);
	r_anal_dwarf_frame_pointer_proofs_free (exact_frame_pointer_proofs);
	r_th_lock_leave (mutable_anal->lock);
}

bool filter_sdb_function_names(void *user, const char *k, const char *v) {
	(void) user;
	(void) k;
	return !strcmp (v, "fcn");
}

typedef struct dwarf_exact_formal_record_t {
	char *name;
	char *type;
	char kind;
	st64 offset;
	int ordinal;
} DwarfExactFormalRecord;

static void dwarf_exact_formal_record_fini(DwarfExactFormalRecord *record) {
	if (record) {
		free (record->name);
		free (record->type);
		memset (record, 0, sizeof (*record));
	}
}

static bool dwarf_parse_st64(const char *text, R_OUT st64 *value) {
	if (R_STR_ISEMPTY (text) || !value) {
		return false;
	}
	errno = 0;
	char *end = NULL;
	const long long parsed = strtoll (text, &end, 10);
	if (errno == ERANGE || !end || *end || (st64)parsed != parsed) {
		return false;
	}
	*value = (st64)parsed;
	return true;
}

static bool dwarf_parse_canonical_st64(const char *text, R_OUT st64 *value) {
	if (R_STR_ISEMPTY (text) || !value || *text == '+') {
		return false;
	}
	st64 parsed;
	if (!dwarf_parse_st64 (text, &parsed)) {
		return false;
	}
	char canonical[64];
	const int length = snprintf (canonical, sizeof (canonical),
		"%" PFMT64d, parsed);
	if (length < 1 || (size_t)length >= sizeof (canonical)
		|| strcmp (canonical, text)) {
		return false;
	}
	*value = parsed;
	return true;
}

static char *dwarf_decode_canonical_string(const char *encoded) {
	if (R_STR_ISEMPTY (encoded)) {
		return NULL;
	}
	int length = 0;
	ut8 *decoded = r_base64_decode_dyn (encoded, -1, &length, true);
	if (!decoded || length < 1 || memchr (decoded, 0, (size_t)length)) {
		free (decoded);
		return NULL;
	}
	char *canonical = r_base64_encode_dyn (decoded, length);
	if (!canonical || strcmp (canonical, encoded)) {
		free (canonical);
		free (decoded);
		return NULL;
	}
	free (canonical);
	char *text = malloc ((size_t)length + 1);
	if (!text) {
		free (decoded);
		return NULL;
	}
	memcpy (text, decoded, (size_t)length);
	text[length] = 0;
	free (decoded);
	return text;
}

static bool dwarf_exact_formal_record_parse(char *serialized,
		R_OUT DwarfExactFormalRecord *record) {
	R_RETURN_VAL_IF_FAIL (serialized && record, false);
	char *fields[6] = {0};
	char *cursor = serialized;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (fields); i++) {
		if (!cursor) {
			return false;
		}
		char *next = NULL;
		fields[i] = sdb_anext (cursor, &next);
		if (R_STR_ISEMPTY (fields[i])) {
			return false;
		}
		cursor = next;
	}
	if (cursor || strcmp (fields[0], DWARF_EXACT_FORMAL_RECORD_V1)) {
		return false;
	}
	st64 ordinal;
	st64 offset;
	if (!dwarf_parse_canonical_st64 (fields[1], &ordinal)
		|| ordinal < 0 || ordinal > INT_MAX
		|| (strcmp (fields[2], "b") && strcmp (fields[2], "s"))
		|| !dwarf_parse_canonical_st64 (fields[3], &offset)) {
		return false;
	}
	record->name = dwarf_decode_canonical_string (fields[4]);
	record->type = dwarf_decode_canonical_string (fields[5]);
	if (!record->name || !record->type) {
		dwarf_exact_formal_record_fini (record);
		return false;
	}
	record->kind = fields[2][0];
	record->offset = offset;
	record->ordinal = (int)ordinal;
	return true;
}

static bool integrate_dwarf_var(RAnal *anal, RFlag *flags, RAnalFunction *fcn, const char *var_name, char *var_data, bool is_arg, int arg_index) {
	R_RETURN_VAL_IF_FAIL (anal && flags && var_name && var_data, false);
	char *extra = NULL;
	char *kind = sdb_anext (var_data, &extra);
	char *type = NULL;
	extra = sdb_anext (extra, &type);
	if (!kind || !extra || !type || !*kind) {
		return false;
	}
	st64 offset = 0;
	if (*kind != 'r' && !dwarf_parse_st64 (extra, &offset)) {
		return false;
	}
	if (*kind == 'g') { /* global, fixed addr TODO add size to variables? */
		char *global_name = r_str_newf ("global_%s", var_name);
		r_flag_unset_addr (flags, offset);
		r_flag_set_next (flags, global_name, offset, 4);
		free (global_name);
		return true;
	}
	if (!fcn) {
		return false;
	}
	RAnalVar *var = NULL;
	if (*kind == 's') {
		st64 delta;
		if (r_sub_overflow (offset, (st64)fcn->maxstack, &delta)
			|| delta < INT_MIN || delta > INT_MAX) {
			return false;
		}
		RAnalVar *named = arg_index >= 0
			? r_anal_function_get_var_byname (fcn, var_name): NULL;
		if (named) {
			var = r_anal_function_get_var (fcn, *kind, (int)delta);
		}
		if (var && var != named) {
			r_anal_var_set_type (anal, var, type);
			var->isarg = true;
		} else {
			var = r_anal_function_set_var (
				fcn, (int)delta, *kind, type, 4, is_arg, var_name);
		}
	} else if (*kind == 'r') {
		RRegItem *ri = r_reg_get (anal->reg, extra, -1);
		if (!ri) {
			return false;
		}
		var = r_anal_function_set_var (
			fcn, ri->index, *kind, type, 4, is_arg, var_name);
		r_unref (ri);
	} else if (*kind == 'b') {
		st64 delta;
		if (r_sub_overflow (offset, fcn->bp_off, &delta)
			|| delta < INT_MIN || delta > INT_MAX) {
			return false;
		}
		RAnalVar *named = arg_index >= 0
			? r_anal_function_get_var_byname (fcn, var_name): NULL;
		if (named) {
			var = r_anal_function_get_var (fcn, *kind, (int)delta);
		}
		if (var && var != named) {
			r_anal_var_set_type (anal, var, type);
			var->isarg = true;
		} else {
			var = r_anal_function_set_var (
				fcn, (int)delta, *kind, type, 4, is_arg, var_name);
		}
	} else {
		return false;
	}
	if (!var) {
		return false;
	}
	if (is_arg) {
		var->argnum = arg_index;
		if (arg_index >= 0 && !r_anal_var_exact_formal_set (anal, var,
				fcn->addr, arg_index, var->kind, var->delta, offset, var->type)) {
			var->argnum = -1;
		}
	}
	return true;
}

/**
 * @brief Use parsed DWARF function info from Sdb in the anal functions
 *  XXX right now we only save parsed name and variables, we can't use signature now
 *  XXX refactor to be more readable
 * @param anal
 * @param dwarf_sdb
 */
R_API void r_anal_dwarf_integrate_functions(RAnal *anal, RFlag *flags, Sdb *dwarf_sdb) {
	R_RETURN_IF_FAIL (anal && dwarf_sdb);
	r_th_lock_enter (anal->lock);
	(void)r_anal_dwarf_frame_pointer_proofs_rebind_current (anal);

	/* get all entries with value == func */
	SdbList *sdb_list = sdb_foreach_list_filter (dwarf_sdb, filter_sdb_function_names, false);
	if (!sdb_list) {
		goto beach;
	}
	SdbListIter *it;
	SdbKv *kv;
	/* iterate all function entries */
	ls_foreach (sdb_list, it, kv) {
		char *func_sname = kv->base.key;

		ut64 faddr = sdb_num_getf (dwarf_sdb, NULL, "fcn.%s.addr", func_sname);

		/* if the function is analyzed so we can edit */
		RAnalFunction *fcn = r_anal_get_function_at (anal, faddr);
		if (fcn) {
			RAnalVar **var_it;
			R_VEC_FOREACH (&fcn->vars, var_it) {
				r_anal_var_exact_formal_clear (anal, *var_it);
			}
			/* prepend dwarf debug info stuff with dbg. */
			const char *value = sdb_const_getf (dwarf_sdb, NULL, "fcn.%s.name", func_sname);
			char *real_name = value? strdup (value): NULL;
			if (real_name) {
				r_str_ansi_strip (real_name);
				char *dwf_name = r_str_newf ("dbg.%s", real_name);
				r_anal_function_rename (fcn, dwf_name);
				free (dwf_name);
			}
			free (real_name);

			value = sdb_const_getf (dwarf_sdb, NULL, "fcn.%s.sig", func_sname);
			char *fcnstr = value? strdup (value): NULL;
			if (fcnstr) {
				r_str_ansi_strip (fcnstr);
				/* Apply signature as a comment at a function address */
				r_meta_set_string (anal, R_META_TYPE_COMMENT, faddr, fcnstr);
			}
			free (fcnstr);
			// What the source declared and what recovery guessed can describe
			// the same bytes twice, and a layout that says so is not one a
			// consumer can read.
			r_anal_function_resolve_var_overlaps (anal, fcn);
		}
		int arg_index;
		for (arg_index = 0; ; arg_index++) {
			const char *value = sdb_const_getf (dwarf_sdb, NULL, "fcn.%s.arg.%d", func_sname, arg_index);
			char *arg_data = value? strdup (value): NULL;
			if (!arg_data) {
				break;
			}
			if (r_str_startswith (arg_data, DWARF_EXACT_FORMAL_RECORD_V1 ",")) {
				DwarfExactFormalRecord exact = {0};
				if (r_anal_dwarf_exact_formal_record_matches (
						anal, faddr, arg_index, arg_data)
					&& dwarf_exact_formal_record_parse (arg_data, &exact)
					&& exact.ordinal == arg_index) {
					char *meta = r_str_newf ("%c,%" PFMT64d ",%s",
						exact.kind, exact.offset, exact.type);
					if (meta) {
						(void)integrate_dwarf_var (anal, flags, fcn,
							exact.name, meta, true, exact.ordinal);
					}
					free (meta);
				}
				dwarf_exact_formal_record_fini (&exact);
			} else {
				char *meta = NULL;
				char *arg_name = sdb_anext (arg_data, &meta);
				if (meta && R_STR_ISNOTEMPTY (arg_name)) {
					(void)integrate_dwarf_var (anal, flags, fcn,
						arg_name, meta, true, -1);
				}
			}
			free (arg_data);
		}
		const char *value = sdb_const_getf (dwarf_sdb, NULL, "fcn.%s.vars", func_sname);
		char *vars = value? strdup (value): NULL;
		if (vars) {
			r_str_ansi_strip (vars);
		}
		char *var_name;
		sdb_aforeach (var_name, vars) {
			value = sdb_const_getf (dwarf_sdb, NULL, "fcn.%s.var.%s", func_sname, var_name);
			char *var_data = value? strdup (value): NULL;
			if (var_data) {
				(void)integrate_dwarf_var (
					anal, flags, fcn, var_name, var_data, false, -1);
			}
			free (var_data);
			sdb_aforeach_next (var_name);
		}
		free (vars);
	}
	ls_free (sdb_list);
beach:
	r_th_lock_leave (anal->lock);
}
