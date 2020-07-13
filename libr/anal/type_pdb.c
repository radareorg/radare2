#include <r_bin.h>
#include <r_core.h>
#include <r_anal.h>
#include "../bin/pdb/types.h"

static bool is_parsable_type (const ELeafType type) {
	return (type == eLF_STRUCTURE ||
		type == eLF_UNION ||
		type == eLF_ENUM ||
		type == eLF_CLASS);
}
//  These could be refactored into type.c so 
// I don't have to dupe it everywhere (for dwarf and here for pdbd)
static void struct_type_fini(void *e, void *user) {
	(void)user;
	RAnalStructMember *member = e;
	free ((char *)member->name);
	free ((char *)member->type);
}

static void enum_type_fini(void *e, void *user) {
	(void)user;
	RAnalEnumCase *cas = e;
	free ((char *)cas->name);
}
// TODO delete
static void debug_print_struct(const RAnalBaseType *base_type, const char *name, const int size) {
	printf ("struct %s {\n", name);
	RVector members = base_type->struct_data.members;
	RAnalStructMember *member;
	r_vector_foreach (&members, member) {
		printf ("\t%s %s; (+%d)\n", member->type, member->name, member->offset);
	}
	printf ("}\n");
}

// TODO delete
static void debug_print_union(const RAnalBaseType *base_type, const char *name, const int size) {
	printf ("union %s {\n", name);
	RVector members = base_type->union_data.members;
	RAnalUnionMember *member;
	r_vector_foreach (&members, member) {
		printf ("\t%s %s;\n", member->type, member->name);
	}
	printf ("}\n");
}

// TODO delete
static void debug_print_enum(const RAnalBaseType *base_type, const char *name, const char *type) {
	printf ("enum %s { // type: %s\n", name, type);
	RVector members = base_type->enum_data.cases;
	RAnalEnumCase *enum_case;
	r_vector_foreach (&members, enum_case) {
		printf ("\t%s = %d;\n", enum_case->name, enum_case->val);
	}
	printf ("}\n");
}

static RAnalStructMember *parse_member(STypeInfo *type_info, RList *types) {
	r_return_val_if_fail (type_info && types, NULL);
	r_return_val_if_fail (type_info->get_name && 
	type_info->get_print_type, NULL);
	// ignore LF_METHOD, LF_NESTTYPE, bitfields, etc for now
	if (type_info->leaf_type != eLF_MEMBER) {
		return NULL;
	}
	char *name = NULL;
	char *type = NULL;
	int offset = 0;
	// sometimes, the type doesn't have get_val
	if (type_info->get_val) {
		type_info->get_val (type_info, &offset);
	}
	type_info->get_name (type_info, &name);
	type_info->get_print_type (type_info, &type);
	RAnalStructMember *member = R_NEW0 (RAnalStructMember);
	if (!member) {
		goto cleanup;
	}
	member->name = name;
	member->type = type;
	member->offset = offset;
	return member;
cleanup:
	free (name);
	free (type);
	return NULL;
}
static RAnalEnumCase *parse_enumerate(STypeInfo *type_info, RList *types) {
	r_return_val_if_fail (type_info && types && type_info->leaf_type == eLF_ENUMERATE, NULL);
	r_return_val_if_fail (type_info->get_val && type_info->get_name, NULL);

	char *name = NULL;
	int value = 0;
	// sometimes, the type doesn't have get_val
	if (type_info->get_val) {
		type_info->get_val (type_info, &value);
	}
	type_info->get_name (type_info, &name);
	RAnalEnumCase *cas = R_NEW0 (RAnalEnumCase);
	if (!cas) {
		goto cleanup;
	}
	cas->name = name;
	cas->val = value;
	return cas;
cleanup:
	free (name);
	return NULL;
}

static void parse_enum(const RAnal *anal, SType *type, RList *types) {
	r_return_if_fail (anal && type && types);

	STypeInfo *type_info = &type->type_data;

	r_return_if_fail (type_info->get_members &&
		type_info->get_name);
	// I need the DWARF PR to be merged to use
	// extra type functions I created there
	RAnalBaseType *base_type = R_NEW0 (RAnalBaseType);
	if (!base_type) {
		return;
	}
	char *name = NULL;
	RList *members = r_list_new ();
	if (!members) {
		goto cleanup;
	}
	type_info->get_name (type_info, &name);
	// gets the underlying enum type, but the
	// way the function is done is useless to use
	// would need restructuring to get the data out of it
	char *type_name = NULL;
	type_info->get_utype (type_info, &type);
	if (type && type->type_data.type_info) {
		SLF_BASE_TYPE *base_type = type->type_data.type_info;
		type_name = base_type->type;
	}
	type_info->get_members (type_info, &members);

	r_vector_init (&base_type->enum_data.cases,
		sizeof (RAnalEnumCase), enum_type_fini, NULL);

	RListIter *it = r_list_iterator (members);
	while (r_list_iter_next (it)) {
		STypeInfo *member_info = r_list_iter_get (it);
		RAnalEnumCase *enum_case = parse_enumerate (member_info, types);
		if (!enum_case) {
			continue;
			// TODO
			// goto cleanup;
		}
		void *element = r_vector_push (&base_type->struct_data.members, enum_case);
		if (!element) {
			goto cleanup;
		}
	}
	base_type->kind = R_ANAL_BASE_TYPE_KIND_ENUM;
	// Waiting for DWARF PR merge to finish these
	// base_type->name = .....
	// base_type->size = .....
	// r_anal_save_base_type (base_type);
	// debug_print_enum (base_type, name, type_name);
cleanup:
	// TODO
	return;
}

// parses classes, unions and structures for now
static void parse_structure(const RAnal *anal, SType *type, RList *types) {
	r_return_if_fail (anal && type && types);
	STypeInfo *type_info = &type->type_data;
	// check if all those methods are initialized
	r_return_if_fail (type_info->get_members &&
		type_info->is_fwdref &&
		type_info->get_name &&
		type_info->get_val);

	int is_forward_decl;
	type_info->is_fwdref (type_info, &is_forward_decl);
	if (is_forward_decl) { // we skip those, atleast for now
		return;
	}
	/*
		TODO - what do I need
		name - [x]
		size - [x]
		members: [x]
			type, name, size for each member [x]
	*/
	// I need the DWARF PR to be merged to use
	// extra type functions I created there
	RAnalBaseType *base_type = R_NEW0 (RAnalBaseType);
	if (!base_type) {
		return;
	}
	int size;
	char *name = NULL;
	RList *members = r_list_new ();
	if (!members) {
		goto cleanup;
	}
	type_info->get_name (type_info, &name);
	type_info->get_val (type_info, &size);
	type_info->get_members (type_info, &members);

	r_vector_init (&base_type->struct_data.members,
		sizeof (RAnalStructMember), struct_type_fini, NULL);

	RListIter *it = r_list_iterator (members);
	while (r_list_iter_next (it)) {
		STypeInfo *member_info = r_list_iter_get (it);
		RAnalStructMember *struct_member = parse_member (member_info, types);
		if (!struct_member) {
			continue;
			// TODO
			// goto cleanup;
		}
		void *element = r_vector_push (&base_type->struct_data.members, struct_member);
		if (!element) {
			goto cleanup;
		}
	}
	if (type_info->leaf_type == eLF_STRUCTURE || type_info->leaf_type == eLF_CLASS) {
		base_type->kind = R_ANAL_BASE_TYPE_KIND_STRUCT;
		// debug_print_struct (base_type, name, size);
	} else { // union
		base_type->kind = R_ANAL_BASE_TYPE_KIND_UNION;
		// debug_print_union (base_type, name, size);
	}
	// Waiting for DWARF PR merge to finish these
	// base_type->name = .....
	// base_type->size = .....
	// r_anal_save_base_type (base_type);
	return;
cleanup:
	// TODO
	return;
}

static void parse_type (const RAnal *anal, SType *type, RList *types) {
	r_return_if_fail (anal && type && types);
	switch (type->type_data.leaf_type) {
	case eLF_CLASS:
	case eLF_STRUCTURE:
	case eLF_UNION:
		parse_structure (anal ,type, types);
		break;
	case eLF_ENUM:
		parse_enum (anal ,type, types);
		break;
	default:
		eprintf ("Unknown type record");
		break;
	}
}

/**
 * @brief Saves PDB types from TPI stream into the SDB
 * 
 * @param anal 
 * @param pdb 
 */
R_API void parse_pdb_types(const RAnal *anal, const R_PDB *pdb) {
	r_return_if_fail (anal && pdb);
	RList *plist = pdb->pdb_streams;
	// getting the TPI stream from the streams list
	STpiStream *tpi_stream = r_list_get_n (plist, ePDB_STREAM_TPI);
	if (!tpi_stream) { // no TPI stream found
		return;
	}
	// Types should be DAC - only references previous records
	RListIter *iter = r_list_iterator (tpi_stream->types);
	while (r_list_iter_next (iter)) { // iterate all types
		SType *type = r_list_iter_get (iter);
		if (is_parsable_type (type->type_data.leaf_type)) {
			parse_type (anal, type, tpi_stream->types);
		}
	}
}