#include <r_bin.h>
#include <r_core.h>
#include <r_anal.h>
#include "../bin/pdb/types.h"

static bool is_parsable_type (ELeafType type) {
	return (type == eLF_STRUCTURE ||
		type == eLF_UNION ||
		type == eLF_ENUM ||
		type == eLF_CLASS);
}

static RAnalStructMember *parse_struct_member (STypeInfo *type_info, RList *types) {
	return NULL;
}

static void parse_structure(SType *type, RList *types) {
	SLF_STRUCTURE *structure = type->type_data.type_info;
	STypeInfo *type_info = &type->type_data;
	/*
		TODO - what do I need
		name - [x]
		size - [x]
		members:
			type, name, size for each member
	*/
	// RAnalBaseType *base_type; I need the DWARF PR to be merge to use
	// extra type functions I created there
	int size;
	char *name = NULL;
	type_info->get_name (type_info, &name);
	type_info->get_val (type_info, &size);
	RList *members = r_list_new ();
	type_info->get_members (&type->type_data, &members);
	RListIter *it = r_list_iterator (members);
	while (r_list_iter_next (it)) {
		STypeInfo *member_info = r_list_iter_get (it);
		RAnalStructMember *struct_member = parse_struct_member (member_info, types);
	}
}

static void parse_type (SType *type, RList *types) {
	switch (type->type_data.leaf_type) {
	case eLF_STRUCTURE:
		parse_structure (type, types);
		break;
	case eLF_CLASS:
	case eLF_ENUM:
	case eLF_UNION:
		break;
	default:
		eprintf ("Unknown type record");
		break;
	}
}

R_API void parse_pdb_types(RAnal *anal, R_PDB *pdb) {
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
			parse_type (type, tpi_stream->types);
		}
	}
}