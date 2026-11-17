#include <r_util.h>
#include "minunit.h"
#include <r_anal.h>
#include <r_bin.h>
#include <r_core.h>
#include <r_bin_dwarf.h>
#include "../../libr/bin/format/pdb/types.h"
#include "../../libr/bin/format/pdb/tpi.h"
#include "../../libr/bin/format/pdb/stream_file.h"

#define MODE 2

#define check_kv(k, v)                                                         \
	do {                                                                   \
		char *value = sdb_get (anal->sdb_types, k, NULL);                    \
		mu_assert_nullable_streq (value, v, "Wrong key - value pair"); \
		free (value);                                                  \
	} while (0)

// copy from cbin.c modified to get pdb back
int pdb_info(const char *file, RBinPdb *pdb) {
	if (!r_bin_pdb_parser (pdb, file)) {
		return false;
	}
	if (!pdb->pdb_parse (pdb)) {
		eprintf ("pdb was not parsed\n");
		pdb->finish_pdb_parse (pdb);
		return false;
	}
	return true;
}

int pdb_info_save_types(RAnal *anal, const char *file, RBinPdb *pdb) {
	if (!r_bin_pdb_parser (pdb, file)) {
		return false;
	}
	if (!pdb->pdb_parse (pdb)) {
		eprintf ("pdb was not parsed\n");
		pdb->finish_pdb_parse (pdb);
		return false;
	}
	r_parse_pdb_types (anal, pdb);
	pdb->finish_pdb_parse (pdb);
	return true;
}

bool test_pdb_guid_age(void) {
	RBinPdb pdb = {0};
	mu_assert_true (pdb_info ("bins/pdb/SimplePDB.pdb", &pdb), "parse PDB identity");
	char *guid = r_bin_pdb_guid (&pdb);
	mu_assert_streq (guid, "1516D2A3E6864C06BD82C50FBE6152363", "GUID includes age");
	free (guid);
	SPDBInfoStream *info = r_list_get_n (pdb.pdb_streams, ePDB_STREAM_PDB);
	info->age = 0x10;
	guid = r_bin_pdb_guid (&pdb);
	mu_assert_streq (guid, "1516D2A3E6864C06BD82C50FBE61523610", "age uses hexadecimal");
	free (guid);
	pdb.finish_pdb_parse (&pdb);
	mu_end;
}

bool test_pdb_tpi_cpp(void) {
	RBinPdb pdb = {0};
	mu_assert_true (pdb_info ("bins/pdb/Project1.pdb", &pdb), "pdb parsing failed");

	RList *plist = pdb.pdb_streams;
	mu_assert_notnull (plist, "PDB streams is NULL");

	mu_assert_eq (pdb.root_stream->num_streams, 50, "Incorrect number of streams");

	STpiStream *tpi_stream = r_list_get_n (plist, ePDB_STREAM_TPI);
	mu_assert_notnull (tpi_stream, "TPIs stream not found in current PDB");
	mu_assert_eq (tpi_stream->header.hdr_size + tpi_stream->header.follow_size, 117156, "Wrong TPI size");
	mu_assert_eq (tpi_stream->header.idx_begin, 0x1000, "Wrong beginning index");

	// tpi_stream->header.
	mu_assert_eq (tpi_stream->types->length, 1148, "Incorrect number of types");
	RListIter *it = r_list_iterator (tpi_stream->types);
	SType *type;
	while (r_list_iter_next (it)) {
		type = r_list_iter_get (it);
		STypeInfo *type_info = &type->type_data;
		if (type->tpi_idx == 0x1028) {
			mu_assert_eq (type_info->leaf_type, eLF_PROCEDURE, "Incorrect data type");
			SType *arglist;
			type_info->get_arglist (tpi_stream, type_info, (void **)&arglist);
			mu_assert_eq (arglist->tpi_idx, 0x1027, "Wrong type index");
			SType *return_type;
			type_info->get_return_type (tpi_stream, type_info, (void **)&return_type);
			mu_assert_eq (return_type->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = return_type->type_data.type_info;
			mu_assert_eq (simple_type->size, 4, "Incorrect return type");
			mu_assert_streq (simple_type->type, "int32_t", "Incorrect return type");
			tpi_free_simple_type (return_type);
		} else if (type->tpi_idx == 0x1161) {
			mu_assert_eq (type_info->leaf_type, eLF_POINTER, "Incorrect data type");
			char *type;
			type_info->get_print_type (tpi_stream, type_info, &type);
			mu_assert_streq (type, "struct _RTC_framedesc*", "Wrong pointer print type");
			free (type);
		} else if (type->tpi_idx == 0x1004) {
			mu_assert_eq (type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			int forward_ref = 0;
			type->type_data.is_fwdref (tpi_stream, type_info, &forward_ref);
			mu_assert_eq (forward_ref, 1, "Wrong fwdref");
		} else if (type->tpi_idx == 0x113F) {
			mu_assert_eq (type_info->leaf_type, eLF_ARRAY, "Incorrect data type");
			char *type;
			type_info->get_print_type (tpi_stream, type_info, &type);
			free (type);
			SType *dump;
			type_info->get_index_type (tpi_stream, type_info, (void **)&dump);
			mu_assert_eq (dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = dump->type_data.type_info;
			mu_assert_eq (simple_type->simple_type, eT_ULONG, "Incorrect return type");
			mu_assert_eq (simple_type->size, 4, "Incorrect return type");
			mu_assert_streq (simple_type->type, "uint32_t", "Incorrect return type");
			tpi_free_simple_type (dump);
			type_info->get_element_type (tpi_stream, type_info, (void **)&dump);
			mu_assert_eq (dump->tpi_idx, 0x113E, "Wrong element type index");
			int size;
			type_info->get_val (tpi_stream, type_info, &size);
			mu_assert_eq (size, 20, "Wrong array size");
		} else if (type->tpi_idx == 0x145A) {
			mu_assert_eq (type_info->leaf_type, eLF_ENUM, "Incorrect data type");
			SType *dump;
			RList *members;
			char *name;
			type_info->get_name (tpi_stream, type_info, &name);
			mu_assert_streq (name, "EXCEPTION_DEBUGGER_ENUM", "wrong enum name");
			type_info->get_utype (tpi_stream, type_info, (void **)&dump);
			mu_assert_eq (dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = dump->type_data.type_info;
			mu_assert_eq (simple_type->simple_type, eT_INT4, "Incorrect return type");
			mu_assert_eq (simple_type->size, 4, "Incorrect return type");
			mu_assert_streq (simple_type->type, "int32_t", "Incorrect return type");
			tpi_free_simple_type (dump);
			type_info->get_members (tpi_stream, type_info, &members);
			mu_assert_eq (members->length, 6, "wrong enum members length");
		} else if (type->tpi_idx == 0x1414) {
			mu_assert_eq (type_info->leaf_type, eLF_VTSHAPE, "Incorrect data type");
		} else if (type->tpi_idx == 0x1421) {
			mu_assert_eq (type_info->leaf_type, eLF_MODIFIER, "Incorrect data type");
			SType *stype = NULL;
			type_info->get_modified_type (tpi_stream, type_info, (void **)&stype);
			mu_assert_eq (stype->tpi_idx, 0x120F, "Incorrect modified type");
			char *type;
			type_info->get_print_type (tpi_stream, type_info, &type);
			mu_assert_streq (type, "const struct Stream", "Incorrect modifier print type");
			free (type);
		} else if (type->tpi_idx == 0x1003) {
			mu_assert_eq (type_info->leaf_type, eLF_UNION, "Incorrect data type");
			char *name;
			type_info->get_name (tpi_stream, type_info, &name);
			mu_assert_streq (name, "R2_TEST_UNION", "wrong union name");
			RList *members;
			type_info->get_members (tpi_stream, type_info, &members);
			mu_assert_eq (members->length, 2, "wrong union member count");
		} else if (type->tpi_idx == 0x100B) {
			mu_assert_eq (type_info->leaf_type, eLF_CLASS, "Incorrect data type");
			char *name;
			type_info->get_name (tpi_stream, type_info, &name);
			mu_assert_streq (name, "TEST_CLASS", "wrong class name");
			RList *members = NULL;
			type_info->get_members (tpi_stream, type_info, &members);
			mu_assert_notnull (members, "no members");
			mu_assert_eq (members->length, 2, "wrong class member count");
			SType *stype = NULL;
			int result = type_info->get_vshape (tpi_stream, type_info, (void **)&stype);
			mu_assert_eq (result || stype, 0, "wrong class vshape");
			result = type_info->get_derived (tpi_stream, type_info, (void **)&stype);
			mu_assert_eq (result || stype, 0, "wrong class derived");
		} else if (type->tpi_idx == 0x1062) {
			mu_assert_eq (type_info->leaf_type, eLF_BITFIELD, "Incorrect data type");
			SType *base_type = NULL;
			type_info->get_base_type (tpi_stream, type_info, (void **)&base_type);
			char *type;
			type_info->get_print_type (tpi_stream, type_info, &type);
			mu_assert_streq (type, "bitfield uint32_t : 1", "Incorrect bitfield print type");
			free (type);
			tpi_free_simple_type (base_type);
		} else if (type->tpi_idx == 0x1258) {
			mu_assert_eq (type_info->leaf_type, eLF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->tpi_idx == 0x107A) {
			mu_assert_eq (type_info->leaf_type, eLF_MFUNCTION, "Incorrect data type");
			SType *ret_type;
			type_info->get_return_type (tpi_stream, type_info, (void **)&ret_type);
			mu_assert_eq (ret_type->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = ret_type->type_data.type_info;
			mu_assert_eq (simple_type->simple_type, eT_BOOL08, "Incorrect return type");
			mu_assert_eq (simple_type->size, 1, "Incorrect return type");
			mu_assert_streq (simple_type->type, "_Bool", "Incorrect return type");
			tpi_free_simple_type (ret_type);
			SType *type;
			type_info->get_class_type (tpi_stream, type_info, (void **)&type);
			mu_assert_eq (type->tpi_idx, 0x1079, "incorrect mfunction class type");
			type_info->get_this_type (tpi_stream, type_info, (void **)&type);
			mu_assert_null (type, "incorrect mfunction this type");
			type_info->get_arglist (tpi_stream, type_info, (void **)&type);
			mu_assert_eq (type->tpi_idx, 0x1027, "incorrect mfunction arglist");
		} else if (type->tpi_idx == 0x113F) {
			mu_assert_eq (type_info->leaf_type, eLF_FIELDLIST, "Incorrect data type");
			RList *members = NULL;
			type_info->get_members (tpi_stream, &type->type_data, &members);
			mu_assert_eq (members->length, 2725, "Incorrect members length");
			RListIter *it = r_list_iterator (members);
			int i = 0;
			while (r_list_iter_next (it)) {
				STypeInfo *type_info = (STypeInfo *)r_list_iter_get (it);
				mu_assert_eq (type_info->leaf_type, eLF_ENUMERATE, "Incorrect data type");
				if (i == 0) {
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "CV_ALLREG_ERR", "Wrong enum name");
					int value = 0;
					type_info->get_val (tpi_stream, type_info, &value);
					mu_assert_eq (value, 30000, "Wrong enumerate value");
				}
				if (i == 2724) {
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "CV_AMD64_YMM15D3", "Wrong enum name");
					int value = 0;
					type_info->get_val (tpi_stream, type_info, &value);
					mu_assert_eq (value, 687, "Wrong enumerate value");
				}
				i++;
			}
		} else if (type->tpi_idx == 0x1231) {
			mu_assert_eq (type_info->leaf_type, eLF_ARGLIST, "Incorrect data type");
		} else if (type->tpi_idx == 0x101A) {
			mu_assert_eq (type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			char *name;
			int is_forward_ref;
			type_info->get_name (tpi_stream, &type->type_data, &name);
			mu_assert_streq (name, "threadlocaleinfostruct", "Wrong name");
			type_info->is_fwdref (tpi_stream, &type->type_data, &is_forward_ref);
			mu_assert_eq (is_forward_ref, false, "Wrong is_fwdref");
			RList *members = NULL;
			type_info->get_members (tpi_stream, &type->type_data, &members);
			mu_assert_eq (members->length, 18, "Incorrect members count");
			RListIter *it = r_list_iterator (members);
			int i = 0;
			while (r_list_iter_next (it)) {
				STypeInfo *type_info = (STypeInfo *)r_list_iter_get (it);
				if (i == 0) {
					mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "refcount", "Wrong member name");
					char *type;
					type_info->get_print_type (tpi_stream, type_info, &type);
					mu_assert_streq (type, "int32_t", "Wrong member type");
					free (type);
				}
				if (i == 1) {
					mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "lc_codepage", "Wrong member name");
					char *type;
					type_info->get_print_type (tpi_stream, type_info, &type);
					mu_assert_streq (type, "uint32_t", "Wrong member type");
					free (type);
				}
				if (i == 17) {
					mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "locale_name", "Wrong method name");
					char *type;
					type_info->get_print_type (tpi_stream, type_info, &type);
					mu_assert_streq (type, "wchar_t *[24]", "Wrong method type");
					free (type);
				}
				i++;
			}
		}
	};
	pdb.finish_pdb_parse (&pdb);
	mu_end;
}

bool test_pdb_tpi_rust(void) {
	RBinPdb pdb = {0};
	mu_assert_true (pdb_info ("bins/pdb/ghidra_rust_pdb_bug.pdb", &pdb), "pdb parsing failed");

	RList *plist = pdb.pdb_streams;
	mu_assert_notnull (plist, "PDB streams is NULL");

	mu_assert_eq (pdb.root_stream->num_streams, 88, "Incorrect number of streams");

	STpiStream *tpi_stream = r_list_get_n (plist, ePDB_STREAM_TPI);
	mu_assert_notnull (tpi_stream, "TPIs stream not found in current PDB");
	mu_assert_eq (tpi_stream->header.hdr_size + tpi_stream->header.follow_size, 305632, "Wrong TPI size");
	mu_assert_eq (tpi_stream->header.idx_begin, 0x1000, "Wrong beginning index");

	// tpi_stream->header.
	mu_assert_eq (tpi_stream->types->length, 4031, "Incorrect number of types");
	RListIter *it = r_list_iterator (tpi_stream->types);
	SType *type;
	while (r_list_iter_next (it)) {
		type = r_list_iter_get (it);
		STypeInfo *type_info = &type->type_data;
		if (type->tpi_idx == 0x101B) {
			mu_assert_eq (type_info->leaf_type, eLF_PROCEDURE, "Incorrect data type");
			SType *arglist;
			type_info->get_arglist (tpi_stream, type_info, (void **)&arglist);
			mu_assert_eq (arglist->tpi_idx, 0x101A, "Wrong type index");
			SType *return_type;
			type_info->get_return_type (tpi_stream, type_info, (void **)&return_type);
			mu_assert_eq (return_type->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = return_type->type_data.type_info;
			mu_assert_eq (simple_type->size, 4, "Incorrect return type");
			mu_assert_streq (simple_type->type, "int32_t", "Incorrect return type");
			tpi_free_simple_type (return_type);
		} else if (type->tpi_idx == 0x1163) {
			mu_assert_eq (type_info->leaf_type, eLF_POINTER, "Incorrect data type");
			char *type;
			type_info->get_print_type (tpi_stream, type_info, &type);
			mu_assert_streq (type, "struct core::fmt::Void*", "Wrong pointer print type");
			free (type);
		} else if (type->tpi_idx == 0x1005) {
			mu_assert_eq (type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			int forward_ref = 0;
			type->type_data.is_fwdref (tpi_stream, type_info, &forward_ref);
			mu_assert_eq (forward_ref, 1, "Wrong fwdref");
		} else if (type->tpi_idx == 0x114A) {
			mu_assert_eq (type_info->leaf_type, eLF_ARRAY, "Incorrect data type");
			SType *dump;

			type_info->get_index_type (tpi_stream, type_info, (void **)&dump);
			mu_assert_eq (dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = dump->type_data.type_info;
			mu_assert_eq (simple_type->simple_type, eT_UQUAD, "Incorrect return type");
			mu_assert_eq (simple_type->size, 8, "Incorrect return type");
			mu_assert_streq (simple_type->type, "uint64_t", "Incorrect return type");
			tpi_free_simple_type (dump);
			type_info->get_element_type (tpi_stream, type_info, (void **)&dump);

			mu_assert_eq (dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			simple_type = dump->type_data.type_info;
			mu_assert_eq (simple_type->simple_type, eT_UCHAR, "Incorrect return type");
			mu_assert_eq (simple_type->size, 1, "Incorrect return type");
			mu_assert_streq (simple_type->type, "uint8_t", "Incorrect return type");
			tpi_free_simple_type (dump);

			int size;
			type_info->get_val (tpi_stream, type_info, &size);
			mu_assert_eq (size, 16, "Wrong array size");
		} else if (type->tpi_idx == 0x1FB4) {
			mu_assert_eq (type_info->leaf_type, eLF_ENUM, "Incorrect data type");
			SType *dump;
			RList *members;
			char *name;
			type_info->get_name (tpi_stream, type_info, &name);
			mu_assert_streq (name, "ISA_AVAILABILITY", "wrong enum name");
			type_info->get_utype (tpi_stream, type_info, (void **)&dump);
			mu_assert_eq (dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = dump->type_data.type_info;
			mu_assert_eq (simple_type->simple_type, eT_INT4, "Incorrect return type");
			mu_assert_eq (simple_type->size, 4, "Incorrect return type");
			mu_assert_streq (simple_type->type, "int32_t", "Incorrect return type");
			tpi_free_simple_type (dump);
			type_info->get_members (tpi_stream, type_info, &members);
			mu_assert_eq (members->length, 10, "wrong enum members length");
		} else if (type->tpi_idx == 0x1E31) {
			mu_assert_eq (type_info->leaf_type, eLF_VTSHAPE, "Incorrect data type");
		} else if (type->tpi_idx == 0x1FB7) {
			mu_assert_eq (type_info->leaf_type, eLF_MODIFIER, "Incorrect data type");
			SType *stype = NULL;
			type_info->get_modified_type (tpi_stream, type_info, (void **)&stype);
			mu_assert_eq (stype->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect modified type");
			tpi_free_simple_type (stype);
			char *type;
			type_info->get_print_type (tpi_stream, type_info, &type);
			mu_assert_streq (type, "const volatile uint64_t", "Incorrect modifier print type");
			free (type);
		// } else if (type->tpi_idx == 0x1F4E) { This whole thing isn't parsed correctly for some reason TODO
		// 	mu_assert_eq (type_info->leaf_type, eLF_UNION, "Incorrect data type");
		// 	char *name;
		// 	type_info->get_name (tpi_stream, type_info, &name);
		// 	mu_assert_streq (name, "_SLIST_HEADER", "wrong union name");
		// 	RList *members;
		// 	type_info->get_members (tpi_stream, type_info, &members);
		// 	mu_assert_eq (members->length, 3, "wrong union member count");
		// 	// mu_assert_eq (members->length, 4, "wrong union member count"); // Doesn't work, missing one (last) member for some reason TODO
		// 	int size = 0;
		// 	type_info->get_val (tpi_stream, type_info, &size);
		// 	// mu_assert_eq (size, 48, " Wrong union size"); // parse wrong should be 48, is 16
		// 	mu_assert_eq (size, 16, " Wrong union size");
		} else if (type->tpi_idx == 0x1EA9) {
			mu_assert_eq (type_info->leaf_type, eLF_CLASS, "Incorrect data type");
			char *name;
			type_info->get_name (tpi_stream, type_info, &name);
			mu_assert_streq (name, "std::bad_typeid", "wrong class name");
			RList *members;
			type_info->get_members (tpi_stream, type_info, &members);
			// mu_assert_eq (members->length, 7, "wrong class member count"); // These members (fieldlist) isn't properly parsed?
			SType *stype = NULL;
			int result = type_info->get_vshape (tpi_stream, type_info, (void **)&stype);
			mu_assert_eq (result || stype, 1, "wrong class vshape");
			result = type_info->get_derived (tpi_stream, type_info, (void **)&stype);
			mu_assert_eq (result || stype, 0, "wrong class derived");
		} else if (type->tpi_idx == 0x1F50) {
			mu_assert_eq (type_info->leaf_type, eLF_BITFIELD, "Incorrect data type");
			SType *base_type = NULL;
			type_info->get_base_type (tpi_stream, type_info, (void **)&base_type);
			char *type;
			type_info->get_print_type (tpi_stream, type_info, &type);
			mu_assert_streq (type, "bitfield uint64_t : 48", "Incorrect bitfield print type");
			free (type);
			tpi_free_simple_type (base_type);
		} else if (type->tpi_idx == 0x1E27) {
			mu_assert_eq (type_info->leaf_type, eLF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->tpi_idx == 0x181C) {
			mu_assert_eq (type_info->leaf_type, eLF_MFUNCTION, "Incorrect data type");
			SType *ret_type;
			type_info->get_return_type (tpi_stream, type_info, (void **)&ret_type);
			mu_assert_eq (ret_type->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = ret_type->type_data.type_info;
			mu_assert_eq (simple_type->simple_type, eT_VOID, "Incorrect return type");
			mu_assert_eq (simple_type->size, 0, "Incorrect return type");
			mu_assert_streq (simple_type->type, "void", "Incorrect return type");
			tpi_free_simple_type (ret_type);
			SType *type;
			type_info->get_class_type (tpi_stream, type_info, (void **)&type);
			mu_assert_eq (type->tpi_idx, 0x107F, "incorrect mfunction class type");
			type_info->get_this_type (tpi_stream, type_info, (void **)&type);
			mu_assert_null (type, "incorrect mfunction this type");
			type_info->get_arglist (tpi_stream, type_info, (void **)&type);
			mu_assert_eq (type->tpi_idx, 0x1000, "incorrect mfunction arglist");
		} else if (type->tpi_idx == 0x13BF) {
			mu_assert_eq (type_info->leaf_type, eLF_FIELDLIST, "Incorrect data type");
			// check size
			RList *members = NULL;
			type_info->get_members (tpi_stream, &type->type_data, &members);
			mu_assert_eq (members->length, 3, "Incorrect members length");
			RListIter *it = r_list_iterator (members);
			int i = 0;
			while (r_list_iter_next (it)) {
				STypeInfo *type_info = (STypeInfo *)r_list_iter_get (it);
				mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
				if (i == 0) {
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "RUST$ENUM$DISR", "Wrong member name");
					// get type
				}
				if (i == 2) {
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "__0", "Wrong member name");
					// get type
				}
				i++;
			}
		} else if (type->tpi_idx == 0x1164) {
			mu_assert_eq (type_info->leaf_type, eLF_ARGLIST, "Incorrect data type");
		} else if (type->tpi_idx == 0x1058) {
			mu_assert_eq (type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			char *name;
			type_info->get_name (tpi_stream, &type->type_data, &name);
			mu_assert_streq (name, "std::thread::local::fast::Key<core::cell::Cell<core::option::Option<core::ptr::non_null::NonNull<core::task::wake::Context>>>>", "Wrong name");

			int is_forward_ref;
			type_info->is_fwdref (tpi_stream, &type->type_data, &is_forward_ref);
			mu_assert_eq (is_forward_ref, false, "Wrong is_fwdref");

			int size = 0;
			type_info->get_val (tpi_stream, type_info, &size);
			mu_assert_eq (size, 24, "Wrong struct size");

			RList *members = NULL;
			type_info->get_members (tpi_stream, &type->type_data, &members);
			mu_assert_eq (members->length, 2, "Incorrect members count");

			RListIter *it = r_list_iterator (members);
			int i = 0;
			while (r_list_iter_next (it)) {
				STypeInfo *type_info = (STypeInfo *)r_list_iter_get (it);
				if (i == 0) {
					mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "inner", "Wrong member name");
					// todo add type idx
				}
				if (i == 1) {
					mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name (tpi_stream, type_info, &name);
					mu_assert_streq (name, "dtor_state", "Wrong member name");
				}
				i++;
			}
		}
	};
	pdb.finish_pdb_parse (&pdb);
	mu_end;
}

bool test_pdb_type_save(void) {
	RBinPdb pdb = {0};
	RAnal *anal = r_anal_new ();
	mu_assert_true (pdb_info_save_types (anal, "bins/pdb/Project1.pdb", &pdb), "pdb parsing failed");
	check_kv ("R2_TEST_ENUM", "enum");
	check_kv ("enum.R2_TEST_ENUM", "eENUM1_R2,eENUM2_R2,eENUM_R2_MAX");
	check_kv ("enum.R2_TEST_ENUM.0x10", "eENUM1_R2");
	check_kv ("enum.R2_TEST_ENUM.eENUM1_R2", "0x10");

	check_kv ("R2_TEST_UNION", "union");
	check_kv ("union.R2_TEST_UNION", "r2_union_var_1,r2_union_var_2");
	check_kv ("union.R2_TEST_UNION.r2_union_var_1", "int32_t,0,0");
	check_kv ("union.R2_TEST_UNION.r2_union_var_2", "double,0,0");

	check_kv ("__m64", "union");
	check_kv ("union.__m64", "m64_u64,m64_f32,m64_i8,m64_i16,m64_i32,m64_i64,m64_u8,m64_u16,m64_u32");
	check_kv ("union.__m64.m64_u64", "uint64_t,0,0");
	check_kv ("union.__m64.m64_f32", "float[8],0,0");
	check_kv ("union.__m64.m64_i8", "char[8],0,0");
	check_kv ("union.__m64.m64_i16", "int16_t[8],0,0");
	check_kv ("union.__m64.m64_i32", "int32_t[8],0,0");
	check_kv ("union.__m64.m64_i64", "int64_t,0,0");
	check_kv ("union.__m64.m64_u8", "uint8_t[8],0,0");
	check_kv ("union.__m64.m64_u16", "uint16_t[8],0,0");
	check_kv ("union.__m64.m64_u32", "uint32_t[8],0,0");

	check_kv ("TEST_CLASS", "struct");
	check_kv ("struct.TEST_CLASS", "class_var1,calss_var2");
	check_kv ("struct.TEST_CLASS.class_var1", "int32_t,0,0");
	check_kv ("struct.TEST_CLASS.calss_var2", "int16_t,4,0");

	check_kv ("localeinfo_struct", "struct");
	check_kv ("struct.localeinfo_struct", "locinfo,mbcinfo");
	check_kv ("struct.localeinfo_struct.locinfo", "struct threadlocaleinfostruct*,0,0");
	check_kv ("struct.localeinfo_struct.mbcinfo", "struct threadmbcinfostruct*,4,0");
	r_anal_free (anal);
	mu_end;
}

bool test_pdb_enum_modified_utype(void) {
	RBinPdb pdb = {0};
	RAnal *anal = r_anal_new ();
	mu_assert_true (pdb_info_save_types (anal, "bins/pdb/issue_12924.pdb", &pdb), "pdb parsing failed");
	check_kv ("tagCOINITBASE", "enum");
	check_kv ("enum.tagCOINITBASE", "COINITBASE_MULTITHREADED");
	check_kv ("enum.tagCOINITBASE.COINITBASE_MULTITHREADED", "0x0");
	check_kv ("enum.tagCOINITBASE.0x0", "COINITBASE_MULTITHREADED");
	r_anal_free (anal);
	mu_end;
}

bool test_pdb_stream_file_size(void) {
	R_STREAM_FILE stream = {0};
	stream.page_size = 4096;
	stream.end = 10000;

	// At start of stream
	stream.pos = 0;
	mu_assert_eq (stream_file_get_size (&stream), 10000, "size at pos 0");

	// Intra-first-page
	stream.pos = 500;
	mu_assert_eq (stream_file_get_size (&stream), 9500, "size at pos 500");

	// Multi-page offset (pos = 4196 on 4096-byte pages)
	// Pre-patch bug: subtracted only (pos % page_size) = 100, returning 9900 (+4096 bytes)
	stream.pos = 4196;
	mu_assert_eq (stream_file_get_size (&stream), 5804, "size past page boundary");

	// High page offset
	stream.pos = 9000;
	mu_assert_eq (stream_file_get_size (&stream), 1000, "size at pos 9000");

	// At EOF
	// Pre-patch bug: 10000 % 4096 = 1808, returning 8192 instead of 0
	stream.pos = 10000;
	mu_assert_eq (stream_file_get_size (&stream), 0, "size at EOF");

	// Past EOF
	stream.pos = 10001;
	mu_assert_eq (stream_file_get_size (&stream), 0, "size past EOF");

	// Stream with error flag set
	stream.pos = 0;
	stream.error = 1;
	mu_assert_eq (stream_file_get_size (&stream), 0, "size with error set");

	// Negative position
	stream.error = 0;
	stream.pos = -1;
	mu_assert_eq (stream_file_get_size (&stream), 0, "size with negative pos");

	// NULL stream
	mu_assert_eq (stream_file_get_size (NULL), 0, "size with NULL stream");

	mu_end;
}

bool test_pdb_page_bounds(void) {
	const struct {
		ut32 offset, value, size;
		bool valid;
	} cases[] = {
		{ 52, 1, 3072, true },
		{ 44, 3073, 3072, false },
		{ 44, 3, 3072, false },
		{ 52, 6, 3072, false },
		{ 52, UT32_MAX, 3072, false },
		{ 52, 1, 1023, false },
		{ 52, 5, 3071, false },
		{ 1028, 0x80000000, 3072, false },
		{ 1028, UT32_MAX - 1, 3072, false },
		{ 1028, UT32_MAX, 3072, true },
		{ 1028, 0, 3072, true },
		{ 1028, 3073, 3072, false },
		{ 1028, 1024, 3072, false },
		{ 1032, 6, 3072, false },
		{ 1032, UT32_MAX, 3072, false },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		ut8 data[3072] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
		r_write_le32 (data + 32, 512);
		r_write_le32 (data + 40, 6);
		r_write_le32 (data + 44, 12);
		r_write_le32 (data + 52, 1);
		r_write_le32 (data + 512, 2);
		r_write_le32 (data + 2560, 2);
		r_write_le32 (data + 1024, 1);
		r_write_le32 (data + 1028, 4);
		r_write_le32 (data + 1032, 3);
		r_write_le32 (data + cases[i].offset, cases[i].value);
		RBinPdb pdb = {0};
		mu_assert_true (r_bin_pdb_parser_with_buf (&pdb, r_buf_new_with_bytes (data, cases[i].size)), "PDB header");
		bool parsed = pdb.pdb_parse (&pdb);
		pdb.finish_pdb_parse (&pdb);
		mu_assert_eq (parsed, cases[i].valid, "PDB page bounds");
	}
	mu_end;
}

static bool pdb_info_tpi(RBinPdb *pdb, const char *records, ut32 count, ut32 continuation) {
	ut8 data[3072] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
	if (strlen (records) > 2 * (512 - 56)) {
		return false;
	}
	int size = r_hex_str2bin (records, data + 2560 + 56);
	if (size < 0) {
		return false;
	}
	r_write_le32 (data + 32, 512);
	r_write_le32 (data + 40, 6);
	r_write_le32 (data + 44, 28);
	r_write_le32 (data + 52, 1);
	r_write_le32 (data + 512, 2);
	r_write_le32 (data + 1024, 3);
	r_write_le32 (data + 1028, 4);
	r_write_le32 (data + 1032, 32);
	r_write_le32 (data + 1036, 56 + size);
	r_write_le32 (data + 1040, 3);
	r_write_le32 (data + 1044, 4);
	r_write_le32 (data + 1048, 5);
	r_write_le32 (data + 2560, 20040203);
	r_write_le32 (data + 2564, 56);
	r_write_le32 (data + 2568, 0x1000);
	r_write_le32 (data + 2572, 0x1000 + count);
	r_write_le32 (data + 2576, size);
	if (continuation != UT32_MAX) {
		r_write_le32 (data + 2560 + 56 + 20, continuation);
	}
	return r_bin_pdb_parser_with_buf (pdb, r_buf_new_with_bytes (data, sizeof (data)))
		&& pdb->pdb_parse (pdb);
}

bool test_pdb_fieldlist_continuation(void) {
	const char *records =
		"160003120d15030074000000000061000414000001100000"
		"0e0003120d1503007400000004006200"
		"1a000515020000000010000000000000000000000800436861696e00";
	const ut32 indices[] = { 0x1001, 0x1000, 0x1002, 0x1999, 0x74, 0 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (indices); i++) {
		RBinPdb pdb = {0};
		mu_assert_true (pdb_info_tpi (&pdb, records, 3, indices[i]), "parse chained field list");
		STpiStream *ss = r_list_get_n (pdb.pdb_streams, ePDB_STREAM_TPI);
		mu_assert_notnull (ss, "TPI stream present");
		SType *type = r_list_get_n (ss->types, 2);
		RList *members = NULL;
		type->type_data.get_members (ss, &type->type_data, &members);
		mu_assert_eq (r_list_length (members), i? 1: 2, "continuation members or bounded invalid link");
		RList *cached = NULL;
		type->type_data.get_members (ss, &type->type_data, &cached);
		mu_assert_ptreq (members, cached, "member list is cached");
		char *format = pdb.print_types (&pdb, NULL, 'r');
		mu_assert_streq (format, i? "": "pf.Chain n4n4 a b \n", "complete layouts only");
		free (format);
		if (!i) {
			RAnal *anal = r_anal_new ();
			r_parse_pdb_types (anal, &pdb);
			check_kv ("struct.Chain.b", "int32_t,4,0");
			r_anal_free (anal);
		}
		pdb.finish_pdb_parse (&pdb);
	}
	mu_end;
}

bool test_pdb_fieldlist_invalid_continuation(void) {
	const char *records[] = {
		"160003120d15030074000000000061000414000001100000"
		"160003120d15030074000000040062000414000000100000"
		"1a000515020000000010000000000000000000000800436861696e00",
		"120003120d150300740000000000610004140000"
		"0e0003120d1503007400000004006200"
		"1a000515020000000010000000000000000000000800436861696e00"
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (records); i++) {
		RBinPdb pdb = {0};
		mu_assert_true (pdb_info_tpi (&pdb, records[i], 3, UT32_MAX), "parse cyclic or truncated continuation");
		STpiStream *ss = r_list_get_n (pdb.pdb_streams, ePDB_STREAM_TPI);
		mu_assert_notnull (ss, "TPI stream present");
		SType *type = r_list_get_n (ss->types, 2);
		RList *members = NULL;
		type->type_data.get_members (ss, &type->type_data, &members);
		mu_assert_eq (r_list_length (members), i? 1: 2, "do not duplicate members on a cycle");
		char *format = pdb.print_types (&pdb, NULL, 'r');
		mu_assert_streq (format, "", "incomplete field list has no format");
		free (format);
		pdb.finish_pdb_parse (&pdb);
	}
	mu_end;
}

bool test_pdb_base_class_layout(void) {
	const char *records =
		"160003120d15030074000000000061000414000001100000"
		"0e0003120d1503007400000004006200"
		"1a000515020000000010000000000000000000000800436861696e00"
		"1e00031200140300021000000000f2f10d15030074000000040076616c756500"
		"1e0005150200000003100000000000000000000008004465726976656400f2f1";
	RBinPdb pdb = {0};
	mu_assert_true (pdb_info_tpi (&pdb, records, 5, 0x1001), "parse base class and member");
	char *listing = pdb.print_types (&pdb, NULL, 'd');
	mu_assert_notnull (strstr (listing, "int32_t value; // offset +0x4"), "retain recorded member offset");
	free (listing);
	char *format = pdb.print_types (&pdb, NULL, 'r');
	mu_assert_null (strstr (format, "pf.Derived"), "do not format skipped base as offset zero");
	mu_assert_notnull (strstr (format, "pf.Chain"), "representable format retained");
	free (format);
	pdb.finish_pdb_parse (&pdb);
	mu_end;
}

bool test_pdb_duplicate_thunks(void) {
	size_t size;
	ut8 *data = (ut8 *)r_file_slurp ("bins/pdb/Project1.pdb", &size);
	mu_assert_notnull (data, "read thunk fixture");
	mu_assert_true (size >= 0x1f164, "thunk records fit in fixture");
	ut8 *first = data + 0x1f13c;
	ut8 *second = data + 0x1f150;
	mu_assert_eq (r_read_le16 (first + 2), PDB_S_TRAMPOLINE, "first trampoline record");
	mu_assert_eq (r_read_le16 (second + 2), PDB_S_TRAMPOLINE, "second trampoline record");
	r_write_le32 (second + 12, r_read_le32 (first + 12));
	r_write_le16 (second + 18, r_read_le16 (first + 18));
	RBuffer *buf = r_buf_new_with_bytes (data, size);
	free (data);
	RBinPdb pdb = {0};
	mu_assert_true (r_bin_pdb_parser_with_buf (&pdb, buf), "open modified thunk fixture");
	mu_assert_true (pdb.pdb_parse (&pdb), "parse duplicate thunks");
	char *script = pdb.print_gvars (&pdb, 0, NULL, 'r');
	mu_assert_notnull (strstr (script, "'@0x11005'f j.pdb.__setdefaultprecision\n"), "first thunk flag");
	mu_assert_notnull (strstr (script, "'@0x1100a'f j.pdb.__setdefaultprecision_1100a\n"), "unique second thunk flag");
	mu_assert_notnull (strstr (script, "'@0x1100a'afia+ thunk\n"), "native thunk attribute");
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 32);
	RIODesc *file = r_core_file_open (core, "malloc://0x20000", R_PERM_RWX, 0);
	mu_assert_notnull (file, "open thunk code");
	mu_assert_notnull (r_io_map_add (core->io, file->fd, R_PERM_RWX, 0, 0, 0x20000), "map thunk code");
	r_core_cmd0 (core, "wx c3 @ 0x12f10");
	r_core_cmd0 (core, "wx e9061f0000e9011f0000 @ 0x11005");
	r_core_cmd0 (core, "wx e920fcffff @ 0x113e0");
	r_core_cmd_lines (core, script);
	free (script);
	RFlagItem *flag = r_flag_get (core->flags, "j.pdb.__setdefaultprecision");
	mu_assert_notnull (flag, "first flag survives replay");
	mu_assert_eq (flag->addr, 0x11005, "first flag does not move");
	RAnalFunction *caller = r_anal_get_function_at (core->anal, 0x113e0);
	mu_assert_notnull (caller, "tail caller analyzed");
	mu_assert_eq (RVecAnalBlockPtr_length (&caller->bbs), 1, "tail call does not absorb thunk");
	mu_assert_eq (r_anal_function_realsize (caller), 5, "tail caller size");
	RAnalFunction *thunk = r_anal_get_function_at (core->anal, 0x1100a);
	mu_assert_notnull (thunk, "duplicate thunk analyzed");
	mu_assert_true (thunk->attrs & R_ANAL_FCN_ATTR_THUNK, "native thunk attribute retained");
	mu_assert_true (r_config_get_b (core->config, "anal.nopskip"), "PDB analysis restores nopskip");
	r_core_free (core);
	pdb.finish_pdb_parse (&pdb);
	mu_end;
}

bool all_tests(void) {
#if R_SYS_ENDIAN == 0
	mu_run_test (test_pdb_tpi_cpp);
	mu_run_test (test_pdb_guid_age);
	mu_run_test (test_pdb_tpi_rust);
	mu_run_test (test_pdb_type_save);
	mu_run_test (test_pdb_enum_modified_utype);
	mu_run_test (test_pdb_stream_file_size);
	mu_run_test (test_pdb_page_bounds);
	mu_run_test (test_pdb_fieldlist_continuation);
	mu_run_test (test_pdb_fieldlist_invalid_continuation);
	mu_run_test (test_pdb_base_class_layout);
	mu_run_test (test_pdb_duplicate_thunks);
#endif
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
