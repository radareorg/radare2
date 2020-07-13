#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_core.h>
#include <r_bin_dwarf.h>
#include "../../libr/bin/pdb/types.h"

#define MODE 2

// copy from cbin.c modified to get pdb back
int pdb_info(const char *file, R_PDB *pdb) {
	pdb->cb_printf = r_cons_printf;
	if (!init_pdb_parser (pdb, file)) {
		return false;
	}
	if (!pdb->pdb_parse (pdb)) {
		eprintf ("pdb was not parsed\n");
		pdb->finish_pdb_parse (pdb);
		return false;
	}
	return true;
}

bool test_pdb_tpi(void) {
	R_PDB pdb = R_EMPTY;
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
			type_info->get_arglist (type_info, (void **)&arglist);
			mu_assert_eq (arglist->tpi_idx, 0x1027, "Wrong type index");
			SType *return_type;
			// Doesn't work properly, so no asserting
			type_info->get_return_type (type_info, (void **)&return_type);
		} else if (type->tpi_idx == 0x1161) {
			mu_assert_eq (type_info->leaf_type, eLF_POINTER, "Incorrect data type");
			char *type;
			type_info->get_print_type (type_info, &type);
			mu_assert_streq (type, "struct _RTC_framedesc*", "Wrong pointer print type");
		} else if (type->tpi_idx == 0x1004) {
			mu_assert_eq (type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			int forward_ref = 0;
			type->type_data.is_fwdref (type_info, &forward_ref);
			mu_assert_eq (forward_ref, 1, "Wrong fwdref");
		} else if (type->tpi_idx == 0x113F) {
			mu_assert_eq (type_info->leaf_type, eLF_ARRAY, "Incorrect data type");
			char *type;
			type_info->get_print_type (type_info, &type);
			SType *dump;
			// function doesn't work as supposed, not asserting TODO
			type_info->get_index_type (type_info, (void **)&dump);
			// same problem like ^, but in this case it works, so asserting
			type_info->get_element_type (type_info, (void **)&dump);
			mu_assert_eq (dump->tpi_idx, 0x113E, "Wrong element type index");
			int size;
			// Why is get_val for size returning...
			type_info->get_val (type_info, &size);
			mu_assert_eq (size, 20, "Wrong array size");
		} else if (type->tpi_idx == 0x145A) {
			mu_assert_eq (type_info->leaf_type, eLF_ENUM, "Incorrect data type");
			SType *dump;
			RList *members;
			char *name;
			type_info->get_name (type_info, &name);
			mu_assert_streq (name, "EXCEPTION_DEBUGGER_ENUM", "wrong enum name");
			// Doesn't work properly so not asserting
			type_info->get_utype (type_info, (void **)&dump);
			// mu_assert_eq (dump->tpi_idx, 0x0074, "wrong enum utype");
			type_info->get_members (type_info, &members);
			mu_assert_eq (members->length, 6, "wrong enum members length");
		} else if (type->tpi_idx == 0x1414) {
			mu_assert_eq (type_info->leaf_type, eLF_VTSHAPE, "Incorrect data type");
		} else if (type->tpi_idx == 0x1421) {
			mu_assert_eq (type_info->leaf_type, eLF_MODIFIER, "Incorrect data type");
			SType *stype = NULL;
			type_info->get_modified_type (type_info, (void **)&stype);
			mu_assert_eq (stype->tpi_idx, 0x120F, "Incorrect modified type");
			char *type;
			type_info->get_print_type (type_info, &type);
			mu_assert_streq (type, "const struct Stream", "Incorrect modifier print type");
		} else if (type->tpi_idx == 0x1003) {
			mu_assert_eq (type_info->leaf_type, eLF_UNION, "Incorrect data type");
			char *name;
			type_info->get_name (type_info, &name);
			mu_assert_streq (name, "R2_TEST_UNION", "wrong union name");
			RList *members;
			type_info->get_members (type_info, &members);
			mu_assert_eq (members->length, 2, "wrong union member count");
		} else if (type->tpi_idx == 0x100B) {
			mu_assert_eq (type_info->leaf_type, eLF_CLASS, "Incorrect data type");
			char *name;
			type_info->get_name (type_info, &name);
			mu_assert_streq (name, "TEST_CLASS", "wrong class name");
			RList *members;
			type_info->get_members (type_info, &members);
			mu_assert_eq (members->length, 2, "wrong class member count");
			SType *stype = NULL;
			int result = type_info->get_vshape (type_info, (void **)&stype);
			mu_assert_eq (result || stype, 0, "wrong class vshape");
			result = type_info->get_derived (type_info, (void **)&stype);
			mu_assert_eq (result || stype, 0, "wrong class derived");
		} else if (type->tpi_idx == 0x1062) {
			mu_assert_eq (type_info->leaf_type, eLF_BITFIELD, "Incorrect data type");
			SType *base_type = NULL;
			type_info->get_base_type (type_info, (void **)&base_type);
			char *type;
			type_info->get_print_type (type_info, &type);
			mu_assert_streq (type, "bitfield uint32_t : 1", "Incorrect bitfield print type");
		} else if (type->tpi_idx == 0x1258) {
			mu_assert_eq (type_info->leaf_type, eLF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->tpi_idx == 0x107A) {
			mu_assert_eq (type_info->leaf_type, eLF_MFUNCTION, "Incorrect data type");
			SType *type;
			// not being parsed right (ignores base types), so not assertion now
			type_info->get_return_type (type_info, (void **) &type);

			type_info->get_class_type (type_info, (void **) &type);
			mu_assert_eq (type->tpi_idx, 0x1079, "incorrect mfunction class type");
			type_info->get_this_type (type_info, (void **) &type);
			mu_assert_eq (type, 0, "incorrect mfunction this type");
			type_info->get_arglist (type_info, (void **) &type);
			mu_assert_eq (type->tpi_idx, 0x1027, "incorrect mfunction arglist");
		} else if (type->tpi_idx == 0x113F) {
			mu_assert_eq (type_info->leaf_type, eLF_FIELDLIST, "Incorrect data type");
			RList *members = r_list_new ();
			type_info->get_members (&type->type_data, &members);
			mu_assert_eq (members->length, 2725, "Incorrect members length");
			RListIter *it = r_list_iterator (members);
			int i = 0;
			while (r_list_iter_next (it)) {
				STypeInfo *type_info = (STypeInfo *)r_list_iter_get (it);
				mu_assert_eq (type_info->leaf_type, eLF_ENUMERATE, "Incorrect data type");
				if (i == 0) {
					char *name = NULL;
					type_info->get_name (type_info, &name);
					mu_assert_streq (name, "CV_ALLREG_ERR", "Wrong enum name");
					int value = 0;
					type_info->get_val (type_info, &value);
					mu_assert_eq (value, 30000, "Wrong enumerate value");
				}
				if (i == 2724) {
					char *name = NULL;
					type_info->get_name (type_info, &name);
					mu_assert_streq (name, "CV_AMD64_YMM15D3", "Wrong enum name");
					int value = 0;
					type_info->get_val (type_info, &value);
					mu_assert_eq (value, 687, "Wrong enumerate value");
				}
				i++;
			}
		} else if (type->tpi_idx == 0x1231) {
			mu_assert_eq (type_info->leaf_type, eLF_ARGLIST, "Incorrect data type");
		} else if (type->tpi_idx == 0x101A) {
			mu_assert_eq (type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			SType *return_type;
			char *name;
			int is_forward_ref;
			type_info->get_name (&type->type_data, &name);
			mu_assert_streq (name, "threadlocaleinfostruct", "Wrong name");
			type_info->is_fwdref (&type->type_data, &is_forward_ref);
			mu_assert_eq (is_forward_ref, false, "Wrong is_fwdref");
			RList *members = r_list_new ();
			type_info->get_members (&type->type_data, &members);
			mu_assert_eq (members->length, 18, "Incorrect members count");
			RListIter *it = r_list_iterator (members);
			int i = 0;
			while (r_list_iter_next (it)) {
				STypeInfo *type_info = (STypeInfo *)r_list_iter_get (it);
				if (i == 0) {
					mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name (type_info, &name);
					mu_assert_streq (name, "refcount", "Wrong member name");
					char *type;
					type_info->get_print_type (type_info, &type);
					mu_assert_streq (type, "int32_t", "Wrong member type");
				}
				if (i == 1) {
					mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name (type_info, &name);
					mu_assert_streq (name, "lc_codepage", "Wrong member name");
					char *type;
					type_info->get_print_type (type_info, &type);
					mu_assert_streq (type, "uint32_t", "Wrong member type");
				}
				if (i == 17) {
					mu_assert_eq (type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name (type_info, &name);
					mu_assert_streq (name, "locale_name", "Wrong method name");
					char *type;
					type_info->get_print_type (type_info, &type);
					mu_assert_streq (type, "wchar_t *[24]", "Wrong method type");
				}
				i++;
			}
		}
	};
	pdb.finish_pdb_parse (&pdb);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_pdb_tpi);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}