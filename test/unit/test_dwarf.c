#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_core.h>
#include <r_bin_dwarf.h>

#define MODE 2

// RListComparator should return -1, 0, 1 to indicate "a<b", "a==b", "a>b".
/**
 * @brief Comparator to sort list of line statements by address(collection of DwarfRows)
 */
int row_comparator(const void *a, const void *b){
	const RBinDwarfRow *left = a;
	const RBinDwarfRow *right = b;

	return (left->address >= right->address) ? 1 : -1;
}

int int_compare(const void *a, const void *b){
	const int *left = a;
	const int *right = b;
	return (*left >= *right) ? 1 : -1;
}

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C binary
 */
bool test_dwarf3_c_basic(void) { // this should work for dwarf2 aswell
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "/home/hound/r2test/dwarf/c/dwarf3", &opt);
	mu_assert ("couldn't open dwarf3", res);

	RBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_eq (da->length, 7, "Incorrect number of abbreviation");

	// order matters
	// I nest scopes to make it more readable, (hopefully)
	mu_assert_eq (da->decls[0].tag, DW_TAG_compile_unit, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[0].has_children, 1, "Incorret children flag");
		// specs length is 8, because we don't parse  
		// DW_AT value: 0     DW_FORM value: 0
		// so we have just 7 attrs below
		mu_assert_eq (da->decls[0].length, 8, "Incorret number of attributes");
		{
			int i = 0;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_producer, "Incorret children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_strp, "Incorret children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_language, "Incorret children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_data1, "Incorret children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_name, "Incorret children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_strp, "Incorret children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_comp_dir, "Incorret children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_strp, "Incorret children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_low_pc, "Incorret children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_addr, "Incorret children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_high_pc, "Incorret children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_addr, "Incorret children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_stmt_list, "Incorret children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_data4, "Incorret children flag");
		}
	}
	mu_assert_eq (da->decls[1].tag, DW_TAG_variable,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[1].has_children, 0, "Incorret children flag");
		mu_assert_eq (da->decls[1].length, 8, "Incorret number of attributes");
	}
	mu_assert_eq (da->decls[2].tag, DW_TAG_base_type,  "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[2].has_children, 0, "Incorret children flag");
		mu_assert_eq (da->decls[2].length, 4, "Incorret number of attributes");
	}
	mu_assert_eq (da->decls[3].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[3].has_children, 1, "Incorret children flag");
		mu_assert_eq (da->decls[3].length, 12, "Incorret number of attributes");
	}
	mu_assert_eq (da->decls[4].tag, DW_TAG_variable,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[4].has_children, 0, "Incorret children flag");
		mu_assert_eq (da->decls[4].length, 7, "Incorret number of attributes");
	}
	mu_assert_eq (da->decls[5].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[5].has_children, 1, "Incorret children flag");
		mu_assert_eq (da->decls[5].length, 10, "Incorret number of attributes");
	}
	mu_assert_eq (da->decls[6].tag, DW_TAG_variable,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[6].has_children, 0, "Incorret children flag");
		mu_assert_eq (da->decls[6].length, 6, "Incorret number of attributes");
	}

	// r_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// r_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RList *line_list = NULL;

	line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (line_list->length, 8, "Amount of line information parse doesn't match");

	RBinDwarfRow *row;
	RListIter *iter;

	// sort it so it can be more consistently tested?
	// we could also sort it in the `id` output like readelf does
	r_list_sort (line_list, row_comparator);

	const int test_addresses[] = {
		0x1129,
		0x1131,
		0x1134,
		0x1140,
		0x114a,
		0x1151,
		0x1154,
		0x1156
	};

	int i = 0;

	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_io_free (io);
	mu_end;
}

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C++ binary
 * 
 * 
 * 
 * 
 */
bool test_dwarf3_cpp_basic(void) { // this should work for dwarf2 aswell
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "/home/hound/r2test/dwarf/cpp/dwarf3", &opt);
	mu_assert ("couldn't open dwarf3", res);

	// this is probably ugly, but I didn't know how to
	// tell core  what bin to open so I did it myself

	RBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert ("Incorrect number of abbreviation", da->length == 32);

	// order matters
	// I nest scopes to make it more readable, (hopefully)
	int i = 0;
	mu_assert_eq (da->decls[i].tag, DW_TAG_compile_unit, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");

		// specs length is 9, but we don't parse it all, unparsed stuff is commented out
		mu_assert_eq (da->decls[i].length, 9, "Incorret number of attributes");
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_producer, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_language, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_name, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_comp_dir, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorret children flag");
			j++;
			/// [xxx] `id` is not printing this
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_ranges, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data4, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_low_pc, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_addr, "Incorret children flag");
			j++;
			/// [xxx] `id` is not printing this
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_entry_pc, "Incorret children flag"); 
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_addr, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_stmt_list, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data4, "Incorret children flag");

			// mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT value: 0, "Incorret children flag");
			// mu_assert_eq (da->decls[i].specs[j].attr_form, DW_AT value: 0, "Incorret children flag");
		}
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_structure_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorret number of attributes");
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_name, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_byte_size, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_file, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_line, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_column, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_containing_type, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_sibling, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorret children flag");

			// mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT value: 0, "Incorret children flag");
			// mu_assert_eq (da->decls[i].specs[j].attr_form, DW_AT value: 0, "Incorret children flag");
		}
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,  "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 2, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_member, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 5, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 10, "Incorret number of attributes");
	}
	i++;

	// 8
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 12, "Incorret number of attributes");
		{
			/**
			 *  Everything commented out is something that is missing from being parsed by Radare
			 */
			int j = 0;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_external, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_flag, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_name, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_file, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_line, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_column, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
				/** 
				 * "DW_AT_MIPS_linkage_name which is used by gcc and g++ to record the external linker symbol for a subprogram.
				 * This is a vendor extension that's been in use for a very long time and shared by multiple vendors."
				 * - not standardized, was purposed but didn't pass
				 */
			// mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_MIPS_linkage_name, "Incorret children flag");
			// mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_virtuality, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_containing_type, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_declaration, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_flag, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_object_pointer, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorret children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_sibling, "Incorret children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorret children flag");

			// mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT value: 0, "Incorret children flag");
			// mu_assert_eq (da->decls[i].specs[j].attr_form, DW_AT value: 0, "Incorret children flag");
		}
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 13, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_const_type,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 2, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_pointer_type,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_reference_type,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subroutine_type,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_unspecified_parameters,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 1, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_base_type,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 4, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_pointer_type,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 4, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_structure_type,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_inheritance,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 10, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 13, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 12, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_variable,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 7, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_variable,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 7, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 5, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 5, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 4, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 9, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 9, "Incorret number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram,   "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorret children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorret number of attributes");
	}


	// r_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// r_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RList *line_list = NULL;

	line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (line_list->length, 60, "Amount of line information parse doesn't match");

	RBinDwarfRow *row;
	RListIter *iter;

	// sort it so it can be more consistently tested?
	// we could also sort it in the `id` output like readelf does
	r_list_sort (line_list, row_comparator);

	int test_addresses[] = {
		0x000011ee,
		0x000011fa,
		0x00001208,
		0x0000120b,
		0x0000120c,
		0x00001218,
		0x00001226,
		0x00001229,
		0x0000122a,
		0x0000123a,
		0x00001259,
		0x0000125a,
		0x00001266,
		0x0000126b,
		0x0000126d,
		0x0000126e,
		0x0000127e,
		0x00001298,
		0x0000129b,
		0x0000129c,
		0x000012ac,
		0x000012c6,
		0x000012c9,
		0x000012ca,
		0x000012da,
		0x000012f9,
		0x000012fa,
		0x00001306,
		0x0000130b,
		0x0000130d,
		0x0000130e,
		0x0000131a,
		0x00001328,
		0x0000132b,
		0x0000132c,
		0x00001338,
		0x00001346,
		0x00001349,
		0x0000134a,
		0x0000135a,
		0x00001379,
		0x0000137a,
		0x00001386,
		0x0000138b,
		0x0000138d,
		0x00001169,
		0x00001176,
		0x0000118b,
		0x0000118f,
		0x000011a4,
		0x000011a8,
		0x000011af,
		0x000011bd,
		0x000011c6,
		0x000011c9,
		0x000011d7,
		0x000011e0,
		0x000011e3,
		0x000011e6,
		0x000011ed,
	};
	qsort(test_addresses, 60, sizeof(int), int_compare);
	i = 0;

	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_io_free (io);
	mu_end;
}
bool test_dwarf3_cpp_many_comp_units(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "/home/hound/r2test/dwarf/cpp/dump/a.out", &opt);
	mu_assert ("couldn't open dwarf3", res);

	RBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_eq (da->length, 58, "Incorrect number of abbreviation");

	mu_assert_eq (da->decls[18].tag, DW_TAG_formal_parameter, "Wrong abbrev TAG");
	mu_assert_eq (da->decls[18].length, 5, "Wrong abbrev length");
	mu_assert_eq (da->decls[18].has_children, false, "Wrong abbrev children");
	mu_assert_eq (da->decls[18].code, 19, "Wrong abbrev code");

	
	mu_assert_eq (da->decls[41].tag, DW_TAG_inheritance, "Wrong abbrev TAG");
	mu_assert_eq (da->decls[41].length, 3, "Wrong abbrev length");
	mu_assert_eq (da->decls[41].has_children, false, "Wrong abbrev children");
	mu_assert_eq (da->decls[41].code, 18, "Wrong abbrev code");

	// r_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// r_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RList *line_list = NULL;

	line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (line_list->length, 64, "Amount of line information parse doesn't match");

	RBinDwarfRow *row;
	RListIter *iter;

	// sort it so it can be more consistently tested?
	// we could also sort it in the `id` output like readelf does
	r_list_sort (line_list, row_comparator);

	int test_addresses[] = {
		0x0000118a,
		0x00001196,
		0x000011a4,
		0x000011a8,
		0x000011b8,
		0x000011d8,
		0x000011e4,
		0x000011e9,
		0x000011eb,
		0x000011f7,
		0x00001206,
		0x00001212,
		0x00001228,
		0x00001234,
		0x00001239,
		0x0000123b,
		0x00001248,
		0x0000125d,
		0x00001261,
		0x00001276,
		0x0000127a,
		0x00001281,
		0x0000128f,
		0x00001298,
		0x0000129b,
		0x000012a9,
		0x000012b2,
		0x000012b5,
		0x000012ba,
		0x000012bf,
		0x000012c6,
		0x000012d2,
		0x000012e0,
		0x000012e3,
		0x000012e4,
		0x000012f4,
		0x0000130e,
		0x00001311,
		0x00001312,
		0x00001322,
		0x0000133c,
		0x0000133f,
		0x00001340,
		0x00001350,
		0x0000136f,
		0x00001370,
		0x0000137c,
		0x00001381,
		0x00001383,
		0x00001384,
		0x00001390,
		0x0000139e,
		0x000013a1,
		0x000013a2,
		0x000013ae,
		0x000013bc,
		0x000013bf,
		0x000013c0,
		0x000013d0,
		0x000013ef,
		0x000013f0,
		0x000013fc,
		0x00001401,
		0x00001403,
	};
	// qsort(test_addresses, 64, sizeof(int), int_compare); // already sorted
	int i = 0;

	// printf("\n");
	r_list_foreach (line_list, iter, row) {
		// printf("0x%llx\t", row->address);
		// printf("%u\t", row->line);
		// printf("%u\n", row->column);
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_io_free (io);
	mu_end;
}

bool test_dwarf3_cpp_empty_line_info(void) { // this should work for dwarf2 aswell
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "/home/hound/Projects/radare2/test/bins/pe/hello_world_not_stripped.exe", &opt);
	mu_assert ("couldn't open file", res);

	RBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = r_bin_dwarf_parse_abbrev (bin, MODE);
	// not ignoring null entries -> 755 abbrevs
	mu_assert_eq (da->length, 731, "Incorrect number of abbreviation");

	for (int i = 0; i < da->length; i++) {
		printf("0x%llx\n", da->decls[i].offset);
		assert (da->decls[i].code != 0);
	}
	// r_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// r_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RList *line_list = NULL;

	line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (line_list->length, 113, "Amount of line information parse doesn't match");

	RBinDwarfRow *row;
	RListIter *iter;

	// sort it so it can be more consistently tested?
	// we could also sort it in the `id` output like readelf does
	r_list_sort (line_list, row_comparator);

	const int test_addresses[] = {
		0x00401014,
		0x004014f2,
		0x004014f5,
		0x004014fa,
		0x00401560,
		0x0040168f,
		0x00401693,
		0x0040169a,
		0x0040169d,
		0x0040169f,
		0x004016ab,
		0x004016af,
		0x004016b0,
		0x004016b2,
		0x004016b4,
		0x004016b6,
		0x004016b9,
		0x004016d0,
		0x004016d9,
		0x004016e0,
		0x004016ea,
		0x004016ec,
		0x004016f0,
		0x004016f6,
		0x00401700,
		0x00401703,
		0x00401710,
		0x00401717,
		0x0040171c,
		0x0040172c,
		0x00401733,
		0x0040173a,
		0x00401742,
		0x00401752,
		0x00401756,
		0x0040175a,
		0x00401762,
		0x00401768,
		0x0040176a,
		0x00401770,
		0x00401772,
		0x00401776,
		0x00401782,
		0x00401790,
		0x00401792,
		0x0040179d,
		0x004017a2,
		0x004017a8,
		0x004017b0,
		0x004017b5,
		0x004017ba,
		0x004017c0,
		0x004017c6,
		0x004017d0,
		0x004017d3,
		0x004017d6,
		0x00402570,
		0x00402572,
		0x00402574,
		0x0040257d,
		0x0040257e,
		0x00402582,
		0x0040258e,
		0x00402592,
		0x00402597,
		0x0040259d,
		0x004025a2,
		0x004025a6,
		0x004025aa,
		0x004025ae,
		0x004025b2,
		0x004025c0,
		0x004025c3,
		0x004025c7,
		0x004025ca,
		0x004025ce,
		0x004025d1,
		0x004025d4,
		0x004025d8,
		0x004025da,
		0x004025e0,
		0x004025e7,
		0x004025f0,
		0x004025f3,
		0x004025f6,
		0x004025fd,
		0x00402604,
		0x00402608,
		0x0040260b,
		0x0040260c,
		0x00402612,
		0x00402614,
		0x00402617,
		0x00402620,
		0x00402621,
		0x00402622,
		0x00402627,
		0x0040262b,
		0x0040262d,
		0x00402633,
		0x00402636,
		0x0040263b,
		0x00402640,
		0x00402642,
		0x00402644,
		0x00402647,
		0x00402648,
		0x00402649,
		0x0040264a,
		0x00402700,
		0x00402710,
		0x0040271a,
		0x0040271b,
	};

	int i = 0;

	printf("\n");
	r_list_foreach (line_list, iter, row) {
		printf("0x%llx\t", row->address);
		printf("%u\t", row->line);
		printf("%u\n", row->column);
		// mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_io_free (io);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_dwarf3_c_basic);
	mu_run_test (test_dwarf3_cpp_basic);
	mu_run_test (test_dwarf3_cpp_many_comp_units);
	mu_run_test (test_dwarf3_cpp_empty_line_info);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
