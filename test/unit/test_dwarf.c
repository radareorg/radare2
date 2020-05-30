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
	return (left->address > right->address) ? 1 : 0;
}
/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C binary
 */
bool test_basic_c_dwarf3(void) { // this should work for dwarf2 aswell
	RCore *core = r_core_new ();
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "/home/hound/r2test/dwarf/c/dwarf3", &opt);
	mu_assert ("couldn't open dwarf3", res);

	// this is probably ugly, but I didn't know how to
	// tell core  what bin to open so I did it myself
	r_bin_free (core->bin);
	core->bin = bin;

	RBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = r_bin_dwarf_parse_abbrev (core->bin, MODE);
	mu_assert ("Incorrect number of abbreviation", da->length == 7);

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

	line_list = r_bin_dwarf_parse_line (core->bin, MODE);
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
	r_core_free (core);
	mu_end;
}

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C++ binary
 * 
 * 
 * 
 * 
 */
bool test_basic_cpp_dwarf3(void) { // this should work for dwarf2 aswell
	RCore *core = r_core_new ();
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "/home/hound/r2test/dwarf/cpp/dwarf3", &opt);
	mu_assert ("couldn't open dwarf3", res);

	// this is probably ugly, but I didn't know how to
	// tell core  what bin to open so I did it myself
	r_bin_free (core->bin);
	core->bin = bin;

	RBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = r_bin_dwarf_parse_abbrev (core->bin, MODE);
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

	line_list = r_bin_dwarf_parse_line (core->bin, MODE);
	mu_assert_eq (line_list->length, 61, "Amount of line information parse doesn't match");

	RBinDwarfRow *row;
	RListIter *iter;

	// sort it so it can be more consistently tested?
	// we could also sort it in the `id` output like readelf does
	r_list_sort (line_list, row_comparator);

	const int test_addresses[] = {
		0x11ee,
		0x11fa,
		0x1208,
		0x120b,
		0x120c,
		0x1218,
		0x1226,
		0x1229,
		0x122a,
		0x123a,
		0x1259,
		0x125a,
		0x1266,
		0x126b,
		0x126d,
		0x126e,
		0x127e,
		0x128f,
		0x1298,
		0x129b,
		0x129c,
		0x12ac,
		0x12bd,
		0x12c6,
		0x12c9,
		0x12ca,
		0x12da,
		0x12f9,
		0x12fa,
		0x1306,
		0x130b,
		0x130e,
		0x131a,
		0x1328,
		0x132b,
		0x132c,
		0x1338,
		0x1346,
		0x1349,
		0x134a,
		0x135a,
		0x1379,
		0x137a,
		0x1386,
		0x138b,
		0x138d,
		0x1169,
		0x1176,
		0x118b,
		0x118f,
		0x11a4,
		0x11a8,
		0x11af,
		0x11bd,
		0x11c6,
		0x11c9,
		0x11d7,
		0x11e0,
		0x11e3,
		0x11e6,
		0x11ed,
	};

	i = 0;

	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_io_free (io);
	r_core_free (core);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_basic_c_dwarf3);
	mu_run_test (test_basic_cpp_dwarf3);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
