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
	bool res = r_bin_open (bin, "bins/elf/dwarf3_c.elf", &opt);
	mu_assert ("couldn't open file", res);

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
		mu_assert_eq (da->decls[0].has_children, 1, "Incorrect children flag");
		// specs length is 8, because we don't parse
		// DW_AT value: 0     DW_FORM value: 0
		// so we have just 7 attrs below
		mu_assert_eq (da->decls[0].length, 8, "Incorrect number of attributes");
		{
			int i = 0;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_producer, "Incorrect children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_strp, "Incorrect children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_language, "Incorrect children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_data1, "Incorrect children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_name, "Incorrect children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_strp, "Incorrect children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_comp_dir, "Incorrect children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_strp, "Incorrect children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_low_pc, "Incorrect children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_addr, "Incorrect children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_high_pc, "Incorrect children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_addr, "Incorrect children flag");
			i++;
			mu_assert_eq (da->decls[0].specs[i].attr_name, DW_AT_stmt_list, "Incorrect children flag");
			mu_assert_eq (da->decls[0].specs[i].attr_form, DW_FORM_data4, "Incorrect children flag");
		}
	}
	mu_assert_eq (da->decls[1].tag, DW_TAG_variable, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[1].has_children, 0, "Incorrect children flag");
		mu_assert_eq (da->decls[1].length, 8, "Incorrect number of attributes");
	}
	mu_assert_eq (da->decls[2].tag, DW_TAG_base_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[2].has_children, 0, "Incorrect children flag");
		mu_assert_eq (da->decls[2].length, 4, "Incorrect number of attributes");
	}
	mu_assert_eq (da->decls[3].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[3].has_children, 1, "Incorrect children flag");
		mu_assert_eq (da->decls[3].length, 12, "Incorrect number of attributes");
	}
	mu_assert_eq (da->decls[4].tag, DW_TAG_variable, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[4].has_children, 0, "Incorrect children flag");
		mu_assert_eq (da->decls[4].length, 7, "Incorrect number of attributes");
	}
	mu_assert_eq (da->decls[5].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[5].has_children, 1, "Incorrect children flag");
		mu_assert_eq (da->decls[5].length, 10, "Incorrect number of attributes");
	}
	mu_assert_eq (da->decls[6].tag, DW_TAG_variable, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[6].has_children, 0, "Incorrect children flag");
		mu_assert_eq (da->decls[6].length, 6, "Incorrect number of attributes");
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
	bool res = r_bin_open (bin, "bins/elf/dwarf3_cpp.elf", &opt);
	mu_assert ("couldn't open file", res);

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
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");

		// specs length is 9, but we don't parse it all, unparsed stuff is commented out
		mu_assert_eq (da->decls[i].length, 9, "Incorrect number of attributes");
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_producer, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_language, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_name, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_comp_dir, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorrect children flag");
			j++;
			/// [xxx] `id` is not printing this
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_ranges, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data4, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_low_pc, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_addr, "Incorrect children flag");
			j++;
			/// [xxx] `id` is not printing this
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_entry_pc, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_addr, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_stmt_list, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data4, "Incorrect children flag");

			// mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT value: 0, "Incorrect children flag");
			// mu_assert_eq (da->decls[i].specs[j].attr_form, DW_AT value: 0, "Incorrect children flag");
		}
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_structure_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorrect number of attributes");
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_name, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_byte_size, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_file, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_line, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_column, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_containing_type, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_sibling, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorrect children flag");

			// mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT value: 0, "Incorrect children flag");
			// mu_assert_eq (da->decls[i].specs[j].attr_form, DW_AT value: 0, "Incorrect children flag");
		}
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 2, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_member, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 5, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 10, "Incorrect number of attributes");
	}
	i++;

	// 8
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 12, "Incorrect number of attributes");
		{
			/**
			 *  Everything commented out is something that is missing from being parsed by Radare
			 */
			int j = 0;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_external, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_flag, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_name, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_file, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_line, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_decl_column, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			/** 
				 * "DW_AT_MIPS_linkage_name which is used by gcc and g++ to record the external linker symbol for a subprogram.
				 * This is a vendor extension that's been in use for a very long time and shared by multiple vendors."
				 * - not standardized, was purposed but didn't pass
				 */
			// mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_MIPS_linkage_name, "Incorrect children flag");
			// mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_strp, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_virtuality, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_data1, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_containing_type, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_declaration, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_flag, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_object_pointer, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorrect children flag");
			j++;
			mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT_sibling, "Incorrect children flag");
			mu_assert_eq (da->decls[i].specs[j].attr_form, DW_FORM_ref4, "Incorrect children flag");

			// mu_assert_eq (da->decls[i].specs[j].attr_name, DW_AT value: 0, "Incorrect children flag");
			// mu_assert_eq (da->decls[i].specs[j].attr_form, DW_AT value: 0, "Incorrect children flag");
		}
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 13, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_const_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 2, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_pointer_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_reference_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subroutine_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_unspecified_parameters, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 1, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_base_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 4, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_pointer_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 4, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_structure_type, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_inheritance, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 10, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 13, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 12, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_variable, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 7, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_variable, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 7, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 5, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 5, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 4, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 9, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_formal_parameter, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, false, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 3, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 9, "Incorrect number of attributes");
	}
	i++;
	mu_assert_eq (da->decls[i].tag, DW_TAG_subprogram, "Incorrect abbreviation");
	{
		mu_assert_eq (da->decls[i].has_children, true, "Incorrect children flag");
		mu_assert_eq (da->decls[i].length, 8, "Incorrect number of attributes");
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
	qsort (test_addresses, 60, sizeof (int), int_compare);
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
	bool res = r_bin_open (bin, "bins/elf/dwarf3_many_comp_units.elf", &opt);
	mu_assert ("couldn't open file", res);

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

	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_io_free (io);
	mu_end;
}

bool test_dwarf_cpp_empty_line_info(void) { // this should work for dwarf2 aswell
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/pe/hello_world_not_stripped.exe", &opt);
	mu_assert ("couldn't open file", res);

	RBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = r_bin_dwarf_parse_abbrev (bin, MODE);
	// not ignoring null entries -> 755 abbrevs
	mu_assert_eq (da->length, 731, "Incorrect number of abbreviation");

	// r_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// r_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RList *line_list = NULL;

	line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (line_list->length, 771, "Amount of line information parse doesn't match");

	RBinDwarfRow *row;
	RListIter *iter;

	// sort it so it can be more consistently tested?
	r_list_sort (line_list, row_comparator);

	const int test_addresses[] = {
		0x00401000,
		0x00401010,
		0x00401013,
		0x00401015,
		0x0040101e,
		0x00401028,
		0x00401032,
		0x0040103c,
		0x00401046,
		0x00401048,
		0x0040104e,
		0x00401058,
		0x0040105e,
		0x00401060,
		0x00401065,
		0x0040106e,
		0x0040107a,
		0x00401086,
		0x0040108c,
		0x00401091,
		0x00401096,
		0x0040109d,
		0x004010a2,
	};

	int i = 0;

	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
		if (i == 23)
			break;
	}

	r_io_free (io);
	mu_end;
}

bool test_dwarf2_cpp_many_comp_units(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf2_many_comp_units.elf", &opt);
	mu_assert ("couldn't open file", res);

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
	mu_assert_eq (da->decls[41].length, 4, "Wrong abbrev length");
	mu_assert_eq (da->decls[41].has_children, false, "Wrong abbrev children");
	mu_assert_eq (da->decls[41].code, 18, "Wrong abbrev code");

	RList *line_list = NULL;

	line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (line_list->length, 64, "Amount of line information parse doesn't match");

	RBinDwarfRow *row;
	RListIter *iter;

	r_list_sort (line_list, row_comparator);

	const int test_addresses[] = {
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

	int i = 0;
	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	// add line information check
	r_io_free (io);
	mu_end;
}

bool test_dwarf4_cpp_many_comp_units(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert ("couldn't open file", res);

	RBinDwarfDebugAbbrev *da = NULL;
	// TODO add abbrev checks

	RList *line_list = NULL;

	line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (line_list->length, 75, "Amount of line information parse doesn't match");

	RBinDwarfRow *row;
	RListIter *iter;

	r_list_sort (line_list, row_comparator);

	const int test_addresses[] = {
		0x00401160,
		0x00401174,
		0x0040117f,
		0x00401194,
		0x00401198,
		0x004011a1,
		0x004011ac,
		0x004011c1,
		0x004011c5,
		0x004011c9,
		0x004011d0,
		0x004011d4,
		0x004011dd,
		0x004011e3,
		0x004011e7,
		0x004011f0,
		0x004011f6,
		0x004011fc,
		0x00401204,
		0x00401206,
		0x0040120e,
		0x00401219,
		0x00401223,
		0x0040122e,
		0x00401233,
		0x0040123c,
		0x00401240,
		0x0040125c,
		0x0040125f,
		0x00401261,
		0x00401270,
		0x00401280,
		0x00401283,
		0x004012a3,
		0x004012a6,
		0x004012ac,
		0x004012b0,
		0x004012b8,
		0x004012ba,
		0x004012c0,
		0x004012d0,
		0x004012e8,
		0x004012ee,
		0x004012f0,
		0x004012f8,
		0x004012ff,
		0x00401300,
		0x0040131c,
		0x0040131f,
		0x00401321,
		0x00401330,
		0x00401340,
		0x00401348,
		0x0040134e,
		0x00401350,
		0x00401360,
		0x00401378,
		0x0040137e,
		0x00401380,
		0x00401388,
		0x0040138f,
		0x00401390,
		0x00401398,
		0x004013a0,
		0x004013b0,
		0x004013c8,
		0x004013d0,
		0x004013d8,
		0x004013e0,
		0x004013e8,
		0x004013f1,
		0x004013f7,
		0x00401400,
		0x00401408,
		0x0040140f,
	};

	int i = 0;
	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_io_free (io);
	mu_end;
}


bool all_tests() {
	// TODO add tests for debug_info section and abbreviations for DWARF4,5
	// after merging debug_info parsing PR
	// right now we test abbreviations + line_information
	mu_run_test (test_dwarf_cpp_empty_line_info);
	mu_run_test (test_dwarf2_cpp_many_comp_units);
	mu_run_test (test_dwarf3_c_basic);
	mu_run_test (test_dwarf3_cpp_basic);
	mu_run_test (test_dwarf3_cpp_many_comp_units);
	mu_run_test (test_dwarf4_cpp_many_comp_units);
	// mu_run_test (test_dwarf5_cpp_many_comp_units); // TODO, implement these for debug_line
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
