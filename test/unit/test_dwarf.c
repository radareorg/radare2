#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_core.h>
#include <r_bin_dwarf.h>

#define MODE 2

#define check_abbrev_code(expected_code) \
	mu_assert_eq (da->decls[i].code, expected_code, "Wrong abbrev code");

#define check_abbrev_tag(expected_tag) \
	mu_assert_eq (da->decls[i].tag, expected_tag, "Incorrect abbreviation tag")

#define check_abbrev_count(expected_count) \
	mu_assert_eq (da->decls[i].count, expected_count, "Incorrect abbreviation count")

#define check_abbrev_children(expected_children) \
	mu_assert_eq (da->decls[i].has_children, expected_children, "Incorrect children flag")

#define check_abbrev_attr_name(expected_name) \
	mu_assert_eq (da->decls[i].defs[j].attr_name, expected_name, "Incorrect children flag");

#define check_abbrev_attr_form(expected_form) \
	mu_assert_eq (da->decls[i].defs[j].attr_form, expected_form, "Incorrect children flag");

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
	mu_assert_eq (da->count, 7, "Incorrect number of abbreviation");

	// order matters
	// I nest scopes to make it more readable, (hopefully)
	int i = 0;
	check_abbrev_tag (DW_TAG_compile_unit);
	{
		check_abbrev_children (true);
		check_abbrev_count (8);
		{
			int j = 0;
			check_abbrev_attr_name (DW_AT_producer);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_language);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_name);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_comp_dir);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_low_pc);
			check_abbrev_attr_form (DW_FORM_addr);
			j++;
			check_abbrev_attr_name (DW_AT_high_pc);
			check_abbrev_attr_form (DW_FORM_addr);
			j++;
			check_abbrev_attr_name (DW_AT_stmt_list);
			check_abbrev_attr_form (DW_FORM_data4);
		}
	}
	i++;
	check_abbrev_tag (DW_TAG_variable);
	{
		check_abbrev_count (8);
		check_abbrev_children (false);
	}
	i++;
	check_abbrev_tag (DW_TAG_base_type);
	{
		check_abbrev_count (4);
		check_abbrev_children (false);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_count (12);
		check_abbrev_children (true);
	}
	i++;
	check_abbrev_tag (DW_TAG_variable);
	{
		check_abbrev_count (7);
		check_abbrev_children (false);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_count (10);
		check_abbrev_children (true);
	}
	i++;
	check_abbrev_tag (DW_TAG_variable);
	{
		check_abbrev_count (6);
		check_abbrev_children (false);
	}
	i++;

	RList *line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (r_list_length (line_list), 8, "Amount of line information parse doesn't match");

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
	i = 0;
	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_list_free (line_list);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
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
	mu_assert ("Incorrect number of abbreviation", da->count == 32);

	// order matters
	// I nest scopes to make it more readable, (hopefully)
	int i = 0;
	check_abbrev_tag (DW_TAG_compile_unit);
	{
		check_abbrev_children (true);
		check_abbrev_count (9);
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			check_abbrev_attr_name (DW_AT_producer);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_language);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_name);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_comp_dir);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_ranges);
			check_abbrev_attr_form (DW_FORM_data4);
			j++;
			check_abbrev_attr_name (DW_AT_low_pc);
			check_abbrev_attr_form (DW_FORM_addr);
			j++;
			check_abbrev_attr_name (DW_AT_entry_pc);
			check_abbrev_attr_form (DW_FORM_addr);
			j++;
			check_abbrev_attr_name (DW_AT_stmt_list);
			check_abbrev_attr_form (DW_FORM_data4);

			// check_abbrev_attr_name (DW_AT value: 0);
			// check_abbrev_attr_form (DW_AT value: 0);
		}
	}
	i++;
	check_abbrev_tag (DW_TAG_structure_type);
	{
		check_abbrev_children (true);
		check_abbrev_count (8);
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			check_abbrev_attr_name (DW_AT_name);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_byte_size);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_decl_file);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_decl_line);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_decl_column);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_containing_type);
			check_abbrev_attr_form (DW_FORM_ref4);
			j++;
			check_abbrev_attr_name (DW_AT_sibling);
			check_abbrev_attr_form (DW_FORM_ref4);

			// check_abbrev_attr_name (DW_AT value: 0);
			// check_abbrev_attr_form (DW_AT value: 0);
		}
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (8);
	}
	i++;
	check_abbrev_tag (DW_TAG_formal_parameter);
	{
		check_abbrev_children (false);
		check_abbrev_count (3);
	}
	i++;
	check_abbrev_tag (DW_TAG_formal_parameter);
	{
		check_abbrev_children (false);
		check_abbrev_count (2);
	}
	i++;
	check_abbrev_tag (DW_TAG_member);
	{
		check_abbrev_children (false);
		check_abbrev_count (5);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (10);
	}
	i++;

	// 8
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (12);
		{
			int j = 0;
			check_abbrev_attr_name (DW_AT_external);
			check_abbrev_attr_form (DW_FORM_flag);
			j++;
			check_abbrev_attr_name (DW_AT_name);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_decl_file);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_decl_line);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_decl_column);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			// check_abbrev_attr_name (DW_AT_MIPS_linkage_name);
			check_abbrev_attr_form (DW_FORM_strp);
			j++;
			check_abbrev_attr_name (DW_AT_virtuality);
			check_abbrev_attr_form (DW_FORM_data1);
			j++;
			check_abbrev_attr_name (DW_AT_containing_type);
			check_abbrev_attr_form (DW_FORM_ref4);
			j++;
			check_abbrev_attr_name (DW_AT_declaration);
			check_abbrev_attr_form (DW_FORM_flag);
			j++;
			check_abbrev_attr_name (DW_AT_object_pointer);
			check_abbrev_attr_form (DW_FORM_ref4);
			j++;
			check_abbrev_attr_name (DW_AT_sibling);
			check_abbrev_attr_form (DW_FORM_ref4);
		}
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (13);
	}
	i++;
	check_abbrev_tag (DW_TAG_const_type);
	{
		check_abbrev_children (false);
		check_abbrev_count (2);
	}
	i++;
	check_abbrev_tag (DW_TAG_pointer_type);
	{
		check_abbrev_children (false);
		check_abbrev_count (3);
	}
	i++;
	check_abbrev_tag (DW_TAG_reference_type);
	{
		check_abbrev_children (false);
		check_abbrev_count (3);
	}
	i++;
	check_abbrev_tag (DW_TAG_subroutine_type);
	{
		check_abbrev_children (true);
		check_abbrev_count (3);
	}
	i++;
	check_abbrev_tag (DW_TAG_unspecified_parameters);
	{
		check_abbrev_children (false);
		check_abbrev_count (1);
	}
	i++;
	check_abbrev_tag (DW_TAG_base_type);
	{
		check_abbrev_children (false);
		check_abbrev_count (4);
	}
	i++;
	check_abbrev_tag (DW_TAG_pointer_type);
	{
		check_abbrev_children (false);
		check_abbrev_count (4);
	}
	i++;
	check_abbrev_tag (DW_TAG_structure_type);
	{
		check_abbrev_children (true);
		check_abbrev_count (8);
	}
	i++;
	check_abbrev_tag (DW_TAG_inheritance);
	{
		check_abbrev_children (false);
		check_abbrev_count (3);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (8);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (10);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (13);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (12);
	}
	i++;
	check_abbrev_tag (DW_TAG_variable);
	{
		check_abbrev_children (false);
		check_abbrev_count (7);
	}
	i++;
	check_abbrev_tag (DW_TAG_variable);
	{
		check_abbrev_children (false);
		check_abbrev_count (7);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (8);
	}
	i++;
	check_abbrev_tag (DW_TAG_formal_parameter);
	{
		check_abbrev_children (false);
		check_abbrev_count (5);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (5);
	}
	i++;
	check_abbrev_tag (DW_TAG_formal_parameter);
	{
		check_abbrev_children (false);
		check_abbrev_count (4);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (9);
	}
	i++;
	check_abbrev_tag (DW_TAG_formal_parameter);
	{
		check_abbrev_children (false);
		check_abbrev_count (3);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (9);
	}
	i++;
	check_abbrev_tag (DW_TAG_subprogram);
	{
		check_abbrev_children (true);
		check_abbrev_count (8);
	}

	// r_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// r_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RList *line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (r_list_length (line_list), 60, "Amount of line information parse doesn't match");

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

	r_list_free (line_list);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
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
	mu_assert_eq (da->count, 58, "Incorrect number of abbreviation");
	int i = 18;

	check_abbrev_tag (DW_TAG_formal_parameter);
	check_abbrev_count (5);
	check_abbrev_children (false);
	check_abbrev_code (19);
	i = 41;
	check_abbrev_tag (DW_TAG_inheritance);
	check_abbrev_count (3);
	check_abbrev_children (false);
	check_abbrev_code (18);

	RList *line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (r_list_length (line_list), 64, "Amount of line information parse doesn't match");

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
	i = 0;

	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_list_free (line_list);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
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
	mu_assert_eq (da->count, 731, "Incorrect number of abbreviation");

	RList *line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (r_list_length (line_list), 771, "Amount of line information parse doesn't match");

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

	r_list_free (line_list);
	r_bin_dwarf_free_debug_abbrev (da);
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
	mu_assert_eq (da->count, 58, "Incorrect number of abbreviation");

	int i = 18;

	check_abbrev_tag (DW_TAG_formal_parameter);
	check_abbrev_count (5);
	check_abbrev_children (false);
	check_abbrev_code (19);
	i = 41;
	check_abbrev_tag (DW_TAG_inheritance);
	check_abbrev_count (4);
	check_abbrev_children (false);
	check_abbrev_code (18);

	RList *line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (r_list_length (line_list), 64, "Amount of line information parse doesn't match");

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

	i = 0;
	r_list_foreach (line_list, iter, row) {
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	// add line information check
	r_list_free (line_list);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
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

	// TODO add abbrev checks

	RList *line_list = r_bin_dwarf_parse_line (bin, MODE);
	mu_assert_eq (r_list_length (line_list), 75, "Amount of line information parse doesn't match");

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

	r_list_free (line_list);
	r_bin_free (bin);
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
