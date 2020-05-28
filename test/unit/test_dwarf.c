#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_core.h>
#include <r_bin_dwarf.h>

#define MODE 2

// RListComparator should return -1, 0, 1 to indicate "a<b", "a==b", "a>b".
int row_comparator(const void *a, const void *b){
	const RBinDwarfRow *left = a;
	const RBinDwarfRow *right = b;
	return (left->address > right->address) ? 1 : 0;
}

bool test_c_dwarf3(void) {
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
	// printf("\n");
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
		// printf("%s\t", row->file);
		// printf("0x%llx\t", row->address);
		// printf("%u\t", row->line); // use proper formatters
		// printf("%u\n", row->column);
		mu_assert_eq (row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	r_io_free (io);
	r_core_free (core);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_c_dwarf3);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
