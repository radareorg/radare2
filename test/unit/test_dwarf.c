#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_core.h>
#include <r_bin_dwarf.h>

#define MODE 2

bool test_c_dwarf3(void) {
	RCore *core = r_core_new ();
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf3", &opt);
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
	mu_assert ("Incorrect abbreviation", da->decls[0].tag == DW_TAG_compile_unit);
	mu_assert ("Incorrect abbreviation", da->decls[1].tag == DW_TAG_variable);
	mu_assert ("Incorrect abbreviation", da->decls[2].tag == DW_TAG_base_type);
	mu_assert ("Incorrect abbreviation", da->decls[3].tag == DW_TAG_subprogram);
	mu_assert ("Incorrect abbreviation", da->decls[4].tag == DW_TAG_variable);
	mu_assert ("Incorrect abbreviation", da->decls[5].tag == DW_TAG_subprogram);
	mu_assert ("Incorrect abbreviation", da->decls[6].tag == DW_TAG_variable);

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
