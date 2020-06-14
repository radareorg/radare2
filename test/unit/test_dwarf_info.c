#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_bin_dwarf.h>

#define MODE 2

bool test_dwarf3_c(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = {0};
	bool res = r_bin_open (bin, "bins/elf/dwarf3_c.elf", &opt);
	mu_assert ("dwarf3_c.elf binary could not be opened", res);

	RBinDwarfDebugAbbrev *da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_eq (da->length, 7, "Incorrect number of abbreviation");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (da, bin, MODE);

	mu_assert_eq (info->length, 1, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit cu = info->comp_units[0];
	RBinDwarfCompUnitHdr hdr =  cu.hdr;
	mu_assert_eq (hdr.version, 3, "Wrong header information");
	mu_assert_eq (hdr.length, 0xa9, "Wrong header information");
	mu_assert_eq (hdr.is_64bit, false, "Wrong header information");
	mu_assert_eq (hdr.address_size, 8, "Wrong header information");
	mu_assert_eq (hdr.abbrev_offset, 0x0, "Wrong header information");

	// check some of the attributes
	mu_assert_eq (cu.length, 10, "Wrong attribute information");
	mu_assert_eq (cu.offset, 0x0, "Wrong attribute information");

	mu_assert_eq (cu.dies[0].abbrev_code, 1, "Wrong attribute information");
	mu_assert_eq (cu.dies[0].length, 7, "Wrong attribute information");
	mu_assert_eq (cu.dies[0].tag, DW_TAG_compile_unit, "Wrong attribute information");
	mu_assert_eq (cu.dies[0].attr_values[0].attr_name, DW_AT_producer, "Wrong attribute information");
	mu_assert_streq(cu.dies[0].attr_values[2].string.content, "main.c", "Wrong attribute information");

	mu_assert_eq (cu.dies[1].abbrev_code, 2, "Wrong attribute information");
	mu_assert_eq (cu.dies[2].abbrev_code, 3, "Wrong attribute information");
	mu_assert_eq (cu.dies[3].abbrev_code, 4, "Wrong attribute information");
	mu_assert_eq (cu.dies[4].abbrev_code, 5, "Wrong attribute information");
	mu_assert_eq (cu.dies[5].abbrev_code, 0, "Wrong attribute information");
	mu_assert_eq (cu.dies[6].abbrev_code, 6, "Wrong attribute information");
	mu_assert_eq (cu.dies[7].abbrev_code, 7, "Wrong attribute information");
	mu_assert_streq(cu.dies[7].attr_values[0].string.content, "b", "Wrong attribute information");
	mu_assert_eq(cu.dies[7].attr_values[3].data, 15, "Wrong attribute information");
	mu_assert_eq (cu.dies[8].abbrev_code, 7, "Wrong attribute information");
	mu_assert_eq (cu.dies[9].abbrev_code, 0, "Wrong attribute information");
	mu_assert_eq (cu.dies[10].abbrev_code, 0, "Wrong attribute information");

	r_bin_dwarf_free_debug_info(info);
	r_bin_dwarf_free_debug_abbrev(da);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}


bool all_tests() {
	mu_run_test(test_dwarf3_c);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
