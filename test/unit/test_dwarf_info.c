#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_bin_dwarf.h>

#define MODE 2

bool test_dwarf3_c(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf3_c.elf", &opt);
	mu_assert ("dwarf3_c.elf binary could not be opened", res);

	RBinDwarfDebugAbbrev *da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_eq (da->length, 7, "Incorrect number of abbreviation");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (da, bin, MODE);

	mu_assert_eq (info->length, 1, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit cu = info->comp_units[0];
	RBinDwarfCompUnitHdr hdr = cu.hdr;
	mu_assert_eq (hdr.version, 3, "Wrong header information");
	mu_assert_eq (hdr.length, 0xa9, "Wrong header information");
	mu_assert_eq (hdr.is_64bit, false, "Wrong header information");
	mu_assert_eq (hdr.address_size, 8, "Wrong header information");
	mu_assert_eq (hdr.abbrev_offset, 0x0, "Wrong header information");

	// check some of the attributes
	mu_assert_eq (cu.length, 11, "Wrong attribute information");
	mu_assert_eq (cu.offset, 0x0, "Wrong attribute information");
	int i = 0;
	mu_assert_eq (cu.dies[i].abbrev_code, 1, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 7, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_compile_unit, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].attr_name, DW_AT_producer, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[2].string.content, "main.c", "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 2, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 3, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 4, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 5, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 6, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 7, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[0].string.content, "b", "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[3].data, 15, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 7, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");

	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

bool test_dwarf4_cpp_multiple_modules(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert ("dwarf4_many_comp_units.elf binary could not be opened", res);

	RBinDwarfDebugAbbrev *da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_eq (da->length, 37, "Incorrect number of abbreviation");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (da, bin, MODE);
	mu_assert_notnull(info, "Failed parsing of debug_info");
	mu_assert_eq (info->length, 2, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit cu = info->comp_units[0];
	RBinDwarfCompUnitHdr hdr = cu.hdr;
	mu_assert_eq (hdr.version, 4, "Wrong header information");
	mu_assert_eq (hdr.length, 0x2c0, "Wrong header information");
	mu_assert_eq (hdr.is_64bit, false, "Wrong header information");
	mu_assert_eq (hdr.address_size, 8, "Wrong header information");
	mu_assert_eq (hdr.abbrev_offset, 0x0, "Wrong header information");

	// check some of the attributes
	mu_assert_eq (cu.length, 73, "Wrong attribute information");
	mu_assert_eq (cu.offset, 0x0, "Wrong attribute information");

	int i = 0;
	mu_assert_eq (cu.dies[i].abbrev_code, 1, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 7, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_compile_unit, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].attr_name, DW_AT_producer, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[2].string.content, "../main.cpp", "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[6].attr_name, DW_AT_ranges, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[6].reference, 0x0, "Wrong attribute information");

	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 2, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 3, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 3, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 3, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	// i == 6
	mu_assert_eq (cu.dies[i].abbrev_code, 4, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].reference, 0x6e, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[1].data, 4, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[2].string.content, "Bird", "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[3].data, 8, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[4].data, 1, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[5].data, 9, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 5, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_member, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[0].string.content, "_vptr$Bird", "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[1].reference, 0xc5, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[2].data, 0, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[3].flag, true, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 6, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 7, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 8, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 7, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 9, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_subprogram, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 10, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[0].string.content, "_ZN4Bird3flyEv", "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[1].string.content, "fly", "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[2].data, 1, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[3].data, 12, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[4].reference, 0xd8, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[6].attr_name, DW_AT_vtable_elem_location, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[7].flag, true, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[7].attr_form, DW_FORM_flag_present	, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[8].attr_name, DW_AT_external, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[8].flag, true, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[9].attr_name, DW_AT_containing_type, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[9].reference, 0x6e, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 7, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 10, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 11, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 12, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 13, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_base_type, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 3, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 10, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 14, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 15, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 4, "Wrong attribute information");
	i = 66;
	mu_assert_eq (cu.dies[i].abbrev_code, 18, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 5, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[3].reference, 0x2a7, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 15, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 4, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].block.length, 2, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].block.data[0], 0x91, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].block.data[1], 0x78, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[1].string.content, "this", "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[2].reference, 0x2be, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[3].flag, true, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 10, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 10, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_pointer_type, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 10, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;

	cu = info->comp_units[1];
	hdr = cu.hdr;
	mu_assert_eq (hdr.version, 4, "Wrong header information");
	mu_assert_eq (hdr.length, 0x192, "Wrong header information");
	mu_assert_eq (hdr.is_64bit, false, "Wrong header information");
	mu_assert_eq (hdr.address_size, 8, "Wrong header information");
	mu_assert_eq (hdr.abbrev_offset, 0xfd, "Wrong header information");

	// check some of the attributes
	mu_assert_eq (cu.length, 42, "Wrong attribute information");
	mu_assert_eq (cu.offset, 0x2c4, "Wrong attribute information");

	i = 0;

	mu_assert_eq (cu.dies[i].abbrev_code, 1, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 7, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_compile_unit, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].attr_name, DW_AT_producer, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[0].string.content, "clang version 10.0.0-4ubuntu1 ", "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[1].data, 33, "Wrong attribute information");
	mu_assert_streq (cu.dies[i].attr_values[2].string.content, "../mammal.cpp", "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[5].address, 0x0, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[5].attr_form, DW_FORM_addr, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[6].attr_name, DW_AT_ranges, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[6].reference, 0xb0, "Wrong attribute information");
	
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 2, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 3, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 4, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 5, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 6, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 5, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i = 35;
	mu_assert_eq (cu.dies[i].abbrev_code, 8, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_pointer_type, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 1, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].attr_form, DW_FORM_ref4, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[0].reference, 0x407, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 19, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].tag, DW_TAG_subprogram, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].length, 5, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[2].attr_name, DW_AT_frame_base, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[2].block.length, 1, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[2].block.data[0], 0x56, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[3].reference, 0x442, "Wrong attribute information");
	mu_assert_eq (cu.dies[i].attr_values[4].reference, 0x410, "Wrong attribute information");
	i=40;
	mu_assert_eq (cu.dies[i].abbrev_code, 8, "Wrong attribute information");
	i++;
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");


	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_dwarf3_c);
	mu_run_test (test_dwarf4_cpp_multiple_modules);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
