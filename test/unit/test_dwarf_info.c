#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_bin_dwarf.h>

#define MODE 2


#define check_attr_string(attr_idx, expect_string) \
	mu_assert_streq (cu.dies[i].attr_values[attr_idx].string.content, expect_string, "Wrong string attribute information")

#define check_attr_name(attr_idx, expect_name) \
	mu_assert_eq (cu.dies[i].attr_values[attr_idx].attr_name, expect_name, "Wrong attribute name")

#define check_attr_address(attr_idx, expect_addr) \
	mu_assert_eq (cu.dies[i].attr_values[attr_idx].address, expect_addr, "Wrong attribute name")

#define check_attr_form(attr_idx, expect_form) \
	mu_assert_eq (cu.dies[i].attr_values[attr_idx].attr_form, expect_form, "Wrong attribute name")
	
#define check_attr_data(attr_idx, expect_data) \
	mu_assert_eq (cu.dies[i].attr_values[attr_idx].uconstant, expect_data, "Wrong attribute data")

#define check_attr_block_length(attr_idx, expect_len) \
	mu_assert_eq (cu.dies[i].attr_values[attr_idx].block.length, expect_len, "Wrong attribute block length")

#define check_attr_block_data(attr_idx, data_idx, expect_data) \
	mu_assert_eq (cu.dies[i].attr_values[attr_idx].block.data[data_idx], expect_data, "Wrong attribute block data")

#define check_attr_reference(attr_idx, expect_ref) \
	mu_assert_eq (cu.dies[i].attr_values[attr_idx].reference, expect_ref, "Wrong attribute reference")

#define check_attr_flag(attr_idx, expect_flag) \
	mu_assert_eq (cu.dies[i].attr_values[attr_idx].flag, expect_flag, "Wrong attribute flag")

#define check_die_abbr_code(expect_code) \
	mu_assert_eq (cu.dies[i].abbrev_code, expect_code, "Wrong abbrev code")

#define check_die_length(len) \
	mu_assert_eq (cu.dies[i].count, len, "Wrong DIE length information")

#define check_die_tag(tg) \
	mu_assert_eq (cu.dies[i].tag, tg, "Wrong DIE tag")

#define check_basic_unit_header(vers, len, is64bit, addr_size, abbr_offset)                              \
	do {                                                                                             \
		mu_assert_eq (hdr.version, vers, "Wrong header version information");                    \
		mu_assert_eq (hdr.length, len, "Wrong header length information");                       \
		mu_assert_eq (hdr.is_64bit, is64bit, "Wrong header is_64bit information");               \
		mu_assert_eq (hdr.address_size, addr_size, "Wrong header address_size information");     \
		mu_assert_eq (hdr.abbrev_offset, abbr_offset, "Wrong header abbrev_offset information"); \
	} while (0)

bool test_dwarf3_c(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf3_c.elf", &opt);
	mu_assert ("dwarf3_c.elf binary could not be opened", res);

	RBinDwarfDebugAbbrev *da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_eq (da->count, 7, "Incorrect number of abbreviation");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (da, bin, MODE);
	mu_assert_eq (info->count, 1, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit cu = info->comp_units[0];
	RBinDwarfCompUnitHdr hdr = cu.hdr;

	check_basic_unit_header (3, 0xa9, false, 8, 0x0);

	mu_assert_eq (cu.count, 11, "Wrong attribute information");
	mu_assert_eq (cu.offset, 0x0, "Wrong attribute information");
	// check some of the attributes
	int i = 0;
	check_die_abbr_code (1);

	check_die_length (7);
	check_die_tag (DW_TAG_compile_unit);

	check_attr_name (0, DW_AT_producer);
	check_attr_string (2, "main.c");
	i++;
	check_die_abbr_code (2);
	i++;
	check_die_abbr_code (3);
	i++;
	check_die_abbr_code (4);
	i++;
	check_die_abbr_code (5);
	i++;
	check_die_abbr_code (0);
	i++;
	check_die_abbr_code (6);
	i++;
	check_die_abbr_code (7);

	check_attr_string (0, "b");
	check_attr_data (3, 15);

	i++;
	check_die_abbr_code (7);
	i++;
	check_die_abbr_code (0);
	i++;
	check_die_abbr_code (0);

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
	mu_assert_eq (da->count, 37, "Incorrect number of abbreviation");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (da, bin, MODE);
	mu_assert_notnull (info, "Failed parsing of debug_info");
	mu_assert_eq (info->count, 2, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit cu = info->comp_units[0];
	RBinDwarfCompUnitHdr hdr = cu.hdr;
	check_basic_unit_header (4, 0x2c0, false, 8, 0x0);

	// check some of the attributes
	mu_assert_eq (cu.count, 73, "Wrong attribute information");
	mu_assert_eq (cu.offset, 0x0, "Wrong attribute information");

	int i = 0;
	check_die_abbr_code (1);
	check_die_length (7);
	check_die_tag (DW_TAG_compile_unit);

	check_attr_name (0, DW_AT_producer);
	check_attr_string (2, "../main.cpp");
	check_attr_name (6, DW_AT_ranges);
	check_attr_reference (6, 0x0);

	i++;
	check_die_abbr_code (2);
	i++;
	check_die_abbr_code (3);
	i++;
	check_die_abbr_code (3);
	i++;
	check_die_abbr_code (3);
	i++;
	check_die_abbr_code (0);
	i++;
	// i == 6
	check_die_abbr_code (4);
	check_attr_reference (0, 0x6e);
	check_attr_data (1, 4);
	check_attr_string (2, "Bird");
	check_attr_data (3, 8);
	check_attr_data (4, 1);
	check_attr_data (5, 9);
	i++;
	check_die_abbr_code (5);
	check_die_tag (DW_TAG_member);
	check_attr_string (0, "_vptr$Bird");
	check_attr_reference (1, 0xc5);
	check_attr_data (2, 0);
	check_attr_flag (3, true);

	i++;
	check_die_abbr_code (6);
	i++;
	check_die_abbr_code (7);
	i++;
	check_die_abbr_code (0);
	i++;
	check_die_abbr_code (8);
	i++;
	check_die_abbr_code (7);
	i++;
	check_die_abbr_code (0);
	i++;
	check_die_abbr_code (9);
	check_die_tag (DW_TAG_subprogram);
	check_die_length (10);
	check_attr_string (0, "_ZN4Bird3flyEv");
	check_attr_string (1, "fly");
	check_attr_data (2, 1);
	check_attr_data (3, 12);
	check_attr_reference (4, 0xd8);
	check_attr_name (6, DW_AT_vtable_elem_location);
	check_attr_form (7, DW_FORM_flag_present);
	check_attr_flag (7, true);
	check_attr_name (8, DW_AT_external);
	check_attr_flag (8, true);
	check_attr_name (9, DW_AT_containing_type);
	check_attr_reference (9, 0x6e);
	i++;
	check_die_abbr_code (7);
	mu_assert_eq (cu.dies[i].abbrev_code, 7, "Wrong attribute information");
	i++;
	check_die_abbr_code (0);
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	check_die_abbr_code (0);
	mu_assert_eq (cu.dies[i].abbrev_code, 0, "Wrong attribute information");
	i++;
	check_die_abbr_code (10);
	mu_assert_eq (cu.dies[i].abbrev_code, 10, "Wrong attribute information");
	i++;
	check_die_abbr_code (11);
	mu_assert_eq (cu.dies[i].abbrev_code, 11, "Wrong attribute information");
	i++;
	check_die_abbr_code (12);
	mu_assert_eq (cu.dies[i].abbrev_code, 12, "Wrong attribute information");
	i++;
	check_die_abbr_code (13);
	check_die_tag (DW_TAG_base_type);
	check_die_length (3);
	i++;
	check_die_abbr_code (10);
	i++;
	check_die_abbr_code (14);
	i++;
	check_die_abbr_code (15);
	i++;
	check_die_abbr_code (0);
	i++;
	check_die_abbr_code (4);
	i = 66;
	check_die_abbr_code (18);
	check_die_length (5);
	check_attr_reference (3, 0x2a7);
	i++;
	check_die_abbr_code (15);
	check_die_length (4);
	check_attr_block_length (0, 2);
	check_attr_block_data (0, 0, 0x91);
	check_attr_block_data (0, 1, 0x78);
	check_attr_string (1, "this");
	check_attr_reference (2, 0x2be);
	check_attr_flag (3, true);
	i++;
	check_die_abbr_code (0);
	i++;
	check_die_abbr_code (10);
	i++;
	check_die_abbr_code (10);
	check_die_tag (DW_TAG_pointer_type);
	i++;
	check_die_abbr_code (10);
	i++;
	check_die_abbr_code (0);
	i++;

	cu = info->comp_units[1];
	hdr = cu.hdr;
	check_basic_unit_header (4, 0x192, false, 8, 0xfd);

	// check some of the attributes
	mu_assert_eq (cu.count, 42, "Wrong attribute information");
	mu_assert_eq (cu.offset, 0x2c4, "Wrong attribute information");

	i = 0;
	check_die_abbr_code (1);
	check_die_length (7);
	check_die_tag (DW_TAG_compile_unit);
	check_attr_name (0, DW_AT_producer);
	check_attr_string (0, "clang version 10.0.0-4ubuntu1 ");
	check_attr_data (1, 33);
	check_attr_string (2, "../mammal.cpp");
	check_attr_address (5, 0x0);
	check_attr_form (5, DW_FORM_addr);
	check_attr_name (6, DW_AT_ranges);
	check_attr_reference (6, 0xb0);
	i++;
	check_die_abbr_code (2);
	i++;
	check_die_abbr_code (3);
	i++;
	check_die_abbr_code (4);
	i++;
	check_die_abbr_code (5);
	i++;
	check_die_abbr_code (0);
	i++;
	check_die_abbr_code (6);
	i++;
	check_die_abbr_code (5);
	i++;
	check_die_abbr_code (0);
	i = 35;
	check_die_abbr_code (8);
	check_die_tag (DW_TAG_pointer_type);
	check_die_length (1);
	check_attr_form (0, DW_FORM_ref4);
	check_attr_reference (0, 0x407);
	i++;
	check_die_abbr_code (19);
	check_die_tag (DW_TAG_subprogram);
	check_die_length (5);
	check_attr_name (2, DW_AT_frame_base);
	check_attr_block_length (2, 1);
	check_attr_block_data (2, 0, 0x56);
	check_attr_reference (3, 0x442);
	check_attr_reference (4, 0x410);
	i=40;
	check_die_abbr_code (8);
	i++;
	check_die_abbr_code (0);

	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

bool test_dwarf2_big_endian(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/ppc64_sudoku_dwarf", &opt);
	mu_assert ("dwarf4_many_comp_units.elf binary could not be opened", res);

	RBinDwarfDebugAbbrev *da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_eq (da->count, 108, "Incorrect number of abbreviation");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (da, bin, MODE);
	mu_assert_notnull (info, "Failed parsing of debug_info");
	mu_assert_eq (info->count, 1, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit cu = info->comp_units[0];
	RBinDwarfCompUnitHdr hdr = cu.hdr;
	check_basic_unit_header (2, 0x38b9, false, 8, 0x0);

	int i = 0;
	check_die_abbr_code (1);
	check_die_length (7);
	check_die_tag (DW_TAG_compile_unit);

	check_attr_name (0, DW_AT_producer);
	check_attr_string (0, "GNU C++14 9.3.0 -msecure-plt -mabi=elfv2 -mcpu=970 -gdwarf-2 -gstrict-dwarf -O1");
	check_attr_name (1, DW_AT_language);
	check_attr_data (1, DW_LANG_C_plus_plus);

	check_attr_name (4, DW_AT_low_pc);
	check_attr_reference (4, 0x0000000010000ec4);
	check_attr_name (5, DW_AT_high_pc);
	check_attr_reference (5, 0x0000000010001c48);
	check_attr_name (6, DW_AT_stmt_list);
	check_attr_reference (6, 0x0);

	i+=2;
	check_die_abbr_code (3);
	check_die_tag (DW_TAG_base_type);

	check_attr_name (0, DW_AT_byte_size);
	check_attr_data (0, 0x08);

	check_attr_name (1, DW_AT_encoding);
	check_attr_data (1, DW_ATE_unsigned);

	check_attr_name (2, DW_AT_name);
	check_attr_string (2, "long unsigned int");

	i++; check_die_abbr_code (4);
	i++; check_die_abbr_code (2);
	i++; check_die_abbr_code (3);
	i++; check_die_abbr_code (2);
	i++;
	// i == 7
	check_die_abbr_code (5);
	check_die_tag (DW_TAG_structure_type);

	check_attr_name (0, DW_AT_name);
	check_attr_string (0, "_IO_FILE");

	check_attr_name (1, DW_AT_byte_size);
	check_attr_data (1, 0x01);

	check_attr_name (2, DW_AT_decl_file);
	check_attr_name (3, DW_AT_decl_line);
	check_attr_name (4, DW_AT_decl_column);
	check_attr_name (5, DW_AT_sibling);

	i = 1668 - 4;
	check_die_abbr_code (108);
	check_die_tag (DW_TAG_subprogram);

	check_attr_name (0, DW_AT_abstract_origin);
	check_attr_reference (0, 0x2f32);

	check_attr_name (1, DW_AT_MIPS_linkage_name);
	check_attr_string (1, "_Z8isnumberc");

	check_attr_name (2, DW_AT_low_pc);
	check_attr_reference (2, 0x0000000010001aa4);

	check_attr_name (3, DW_AT_high_pc);
	check_attr_reference (3, 0x0000000010001ac8);

	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_dwarf3_c);
	mu_run_test (test_dwarf4_cpp_multiple_modules);
	mu_run_test (test_dwarf2_big_endian);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
