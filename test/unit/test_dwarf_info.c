#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>
#include <r_bin_dwarf.h>

#define MODE 2

// Global test context to prevent leaks on early returns
static RBin *bin = NULL;
static RIO *io = NULL;

static bool setup(void) {
	bin = r_bin_new ();
	io = r_io_new ();
	if (!bin || !io) {
		r_bin_free (bin);
		r_io_free (io);
		return false;
	}
	r_io_bind (io, &bin->iob);
	return true;
}

static bool teardown(void) {
	r_bin_free (bin);
	r_io_free (io);
	bin = NULL;
	io = NULL;
	return true;
}

// Helper macro to get attribute value at index with null check
#define GET_ATTR(die, idx) (RVecDwarfAttrValue_at(die.attr_values, idx))

// Improved check macros with proper vector access and null checks
#define check_attr_string(die, attr_idx, expect_string) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_streq(attr->string.content, expect_string, "Wrong string attribute information"); \
} while (0)

#define check_attr_name(die, attr_idx, expect_name) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_eq(attr->attr_name, expect_name, "Wrong attribute name"); \
} while (0)

#define check_attr_address(die, attr_idx, expect_addr) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_eq(attr->address, expect_addr, "Wrong attribute address"); \
} while (0)

#define check_attr_form(die, attr_idx, expect_form) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_eq(attr->attr_form, expect_form, "Wrong attribute form"); \
} while (0)

#define check_attr_data(die, attr_idx, expect_data) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_eq(attr->uconstant, expect_data, "Wrong attribute data"); \
} while (0)

#define check_attr_block_length(die, attr_idx, expect_len) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_eq(attr->block.length, expect_len, "Wrong attribute block length"); \
} while (0)

#define check_attr_block_data(die, attr_idx, data_idx, expect_data) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_notnull(attr->block.data, "Block data is NULL"); \
	mu_assert_eq(attr->block.data[data_idx], expect_data, "Wrong attribute block data"); \
} while (0)

#define check_attr_reference(die, attr_idx, expect_ref) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_eq(attr->reference, expect_ref, "Wrong attribute reference"); \
} while (0)

#define check_attr_flag(die, attr_idx, expect_flag) do { \
	RBinDwarfAttrValue *attr = GET_ATTR(die, attr_idx); \
	mu_assert_notnull(attr, "Attribute value is NULL"); \
	mu_assert_eq(attr->flag, expect_flag, "Wrong attribute flag"); \
} while (0)

#define check_die_abbr_code(die, expect_code) do { \
	mu_assert_eq(die.abbrev_code, expect_code, "Wrong abbrev code"); \
} while (0)

#define check_die_length(die, len) do { \
	ut64 attr_count = RVecDwarfAttrValue_length(die.attr_values); \
	mu_assert_eq(attr_count, len, "Wrong DIE attribute count"); \
} while (0)

#define check_die_tag(die, tg) do { \
	mu_assert_eq(die.tag, tg, "Wrong DIE tag"); \
} while (0)

#define check_basic_unit_header(vers, len, is64bit, addr_size, abbr_offset)                              \
	do {                                                                                             \
		mu_assert_eq (hdr.version, vers, "Wrong header version information");                    \
		mu_assert_eq (hdr.length, len, "Wrong header length information");                       \
		mu_assert_eq (hdr.is_64bit, is64bit, "Wrong header is_64bit information");               \
		mu_assert_eq (hdr.address_size, addr_size, "Wrong header address_size information");     \
		mu_assert_eq (hdr.abbrev_offset, abbr_offset, "Wrong header abbrev_offset information"); \
	} while (0)

bool test_dwarf3_c(void) {

	RBinFileOptions opt = {0};
	bool res = r_bin_open (bin, "bins/elf/dwarf3_c.elf", &opt);
	mu_assert ("dwarf3_c.elf binary could not be opened", res);

	RVecDwarfAbbrevDecl *da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (da, "Failed to parse abbreviations");
	mu_assert_eq (RVecDwarfAbbrevDecl_length(da), 7, "Incorrect number of abbreviations");

	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bin, da, MODE);
	mu_assert_notnull (info, "Failed to parse debug info");
	mu_assert_notnull (info->comp_units, "Compilation units vector is NULL");
	mu_assert_eq (RVecDwarfCompUnit_length(info->comp_units), 1, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit *cu = RVecDwarfCompUnit_at(info->comp_units, 0);
	mu_assert_notnull (cu, "Compilation unit is NULL");
	RBinDwarfCompUnitHdr hdr = cu->hdr;

	check_basic_unit_header (3, 0xa9, false, 8, 0x0);

	mu_assert_notnull (cu->dies, "DIEs vector is NULL");
	mu_assert_eq (RVecDwarfDie_length(cu->dies), 11, "Wrong number of DIEs");
	mu_assert_eq (cu->offset, 0x0, "Wrong compilation unit offset");

	// check some of the attributes
	RBinDwarfDie *dies = cu->dies->_start;
	check_die_abbr_code (dies[0], 1);

	check_die_length (dies[0], 7);
	check_die_tag (dies[0], DW_TAG_compile_unit);

	check_attr_name (dies[0], 0, DW_AT_producer);
	check_attr_string (dies[0], 2, "main.c");
	check_die_abbr_code (dies[1], 2);
	check_die_abbr_code (dies[2], 3);
	check_die_abbr_code (dies[3], 4);
	check_die_abbr_code (dies[4], 5);
	check_die_abbr_code (dies[5], 0);
	check_die_abbr_code (dies[6], 6);
	check_die_abbr_code (dies[7], 7);

	check_attr_string (dies[7], 0, "b");
	check_attr_data (dies[7], 3, 15);

	check_die_abbr_code (dies[8], 7);
	check_die_abbr_code (dies[9], 0);
	check_die_abbr_code (dies[10], 0);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (da);
	mu_end;
}

bool test_dwarf4_cpp_multiple_modules(void) {

	RBinFileOptions opt = {0};
	bool res = r_bin_open (bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert ("dwarf4_many_comp_units.elf binary could not be opened", res);

	RVecDwarfAbbrevDecl *da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (da, "Failed to parse abbreviations");
	mu_assert_eq (RVecDwarfAbbrevDecl_length(da), 37, "Incorrect number of abbreviations");

	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bin, da, MODE);
	mu_assert_notnull (info, "Failed parsing of debug_info");
	mu_assert_notnull (info->comp_units, "Compilation units vector is NULL");
	mu_assert_eq (RVecDwarfCompUnit_length(info->comp_units), 2, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit *cu = RVecDwarfCompUnit_at(info->comp_units, 0);
	mu_assert_notnull (cu, "Compilation unit is NULL");
	RBinDwarfCompUnitHdr hdr = cu->hdr;
	check_basic_unit_header (4, 0x2c0, false, 8, 0x0);

	// check some of the attributes
	mu_assert_notnull (cu->dies, "DIEs vector is NULL");
	mu_assert_eq (RVecDwarfDie_length(cu->dies), 73, "Wrong number of DIEs");
	mu_assert_eq (cu->offset, 0x0, "Wrong compilation unit offset");

	RBinDwarfDie *dies = cu->dies->_start;
	check_die_abbr_code (dies[0], 1);
	check_die_length (dies[0], 7);
	check_die_tag (dies[0], DW_TAG_compile_unit);

	check_attr_name (dies[0], 0, DW_AT_producer);
	check_attr_string (dies[0], 2, "../main.cpp");
	check_attr_name (dies[0], 6, DW_AT_ranges);
	check_attr_reference (dies[0], 6, 0x0);

	check_die_abbr_code (dies[1], 2);
	check_die_abbr_code (dies[2], 3);
	check_die_abbr_code (dies[3], 3);
	check_die_abbr_code (dies[4], 3);
	check_die_abbr_code (dies[5], 0);

	check_die_abbr_code (dies[6], 4);
	check_attr_reference (dies[6], 0, 0x6e);
	check_attr_data (dies[6], 1, 4);
	check_attr_string (dies[6], 2, "Bird");
	check_attr_data (dies[6], 3, 8);
	check_attr_data (dies[6], 4, 1);
	check_attr_data (dies[6], 5, 9);

	check_die_abbr_code (dies[7], 5);
	check_die_tag (dies[7], DW_TAG_member);
	check_attr_string (dies[7], 0, "_vptr$Bird");
	check_attr_reference (dies[7], 1, 0xc5);
	check_attr_data (dies[7], 2, 0);
	check_attr_flag (dies[7], 3, true);

	check_die_abbr_code (dies[8], 6);
	check_die_abbr_code (dies[9], 7);
	check_die_abbr_code (dies[10], 0);
	check_die_abbr_code (dies[11], 8);
	check_die_abbr_code (dies[12], 7);
	check_die_abbr_code (dies[13], 0);
	check_die_abbr_code (dies[14], 9);
	check_die_tag (dies[14], DW_TAG_subprogram);
	check_die_length (dies[14], 10);
	check_attr_string (dies[14], 0, "_ZN4Bird3flyEv");
	check_attr_string (dies[14], 1, "fly");
	check_attr_data (dies[14], 2, 1);
	check_attr_data (dies[14], 3, 12);
	check_attr_reference (dies[14], 4, 0xd8);
	check_attr_name (dies[14], 6, DW_AT_vtable_elem_location);
	check_attr_form (dies[14], 7, DW_FORM_flag_present);
	check_attr_flag (dies[14], 7, true);
	check_attr_name (dies[14], 8, DW_AT_external);
	check_attr_flag (dies[14], 8, true);
	check_attr_name (dies[14], 9, DW_AT_containing_type);
	check_attr_reference (dies[14], 9, 0x6e);
	check_die_abbr_code (dies[16], 0);
	check_die_abbr_code (dies[17], 0);
	check_die_abbr_code (dies[18], 10);
	check_die_abbr_code (dies[19], 11);
	check_die_abbr_code (dies[20], 12);
	check_die_abbr_code (dies[21], 13);
	check_die_tag (dies[21], DW_TAG_base_type);
	check_die_length (dies[21], 3);
	check_die_abbr_code (dies[22], 10);
	check_die_abbr_code (dies[23], 14);
	check_die_abbr_code (dies[24], 15);
	check_die_abbr_code (dies[25], 0);
	check_die_abbr_code (dies[26], 4);

	check_die_abbr_code (dies[66], 18);
	check_die_length (dies[66], 5);
	check_attr_reference (dies[66], 3, 0x2a7);

	check_die_abbr_code (dies[67], 15);
	check_die_length (dies[67], 4);
	check_attr_block_length (dies[67], 0, 2);
	check_attr_block_data (dies[67], 0, 0, 0x91);
	check_attr_block_data (dies[67], 0, 1, 0x78);
	check_attr_string (dies[67], 1, "this");
	check_attr_reference (dies[67], 2, 0x2be);
	check_attr_flag (dies[67], 3, true);

	check_die_abbr_code (dies[68], 0);
	check_die_abbr_code (dies[69], 10);
	check_die_abbr_code (dies[70], 10);
	check_die_tag (dies[70], DW_TAG_pointer_type);

	check_die_abbr_code (dies[71], 10);

	check_die_abbr_code (dies[72], 0);

	cu = RVecDwarfCompUnit_at(info->comp_units, 1);
	hdr = cu->hdr;
	check_basic_unit_header (4, 0x192, false, 8, 0xfd);

	// check some of the attributes
	mu_assert_eq (RVecDwarfDie_length(cu->dies), 42, "Wrong attribute information");
	mu_assert_eq (cu->offset, 0x2c4, "Wrong attribute information");

  dies = cu->dies->_start;

	check_die_abbr_code (dies[0], 1);
	check_die_length (dies[0], 7);
	check_die_tag (dies[0], DW_TAG_compile_unit);
	check_attr_name (dies[0], 0, DW_AT_producer);
	check_attr_string (dies[0], 0, "clang version 10.0.0-4ubuntu1 ");
	check_attr_data (dies[0], 1, 33);
	check_attr_string (dies[0], 2, "../mammal.cpp");
	check_attr_address (dies[0], 5, 0x0);
	check_attr_form (dies[0], 5, DW_FORM_addr);
	check_attr_name (dies[0], 6, DW_AT_ranges);
	check_attr_reference (dies[0], 6, 0xb0);
	check_die_abbr_code (dies[1], 2);
	check_die_abbr_code (dies[2], 3);
	check_die_abbr_code (dies[3], 4);
	check_die_abbr_code (dies[4], 5);
	check_die_abbr_code (dies[5], 0);
	check_die_abbr_code (dies[6], 6);
	check_die_abbr_code (dies[7], 5);
	check_die_abbr_code (dies[8], 0);

	check_die_abbr_code (dies[35], 8);
	check_die_tag (dies[35], DW_TAG_pointer_type);
	check_die_length (dies[35], 1);
	check_attr_form (dies[35], 0, DW_FORM_ref4);
	check_attr_reference (dies[35], 0, 0x407);

	check_die_abbr_code (dies[36], 19);
	check_die_tag (dies[36], DW_TAG_subprogram);
	check_die_length (dies[36], 5);
	check_attr_name (dies[36], 2, DW_AT_frame_base);
	check_attr_block_length (dies[36], 2, 1);
	check_attr_block_data (dies[36], 2, 0, 0x56);
	check_attr_reference (dies[36], 3, 0x442);
	check_attr_reference (dies[36], 4, 0x410);

	check_die_abbr_code (dies[40], 8);
	check_die_abbr_code (dies[41], 0);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (da);
	mu_end;
}

bool test_dwarf2_big_endian(void) {

	RBinFileOptions opt = {0};
	bool res = r_bin_open (bin, "bins/elf/ppc64_sudoku_dwarf", &opt);
	mu_assert ("dwarf4_many_comp_units.elf binary could not be opened", res);

	RVecDwarfAbbrevDecl *da = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_eq (RVecDwarfAbbrevDecl_length(da), 108, "Incorrect number of abbreviation");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bin, da, MODE);
	mu_assert_notnull (info, "Failed parsing of debug_info");
	mu_assert_eq (RVecDwarfCompUnit_length(info->comp_units), 1, "Incorrect number of info compilation units");

	// check header
	RBinDwarfCompUnit *cu = RVecDwarfCompUnit_at(info->comp_units, 0);
	RBinDwarfCompUnitHdr hdr = cu->hdr;
	check_basic_unit_header (2, 0x38b9, false, 8, 0x0);

  RBinDwarfDie *dies = cu->dies->_start;
	check_die_abbr_code (dies[0], 1);
	check_die_length (dies[0], 7);
	check_die_tag (dies[0], DW_TAG_compile_unit);

	check_attr_name (dies[0], 0, DW_AT_producer);
	check_attr_string (dies[0], 0, "GNU C++14 9.3.0 -msecure-plt -mabi=elfv2 -mcpu=970 -gdwarf-2 -gstrict-dwarf -O1");
	check_attr_name (dies[0], 1, DW_AT_language);
	check_attr_data (dies[0], 1, DW_LANG_C_plus_plus);

	check_attr_name (dies[0], 4, DW_AT_low_pc);
	check_attr_reference (dies[0], 4, 0x0000000010000ec4);
	check_attr_name (dies[0], 5, DW_AT_high_pc);
	check_attr_reference (dies[0], 5, 0x0000000010001c48);
	check_attr_name (dies[0], 6, DW_AT_stmt_list);
	check_attr_reference (dies[0], 6, 0x0);

	check_die_abbr_code (dies[2], 3);
	check_die_tag (dies[2], DW_TAG_base_type);

	check_attr_name (dies[2], 0, DW_AT_byte_size);
	check_attr_data (dies[2], 0, 0x08);

	check_attr_name (dies[2], 1, DW_AT_encoding);
	check_attr_data (dies[2], 1, DW_ATE_unsigned);

	check_attr_name (dies[2], 2, DW_AT_name);
	check_attr_string (dies[2], 2, "long unsigned int");

  check_die_abbr_code (dies[3], 4);
  check_die_abbr_code (dies[4], 2);
  check_die_abbr_code (dies[5], 3);
  check_die_abbr_code (dies[6], 2);

	check_die_abbr_code (dies[7], 5);
	check_die_tag (dies[7], DW_TAG_structure_type);

	check_attr_name (dies[7], 0, DW_AT_name);
	check_attr_string (dies[7], 0, "_IO_FILE");

	check_attr_name (dies[7], 1, DW_AT_byte_size);
	check_attr_data (dies[7], 1, 0x01);

	check_attr_name (dies[7], 2, DW_AT_decl_file);
	check_attr_name (dies[7], 3, DW_AT_decl_line);
	check_attr_name (dies[7], 4, DW_AT_decl_column);
	check_attr_name (dies[7], 5, DW_AT_sibling);

	check_die_abbr_code (dies[1664], 108);
	check_die_tag (dies[1664], DW_TAG_subprogram);

	check_attr_name (dies[1664], 0, DW_AT_abstract_origin);
	check_attr_reference (dies[1664], 0, 0x2f32);

	check_attr_name (dies[1664], 1, DW_AT_MIPS_linkage_name);
	check_attr_string (dies[1664], 1, "_Z8isnumberc");

	check_attr_name (dies[1664], 2, DW_AT_low_pc);
	check_attr_reference (dies[1664], 2, 0x0000000010001aa4);

	check_attr_name (dies[1664], 3, DW_AT_high_pc);
	check_attr_reference (dies[1664], 3, 0x0000000010001ac8);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (da);
	mu_end;
}

#define run_test_with_setup(test_func) do { \
	if (!setup()) { \
		printf("Setup failed for " #test_func "\n"); \
		return 1; \
	} \
	mu_run_test(test_func); \
	teardown(); \
} while (0)

bool all_tests(void) {
	run_test_with_setup(test_dwarf3_c);
	run_test_with_setup(test_dwarf4_cpp_multiple_modules);
	run_test_with_setup(test_dwarf2_big_endian);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
