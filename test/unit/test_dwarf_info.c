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

	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Failed to get current bin file");
	RVecDwarfAbbrevDecl *da = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (da, "Failed to parse abbreviations");
	mu_assert_eq (RVecDwarfAbbrevDecl_length(da), 7, "Incorrect number of abbreviations");
	mu_assert_true (r_bin_dwarf_parse_comp_dirs (bf, da),
		"Failed root-only compilation directory parsing");
	mu_assert_notnull (bf->dwarf_metadata.comp_dirs,
		"Legacy data4 statement-list offset was not indexed");
	const char *comp_dir = ht_up_find (bf->dwarf_metadata.comp_dirs, 0, NULL);
	mu_assert_streq (comp_dir, "/home/hound/r2test/dwarf/c",
		"Incorrect root-only compilation directory");

	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, da, MODE);
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

	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Failed to get current bin file");
	RVecDwarfAbbrevDecl *da = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (da, "Failed to parse abbreviations");
	mu_assert_eq (RVecDwarfAbbrevDecl_length(da), 37, "Incorrect number of abbreviations");

	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, da, MODE);
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

	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Failed to get current bin file");
	RVecDwarfAbbrevDecl *da = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_eq (RVecDwarfAbbrevDecl_length(da), 108, "Incorrect number of abbreviation");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, da, MODE);
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

static ut32 dwarf_test_add_section_name(ut8 *table, size_t *size, const char *name) {
	ut32 offset = (ut32)*size;
	size_t length = strlen (name) + 1;
	memcpy (table + *size, name, length);
	*size += length;
	return offset;
}

static void dwarf_test_write_section_header(ut8 *header, ut32 name, ut32 type, ut64 offset, ut64 size, ut64 alignment) {
	r_write_le32 (header, name);
	r_write_le32 (header + 4, type);
	r_write_le64 (header + 24, offset);
	r_write_le64 (header + 32, size);
	r_write_le64 (header + 48, alignment);
}

static RBuffer *dwarf_test_package_buffer(bool malformed_index) {
	ut8 image[2048] = { 0 };
	const ut64 signature = 0x1122334455667788ULL;
	image[0] = 0x7f;
	image[1] = 'E';
	image[2] = 'L';
	image[3] = 'F';
	image[4] = 2;
	image[5] = 1;
	image[6] = 1;
	r_write_le16 (image + 16, 1);
	r_write_le16 (image + 18, 62);
	r_write_le32 (image + 20, 1);
	r_write_le16 (image + 52, 64);
	r_write_le16 (image + 58, 64);
	r_write_le16 (image + 60, 7);
	r_write_le16 (image + 62, 1);

	size_t cursor = 64;
	const size_t shstr_offset = cursor;
	size_t shstr_size = 1;
	ut32 shstr_name = dwarf_test_add_section_name (image + shstr_offset,
		&shstr_size, ".shstrtab");
	ut32 info_name = dwarf_test_add_section_name (image + shstr_offset,
		&shstr_size, ".debug_info.dwo");
	ut32 abbrev_name = dwarf_test_add_section_name (image + shstr_offset,
		&shstr_size, ".debug_abbrev.dwo");
	ut32 str_offsets_name = dwarf_test_add_section_name (image + shstr_offset,
		&shstr_size, ".debug_str_offsets.dwo");
	ut32 str_name = dwarf_test_add_section_name (image + shstr_offset,
		&shstr_size, ".debug_str.dwo");
	ut32 index_name = dwarf_test_add_section_name (image + shstr_offset,
		&shstr_size, ".debug_cu_index");
	cursor += shstr_size;

	const size_t info_offset = cursor;
	r_write_le32 (image + cursor, 18);
	r_write_le16 (image + cursor + 4, 5);
	image[cursor + 6] = DW_UT_split_compile;
	image[cursor + 7] = 8;
	r_write_le32 (image + cursor + 8, 0);
	r_write_le64 (image + cursor + 12, signature);
	image[cursor + 20] = 1;
	image[cursor + 21] = 0;
	cursor += 22;

	const size_t abbrev_offset = cursor;
	const ut8 abbrev[] = {
		0, 0, 0, 0,
		1, DW_TAG_compile_unit, DW_CHILDREN_no,
		DW_AT_name, DW_FORM_strx1, 0, 0, 0,
	};
	memcpy (image + cursor, abbrev, sizeof (abbrev));
	cursor += sizeof (abbrev);

	const size_t str_offsets_offset = cursor;
	r_write_le32 (image + cursor + 4, 8);
	r_write_le16 (image + cursor + 8, 5);
	r_write_le16 (image + cursor + 10, 0);
	r_write_le32 (image + cursor + 12, 0);
	cursor += 16;

	const char packaged_name[] = "packaged.c";
	const size_t str_offset = cursor;
	memcpy (image + cursor, packaged_name, sizeof (packaged_name));
	cursor += sizeof (packaged_name);

	const size_t index_offset = cursor;
	r_write_le16 (image + cursor, 5);
	r_write_le16 (image + cursor + 2, 0);
	r_write_le32 (image + cursor + 4, 3);
	r_write_le32 (image + cursor + 8, 1);
	r_write_le32 (image + cursor + 12, 2);
	r_write_le64 (image + cursor + 16, signature);
	r_write_le32 (image + cursor + 32, malformed_index? 2: 1);
	r_write_le32 (image + cursor + 40, 1);
	r_write_le32 (image + cursor + 44, 3);
	r_write_le32 (image + cursor + 48, 6);
	r_write_le32 (image + cursor + 52, 0);
	r_write_le32 (image + cursor + 56, 4);
	r_write_le32 (image + cursor + 60, 4);
	r_write_le32 (image + cursor + 64, 22);
	r_write_le32 (image + cursor + 68, 8);
	r_write_le32 (image + cursor + 72, 12);
	cursor += 76;

	cursor = (cursor + 7) & ~(size_t)7;
	const size_t section_headers = cursor;
	r_write_le64 (image + 40, section_headers);
	dwarf_test_write_section_header (image + section_headers + 64,
		shstr_name, 3, shstr_offset, shstr_size, 1);
	dwarf_test_write_section_header (image + section_headers + 128,
		info_name, 1, info_offset, 22, 1);
	dwarf_test_write_section_header (image + section_headers + 192,
		abbrev_name, 1, abbrev_offset, sizeof (abbrev), 1);
	dwarf_test_write_section_header (image + section_headers + 256,
		str_offsets_name, 1, str_offsets_offset, 16, 1);
	dwarf_test_write_section_header (image + section_headers + 320,
		str_name, 1, str_offset, sizeof (packaged_name), 1);
	dwarf_test_write_section_header (image + section_headers + 384,
		index_name, 1, index_offset, 76, 8);
	return r_buf_new_with_bytes (image, section_headers + 448);
}

bool test_dwarf5_package_contributions(void) {
	RBuffer *buf = dwarf_test_package_buffer (false);
	mu_assert_notnull (buf, "Couldn't create packaged DWARF fixture");
	RBinFileOptions opt = { 0 };
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "indexed.dwp";
	mu_assert_true (r_bin_open_buf (bin, buf, &opt),
		"Couldn't open packaged DWARF fixture");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get packaged DWARF bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse packaged abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	mu_assert_notnull (info, "Couldn't parse packaged DWARF info");
	mu_assert_eq (RVecDwarfCompUnit_length (info->comp_units), 1,
		"Incorrect packaged unit count");
	RBinDwarfCompUnit *unit = RVecDwarfCompUnit_at (info->comp_units, 0);
	mu_assert_notnull (unit, "Packaged unit is NULL");
	mu_assert_eq (unit->hdr.dwo_id, 0x1122334455667788ULL,
		"64-bit dwo_id was truncated");
	mu_assert_eq (unit->hdr.abbrev_offset, 4,
		"Package abbreviation contribution base was not applied");
	RBinDwarfDie *root = RVecDwarfDie_at (unit->dies, 0);
	mu_assert_notnull (root, "Packaged root DIE is NULL");
	check_attr_form ((*root), 0, DW_FORM_strx1);
	check_attr_string ((*root), 0, "packaged.c");
	RList *files = r_bin_dwarf_parse_comp_unit_files (bf, abbrevs);
	mu_assert_notnull (files, "Couldn't collect packaged source files");
	mu_assert_eq (r_list_length (files), 1, "Incorrect packaged source file count");
	mu_assert_streq (r_list_first (files), "packaged.c",
		"Incorrect packaged source file");
	r_list_free (files);
	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_unref (buf);
	mu_end;
}

bool test_dwarf5_rejects_malformed_package_index(void) {
	RBuffer *buf = dwarf_test_package_buffer (true);
	mu_assert_notnull (buf, "Couldn't create malformed package fixture");
	RBinFileOptions opt = { 0 };
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "malformed.dwp";
	mu_assert_true (r_bin_open_buf (bin, buf, &opt),
		"Couldn't open malformed package fixture");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get malformed package bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse malformed package abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	mu_assert_null (info, "Out-of-range package row must reject the unit");
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_unref (buf);
	mu_end;
}

bool test_dwarf5_indexed_strings_and_addresses(void) {
	RBinFileOptions opt = {0};
	bool res = r_bin_open (bin, "bins/elf/dwarf5_line_cl", &opt);
	mu_assert ("dwarf5_line_cl binary could not be opened", res);

	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Failed to get current bin file");
	RVecDwarfAbbrevDecl *da = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (da, "Failed parsing DWARF5 abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, da, MODE);
	mu_assert_notnull (info, "Failed parsing DWARF5 indexed forms");
	mu_assert_eq (RVecDwarfCompUnit_length (info->comp_units), 1, "Incorrect DWARF5 compilation unit count");

	RBinDwarfCompUnit *cu = RVecDwarfCompUnit_at (info->comp_units, 0);
	mu_assert_notnull (cu, "DWARF5 compilation unit is NULL");
	mu_assert_notnull (cu->dies, "DWARF5 DIE vector is NULL");
	mu_assert ("DWARF5 DIE vector is too short", RVecDwarfDie_length (cu->dies) > 21);
	RBinDwarfDie *dies = cu->dies->_start;
	check_die_tag (dies[0], DW_TAG_compile_unit);
	check_attr_form (dies[0], 0, DW_FORM_strx1);
	check_attr_string (dies[0], 0, "clang version 18.1.8");
	check_attr_string (dies[0], 2, "dwarf-line.c");
	check_attr_string (dies[0], 5, "/usr/w/g/radare2/test/bins/src");
	check_attr_form (dies[0], 6, DW_FORM_addrx);
	check_attr_address (dies[0], 6, 0x1140);

	check_die_tag (dies[11], DW_TAG_subprogram);
	check_attr_address (dies[11], 0, 0x1140);
	check_attr_string (dies[11], 3, "foo");
	check_die_tag (dies[19], DW_TAG_subprogram);
	check_attr_address (dies[19], 0, 0x11c0);
	check_attr_string (dies[19], 3, "main");
	check_attr_string (dies[20], 1, "a");
	check_attr_string (dies[21], 1, "v");

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (da);
	mu_end;
}

bool test_dwarf5_rejects_nonzero_terminal_abbrev(void) {
	RBinFileOptions opt = {0};
	mu_assert_true (r_bin_open (bin, "bins/elf/dwarf5_line_cl", &opt),
		"dwarf5_line_cl binary could not be opened");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Failed to get source bin file");
	RBinSection *debug_info = NULL;
	RVecRBinSection *sections = r_bin_file_get_sections_vec (bf);
	RBinSection *section;
	R_VEC_FOREACH (sections, section) {
		if (section->name && !strcmp (section->name, ".debug_info")) {
			debug_info = section;
			break;
		}
	}
	mu_assert_notnull (debug_info, "Missing .debug_info section");
	ut64 file_size = r_buf_size (bf->buf);
	mu_assert ("Invalid .debug_info file range", debug_info->size > 0
		&& debug_info->paddr <= file_size
		&& debug_info->size <= file_size - debug_info->paddr);
	ut8 *bytes = malloc (file_size);
	mu_assert_notnull (bytes, "Couldn't clone DWARF5 fixture");
	mu_assert_eq (r_buf_read_at (bf->buf, 0, bytes, file_size), file_size,
		"Couldn't read DWARF5 fixture");
	ut64 terminal = debug_info->paddr + debug_info->size - 1;
	mu_assert_eq (bytes[terminal], 0, "DWARF5 fixture must end its CU with a null DIE");
	bytes[terminal] = 1;
	RBuffer *bad_buf = r_buf_new_with_bytes (bytes, file_size);
	free (bytes);
	mu_assert_notnull (bad_buf, "Couldn't create malformed DWARF5 buffer");
	RBin *bad_bin = r_bin_new ();
	RIO *bad_io = r_io_new ();
	mu_assert_notnull (bad_bin, "Couldn't create malformed DWARF bin");
	mu_assert_notnull (bad_io, "Couldn't create malformed DWARF IO");
	r_io_bind (bad_io, &bad_bin->iob);
	RBinFileOptions bad_opt = {0};
	r_bin_file_options_init (&bad_opt, -1, 0, 0, 0);
	bad_opt.filename = "dwarf5_line_cl";
	mu_assert_true (r_bin_open_buf (bad_bin, bad_buf, &bad_opt),
		"Couldn't open malformed DWARF5 fixture");
	RBinFile *bad_bf = r_bin_cur (bad_bin);
	mu_assert_notnull (bad_bf, "Couldn't get malformed DWARF5 bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bad_bf, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse malformed fixture abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bad_bf, abbrevs, MODE);
	mu_assert_null (info, "Nonzero terminal abbreviation code must reject the CU");
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_bin_free (bad_bin);
	r_io_free (bad_io);
	r_unref (bad_buf);
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
	run_test_with_setup(test_dwarf5_package_contributions);
	run_test_with_setup(test_dwarf5_rejects_malformed_package_index);
	run_test_with_setup(test_dwarf5_indexed_strings_and_addresses);
	run_test_with_setup(test_dwarf5_rejects_nonzero_terminal_abbrev);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
