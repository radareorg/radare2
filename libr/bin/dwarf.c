/* radare - LGPL - Copyright 2012-2018 - pancake, Fedor Sakharov */

#define D0 if(1)
#define D1 if(1)

#include <errno.h>

#define DWARF_DUMP 0

#if DWARF_DUMP
#define DBGFD stdout
#else
#define DBGFD NULL
#endif

#include <r_bin.h>
#include <r_bin_dwarf.h>
#include <r_core.h>

#define STANDARD_OPERAND_COUNT_DWARF2 9
#define STANDARD_OPERAND_COUNT_DWARF3 12
#define R_BIN_DWARF_INFO 1

// endianness setting global
static bool big_end = false;

/* This macro seems bad regarding to endianess XXX, use only for single byte */
#define READ(buf, type)                                             \
	(((buf) + sizeof (type) < buf_end) ? *((type *)(buf)) : 0); \
	(buf) += sizeof (type)
#define READ8(buf)                                                \
	(((buf) + sizeof (ut8) < buf_end) ? ((ut8 *)buf)[0] : 0); \
	(buf) += sizeof (ut8)
#define READ16(buf)                                                            \
	(((buf) + sizeof (ut16) < buf_end) ? r_read_ble16 (buf, big_end) : 0); \
	(buf) += sizeof (ut16)
#define READ32(buf)                                                            \
	(((buf) + sizeof (ut32) < buf_end) ? r_read_ble32 (buf, big_end) : 0); \
	(buf) += sizeof (ut32)
#define READ64(buf)                                                            \
	(((buf) + sizeof (ut64) < buf_end) ? r_read_ble64 (buf, big_end) : 0); \
	(buf) += sizeof (ut64)

static const char *dwarf_tag_name_encodings[] = {
	[DW_TAG_null_entry] = "DW_TAG_null_entry",
	[DW_TAG_array_type] = "DW_TAG_array_type",
	[DW_TAG_class_type] = "DW_TAG_class_type",
	[DW_TAG_entry_point] = "DW_TAG_entry_point",
	[DW_TAG_enumeration_type] = "DW_TAG_enumeration_type",
	[DW_TAG_formal_parameter] = "DW_TAG_formal_parameter",
	[DW_TAG_imported_declaration] = "DW_TAG_imported_declaration",
	[DW_TAG_label] = "DW_TAG_label",
	[DW_TAG_lexical_block] = "DW_TAG_lexical_block",
	[DW_TAG_member] = "DW_TAG_member",
	[DW_TAG_pointer_type] = "DW_TAG_pointer_type",
	[DW_TAG_reference_type] = "DW_TAG_reference_type",
	[DW_TAG_compile_unit] = "DW_TAG_compile_unit",
	[DW_TAG_string_type] = "DW_TAG_string_type",
	[DW_TAG_structure_type] = "DW_TAG_structure_type",
	[DW_TAG_subroutine_type] = "DW_TAG_subroutine_type",
	[DW_TAG_typedef] = "DW_TAG_typedef",
	[DW_TAG_union_type] = "DW_TAG_union_type",
	[DW_TAG_unspecified_parameters] = "DW_TAG_unspecified_parameters",
	[DW_TAG_variant] = "DW_TAG_variant",
	[DW_TAG_common_block] = "DW_TAG_common_block",
	[DW_TAG_common_inclusion] = "DW_TAG_common_inclusion",
	[DW_TAG_inheritance] = "DW_TAG_inheritance",
	[DW_TAG_inlined_subroutine] = "DW_TAG_inlined_subroutine",
	[DW_TAG_module] = "DW_TAG_module",
	[DW_TAG_ptr_to_member_type] = "DW_TAG_ptr_to_member_type",
	[DW_TAG_set_type] = "DW_TAG_set_type",
	[DW_TAG_subrange_type] = "DW_TAG_subrange_type",
	[DW_TAG_with_stmt] = "DW_TAG_with_stmt",
	[DW_TAG_access_declaration] = "DW_TAG_access_declaration",
	[DW_TAG_base_type] = "DW_TAG_base_type",
	[DW_TAG_catch_block] = "DW_TAG_catch_block",
	[DW_TAG_const_type] = "DW_TAG_const_type",
	[DW_TAG_constant] = "DW_TAG_constant",
	[DW_TAG_enumerator] = "DW_TAG_enumerator",
	[DW_TAG_file_type] = "DW_TAG_file_type",
	[DW_TAG_friend] = "DW_TAG_friend",
	[DW_TAG_namelist] = "DW_TAG_namelist",
	[DW_TAG_namelist_item] = "DW_TAG_namelist_item",
	[DW_TAG_packed_type] = "DW_TAG_packed_type",
	[DW_TAG_subprogram] = "DW_TAG_subprogram",
	[DW_TAG_template_type_param] = "DW_TAG_template_type_param",
	[DW_TAG_template_value_param] = "DW_TAG_template_value_param",
	[DW_TAG_thrown_type] = "DW_TAG_thrown_type",
	[DW_TAG_try_block] = "DW_TAG_try_block",
	[DW_TAG_variant_part] = "DW_TAG_variant_part",
	[DW_TAG_variable] = "DW_TAG_variable",
	[DW_TAG_volatile_type] = "DW_TAG_volatile_type",
	[DW_TAG_dwarf_procedure] = "DW_TAG_dwarf_procedure",
	[DW_TAG_restrict_type] = "DW_TAG_restrict_type",
	[DW_TAG_interface_type] = "DW_TAG_interface_type",
	[DW_TAG_namespace] = "DW_TAG_namespace",
	[DW_TAG_imported_module] = "DW_TAG_imported_module",
	[DW_TAG_unspecified_type] = "DW_TAG_unspecified_type",
	[DW_TAG_partial_unit] = "DW_TAG_partial_unit",
	[DW_TAG_imported_unit] = "DW_TAG_imported_unit",
	[DW_TAG_mutable_type] = "DW_TAG_mutable_type",
	[DW_TAG_condition] = "DW_TAG_condition",
	[DW_TAG_shared_type] = "DW_TAG_shared_type",
	[DW_TAG_type_unit] = "DW_TAG_type_unit",
	[DW_TAG_rvalue_reference_type] = "DW_TAG_rvalue_reference_type",
	[DW_TAG_template_alias] = "DW_TAG_template_alias",
	[DW_TAG_LAST] = "DW_TAG_LAST",
};

static const char *dwarf_attr_encodings[] = {
	[DW_AT_sibling] = "DW_AT_siblings",
	[DW_AT_location] = "DW_AT_location",
	[DW_AT_name] = "DW_AT_name",
	[DW_AT_ordering] = "DW_AT_ordering",
	[DW_AT_byte_size] = "DW_AT_byte_size",
	[DW_AT_bit_size] = "DW_AT_bit_size",
	[DW_AT_stmt_list] = "DW_AT_stmt_list",
	[DW_AT_low_pc] = "DW_AT_low_pc",
	[DW_AT_high_pc] = "DW_AT_high_pc",
	[DW_AT_language] = "DW_AT_language",
	[DW_AT_discr] = "DW_AT_discr",
	[DW_AT_discr_value] = "DW_AT_discr_value",
	[DW_AT_visibility] = "DW_AT_visibility",
	[DW_AT_import] = "DW_AT_import",
	[DW_AT_string_length] = "DW_AT_string_length",
	[DW_AT_common_reference] = "DW_AT_common_reference",
	[DW_AT_comp_dir] = "DW_AT_comp_dir",
	[DW_AT_const_value] = "DW_AT_const_value",
	[DW_AT_containing_type] = "DW_AT_containing_type",
	[DW_AT_default_value] = "DW_AT_default_value",
	[DW_AT_inline] = "DW_AT_inline",
	[DW_AT_is_optional] = "DW_AT_is_optional",
	[DW_AT_lower_bound] = "DW_AT_lower_bound",
	[DW_AT_producer] = "DW_AT_producer",
	[DW_AT_prototyped] = "DW_AT_prototyped",
	[DW_AT_return_addr] = "DW_AT_return_addr",
	[DW_AT_start_scope] = "DW_AT_start_scope",
	[DW_AT_stride_size] = "DW_AT_stride_size",
	[DW_AT_upper_bound] = "DW_AT_upper_bound",
	[DW_AT_abstract_origin] = "DW_AT_abstract_origin",
	[DW_AT_accessibility] = "DW_AT_accessibility",
	[DW_AT_address_class] = "DW_AT_address_class",
	[DW_AT_artificial] = "DW_AT_artificial",
	[DW_AT_base_types] = "DW_AT_base_types",
	[DW_AT_calling_convention] = "DW_AT_calling_convention",
	[DW_AT_count] = "DW_AT_count",
	[DW_AT_data_member_location] = "DW_AT_data_member_location",
	[DW_AT_decl_column] = "DW_AT_decl_column",
	[DW_AT_decl_file] = "DW_AT_decl_file",
	[DW_AT_decl_line] = "DW_AT_decl_line",
	[DW_AT_declaration] = "DW_AT_declaration",
	[DW_AT_discr_list] = "DW_AT_discr_list",
	[DW_AT_encoding] = "DW_AT_encoding",
	[DW_AT_external] = "DW_AT_external",
	[DW_AT_frame_base] = "DW_AT_frame_base",
	[DW_AT_friend] = "DW_AT_friend",
	[DW_AT_identifier_case] = "DW_AT_identifier_case",
	[DW_AT_macro_info] = "DW_AT_macro_info",
	[DW_AT_namelist_item] = "DW_AT_namelist_item",
	[DW_AT_priority] = "DW_AT_priority",
	[DW_AT_segment] = "DW_AT_segment",
	[DW_AT_specification] = "DW_AT_specification",
	[DW_AT_static_link] = "DW_AT_static_link",
	[DW_AT_type] = "DW_AT_type",
	[DW_AT_use_location] = "DW_AT_use_location",
	[DW_AT_variable_parameter] = "DW_AT_variable_parameter",
	[DW_AT_virtuality] = "DW_AT_virtuality",
	[DW_AT_vtable_elem_location] = "DW_AT_vtable_elem_location",
	[DW_AT_allocated] = "DW_AT_allocated",
	[DW_AT_associated] = "DW_AT_associated",
	[DW_AT_data_location] = "DW_AT_data_location",
	[DW_AT_byte_stride] = "DW_AT_byte_stride",
	[DW_AT_entry_pc] = "DW_AT_entry_pc",
	[DW_AT_use_UTF8] = "DW_AT_use_UTF8",
	[DW_AT_extension] = "DW_AT_extension",
	[DW_AT_ranges] = "DW_AT_ranges",
	[DW_AT_trampoline] = "DW_AT_trampoline",
	[DW_AT_call_column] = "DW_AT_call_column",
	[DW_AT_call_file] = "DW_AT_call_file",
	[DW_AT_call_line] = "DW_AT_call_line",
	[DW_AT_description] = "DW_AT_description",
	[DW_AT_binary_scale] = "DW_AT_binary_scale",
	[DW_AT_decimal_scale] = "DW_AT_decimal_scale",
	[DW_AT_small] = "DW_AT_small",
	[DW_AT_decimal_sign] = "DW_AT_decimal_sign",
	[DW_AT_digit_count] = "DW_AT_digit_count",
	[DW_AT_picture_string] = "DW_AT_picture_string",
	[DW_AT_mutable] = "DW_AT_mutable",
	[DW_AT_threads_scaled] = "DW_AT_threads_scaled",
	[DW_AT_explicit] = "DW_AT_explicit",
	[DW_AT_object_pointer] = "DW_AT_object_pointer",
	[DW_AT_endianity] = "DW_AT_endianity",
	[DW_AT_elemental] = "DW_AT_elemental",
	[DW_AT_pure] = "DW_AT_pure",
	[DW_AT_recursive] = "DW_AT_recursive",
	[DW_AT_signature] = "DW_AT_signature",
	[DW_AT_main_subprogram] = "DW_AT_main_subprogram",
	[DW_AT_data_bit_offset] = "DW_AT_data_big_offset",
	[DW_AT_const_expr] = "DW_AT_const_expr",
	[DW_AT_enum_class] = "DW_AT_enum_class",
	[DW_AT_linkage_name] = "DW_AT_linkage_name",
	[DW_AT_string_length_bit_size] = "DW_AT_string_length_bit_size",
	[DW_AT_string_length_byte_size] = "DW_AT_string_length_byte_size",
	[DW_AT_rank] = "DW_AT_rank",
	[DW_AT_str_offsets_base] = "DW_AT_str_offsets_base",
	[DW_AT_addr_base] = "DW_AT_addr_base",
	[DW_AT_rnglists_base] = "DW_AT_rnglists_base",
	[DW_AT_dwo_name] = "DW_AT_dwo_name",
	[DW_AT_reference] = "DW_AT_reference",
	[DW_AT_rvalue_reference] = "DW_AT_rvalue_reference",
	[DW_AT_macros] = "DW_AT_macros",
	[DW_AT_call_all_calls] = "DW_AT_call_all_calls",
	[DW_AT_call_all_source_calls] = "DW_AT_call_all_source_calls",
	[DW_AT_call_all_tail_calls] = "DW_AT_call_all_tail_calls",
	[DW_AT_call_return_pc] = "DW_AT_call_return_pc",
	[DW_AT_call_value] = "DW_AT_call_value",
	[DW_AT_call_origin] = "DW_AT_call_origin",
	[DW_AT_call_parameter] = "DW_AT_call_parameter",
	[DW_AT_call_pc] = "DW_AT_call_pc",
	[DW_AT_call_tail_call] = "DW_AT_call_tail_call",
	[DW_AT_call_target] = "DW_AT_call_target",
	[DW_AT_call_target_clobbered] = "DW_AT_call_target_clobbered",
	[DW_AT_call_data_location] = "DW_AT_call_data_location",
	[DW_AT_call_data_value] = "DW_AT_call_data_value",
	[DW_AT_noreturn] = "DW_AT_noreturn",
	[DW_AT_alignment] = "DW_AT_alignment",
	[DW_AT_export_symbols] = "DW_AT_export_symbols",
	[DW_AT_deleted] = "DW_AT_deleted",
	[DW_AT_defaulted] = "DW_AT_defaulted",
	[DW_AT_loclists_base] = "DW_AT_loclists_base",

	[DW_AT_lo_user] = "DW_AT_lo_user",
	[DW_AT_MIPS_linkage_name] = "DW_AT_MIPS_linkage_name",
	[DW_AT_GNU_call_site_value] = "DW_AT_GNU_call_site_value",
	[DW_AT_GNU_call_site_data_value] = "DW_AT_GNU_call_site_data_value",
	[DW_AT_GNU_call_site_target] = "DW_AT_GNU_call_site_target",
	[DW_AT_GNU_call_site_target_clobbered] = "DW_AT_GNU_call_site_target_clobbered",
	[DW_AT_GNU_tail_call] = "DW_AT_GNU_tail_call",
	[DW_AT_GNU_all_tail_call_sites] = "DW_AT_GNU_all_tail_call_sites",
	[DW_AT_GNU_all_call_sites] = "DW_AT_GNU_all_call_sites",
	[DW_AT_GNU_all_source_call_sites] = "DW_AT_GNU_all_source_call_sites",
	[DW_AT_GNU_macros] = "DW_AT_GNU_macros",
	[DW_AT_GNU_deleted] = "DW_AT_GNU_deleted",
	[DW_AT_GNU_dwo_name] = "DW_AT_GNU_dwo_name",
	[DW_AT_GNU_dwo_id] = "DW_AT_GNU_dwo_id",
	[DW_AT_GNU_ranges_base] = "DW_AT_GNU_ranges_base",
	[DW_AT_GNU_addr_base] = "DW_AT_GNU_addr_base",
	[DW_AT_GNU_pubnames] = "DW_AT_GNU_pubnames",
	[DW_AT_GNU_pubtypes] = "DW_AT_GNU_pubtypes",
	[DW_AT_hi_user] = "DW_AT_hi_user",
};

static const char *dwarf_attr_form_encodings[] = {
	[DW_FORM_addr] = "DW_FORM_addr",
	[DW_FORM_block2] = "DW_FORM_block2",
	[DW_FORM_block4] = "DW_FORM_block4",
	[DW_FORM_data2] = "DW_FORM_data2",
	[DW_FORM_data4] = "DW_FORM_data4",
	[DW_FORM_data8] = "DW_FORM_data8",
	[DW_FORM_string] = "DW_FORM_string",
	[DW_FORM_block] = "DW_FORM_block",
	[DW_FORM_block1] = "DW_FORM_block1",
	[DW_FORM_data1] = "DW_FORM_data1",
	[DW_FORM_flag] = "DW_FORM_flag",
	[DW_FORM_sdata] = "DW_FORM_sdata",
	[DW_FORM_strp] = "DW_FORM_strp",
	[DW_FORM_udata] = "DW_FORM_udata",
	[DW_FORM_ref_addr] = "DW_FORM_ref_addr",
	[DW_FORM_ref1] = "DW_FORM_ref1",
	[DW_FORM_ref2] = "DW_FORM_ref2",
	[DW_FORM_ref4] = "DW_FORM_ref4",
	[DW_FORM_ref8] = "DW_FORM_ref8",
	[DW_FORM_ref_udata] = "DW_FORM_ref_udata",
	[DW_FORM_indirect] = "DW_FORM_indirect",
	[DW_FORM_sec_offset] = "DW_FORM_sec_offset",
	[DW_FORM_exprloc] = "DW_FORM_exprloc",
	[DW_FORM_flag_present] = "DW_FORM_flag_present",
	[DW_FORM_strx] = "DW_FORM_strx",
	[DW_FORM_addrx] = "DW_FORM_addrx",
	[DW_FORM_ref_sup4] = "DW_FORM_ref_sup4",
	[DW_FORM_strp_sup] = "DW_FORM_strp_sup",
	[DW_FORM_data16] = "DW_FORM_data16",
	[DW_FORM_line_ptr] = "DW_FORM_line_ptr",
	[DW_FORM_ref_sig8] = "DW_FORM_ref_sig8",
	[DW_FORM_implicit_const] = "DW_FORM_implicit_const",
	[DW_FORM_loclistx] = "DW_FORM_loclistx",
	[DW_FORM_rnglistx] = "DW_FORM_rnglistx",
	[DW_FORM_ref_sup8] = "DW_FORM_ref_sup8",
	[DW_FORM_strx1] = "DW_FORM_strx1",
	[DW_FORM_strx2] = "DW_FORM_strx2",
	[DW_FORM_strx3] = "DW_FORM_strx3",
	[DW_FORM_strx4] = "DW_FORM_strx4",
	[DW_FORM_addrx1] = "DW_FORM_addrx1",
	[DW_FORM_addrx2] = "DW_FORM_addrx2",
	[DW_FORM_addrx3] = "DW_FORM_addrx3",
	[DW_FORM_addrx4] = "DW_FORM_addrx4",
};

static const char *dwarf_langs[] = {
	[DW_LANG_C89] = "C89",
	[DW_LANG_C] = "C",
	[DW_LANG_Ada83] = "Ada83",
	[DW_LANG_C_plus_plus] = "C++",
	[DW_LANG_Cobol74] = "Cobol74",
	[DW_LANG_Cobol85] = "Cobol85",
	[DW_LANG_Fortran77] = "Fortran77",
	[DW_LANG_Fortran90] = "Fortran90",
	[DW_LANG_Pascal83] = "Pascal83",
	[DW_LANG_Modula2] = "Modula2",
	[DW_LANG_Java] = "Java",
	[DW_LANG_C99] = "C99",
	[DW_LANG_Ada95] = "Ada95",
	[DW_LANG_Fortran95] = "Fortran95",
	[DW_LANG_PLI] = "PLI",
	[DW_LANG_ObjC] = "ObjC",
	[DW_LANG_ObjC_plus_plus] = "ObjC_plus_plus",
	[DW_LANG_UPC] = "UPC",
	[DW_LANG_D] = "D",
	[DW_LANG_Python] = "Python",
	[DW_LANG_Rust] = "Rust",
	[DW_LANG_C11] = "C11",
	[DW_LANG_Swift] = "Swift",
	[DW_LANG_Julia] = "Julia",
	[DW_LANG_Dylan] = "Dylan",
	[DW_LANG_C_plus_plus_14] = "C++14",
	[DW_LANG_Fortran03] = "Fortran03",
	[DW_LANG_Fortran08] = "Fortran08"
};

static const char *dwarf_unit_types[] = {
	[DW_UT_compile] = "DW_UT_compile",
	[DW_UT_type] = "DW_UT_type",
	[DW_UT_partial] = "DW_UT_partial",
	[DW_UT_skeleton] = "DW_UT_skeleton",
	[DW_UT_split_compile] = "DW_UT_split_compile",
	[DW_UT_split_type] = "DW_UT_split_type",
	[DW_UT_lo_user] = "DW_UT_lo_user",
	[DW_UT_hi_user] = "DW_UT_hi_user",
};

static int abbrev_cmp(const void *a, const void *b) {
	const RBinDwarfAbbrevDecl *first = a;
	const RBinDwarfAbbrevDecl *second = b;

	if (first->offset > second->offset) {
		return 1;
	} else if (first->offset < second->offset) {
		return -1;
	} else {
		return 0;
	}
}

static inline bool is_printable_attr(ut64 attr_code) {
	return (attr_code >= DW_AT_sibling && attr_code <= DW_AT_loclists_base) ||
			attr_code == DW_AT_MIPS_linkage_name ||
			(attr_code >= DW_AT_GNU_call_site_value && attr_code <= DW_AT_GNU_deleted) ||
			(attr_code >= DW_AT_GNU_dwo_name && attr_code <= DW_AT_GNU_pubtypes);
}

static inline bool is_printable_form(ut64 form_code) {
	return form_code >= DW_FORM_addr && form_code <= DW_FORM_addrx4;
}

static inline bool is_printable_tag(ut64 attr_code) {
	return attr_code <= DW_TAG_LAST;
}

static inline bool is_printable_unit_type(ut64 unit_type) {
	return unit_type > 0 && unit_type <= DW_UT_split_type;
}

/**
 * @brief Reads 64/32 bit unsigned based on format
 *
 * @param is_64bit Format of the comp unit
 * @param buf Pointer to the buffer to read from, to update after read
 * @param buf_end To check the boundary /for READ macro/
 * @return ut64 Read value
 */
static inline ut64 dwarf_read_offset(bool is_64bit, const ut8 **buf, const ut8 *buf_end) {
	ut64 result;
	if (is_64bit) {
		result = READ64 (*buf);
	} else {
		result = READ32 (*buf);
	}
	return result;
}

static inline ut64 dwarf_read_address(size_t size, const ut8 **buf, const ut8 *buf_end) {
	ut64 result;
	switch (size) {
		case 2:
		result = READ16 (*buf); break;
		case 4:
		result = READ32 (*buf); break;
		case 8:
		result = READ64 (*buf); break;
		default:
		result = 0;
		*buf += size;
		eprintf ("Weird dwarf address size: %zu.", size);
	}
	return result;
}

static int add_sdb_include_dir(Sdb *s, const char *incl, int idx) {
	if (!s || !incl) {
		return false;
	}
	return sdb_array_set (s, "includedirs", idx, incl, 0);
}

static void line_header_fini(RBinDwarfLineHeader *hdr) {
	if (hdr) {
		size_t i;

		for (i = 0; i < hdr->file_names_count; i ++) {
			free (hdr->file_names[i].name);
		}

		free (hdr->std_opcode_lengths);
		free (hdr->file_names);
	}
}

// Parses source file header of DWARF version <= 4
static const ut8 *parse_line_header_source(RBinFile *bf, const ut8 *buf, const ut8 *buf_end,
	RBinDwarfLineHeader *hdr, Sdb *sdb, int mode, PrintfCallback print) {
	int i = 0;
	size_t count;
	const ut8 *tmp_buf = NULL;

	if (mode == R_MODE_PRINT) {
		print (" The Directory Table:\n");
	}
	while (buf + 1 < buf_end) {
		size_t maxlen = R_MIN ((size_t) (buf_end - buf) - 1, 0xfff);
		size_t len = r_str_nlen ((const char *)buf, maxlen);
		char *str = r_str_ndup ((const char *)buf, len);
		if (len < 1 || len >= 0xfff || !str) {
			buf += 1;
			free (str);
			break;
		}
		if (mode == R_MODE_PRINT) {
			print ("  %d     %s\n", i + 1, str);
		}
		add_sdb_include_dir (sdb, str, i);
		free (str);
		i++;
		buf += len + 1;
	}

	tmp_buf = buf;
	count = 0;
	if (mode == R_MODE_PRINT) {
		print ("\n");
		print (" The File Name Table:\n");
		print ("  Entry Dir     Time      Size       Name\n");
	}
	int entry_index = 1; // used for printing information

	for (i = 0; i < 2; i++) {
		while (buf + 1 < buf_end) {
			const char *filename = (const char *)buf;
			size_t maxlen = R_MIN ((size_t) (buf_end - buf - 1), 0xfff);
			ut64 id_idx, mod_time, file_len;
			size_t len = r_str_nlen (filename, maxlen);

			if (!len) {
				buf++;
				break;
			}
			buf += len + 1;
			if (buf >= buf_end) {
				buf = NULL;
				goto beach;
			}
			buf = r_uleb128 (buf, buf_end - buf, &id_idx, NULL);
			if (buf >= buf_end) {
				buf = NULL;
				goto beach;
			}
			buf = r_uleb128 (buf, buf_end - buf, &mod_time, NULL);
			if (buf >= buf_end) {
				buf = NULL;
				goto beach;
			}
			buf = r_uleb128 (buf, buf_end - buf, &file_len, NULL);
			if (buf >= buf_end) {
				buf = NULL;
				goto beach;
			}

			if (i) {
				char *include_dir = NULL, *comp_dir = NULL, *pinclude_dir = NULL;
				if (id_idx > 0) {
					include_dir = pinclude_dir = sdb_array_get (sdb, "includedirs", id_idx - 1, 0);
					if (include_dir && include_dir[0] != '/') {
						comp_dir = sdb_get (bf->sdb_addrinfo, "DW_AT_comp_dir", 0);
						if (comp_dir) {
							include_dir = r_str_newf("%s/%s/", comp_dir, include_dir);
						}
					}
				} else {
					include_dir = pinclude_dir = sdb_get (bf->sdb_addrinfo, "DW_AT_comp_dir", 0);
					if (!include_dir) {
						include_dir = "./";
					}
				}

				if (hdr->file_names) {
					hdr->file_names[count].name = r_str_newf("%s/%s", r_str_get (include_dir), filename);
					hdr->file_names[count].id_idx = id_idx;
					hdr->file_names[count].mod_time = mod_time;
					hdr->file_names[count].file_len = file_len;
				}
				if (comp_dir) {
					R_FREE (include_dir);
					R_FREE (comp_dir);
				}
				R_FREE (pinclude_dir);
			}
			count++;
			if (mode == R_MODE_PRINT && i) {
				print ("  %d     %" PFMT64d "       %" PFMT64d "         %" PFMT64d "          %s\n", entry_index++, id_idx, mod_time, file_len, filename);
			}
		}
		if (i == 0) {
			if (count > 0) {
				hdr->file_names = calloc (sizeof (file_entry), count);
			} else {
				hdr->file_names = NULL;
			}
			hdr->file_names_count = count;
			buf = tmp_buf;
			count = 0;
		}
	}
	if (mode == R_MODE_PRINT) {
		print ("\n");
	}

beach:
	sdb_free (sdb);

	return buf;
}
// TODO DWARF 5 line header parsing, very different from ver. 4
// Because this function needs ability to parse a lot of FORMS just like debug info
// I'll complete this function after completing debug_info parsing and merging
// for the meanwhile I am skipping the space.
static const ut8 *parse_line_header_source_dwarf5(RBinFile *bf, const ut8 *buf, const ut8 *buf_end,
	RBinDwarfLineHeader *hdr, Sdb *sdb, int mode) {
// 	int i = 0;
// 	size_t count;
// 	const ut8 *tmp_buf = NULL;

// 	ut8 dir_entry_count = READ8 (buf);
// 	// uleb128 pairs
// 	ut8 dir_count = READ8 (buf);

// 	// dirs

// 	ut8 file_entry_count = READ8 (buf);
// 	// uleb128 pairs
// 	ut8 file_count = READ8 (buf);
// 	// file names

// beach:
// 	sdb_free (sdb);

	return NULL;
}

static const ut8 *parse_line_header (
	RBinFile *bf, const ut8 *buf, const ut8 *buf_end,
	RBinDwarfLineHeader *hdr, int mode, PrintfCallback print) {

	r_return_val_if_fail(hdr && bf && buf, NULL);

	hdr->is_64bit = false;
	hdr->unit_length = READ32 (buf);

	if (hdr->unit_length == DWARF_INIT_LEN_64) {
		hdr->unit_length = READ64 (buf);
		hdr->is_64bit = true;
	}

	hdr->version = READ16 (buf);

	if (hdr->version == 5) {
		hdr->address_size = READ8 (buf);
		hdr->segment_selector_size = READ8 (buf);
	}

	hdr->header_length = dwarf_read_offset(hdr->is_64bit, &buf, buf_end);

	const ut8 *tmp_buf = buf; // So I can skip parsing DWARF 5 headers for now

	if (buf_end - buf < 8) {
		return NULL;
	}
	hdr->min_inst_len = READ8 (buf);
	if (hdr->version >= 4) {
		hdr->max_ops_per_inst = READ8 (buf);
	}
	hdr->default_is_stmt = READ8 (buf);
	hdr->line_base = READ (buf, int8_t); // signed
	hdr->line_range = READ8 (buf);
	hdr->opcode_base = READ8 (buf);

	hdr->file_names = NULL;

	if (mode == R_MODE_PRINT) {
		print (" Header information:\n");
		print ("  Length:                             %" PFMT64u "\n", hdr->unit_length);
		print ("  DWARF Version:                      %d\n", hdr->version);
		print ("  Header Length:                      %" PFMT64d "\n", hdr->header_length);
		print ("  Minimum Instruction Length:         %d\n", hdr->min_inst_len);
		print ("  Maximum Operations per Instruction: %d\n", hdr->max_ops_per_inst);
		print ("  Initial value of 'is_stmt':         %d\n", hdr->default_is_stmt);
		print ("  Line Base:                          %d\n", hdr->line_base);
		print ("  Line Range:                         %d\n", hdr->line_range);
		print ("  Opcode Base:                        %d\n\n", hdr->opcode_base);
	}

	if (hdr->opcode_base > 0) {
		hdr->std_opcode_lengths = calloc (sizeof (ut8), hdr->opcode_base);

		if (mode == R_MODE_PRINT) {
			print (" Opcodes:\n");
		}
		size_t i;
		for (i = 1; i < hdr->opcode_base; i++) {
			if (buf + 2 > buf_end) {
				break;
			}
			hdr->std_opcode_lengths[i] = READ (buf, ut8);
			if (mode == R_MODE_PRINT) {
				print ("  Opcode %zu has %d arg\n", i, hdr->std_opcode_lengths[i]);
			}
		}
		if (mode == R_MODE_PRINT) {
			print ("\n");
		}
	} else {
		hdr->std_opcode_lengths = NULL;
	}
	// TODO finish parsing of source files out of DWARF 5 header
	// for now we skip
	if (hdr->version == 5) {
		tmp_buf += hdr->header_length;
		return tmp_buf;
	}

	Sdb *sdb = sdb_new (NULL, NULL, 0);
	if (!sdb) {
		return NULL;
	}

	if (hdr->version <= 4) {
		buf = parse_line_header_source (bf, buf, buf_end, hdr, sdb, mode, print);
	} else { // because Version 5 source files are very different
		buf = parse_line_header_source_dwarf5 (bf, buf, buf_end, hdr, sdb, mode);
	}

	return buf;
}

static inline void add_sdb_addrline(Sdb *s, ut64 addr, const char *file, ut64 line, int mode, PrintfCallback print) {
	const char *p;
	char *fileline;
	char offset[64];
	char *offset_ptr;

	if (!s || !file) {
		return;
	}
	p = r_str_rchr (file, NULL, '/');
	if (p) {
		p++;
	} else {
		p = file;
	}
	// includedirs and properly check full paths
	switch (mode) {
	case 1:
	case 'r':
	case '*':
		print ("CL %s:%d 0x%08"PFMT64x"\n", p, (int)line, addr);
		break;
	}
#if 0
	/* THIS IS TOO SLOW */
	if (r_file_exists (file)) {
		p = file;
	}
#else
	p = file;
#endif
	fileline = r_str_newf ("%s|%"PFMT64d, p, line);
	offset_ptr = sdb_itoa (addr, offset, 16);
	sdb_add (s, offset_ptr, fileline, 0);
	sdb_add (s, fileline, offset_ptr, 0);
	free (fileline);
}

static const ut8 *parse_ext_opcode(const RBin *bin, const ut8 *obuf,
	size_t len, const RBinDwarfLineHeader *hdr,
	RBinDwarfSMRegisters *regs, int mode) {

	r_return_val_if_fail (bin && bin->cur && obuf && hdr && regs, NULL);

	PrintfCallback print = bin->cb_printf;
	const ut8 *buf;
	const ut8 *buf_end;
	ut8 opcode;
	ut64 addr;
	buf = obuf;
	st64 op_len;
	RBinFile *binfile = bin->cur;
	RBinObject *o = binfile->o;
	ut32 addr_size = o && o->info && o->info->bits ? o->info->bits / 8 : 4;
	const char *filename;

	buf_end = buf + len;
	buf = r_leb128 (buf, len, &op_len);
	if (buf >= buf_end) {
		return NULL;
	}

	opcode = *buf++;

	if (mode == R_MODE_PRINT) {
		print ("  Extended opcode %d: ", opcode);
	}

	switch (opcode) {
	case DW_LNE_end_sequence:
		regs->end_sequence = DWARF_TRUE;

		if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
			int fnidx = regs->file - 1;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline(binfile->sdb_addrinfo, regs->address,
						hdr->file_names[fnidx].name, regs->line, mode, print);
			}
		}

		if (mode == R_MODE_PRINT) {
			print ("End of Sequence\n");
		}
		break;
	case DW_LNE_set_address:
		if (addr_size == 8) {
			addr = READ64 (buf);
		} else {
			addr = READ32 (buf);
		}
		regs->address = addr;
		if (mode == R_MODE_PRINT) {
			print ("set Address to 0x%"PFMT64x"\n", addr);
		}
		break;
	case DW_LNE_define_file:
		filename = (const char*)buf;

		if (mode == R_MODE_PRINT) {
			print ("define_file\n");
			print ("filename %s\n", filename);
		}

		buf += (strlen (filename) + 1);
		ut64 dir_idx;
		ut64 ignore;
		if (buf + 1 < buf_end) {
			buf = r_uleb128 (buf, buf_end - buf, &dir_idx, NULL);
		}
		if (buf + 1 < buf_end) {
			buf = r_uleb128 (buf, buf_end - buf, &ignore, NULL);
		}
		if (buf + 1 < buf_end) {
			buf = r_uleb128 (buf, buf_end - buf, &ignore, NULL);
		}
		break;
	case DW_LNE_set_discriminator:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		if (mode == R_MODE_PRINT) {
			print ("set Discriminator to %"PFMT64d"\n", addr);
		}
		regs->discriminator = addr;
		break;
	default:
		if (mode == R_MODE_PRINT) {
			print ("Unexpected ext opcode %d\n", opcode);
		}
		buf = NULL;
		break;
	}

	return buf;
}

static const ut8 *parse_spec_opcode(
	const RBin *bin, const ut8 *obuf, size_t len,
	const RBinDwarfLineHeader *hdr,
	RBinDwarfSMRegisters *regs,
	ut8 opcode, int mode) {

	r_return_val_if_fail (bin && obuf && hdr && regs, NULL);

	PrintfCallback print = bin->cb_printf;
	RBinFile *binfile = bin->cur;
	const ut8 *buf = obuf;
	ut8 adj_opcode = 0;
	ut64 advance_adr;

	adj_opcode = opcode - hdr->opcode_base;
	if (!hdr->line_range) {
		// line line-range information. move away
		return NULL;
	}
	advance_adr = (adj_opcode / hdr->line_range) * hdr->min_inst_len;
	regs->address += advance_adr;
	int line_increment =  hdr->line_base + (adj_opcode % hdr->line_range);
	regs->line += line_increment;
	if (mode == R_MODE_PRINT) {
		print ("  Special opcode %d: ", adj_opcode);
		print ("advance Address by %"PFMT64d" to 0x%"PFMT64x" and Line by %d to %"PFMT64d"\n",
			advance_adr, regs->address, line_increment, regs->line);
	}
	if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
		int idx = regs->file -1;
		if (idx >= 0 && idx < hdr->file_names_count) {
			add_sdb_addrline (binfile->sdb_addrinfo, regs->address,
					hdr->file_names[idx].name,
					regs->line, mode, print);
		}
	}
	regs->basic_block = DWARF_FALSE;
	regs->prologue_end = DWARF_FALSE;
	regs->epilogue_begin = DWARF_FALSE;
	regs->discriminator = 0;

	return buf;
}

static const ut8 *parse_std_opcode(
	const RBin *bin, const ut8 *obuf, size_t len,
	const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs,
	ut8 opcode, int mode) {

	r_return_val_if_fail (bin && bin->cur && obuf && hdr && regs, NULL);

	PrintfCallback print = bin->cb_printf;
	RBinFile *binfile = bin->cur;
	const ut8* buf = obuf;
	const ut8* buf_end = obuf + len;
	ut64 addr = 0LL;
	st64 sbuf;
	ut8 adj_opcode;
	ut64 op_advance;
	ut16 operand;

	if (mode == R_MODE_PRINT) {
		print ("  "); // formatting
	}
	switch (opcode) {
	case DW_LNS_copy:
		if (mode == R_MODE_PRINT) {
			print ("Copy\n");
		}
		if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
			int fnidx = regs->file - 1;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline (binfile->sdb_addrinfo,
					regs->address,
					hdr->file_names[fnidx].name,
					regs->line, mode, print);
			}
		}
		regs->basic_block = DWARF_FALSE;
		break;
	case DW_LNS_advance_pc:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		regs->address += addr * hdr->min_inst_len;
		if (mode == R_MODE_PRINT) {
			print ("Advance PC by %"PFMT64d" to 0x%"PFMT64x"\n",
				addr * hdr->min_inst_len, regs->address);
		}
		break;
	case DW_LNS_advance_line:
		buf = r_leb128(buf, buf_end - buf, &sbuf);
		regs->line += sbuf;
		if (mode == R_MODE_PRINT) {
			print ("Advance line by %"PFMT64d", to %"PFMT64d"\n", sbuf, regs->line);
		}
		break;
	case DW_LNS_set_file:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		if (mode == R_MODE_PRINT) {
			print ("Set file to %"PFMT64d"\n", addr);
		}
		regs->file = addr;
		break;
	case DW_LNS_set_column:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		if (mode == R_MODE_PRINT) {
			print ("Set column to %"PFMT64d"\n", addr);
		}
		regs->column = addr;
		break;
	case DW_LNS_negate_stmt:
		regs->is_stmt = regs->is_stmt ? DWARF_FALSE : DWARF_TRUE;
		if (mode == R_MODE_PRINT) {
			print ("Set is_stmt to %d\n", regs->is_stmt);
		}
		break;
	case DW_LNS_set_basic_block:
		if (mode == R_MODE_PRINT) {
			print ("set_basic_block\n");
		}
		regs->basic_block = DWARF_TRUE;
		break;
	case DW_LNS_const_add_pc:
		adj_opcode = 255 - hdr->opcode_base;
		if (hdr->line_range > 0) { // to dodge division by zero
			op_advance = (adj_opcode / hdr->line_range) * hdr->min_inst_len;
		} else {
			op_advance = 0;
		}
		regs->address += op_advance;
		if (mode == R_MODE_PRINT) {
			print ("Advance PC by constant %"PFMT64d" to 0x%"PFMT64x"\n",
				op_advance, regs->address);
		}
		break;
	case DW_LNS_fixed_advance_pc:
		operand = READ16 (buf);
		regs->address += operand;
		if (mode == R_MODE_PRINT) {
			print ("Fixed advance pc to %"PFMT64d"\n", regs->address);
		}
		break;
	case DW_LNS_set_prologue_end:
		regs->prologue_end = ~0;
		if (mode == R_MODE_PRINT) {
			print ("set_prologue_end\n");
		}
		break;
	case DW_LNS_set_epilogue_begin:
		regs->epilogue_begin = ~0;
		if (mode == R_MODE_PRINT) {
			print ("set_epilogue_begin\n");
		}
		break;
	case DW_LNS_set_isa:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		regs->isa = addr;
		if (mode == R_MODE_PRINT) {
			print ("set_isa\n");
		}
		break;
	default:
		if (mode == R_MODE_PRINT) {
			print ("Unexpected std opcode %d\n", opcode);
		}
		break;
	}
	return buf;
}

static void set_regs_default(const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs) {
	regs->address = 0;
	regs->file = 1;
	regs->line = 1;
	regs->column = 0;
	regs->is_stmt = hdr->default_is_stmt;
	regs->basic_block = DWARF_FALSE;
	regs->end_sequence = DWARF_FALSE;
	regs->prologue_end = DWARF_FALSE;
	regs->epilogue_begin = DWARF_FALSE;
	regs->isa = 0;
}

// Passing bin should be unnecessary (after we stop printing inside bin_dwarf)
static size_t parse_opcodes(const RBin *bin, const ut8 *obuf,
		size_t len, const RBinDwarfLineHeader *hdr,
		RBinDwarfSMRegisters *regs, int mode) {
	const ut8 *buf, *buf_end;
	ut8 opcode, ext_opcode;

	if (!bin || !obuf || len < 8) {
		return 0;
	}
	buf = obuf;
	buf_end = obuf + len;

	while (buf && buf + 1 < buf_end) {
		opcode = *buf++;
		len--;
		if (!opcode) {
			ext_opcode = *buf;
			buf = parse_ext_opcode (bin, buf, len, hdr, regs, mode);
			if (!buf || ext_opcode == DW_LNE_end_sequence) {
				set_regs_default (hdr, regs); // end_sequence should reset regs to default
				break;
			}
		} else if (opcode >= hdr->opcode_base) {
			buf = parse_spec_opcode (bin, buf, len, hdr, regs, opcode, mode);
		} else {
			buf = parse_std_opcode (bin, buf, len, hdr, regs, opcode, mode);
		}
		len = (size_t)(buf_end - buf);
	}
	if (mode == R_MODE_PRINT) {
		bin->cb_printf ("\n"); // formatting of the output
	}
	if (!buf) {
		return 0;
	}
	return (size_t) (buf - obuf); // number of bytes we've moved by
}

static int parse_line_raw(const RBin *a, const ut8 *obuf,
				       ut64 len, int mode) {

	RBinFile *binfile = a ? a->cur : NULL;
	r_return_val_if_fail(binfile && obuf, false);
	PrintfCallback print = a->cb_printf;

	if (mode == R_MODE_PRINT) {
		print ("Raw dump of debug contents of section .debug_line:\n\n");
	}
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;
	const ut8 *tmpbuf = NULL;

	RBinDwarfLineHeader hdr = { 0 };
	ut64 buf_size;

	// each iteration we read one header AKA comp. unit
	while (buf <= buf_end) {
		// How much did we read from the compilation unit
		size_t bytes_read = 0;
		// calculate how much we've read by parsing header
		// because header unit_length includes itself
		buf_size = buf_end - buf;

		tmpbuf = buf;
		buf = parse_line_header (a->cur, buf, buf_end, &hdr, mode, print);
		if (!buf) {
			return false;
		}

		if (mode == R_MODE_PRINT) {
			print (" Line Number Statements:\n");
		}
		bytes_read = buf - tmpbuf;

		RBinDwarfSMRegisters regs;
		set_regs_default (&hdr, &regs);

		// If there is more bytes in the buffer than size of the header
		// It means that there has to be another header/comp.unit
		if (buf_size > hdr.unit_length) {
			buf_size = hdr.unit_length + (hdr.is_64bit * 8 + 4); // we dif against bytes_read, but
				// unit_length doesn't account unit_length field
		}
		// this deals with a case that there is compilation unit with any line information
		if (buf_size == bytes_read) {
			if (mode == R_MODE_PRINT) {
				print (" Line table is present, but no lines present\n");
			}
			line_header_fini (&hdr);
			continue;
		}
		if (buf_size > (buf_end - buf) + bytes_read || buf > buf_end) {
			line_header_fini (&hdr);
			return false;
		}
		size_t tmp_read = 0;
		// we read the whole compilation unit (that might be composed of more sequences)
		do {
			// reads one whole sequence
			tmp_read = parse_opcodes (a, buf, buf_end - buf, &hdr, &regs, mode);
			bytes_read += tmp_read;
			buf += tmp_read; // Move in the buffer forward
		} while (bytes_read < buf_size && tmp_read != 0); // if nothing is read -> error, exit

		line_header_fini (&hdr);
		if (!tmp_read) {
			return false;
		}
	}
	return true;
}

#define READ_BUF(x,y) if (idx+sizeof(y)>=len) { return false;} \
	(x)=*(y*)buf; idx+=sizeof(y);buf+=sizeof(y)

#define READ_BUF64(x) if (idx+sizeof(ut64)>=len) { return false;} \
	(x)=r_read_ble64(buf, big_end); idx+=sizeof(ut64);buf+=sizeof(ut64)
#define READ_BUF32(x) if (idx+sizeof(ut32)>=len) { return false;} \
	(x)=r_read_ble32(buf, big_end); idx+=sizeof(ut32);buf+=sizeof(ut32)
#define READ_BUF16(x) if (idx+sizeof(ut16)>=len) { return false;} \
	(x)=r_read_ble16(buf, big_end); idx+=sizeof(ut16);buf+=sizeof(ut16)

static int parse_aranges_raw(const ut8 *obuf, int len, int mode, PrintfCallback print) {
	ut32 length, offset;
	ut16 version;
	ut32 debug_info_offset;
	ut8 address_size, segment_size;
	const ut8 *buf = obuf;
	int idx = 0;

	if (!buf || len< 4) {
		return false;
	}

	READ_BUF32 (length);
	if (mode == R_MODE_PRINT) {
		print ("parse_aranges\n");
		print ("length 0x%x\n", length);
	}

	if (idx + 12 >= len) {
		return false;
	}

	READ_BUF16 (version);
	if (mode == R_MODE_PRINT) {
		print("Version %d\n", version);
	}

	READ_BUF32 (debug_info_offset);
	if (mode == R_MODE_PRINT) {
		print ("Debug info offset %d\n", debug_info_offset);
	}

	READ_BUF (address_size, ut8);
	if (mode == R_MODE_PRINT) {
		print ("address size %d\n", (int)address_size);
	}

	READ_BUF (segment_size, ut8);
	if (mode == R_MODE_PRINT) {
		print ("segment size %d\n", (int)segment_size);
	}

	offset = segment_size + address_size * 2;

	if (offset) {
		ut64 n = (((ut64) (size_t)buf / offset) + 1) * offset - ((ut64)(size_t)buf);
		if (idx+n>=len) {
			return false;
		}
		buf += n;
		idx += n;
	}

	while ((buf - obuf) < len) {
		ut64 adr, length;
		if ((idx+8)>=len) {
			break;
		}
		READ_BUF64 (adr);
		READ_BUF64 (length);
		if (mode == R_MODE_PRINT) {
			print ("length 0x%" PFMT64x " address 0x%" PFMT64x "\n", length, adr);
		}
	}

	return 0;
}

static int init_debug_info(RBinDwarfDebugInfo *inf) {
	if (!inf) {
		return -1;
	}
	inf->comp_units = calloc (sizeof (RBinDwarfCompUnit), DEBUG_INFO_CAPACITY);

	inf->lookup_table = ht_up_new0 ();

	if (!inf->comp_units) {
		return -1;
	}

	inf->capacity = DEBUG_INFO_CAPACITY;
	inf->count = 0;
	return true;
}

static int init_die(RBinDwarfDie *die, ut64 abbr_code, ut64 attr_count) {
	if (!die) {
		return -1;
	}
	die->attr_values = calloc (sizeof (RBinDwarfAttrValue), attr_count);
	if (!die->attr_values) {
		return -1;
	}
	die->abbrev_code = abbr_code;
	die->capacity = attr_count;
	die->count = 0;
	return 0;
}

static int init_comp_unit(RBinDwarfCompUnit *cu) {
	if (!cu) {
		return -EINVAL;
	}
	cu->dies = calloc (sizeof (RBinDwarfDie), COMP_UNIT_CAPACITY);
	if (!cu->dies) {
		return -ENOMEM;
	}
	cu->capacity = COMP_UNIT_CAPACITY;
	cu->count = 0;
	return 0;
}

static int expand_cu(RBinDwarfCompUnit *cu) {
	RBinDwarfDie *tmp;

	if (!cu || cu->capacity == 0 || cu->capacity != cu->count) {
		return -EINVAL;
	}

	tmp = (RBinDwarfDie *)realloc (cu->dies,
		cu->capacity * 2 * sizeof (RBinDwarfDie));
	if (!tmp) {
		return -ENOMEM;
	}

	memset ((ut8 *)tmp + cu->capacity * sizeof (RBinDwarfDie),
		0, cu->capacity * sizeof (RBinDwarfDie));
	cu->dies = tmp;
	cu->capacity *= 2;

	return 0;
}

static int init_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	if (!ad) {
		return -EINVAL;
	}
	ad->defs = calloc (sizeof (RBinDwarfAttrDef), ABBREV_DECL_CAP);

	if (!ad->defs) {
		return -ENOMEM;
	}

	ad->capacity = ABBREV_DECL_CAP;
	ad->count = 0;

	return 0;
}

static int expand_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	RBinDwarfAttrDef *tmp;

	if (!ad || !ad->capacity || ad->capacity != ad->count) {
		return -EINVAL;
	}

	tmp = (RBinDwarfAttrDef *)realloc (ad->defs,
		ad->capacity * 2 * sizeof (RBinDwarfAttrDef));

	if (!tmp) {
		return -ENOMEM;
	}

	// Set the area in the buffer past the length to 0
	memset ((ut8 *)tmp + ad->capacity * sizeof (RBinDwarfAttrDef),
		0, ad->capacity * sizeof (RBinDwarfAttrDef));
	ad->defs = tmp;
	ad->capacity *= 2;

	return 0;
}

static int init_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	if (!da) {
		return -EINVAL;
	}
	da->decls = calloc (sizeof (RBinDwarfAbbrevDecl), DEBUG_ABBREV_CAP);
	if (!da->decls) {
		return -ENOMEM;
	}
	da->capacity = DEBUG_ABBREV_CAP;
	da->count = 0;

	return 0;
}

static int expand_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	RBinDwarfAbbrevDecl *tmp;

	if (!da || da->capacity == 0 || da->capacity != da->count) {
		return -EINVAL;
	}

	tmp = (RBinDwarfAbbrevDecl *)realloc (da->decls,
		da->capacity * 2 * sizeof (RBinDwarfAbbrevDecl));

	if (!tmp) {
		return -ENOMEM;
	}
	memset ((ut8 *)tmp + da->capacity * sizeof (RBinDwarfAbbrevDecl),
		0, da->capacity * sizeof (RBinDwarfAbbrevDecl));

	da->decls = tmp;
	da->capacity *= 2;

	return 0;
}

static void print_abbrev_section(RBinDwarfDebugAbbrev *da, PrintfCallback print) {
	size_t i, j;
	ut64 attr_name, attr_form;

	if (!da) {
		return;
	}
	for (i = 0; i < da->count; i++) {
		int declstag = da->decls[i].tag;
		print ("   %-4"PFMT64d" ", da->decls[i].code);
		if (declstag>=0 && declstag < DW_TAG_LAST) {
			print ("  %-25s ", dwarf_tag_name_encodings[declstag]);
		}
		print ("[%s]", da->decls[i].has_children ?
				"has children" : "no children");
		print (" (0x%"PFMT64x")\n", da->decls[i].offset);

		if (da->decls[i].defs) {
			for (j = 0; j < da->decls[i].count; j++) {
				attr_name = da->decls[i].defs[j].attr_name;
				attr_form = da->decls[i].defs[j].attr_form;
				if (is_printable_attr(attr_name) && is_printable_form(attr_form)) {
					print ("    %-30s %-30s\n",
							dwarf_attr_encodings[attr_name],
							dwarf_attr_form_encodings[attr_form]);
				}
			}
		}
	}
}

R_API void r_bin_dwarf_free_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	size_t i;
	if (!da) {
		return;
	}
	for (i = 0; i < da->count; i++) {
		R_FREE (da->decls[i].defs);
	}
	R_FREE (da->decls);
	free (da);
}

static void free_attr_value(RBinDwarfAttrValue *val) {
	// TODO adjust to new forms, now we're leaking
	if (!val) {
		return;
	}
	switch (val->attr_form) {
	case DW_FORM_strp:
	case DW_FORM_string:
		R_FREE (val->string.content);
		break;
	case DW_FORM_exprloc:
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
		R_FREE (val->block.data);
		break;
	default:
		break;
	};
}

static void free_die(RBinDwarfDie *die) {
	size_t i;
	if (!die) {
		return;
	}
	for (i = 0; i < die->count; i++) {
		free_attr_value (&die->attr_values[i]);
	}
	R_FREE (die->attr_values);
}

static void free_comp_unit(RBinDwarfCompUnit *cu) {
	size_t i;
	if (!cu) {
		return;
	}
	for (i = 0; i < cu->count; i++) {
		if (cu->dies) {
			free_die (&cu->dies[i]);
		}
	}
	R_FREE (cu->dies);
}

R_API void r_bin_dwarf_free_debug_info(RBinDwarfDebugInfo *inf) {
	size_t i;
	if (!inf) {
		return;
	}
	for (i = 0; i < inf->count; i++) {
		free_comp_unit (&inf->comp_units[i]);
	}
	ht_up_free (inf->lookup_table);
	free (inf->comp_units);
	free(inf);
}

static void print_attr_value(const RBinDwarfAttrValue *val, PrintfCallback print) {
	size_t i;
	r_return_if_fail(val);

	switch (val->attr_form) {
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_exprloc:
		print ("%"PFMT64u" byte block:", val->block.length);
		for (i = 0; i < val->block.length; i++) {
			print (" 0x%02x", val->block.data[i]);
		}
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_data16:
		print ("%"PFMT64u"", val->uconstant);
		if (val->attr_name == DW_AT_language) {
			print ("   (%s)", dwarf_langs[val->uconstant]);
		}
		break;
	case DW_FORM_string:
		if (val->string.content) {
			print ("%s", val->string.content);
		} else {
			print ("No string found");
		}
		break;
	case DW_FORM_flag:
		print ("%u", val->flag);
		break;
	case DW_FORM_sdata:
		print ("%"PFMT64d"", val->sconstant);
		break;
	case DW_FORM_udata:
		print ("%"PFMT64u"", val->uconstant);
		break;
	case DW_FORM_ref_addr:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_ref_sig8:
	case DW_FORM_ref_udata:
	case DW_FORM_ref_sup4:
	case DW_FORM_ref_sup8:
	case DW_FORM_sec_offset:
		print ("<0x%"PFMT64x">", val->reference);
		break;
	case DW_FORM_flag_present:
		print ("1");
		break;
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_ptr:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
		print ("(indirect string, offset: 0x%"PFMT64x"): %s",
			val->string.offset, val->string.content);
		break;
	case DW_FORM_addr:
	case DW_FORM_addrx:
	case DW_FORM_addrx1:
	case DW_FORM_addrx2:
	case DW_FORM_addrx3:
	case DW_FORM_addrx4:
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		print ("0x%"PFMT64x"", val->address);
		break;
	case DW_FORM_implicit_const:
		print ("0x%"PFMT64d"", val->uconstant);
		break;
	default:
		print ("Unknown attr value form %"PFMT64d"\n", val->attr_form);
		break;
	};
}

static void print_debug_info(const RBinDwarfDebugInfo *inf, PrintfCallback print) {
	size_t i, j, k;
	RBinDwarfDie *dies;
	RBinDwarfAttrValue *values;

	r_return_if_fail(inf);

	for (i = 0; i < inf->count; i++) {
		print ("\n");
		print ("  Compilation Unit @ offset 0x%" PFMT64x ":\n", inf->comp_units[i].offset);
		print ("   Length:        0x%" PFMT64x "\n", inf->comp_units[i].hdr.length);
		print ("   Version:       %d\n", inf->comp_units[i].hdr.version);
		print ("   Abbrev Offset: 0x%" PFMT64x "\n", inf->comp_units[i].hdr.abbrev_offset);
		print ("   Pointer Size:  %d\n", inf->comp_units[i].hdr.address_size);
		if (is_printable_unit_type(inf->comp_units[i].hdr.unit_type)) {
			print ("   Unit Type:     %s\n", dwarf_unit_types[inf->comp_units[i].hdr.unit_type]);
		}
		print ("\n");

		dies = inf->comp_units[i].dies;

		for (j = 0; j < inf->comp_units[i].count; j++) {
			print ("<0x%"PFMT64x">: Abbrev Number: %-4" PFMT64u " ", dies[j].offset,dies[j].abbrev_code);

			if (is_printable_tag (dies[j].tag)) {
				print ("(%s)\n", dwarf_tag_name_encodings[dies[j].tag]);
			} else {
				print ("(Unknown abbrev tag)\n");
			}

			if (!dies[j].abbrev_code) {
				continue;
			}
			values = dies[j].attr_values;

			for (k = 0; k < dies[j].count; k++) {
				if (!values[k].attr_name) {
					continue;
				}
				if (is_printable_attr (values[k].attr_name)) {
					print ("     %-25s : ", dwarf_attr_encodings[values[k].attr_name]);
				} else {
					print ("     AT_UNKWN [0x%-3" PFMT64x "]\t : ", values[k].attr_name);
				}
				print_attr_value (&values[k], print);
				print ("\n");
			}
		}
	}
}

static const ut8 *fill_block_data(const ut8 *buf, const ut8 *buf_end, RBinDwarfBlock *block) {
	block->data = calloc (sizeof (ut8), block->length);
	if (!block->data) {
		return NULL;
	}
	/* Maybe unroll this as an optimization in future? */
	if (block->data) {
		size_t j = 0;
		for (j = 0; j < block->length; j++) {
			block->data[j] = READ (buf, ut8);
		}
	}
	return buf;
}

/**
 * This function is quite incomplete and requires lot of work
 * With parsing various new FORM values
 * @brief Parses attribute value based on its definition
 *        and stores it into `value`
 *
 * @param obuf
 * @param obuf_len Buffer max capacity
 * @param def Attribute definition
 * @param value Parsed value storage
 * @param hdr Current unit header
 * @param debug_str Ptr to string section start
 * @param debug_str_len Length of the string section
 * @return const ut8* Updated buffer
 */
static const ut8 *parse_attr_value(const ut8 *obuf, int obuf_len,
		RBinDwarfAttrDef *def, RBinDwarfAttrValue *value,
		const RBinDwarfCompUnitHdr *hdr,
		const ut8 *debug_str, size_t debug_str_len) {

	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + obuf_len;
	size_t j;

	r_return_val_if_fail(def && value && hdr && obuf && obuf_len >= 1, NULL);

	value->attr_form = def->attr_form;
	value->attr_name = def->attr_name;
	value->block.data = NULL;
	value->string.content = NULL;
	value->string.offset = 0;

	// http://www.dwarfstd.org/doc/DWARF4.pdf#page=161&zoom=100,0,560
	switch (def->attr_form) {
	case DW_FORM_addr:
		value->kind = DW_AT_KIND_ADDRESS;
		switch (hdr->address_size) {
		case 1:
			value->address = READ8 (buf);
			break;
		case 2:
			value->address = READ16 (buf);
			break;
		case 4:
			value->address = READ32 (buf);
			break;
		case 8:
			value->address = READ64 (buf);
			break;
		default:
			eprintf ("DWARF: Unexpected pointer size: %u\n", (unsigned)hdr->address_size);
			return NULL;
		}
		break;
	case DW_FORM_data1:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ8 (buf);
		break;
	case DW_FORM_data2:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ16 (buf);
		break;
	case DW_FORM_data4:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ32 (buf);
		break;
	case DW_FORM_data8:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ64 (buf);
		break;
	case DW_FORM_data16: // TODO Fix this, right now I just read the data, but I need to make storage for it
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ64 (buf);
		value->uconstant = READ64 (buf);
		break;
	case DW_FORM_sdata:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = r_leb128 (buf, buf_end - buf, &value->sconstant);
		break;
	case DW_FORM_udata:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = r_uleb128 (buf, buf_end - buf, &value->uconstant, NULL);
		break;
	case DW_FORM_string:
		value->kind = DW_AT_KIND_STRING;
		value->string.content = *buf ? strdup ((const char *)buf) : NULL;
		buf += (strlen ((const char *)buf) + 1);
		break;
	case DW_FORM_block1:
		value->kind = DW_AT_KIND_BLOCK;
		value->block.length = READ8 (buf);
		buf = fill_block_data (buf, buf_end, &value->block);
		break;
	case DW_FORM_block2:
		value->kind = DW_AT_KIND_BLOCK;
		value->block.length = READ16 (buf);
		if (value->block.length > 0) {
			value->block.data = calloc (sizeof (ut8), value->block.length);
			if (!value->block.data) {
				return NULL;
			}
			for (j = 0; j < value->block.length; j++) {
				value->block.data[j] = READ (buf, ut8);
			}
		}
		break;
	case DW_FORM_block4:
		value->kind = DW_AT_KIND_BLOCK;
		value->block.length = READ32 (buf);
		buf = fill_block_data (buf, buf_end, &value->block);
		break;
	case DW_FORM_block: // variable length ULEB128
		value->kind = DW_AT_KIND_BLOCK;
		buf = r_uleb128 (buf, buf_end - buf, &value->block.length, NULL);
		if (!buf || buf >= buf_end) {
			return NULL;
		}
		buf = fill_block_data (buf, buf_end, &value->block);
		break;
	case DW_FORM_flag:
		value->kind = DW_AT_KIND_FLAG;
		value->flag = READ (buf, ut8);
		break;
	// offset in .debug_str
	case DW_FORM_strp:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = dwarf_read_offset(hdr->is_64bit, &buf, buf_end);
		if (debug_str && value->string.offset < debug_str_len) {
			value->string.content =
				strdup ((const char *)(debug_str + value->string.offset));
		} else {
			value->string.content = NULL; // Means malformed DWARF, should we print error message?
		}
		break;
	// offset in .debug_info
	case DW_FORM_ref_addr:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = dwarf_read_offset(hdr->is_64bit, &buf, buf_end);
		break;
	// This type of reference is an offset from the first byte of the compilation
	// header for the compilation unit containing the reference
	case DW_FORM_ref1:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = hdr->unit_offset + READ8 (buf);
		break;
	case DW_FORM_ref2:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = hdr->unit_offset + READ16 (buf);
		break;
	case DW_FORM_ref4:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = hdr->unit_offset + READ32 (buf);
		break;
	case DW_FORM_ref8:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = hdr->unit_offset + READ64 (buf);
		break;
	case DW_FORM_ref_udata:
		value->kind = DW_AT_KIND_REFERENCE;
		// uleb128 is enough to fit into ut64?
		buf = r_uleb128 (buf, buf_end - buf, &value->reference, NULL);
		value->reference += hdr->unit_offset;
		break;
	// offset in a section other than .debug_info or .debug_str
	case DW_FORM_sec_offset:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = dwarf_read_offset(hdr->is_64bit, &buf, buf_end);
		break;
	case DW_FORM_exprloc:
		value->kind = DW_AT_KIND_BLOCK;
		buf = r_uleb128 (buf, buf_end - buf, &value->block.length, NULL);
		if (!buf || buf >= buf_end) {
			return NULL;
		}
		buf = fill_block_data (buf, buf_end, &value->block);
		break;
	// this means that the flag is present, nothing is read
	case DW_FORM_flag_present:
		value->kind = DW_AT_KIND_FLAG;
		value->flag = true;
		break;
	case DW_FORM_ref_sig8:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = READ64 (buf);
		break;
	// offset into .debug_line_str section, can't parse the section now, so we just skip
	case DW_FORM_strx:
		value->kind = DW_AT_KIND_STRING;
		// value->string.offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end);
		// if (debug_str && value->string.offset < debug_line_str_len) {
		// 	value->string.content =
		// 		strdup ((const char *)(debug_str + value->string.offset));
		// } else {
		// 	value->string.content = NULL; // Means malformed DWARF, should we print error message?
		// }
		break;
	case DW_FORM_strx1:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = READ8 (buf);
		break;
	case DW_FORM_strx2:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = READ16 (buf);
		break;
	case DW_FORM_strx3: // TODO Add 3 byte int read
		value->kind = DW_AT_KIND_STRING;
		buf += 3;
		break;
	case DW_FORM_strx4:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = READ32 (buf);
		break;
	case DW_FORM_implicit_const:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = def->special;
		break;
	/*  addrx* forms : The index is relative to the value of the
		DW_AT_addr_base attribute of the associated compilation unit.
	    index into an array of addresses in the .debug_addr section.*/
	case DW_FORM_addrx:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = r_uleb128 (buf, buf_end - buf, &value->address, NULL);
		break;
	case DW_FORM_addrx1:
		value->kind = DW_AT_KIND_ADDRESS;
		value->address = READ8 (buf);
		break;
	case DW_FORM_addrx2:
		value->kind = DW_AT_KIND_ADDRESS;
		value->address = READ16 (buf);
		break;
	case DW_FORM_addrx3:
		// I need to add 3byte endianess free read here TODO
		value->kind = DW_AT_KIND_ADDRESS;
		buf += 3;
		break;
	case DW_FORM_addrx4:
		value->kind = DW_AT_KIND_ADDRESS;
		value->address = READ32 (buf);
		break;
	case DW_FORM_line_ptr: // offset in a section .debug_line_str
	case DW_FORM_strp_sup: // offset in a section .debug_line_str
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end);
		// if (debug_str && value->string.offset < debug_line_str_len) {
		// 	value->string.content =
		// 		strdupsts
		break;
	// offset in the supplementary object file
	case DW_FORM_ref_sup4:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = READ32 (buf);
		break;
	case DW_FORM_ref_sup8:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = READ64 (buf);
		break;
	// An index into the .debug_loc
	case DW_FORM_loclistx:
		value->kind = DW_AT_KIND_LOCLISTPTR;
		value->reference = dwarf_read_offset (hdr->is_64bit, &buf, buf_end);
		break;
	 // An index into the .debug_rnglists
	case DW_FORM_rnglistx:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = r_uleb128 (buf, buf_end - buf, &value->address, NULL);
		break;
	default:
		eprintf ("Unknown DW_FORM 0x%02" PFMT64x "\n", def->attr_form);
		value->uconstant = 0;
		return NULL;
	}
	return buf;
}

/**
 * @brief
 *
 * @param buf Start of the DIE data
 * @param buf_end
 * @param abbrev Abbreviation of the DIE
 * @param hdr Unit header
 * @param die DIE to store the parsed info into
 * @param debug_str Ptr to string section start
 * @param debug_str_len Length of the string section
 * @param sdb
 * @return const ut8* Updated buffer
 */
static const ut8 *parse_die(const ut8 *buf, const ut8 *buf_end, RBinDwarfAbbrevDecl *abbrev,
		RBinDwarfCompUnitHdr *hdr, RBinDwarfDie *die, const ut8 *debug_str, size_t debug_str_len, Sdb *sdb) {
	size_t i;
	for (i = 0; i < abbrev->count - 1; i++) {
		memset (&die->attr_values[i], 0, sizeof (die->attr_values[i]));

		buf = parse_attr_value (buf, buf_end - buf, &abbrev->defs[i],
			&die->attr_values[i], hdr, debug_str, debug_str_len);

		RBinDwarfAttrValue *attribute = &die->attr_values[i];

		bool is_valid_string_form = (attribute->attr_form == DW_FORM_strp ||
			attribute->attr_form == DW_FORM_string) &&
			attribute->string.content;
		// TODO  does this have a purpose anymore?
		// Or atleast it needs to rework becase there will be
		// more comp units -> more comp dirs and only the last one will be kept
		if (attribute->attr_name == DW_AT_comp_dir && is_valid_string_form) {
			const char *name = attribute->string.content;
			sdb_set (sdb, "DW_AT_comp_dir", name, 0);
		}
		die->count++;
	}

	return buf;
}

/**
 * @brief Reads throught comp_unit buffer and parses all its DIEntries
 *
 * @param sdb
 * @param buf_start Start of the compilation unit data
 * @param unit Unit to store the newly parsed information
 * @param abbrevs Parsed abbrev section info of *all* abbreviations
 * @param first_abbr_idx index for first abbrev of the current comp unit in abbrev array
 * @param debug_str Ptr to string section start
 * @param debug_str_len Length of the string section
 *
 * @return const ut8* Update buffer
 */
static const ut8 *parse_comp_unit(RBinDwarfDebugInfo *info, Sdb *sdb, const ut8 *buf_start,
		RBinDwarfCompUnit *unit, const RBinDwarfDebugAbbrev *abbrevs,
		size_t first_abbr_idx, const ut8 *debug_str, size_t debug_str_len) {

	const ut8 *buf = buf_start;
	const ut8 *buf_end = buf_start + unit->hdr.length - unit->hdr.header_size;

	while (buf && buf < buf_end && buf >= buf_start) {
		if (unit->count && unit->capacity == unit->count) {
			expand_cu (unit);
		}
		RBinDwarfDie *die = &unit->dies[unit->count];
		// add header size to the offset;
		die->offset = buf - buf_start + unit->hdr.header_size + unit->offset;
		die->offset += unit->hdr.is_64bit ? 12 : 4;

		// DIE starts with ULEB128 with the abbreviation code
		ut64 abbr_code;
		buf = r_uleb128 (buf, buf_end - buf, &abbr_code, NULL);

		if (abbr_code > abbrevs->count || !buf) { // something invalid
			return NULL;
		}

		if (buf >= buf_end) {
			unit->count++; // we wanna store this entry too, usually the last one is null_entry
			return buf; // return the buffer to parse next compilation units
		}
		// there can be "null" entries that have abbr_code == 0
		if (!abbr_code) {
			unit->count++;
			continue;
		}
		ut64 abbr_idx = first_abbr_idx + abbr_code;

		if (abbrevs->count < abbr_idx) {
			return NULL;
		}
		RBinDwarfAbbrevDecl *abbrev = &abbrevs->decls[abbr_idx - 1];

		if (init_die (die, abbr_code, abbrev->count)) {
			return NULL; // error
		}
		die->tag = abbrev->tag;
		die->has_children = abbrev->has_children;

		buf = parse_die (buf, buf_end, abbrev, &unit->hdr, die, debug_str, debug_str_len, sdb);
		if (!buf) {
			return NULL;
		}

		unit->count++;
	}
	return buf;
}

/**
 * @brief Reads all information about compilation unit header
 *
 * @param buf Start of the buffer
 * @param buf_end Upper bound of the buffer
 * @param unit Unit to read information into
 * @return ut8* Advanced position in a buffer
 */
static const ut8 *info_comp_unit_read_hdr(const ut8 *buf, const ut8 *buf_end, RBinDwarfCompUnitHdr *hdr) {
	// 32-bit vs 64-bit dwarf formats
	// http://www.dwarfstd.org/doc/Dwarf3.pdf section 7.4
	hdr->length = READ32 (buf);
	if (hdr->length == (ut32)DWARF_INIT_LEN_64) { // then its 64bit
		hdr->length = READ64 (buf);
		hdr->is_64bit = true;
	}
	const ut8 *tmp = buf; // to calculate header size
	hdr->version = READ16 (buf);
	if (hdr->version == 5) {
		hdr->unit_type = READ8 (buf);
		hdr->address_size = READ8 (buf);
		hdr->abbrev_offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end);

		if (hdr->unit_type == DW_UT_skeleton || hdr->unit_type == DW_UT_split_compile) {
			hdr->dwo_id = READ8 (buf);
		} else if (hdr->unit_type == DW_UT_type || hdr->unit_type == DW_UT_split_type) {
			hdr->type_sig = READ64 (buf);
			hdr->type_offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end);
		}
	} else {
		hdr->abbrev_offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end);
		hdr->address_size = READ8 (buf);
	}
	hdr->header_size = buf - tmp; // header size excluding length field
	return buf;
}
static int expand_info(RBinDwarfDebugInfo *info) {
	r_return_val_if_fail (info && info->capacity == info->count, -1);

	RBinDwarfCompUnit *tmp = realloc (info->comp_units,
		info->capacity * 2 * sizeof (RBinDwarfCompUnit));
	if (!tmp) {
		return -1;
	}

	memset ((ut8 *)tmp + info->capacity * sizeof (RBinDwarfCompUnit),
		0, info->capacity * sizeof (RBinDwarfCompUnit));

	info->comp_units = tmp;
	info->capacity *= 2;

	return 0;
}

/**
 * @brief Parses whole .debug_info section
 *
 * @param sdb Sdb to store line related information into
 * @param da Parsed Abbreviations
 * @param obuf .debug_info section buffer start
 * @param len length of the section buffer
 * @param debug_str start of the .debug_str section
 * @param debug_str_len length of the debug_str section
 * @param mode
 * @return R_API* parse_info_raw Parsed information
 */
static RBinDwarfDebugInfo *parse_info_raw(Sdb *sdb, RBinDwarfDebugAbbrev *da,
		const ut8 *obuf, size_t len,
		const ut8 *debug_str, size_t debug_str_len) {

	r_return_val_if_fail (da && sdb && obuf, false);

	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;

	RBinDwarfDebugInfo *info = R_NEW0 (RBinDwarfDebugInfo);
	if (!info) {
		return NULL;
	}
	if (init_debug_info (info) < 0) {
		goto cleanup;
	}
	int unit_idx = 0;

	while (buf < buf_end) {
		if (info->count >= info->capacity) {
			if (expand_info (info)) {
				break;
			}
		}

		RBinDwarfCompUnit *unit = &info->comp_units[unit_idx];
		if (init_comp_unit (unit) < 0) {
			unit_idx--;
			goto cleanup;
		}
		info->count++;

		unit->offset = buf - obuf;
		// small redundancy, because it was easiest solution at a time
		unit->hdr.unit_offset = buf - obuf;

		buf = info_comp_unit_read_hdr (buf, buf_end, &unit->hdr);

		if (unit->hdr.length > len) {
			goto cleanup;
		}

		if (da->decls->count >= da->capacity) {
			eprintf ("WARNING: malformed dwarf have not enough buckets for decls.\n");
		}
		r_warn_if_fail (da->count <= da->capacity);

		// find abbrev start for current comp unit
		// we could also do naive, ((char *)da->decls) + abbrev_offset,
		// but this is more bulletproof to invalid DWARF
		RBinDwarfAbbrevDecl key = { .offset = unit->hdr.abbrev_offset };
		RBinDwarfAbbrevDecl *abbrev_start = bsearch (&key, da->decls, da->count, sizeof (key), abbrev_cmp);
		if (!abbrev_start) {
			goto cleanup;
		}
		// They point to the same array object, so should be def. behaviour
		size_t first_abbr_idx = abbrev_start - da->decls;

		buf = parse_comp_unit (info, sdb, buf, unit, da, first_abbr_idx, debug_str, debug_str_len);

		if (!buf) {
			goto cleanup;
		}

		unit_idx++;
	}

	return info;

cleanup:
	r_bin_dwarf_free_debug_info (info);
	return NULL;
}

static RBinDwarfDebugAbbrev *parse_abbrev_raw(const ut8 *obuf, size_t len) {
	const ut8 *buf = obuf, *buf_end = obuf + len;
	ut64 tmp, attr_code, attr_form, offset;
	st64 special;
	ut8 has_children;
	RBinDwarfAbbrevDecl *tmpdecl;

	// XXX - Set a suitable value here.
	if (!obuf || len < 3) {
		return NULL;
	}
	RBinDwarfDebugAbbrev *da = R_NEW0 (RBinDwarfDebugAbbrev);

	init_debug_abbrev (da);

	while (buf && buf+1 < buf_end) {
		offset = buf - obuf;
		buf = r_uleb128 (buf, (size_t)(buf_end-buf), &tmp, NULL);
		if (!buf || !tmp || buf >= buf_end) {
			continue;
		}
		if (da->count == da->capacity) {
			expand_debug_abbrev(da);
		}
		tmpdecl = &da->decls[da->count];
		init_abbrev_decl (tmpdecl);

		tmpdecl->code = tmp;
		buf = r_uleb128 (buf, (size_t)(buf_end-buf), &tmp, NULL);
		tmpdecl->tag = tmp;

		tmpdecl->offset = offset;
		if (buf >= buf_end) {
			break;
		}
		has_children = READ (buf, ut8);
		tmpdecl->has_children = has_children;
		do {
			if (tmpdecl->count == tmpdecl->capacity) {
				expand_abbrev_decl (tmpdecl);
			}
			buf = r_uleb128 (buf, (size_t)(buf_end - buf), &attr_code, NULL);
			if (buf >= buf_end) {
				break;
			}
			buf = r_uleb128 (buf, (size_t)(buf_end - buf), &attr_form, NULL);
			// http://www.dwarfstd.org/doc/DWARF5.pdf#page=225
			if (attr_form == DW_FORM_implicit_const) {
				buf = r_leb128 (buf, (size_t)(buf_end - buf), &special);
				tmpdecl->defs[tmpdecl->count].special = special;
			}
			tmpdecl->defs[tmpdecl->count].attr_name = attr_code;
			tmpdecl->defs[tmpdecl->count].attr_form = attr_form;
			tmpdecl->count++;
		} while (attr_code && attr_form);

		da->count++;
	}
	return da;
}

RBinSection *getsection(RBin *a, const char *sn) {
	RListIter *iter;
	RBinSection *section = NULL;
	RBinFile *binfile = a ? a->cur: NULL;
	RBinObject *o = binfile ? binfile->o : NULL;

	if ( o && o->sections) {
		r_list_foreach (o->sections, iter, section) {
			if (strstr (section->name, sn)) {
				return section;
			}
		}
	}
	return NULL;
}

static ut8 *get_section_bytes(RBin *bin, const char *sect_name, size_t *len) {
	RBinSection *section = getsection (bin, sect_name);
	RBinFile *binfile = bin ? bin->cur: NULL;
	if (!section || !binfile) {
		return NULL;
	}
	if (section->size > binfile->size) {
		return NULL;
	}
	*len = section->size;
	ut8 *buf = calloc (1,*len);
	r_buf_read_at (binfile->buf, section->paddr, buf, *len);
	return buf;
}

/**
 * @brief Parses .debug_info section
 *
 * @param da Parsed abbreviations
 * @param bin
 * @param mode R_MODE_PRINT to print
 * @return RBinDwarfDebugInfo* Parsed information, NULL if error
 */
R_API RBinDwarfDebugInfo *r_bin_dwarf_parse_info(RBinDwarfDebugAbbrev *da, RBin *bin, int mode) {
	RBinDwarfDebugInfo *info = NULL;
	RBinSection *debug_str;
	RBinSection *section = getsection (bin, "debug_info");
	RBinFile *binfile = bin ? bin->cur : NULL;

	ut64 debug_str_len = 0;
	ut8 *debug_str_buf = NULL;

	if (binfile && section) {
		debug_str = getsection (bin, "debug_str");
		if (debug_str) {
			debug_str_len = debug_str->size;
			debug_str_buf = calloc (1, debug_str_len + 1);
			if (!debug_str_buf) {
				goto cleanup;
			}
			st64 ret = r_buf_read_at (binfile->buf, debug_str->paddr,
				debug_str_buf, debug_str_len);
			if (!ret) {
				goto cleanup;
			}
		}

		ut64 len = section->size;
		// what is this checking for?
		if (len > (UT32_MAX >> 1) || len < 1) {
			goto cleanup;
		}
		ut8 *buf = calloc (1, len);
		if (!buf) {
			goto cleanup;
		}
		if (!r_buf_read_at (binfile->buf, section->paddr, buf, len)) {
			free (buf);
			goto cleanup;
		}
		/* set the endianity global [HOTFIX] */
		big_end = r_bin_is_big_endian (bin);
		info = parse_info_raw (binfile->sdb_addrinfo, da, buf, len,
			debug_str_buf, debug_str_len);

		if (mode == R_MODE_PRINT && info) {
			print_debug_info (info, bin->cb_printf);
		}
		// build hashtable after whole parsing because of possible relocations
		if (info) {
			size_t i, j;
			for (i = 0; i < info->count; i++) {
				RBinDwarfCompUnit *unit = &info->comp_units[i];
				for (j = 0; j < unit->count; j++) {
					RBinDwarfDie *die = &unit->dies[j];
					ht_up_insert (info->lookup_table, die->offset, die); // optimization for further processing}
				}
			}
		}
		free (debug_str_buf);
		free (buf);
		return info;
	}
cleanup:
	free (debug_str_buf);
	return NULL;
}

static RBinDwarfRow *row_new(ut64 addr, const char *file, int line, int col) {
	RBinDwarfRow *row = R_NEW0 (RBinDwarfRow);
	if (!row) {
		return NULL;
	}
	row->file = strdup (file);
	row->address = addr;
	row->line = line;
	row->column = 0;
	return row;
}

static void row_free(void *p) {
	RBinDwarfRow *row = (RBinDwarfRow*)p;
	free (row->file);
	free (row);
}

R_API RList *r_bin_dwarf_parse_line(RBin *bin, int mode) {
	ut8 *buf;
	RList *list = NULL;
	int len, ret;
	RBinSection *section = getsection (bin, "debug_line");
	RBinFile *binfile = bin ? bin->cur: NULL;
	if (binfile && section) {
		len = section->size;
		if (len < 1) {
			return NULL;
		}
		buf = calloc (1, len + 1);
		if (!buf) {
			return NULL;
		}
		ret = r_buf_read_at (binfile->buf, section->paddr, buf, len);
		if (ret != len) {
			free (buf);
			return NULL;
		}
		list = r_list_newf (row_free);
		if (!list) {
			free (buf);
			return NULL;
		}
		/* set the endianity global [HOTFIX] */
		big_end = r_bin_is_big_endian (bin);
		// Actually parse the section
		parse_line_raw (bin, buf, len, mode);
		// k bin/cur/addrinfo/*
		SdbListIter *iter;
		SdbKv *kv;
		SdbList *ls = sdb_foreach_list (binfile->sdb_addrinfo, false);
		// Use the parsed information from _raw and transform it to more useful format
		ls_foreach (ls, iter, kv) {
			if (!strncmp (sdbkv_key (kv), "0x", 2)) {
				ut64 addr;
				RBinDwarfRow *row;
				int line;
				char *file = strdup (sdbkv_value (kv));
				if (!file) {
					free (buf);
					ls_free (ls);
					r_list_free (list);
					return NULL;
				}
				char *tok = strchr (file, '|');
				if (tok) {
					*tok++ = 0;
					line = atoi (tok);
					addr = r_num_math (NULL, sdbkv_key (kv));
					row = row_new (addr, file, line, 0);
					r_list_append (list, row);
				}
				free (file);
			}
		}
		ls_free (ls);
		free (buf);
	}
	return list;
}

R_API RList *r_bin_dwarf_parse_aranges(RBin *bin, int mode) {
	ut8 *buf;
	int ret;
	size_t len;
	RBinSection *section = getsection (bin, "debug_aranges");
	RBinFile *binfile = bin ? bin->cur: NULL;

	if (binfile && section) {
		len = section->size;
		if (len < 1 || len > ST32_MAX) {
			return NULL;
		}
		buf = calloc (1, len);
		ret = r_buf_read_at (binfile->buf, section->paddr, buf, len);
		if (!ret) {
			free (buf);
			return NULL;
		}
		/* set the endianity global [HOTFIX] */
		big_end = r_bin_is_big_endian (bin);
		parse_aranges_raw (buf, len, mode, bin->cb_printf);

		free (buf);
	}
	return NULL;
}

R_API RBinDwarfDebugAbbrev *r_bin_dwarf_parse_abbrev(RBin *bin, int mode) {
	size_t len = 0;
	ut8 *buf = get_section_bytes (bin, "debug_abbrev", &len);
	if (!buf) {
		return NULL;
	}
	RBinDwarfDebugAbbrev *abbrevs = parse_abbrev_raw (buf, len);

	if (mode == R_MODE_PRINT && abbrevs) {
		print_abbrev_section (abbrevs, bin->cb_printf);
	}
	free (buf);
	return abbrevs;
}

static inline ut64 get_max_offset(size_t addr_size) {
	switch (addr_size) {
		case 2:
		return UT16_MAX;
		case 4:
		return UT32_MAX;
		case 8:
		return UT64_MAX;
	}
	return 0;
}

static inline RBinDwarfLocList *create_loc_list(ut64 offset) {
	RBinDwarfLocList *list = R_NEW0 (RBinDwarfLocList);
	if (list) {
		list->list = r_list_new ();
		list->offset = offset;
	}
	return list;
}

static inline RBinDwarfLocRange *create_loc_range(ut64 start, ut64 end, RBinDwarfBlock *block) {
	RBinDwarfLocRange *range = R_NEW0 (RBinDwarfLocRange);
	if (range) {
		range->start = start;
		range->end = end;
		range->expression = block;
	}
	return range;
}

static void free_loc_table_list(RBinDwarfLocList *loc_list) {
	RListIter *iter;
	RBinDwarfLocRange *range;
	r_list_foreach (loc_list->list, iter, range) {
		free (range->expression->data);
		free (range->expression);
		free (range);
	}
	r_list_free (loc_list->list);
	free (loc_list);
}

static HtUP *parse_loc_raw(HtUP/*<offset, List *<LocListEntry>*/ *loc_table, const ut8 *buf, size_t len, size_t addr_size) {
	/* GNU has their own extensions GNU locviews that we can't parse */
	const ut8 *const buf_start = buf;
	const ut8 *buf_end = buf + len;
	/* for recognizing Base address entry */
	ut64 max_offset = get_max_offset (addr_size);

	ut64 address_base = 0; /* remember base of the loclist */
	ut64 list_offset = 0;

	RBinDwarfLocList *loc_list = NULL;
	RBinDwarfLocRange *range = NULL;
	while (buf && buf < buf_end) {
		ut64 start_addr = dwarf_read_address (addr_size, &buf, buf_end);
		ut64 end_addr = dwarf_read_address (addr_size, &buf, buf_end);

		if (start_addr == 0 && end_addr == 0) { /* end of list entry: 0, 0 */
			if (loc_list) {
				ht_up_insert (loc_table, loc_list->offset, loc_list);
				list_offset = buf - buf_start;
				loc_list = NULL;
			}
			address_base = 0;
			continue;
		} else if (start_addr == max_offset && end_addr != max_offset) {
			/* base address, DWARF2 doesn't have this type of entry, these entries shouldn't
			   be in the list, they are just informational entries for further parsing (address_base) */
			address_base = end_addr;
		} else { /* location list entry: */
			if (!loc_list) {
				loc_list = create_loc_list (list_offset);
			}
			/* TODO in future parse expressions to better structure in dwarf.c and not in dwarf_process.c */
			RBinDwarfBlock *block = R_NEW0 (RBinDwarfBlock);
			block->length = READ16 (buf);
			buf = fill_block_data (buf, buf_end, block);
			range = create_loc_range (start_addr + address_base, end_addr + address_base, block);
			r_list_append (loc_list->list, range);
			range = NULL;
		}
	}
	/* if for some reason end of list is missing, then loc_list would leak */
	if (loc_list) {
		free_loc_table_list (loc_list);
	}
	return loc_table;
}

/**
 * @brief Parses out the .debug_loc section into a table that maps each list as
 *        offset of a list -> LocationList
 *
 * @param bin
 * @param addr_size machine address size used in executable (necessary for parsing)
 * @return R_API*
 */
R_API HtUP/*<offset, RBinDwarfLocList*/ *r_bin_dwarf_parse_loc(RBin *bin, int addr_size) {
	r_return_val_if_fail  (bin, NULL);
	/* The standarparse_loc_raw_frame, not sure why is that */
	size_t len = 0;
	ut8 *buf = get_section_bytes (bin, "debug_loc", &len);
	if (!buf) {
		return NULL;
	}
	/* set the endianity global [HOTFIX] */
	big_end = r_bin_is_big_endian (bin);
	HtUP /*<offset, RBinDwarfLocList*/ *loc_table = ht_up_new0 ();
	if (!loc_table) {
		free (buf);
		return NULL;
	}
	loc_table = parse_loc_raw (loc_table, buf, len, addr_size);
	free (buf);
	return loc_table;
}

static int offset_comp(const void *a, const void *b) {
	const RBinDwarfLocList *f = a;
	const RBinDwarfLocList *s = b;
	ut64 first = f->offset;
	ut64 second = s->offset;
	if (first < second) {
		return -1;
	}
	if (first > second) {
		return 1;
	}
	return 0;
}

static bool sort_loclists(void *user, const ut64 key, const void *value) {
	RBinDwarfLocList *loc_list = (RBinDwarfLocList *)value;
	RList *sort_list = user;
	r_list_add_sorted (sort_list, loc_list, offset_comp);
	return true;
}

R_API void r_bin_dwarf_print_loc(HtUP /*<offset, RBinDwarfLocList*/ *loc_table, int addr_size, PrintfCallback print) {
	r_return_if_fail (loc_table && print);
	print ("\nContents of the .debug_loc section:\n");
	RList /*<RBinDwarfLocList *>*/ *sort_list = r_list_new ();
	/* sort the table contents by offset and print sorted
	   a bit ugly, but I wanted to decouple the parsing and printing */
	ht_up_foreach (loc_table, sort_loclists, sort_list);
	RListIter *i;
	RBinDwarfLocList *loc_list;
	r_list_foreach (sort_list, i, loc_list) {
		RListIter *j;
		RBinDwarfLocRange *range;
		ut64 base_offset = loc_list->offset;
		r_list_foreach (loc_list->list, j, range) {
			print ("0x%" PFMT64x " 0x%" PFMT64x " 0x%" PFMT64x "\n", base_offset, range->start, range->end);
			base_offset += addr_size * 2;
			if (range->expression) {
				base_offset += 2 + range->expression->length; /* 2 bytes for expr length */
			}
		}
		print ("0x%" PFMT64x " <End of list>\n", base_offset);
	}
	print ("\n");
	r_list_free (sort_list);
}

static void free_loc_table_entry(HtUPKv *kv) {
	if (kv) {
		free_loc_table_list (kv->value);
	}
}

R_API void r_bin_dwarf_free_loc(HtUP /*<offset, RBinDwarfLocList*>*/ *loc_table) {
	r_return_if_fail (loc_table);
	loc_table->opt.freefn = free_loc_table_entry;
	ht_up_free (loc_table);
}
