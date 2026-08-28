/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include <r_core.h>
#include "format/elf/elf.h"
#include "r_bin.h"
#include "r_bin_dwarf.h"
#include "r_util/r_assert.h"
#include "i/private.h"

#define READ8(buf) \
	(((buf) + sizeof (ut8) <= buf_end)? ((ut8 *)buf)[0]: 0); \
	(buf) += sizeof (ut8)
#define READ16(buf) \
	(((buf) + sizeof (ut16) <= buf_end)? r_read_ble16 (buf, be): 0); \
	(buf) += sizeof (ut16)
#define READ32(buf) \
	(((buf) + sizeof (ut32) <= buf_end)? r_read_ble32 (buf, be): 0); \
	(buf) += sizeof (ut32)
#define READ64(buf) \
	(((buf) + sizeof (ut64) <= buf_end)? r_read_ble64 (buf, be): 0); \
	(buf) += sizeof (ut64)

#define READ_BUF(x, y) \
	if (idx + sizeof (y) >= len) { \
		return false; \
	} \
	(x) = *(y *)buf; \
	idx += sizeof (y); \
	buf += sizeof (y)

#define READ_BUF64(x) \
	if (idx + sizeof (ut64) >= len) { \
		return false; \
	} \
	(x) = r_read_ble64 (buf, be); \
	idx += sizeof (ut64); \
	buf += sizeof (ut64)
#define READ_BUF32(x) \
	if (idx + sizeof (ut32) >= len) { \
		return false; \
	} \
	(x) = r_read_ble32 (buf, be); \
	idx += sizeof (ut32); \
	buf += sizeof (ut32)
#define READ_BUF16(x) \
	if (idx + sizeof (ut16) >= len) { \
		return false; \
	} \
	(x) = r_read_ble16 (buf, be); \
	idx += sizeof (ut16); \
	buf += sizeof (ut16)

#define DWARF_STRING_MAX ((size_t)0xfff)

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
	[DW_TAG_coarray_type] = "DW_TAG_coarray_type",
	[DW_TAG_generic_subrange] = "DW_TAG_generic_subrange",
	[DW_TAG_dynamic_type] = "DW_TAG_dynamic_type",
	[DW_TAG_atomic_type] = "DW_TAG_atomic_type",
	[DW_TAG_call_site] = "DW_TAG_call_site",
	[DW_TAG_call_site_parameter] = "DW_TAG_call_site_parameter",
	[DW_TAG_skeleton_unit] = "DW_TAG_skeleton_unit",
	[DW_TAG_immutable_type] = "DW_TAG_immutable_type",
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
	[DW_FORM_line_strp] = "DW_FORM_line_strp",
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
	[DW_LANG_Fortran08] = "Fortran08",
	[DW_LANG_Modula3] = "Modula3",
	[DW_LANG_OpenCL] = "OpenCL",
	[DW_LANG_Kotlin] = "Kotlin",
	[DW_LANG_Zig] = "Zig",
	[DW_LANG_Crystal] = "Crystal",
	[DW_LANG_C_plus_plus_17] = "C++17",
	[DW_LANG_C_plus_plus_20] = "C++20",
	[DW_LANG_C17] = "C17",
	[DW_LANG_Fortran18] = "Fortran18",
	[DW_LANG_Ada2005] = "Ada2005",
	[DW_LANG_Ada2012] = "Ada2012",
	[DW_LANG_HIP] = "HIP",
	[DW_LANG_Assembly] = "Assembly",
	[DW_LANG_C_sharp] = "C#",
	[DW_LANG_Mojo] = "Mojo",
	[DW_LANG_GLSL] = "GLSL",
	[DW_LANG_GLSL_ES] = "GLSL_ES",
	[DW_LANG_HLSL] = "HLSL",
	[DW_LANG_OpenCL_CPP] = "OpenCL-c++",
	[DW_LANG_CPP_for_OpenCL] = "C++ for OpenCL",
	[DW_LANG_SYCL] = "SyCL",
	[DW_LANG_C_plus_plus_23] = "C++23",
	[DW_LANG_Odin] = "Odin",
	[DW_LANG_P4] = "P4",
	[DW_LANG_Metal] = "Metal",
	[DW_LANG_C23] = "C23",
	[DW_LANG_Fortran23] = "Fortran23",
	[DW_LANG_Ruby] = "Ruby",
	[DW_LANG_Move] = "Move",
	[DW_LANG_Hylo] = "Hylo",
	[DW_LANG_V] = "V"
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

enum {
	DWARF_SN_ABBREV,
	DWARF_SN_INFO,
	DWARF_SN_FRAME,
	DWARF_SN_LINE,
	DWARF_SN_LOC,
	DWARF_SN_STR,
	DWARF_SN_LINE_STR,
	DWARF_SN_STR_OFFSETS,
	DWARF_SN_ADDR,
	DWARF_SN_RANGES,
	DWARF_SN_ARANGES,
	DWARF_SN_PUBNAMES,
	DWARF_SN_PUBTYPES,

	DWARF_SN_MAX
};

static const char *dwarf_sn_elf[DWARF_SN_MAX] = {
	[DWARF_SN_ABBREV] = "debug_abbrev",
	[DWARF_SN_INFO] = "debug_info",
	[DWARF_SN_FRAME] = "debug_frame",
	[DWARF_SN_LINE] = "debug_line",
	[DWARF_SN_LOC] = "debug_loc",
	[DWARF_SN_STR] = "debug_str",
	[DWARF_SN_LINE_STR] = "debug_line_str",
	[DWARF_SN_STR_OFFSETS] = "debug_str_offs",
	[DWARF_SN_ADDR] = "debug_addr",
	[DWARF_SN_RANGES] = "debug_ranges",
	[DWARF_SN_ARANGES] = "debug_aranges",
	[DWARF_SN_PUBNAMES] = "debug_pubnames",
	[DWARF_SN_PUBTYPES] = "debug_pubtypes",
};

/* XXX: xcoff64 discovers DWARF sections by SSUBTYP_DW{...}, not by name */
static const char *dwarf_sn_xcoff64[DWARF_SN_MAX] = {
	[DWARF_SN_ABBREV] = "dwabrev",
	[DWARF_SN_INFO] = "dwinfo",
	[DWARF_SN_FRAME] = "dwframe",
	[DWARF_SN_LINE] = "dwline",
	[DWARF_SN_LOC] = "dwloc",
	[DWARF_SN_RANGES] = "dwrnges",
	[DWARF_SN_ARANGES] = "dwarnge",
	[DWARF_SN_STR] = "dwstr", /* XXX: unverified */
	[DWARF_SN_PUBNAMES] = "dwpbnms",
	[DWARF_SN_PUBTYPES] = "dwpbtyp"
};

static RBinSection *get_section(RBinFile *bf, int sn) {
	R_RETURN_VAL_IF_FAIL (sn >= 0 && sn < DWARF_SN_MAX, NULL);
	RBinObject *o = bf->bo;
	const char *rclass = (o && o->info)? o->info->rclass: NULL;
	if (R_LIKELY (o)) {
		/* XXX: xcoff64 specific hack */
		const char *const *name_tab = rclass && !strcmp (o->info->rclass, "xcoff64")
			? dwarf_sn_xcoff64
			: dwarf_sn_elf;
		const char *name_str = name_tab[sn];
		if (!name_str) {
			return NULL;
		}
		RBinSection *section;
		R_VEC_FOREACH (&o->sections_vec, section) {
			if (section->name && strstr (section->name, name_str)) {
				if (sn == DWARF_SN_STR && strstr (section->name, "debug_str_off")) {
					continue;
				}
				/* accept matching section, including compressed or zdebug variants */
				return section;
			}
		}
	}
	return NULL;
}

// this function caches full section data in section->bytes
static const ut8 *get_section_bytes(RBinFile *bf, RBinSection *section) {
	if (section->bytes.len && section->bytes.ptr) {
		return section->bytes.ptr;
	}

	if (!bf->buf || section->paddr > bf->size || section->size > bf->size - section->paddr) {
		return NULL;
	}
	/* Handle compressed DWARF sections (.zdebug_* or SHF_COMPRESSED) */
	if (R_BIN_ELF_SCN_IS_COMPRESSED (section->flags) || (section->name && strstr (section->name, "zdebug"))) {
		ut64 raw_size = section->size;
		if (raw_size < 12 || raw_size > ST32_MAX) {
			return NULL;
		}
		ut8 *rawbuf = calloc (1, raw_size);
		if (!rawbuf) {
			return NULL;
		}
		if (!r_buf_read_at (bf->buf, section->paddr, rawbuf, raw_size)) {
			free (rawbuf);
			return NULL;
		}
		/* Determine ELF class and endianness */
		RBinObject *ro = bf->bo;
		ELFOBJ *eo = (ELFOBJ *)ro->bin_obj;
		bool is64 = eo && eo->ehdr.e_ident[EI_CLASS] == ELFCLASS64;
		bool be = r_bin_is_big_endian (bf->rbin);
		/* Parse compression header */
		if (is64 && raw_size < 24) {
			free (rawbuf);
			return NULL;
		}
		ut32 ch_type = r_read_ble32 (rawbuf, be);
		ut64 ch_size = 0;
		size_t header_size = 0;
		if (is64) {
			/* Elf64_Chdr: type (4), reserved (4), size (8), align (8) */
			ch_size = r_read_ble64 (rawbuf + 8, be);
			header_size = 24;
		} else {
			/* Elf32_Chdr: type (4), size (4), align (4) */
			ch_size = r_read_ble32 (rawbuf + 4, be);
			header_size = 12;
		}
		/* Only support zlib compression (type 1) */
		if (ch_type != 1) {
			free (rawbuf);
			return NULL;
		}
		if (raw_size <= header_size) {
			free (rawbuf);
			return NULL;
		}
		/* Decompress data after header */
		int dst_len = 0;
		ut8 *decomp = r_inflate (rawbuf + header_size, (int) (raw_size - header_size), NULL, &dst_len);
		free (rawbuf);
		if (!decomp) {
			return NULL;
		}
		if ((ut64)dst_len != ch_size) {
			R_LOG_WARN ("DWARF: decompressed %d bytes, expected %" PFMT64u, dst_len, ch_size);
		}

		// allocate 1 byte more to safely treat any offset as string if needed
		RSlice buf = r_arena_scalloc (bf->arena, dst_len + 1);
		memcpy ((void *)buf.ptr, decomp, dst_len);
		free (decomp);

		section->bytes = buf;
		return buf.ptr;
	}
	// allocate 1 byte more to safely treat any offset as string if needed
	ut8 *buf = r_arena_calloc (bf->arena, section->size + 1);
	if (R_LIKELY (buf)) {
		r_buf_read_at (bf->buf, section->paddr, buf, section->size);
	}
	section->bytes = r_slice (buf, section->size);

	return buf;
}

static int abbrev_cmp(const void *a, const void *b) {
	const RBinDwarfAbbrevDecl *first = a;
	const RBinDwarfAbbrevDecl *second = b;
	if (first->offset > second->offset) {
		return 1;
	}
	if (first->offset < second->offset) {
		return -1;
	}
	return 0;
}

static bool is_printable_lang(ut64 attr_code) {
	if (attr_code >= sizeof (dwarf_langs) / sizeof (dwarf_langs[0])) {
		return false;
	}
	return dwarf_langs[attr_code];
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

#if 0
* @brief Reads 64/32 bit unsigned based on format
*
* @param is_64bit Format of the comp unit
* @param buf Pointer to the buffer to read from, to update after read
* @param buf_end To check the boundary /for READ macro/
* @return ut64 Read value
#endif
static inline ut64 dwarf_read_offset(RBin *bin, bool is_64bit, const ut8 **buf, const ut8 *buf_end) {
	const bool be = r_bin_is_big_endian (bin);
	ut64 result;
	if (!buf || !*buf || !buf_end) {
		return 0;
	}
	if (is_64bit) {
		if (*buf > buf_end || (size_t)(buf_end - *buf) < 8) {
			return 0;
		}
		result = READ64 (*buf);
	} else {
		if (*buf > buf_end || (size_t)(buf_end - *buf) < 4) {
			return 0;
		}
		result = (ut64)READ32 (*buf);
	}
	return result;
}

static inline ut64 dwarf_read_address(RBin *bin, size_t size, const ut8 **buf, const ut8 *buf_end) {
	const bool be = r_bin_is_big_endian (bin);
	ut64 result;
	switch (size) {
	case 2: result = READ16 (*buf); break;
	case 4: result = READ32 (*buf); break;
	case 8: result = READ64 (*buf); break;
	default:
		result = 0;
		*buf += size;
		R_LOG_WARN ("Unsupported dwarf address size: %u", (int)size);
	}
	return result;
}

static int add_sdb_include_dir(Sdb *s, const char *incl, int idx) {
	if (!s || !incl) {
		return false;
	}
	return sdb_array_set (s, "includedirs", idx, incl, 0);
}

// Parses source file header of DWARF version <= 4
static const ut8 *parse_line_header_source(RBin *bin, RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, Sdb *sdb, int mode, PrintfCallback print, int debug_line_offset) {
	int i = 0;
	size_t count = 1;
	const ut8 *tmp_buf = NULL;
	char *fn = NULL;

	if (mode == R_MODE_PRINT) {
		print (" The Directory Table:\n");
	}
	while (buf < buf_end) {
		int maxlen = (int)R_MIN ((size_t) (buf_end - buf) - 1, DWARF_STRING_MAX);
		size_t len = r_str_nlen ((const char *)buf, maxlen);
		char *str = r_str_ndup ((const char *)buf, (int)len);
		if (len < 1 || len >= DWARF_STRING_MAX || !str) {
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
	if (mode == R_MODE_PRINT) {
		print ("\n");
		print (" The File Name Table:\n");
		print ("  Entry Dir     Time      Size       Name\n");
	}
	int entry_index = 1; // used for printing information

	for (i = 0; i < 2; i++) {
		while (buf + 1 < buf_end) {
			int maxlen = (int)R_MIN ((size_t) (buf_end - buf - 1), DWARF_STRING_MAX);
			ut64 id_idx, mod_time, file_len;
			free (fn);
			fn = r_str_ndup ((const char *)buf, maxlen);
			r_str_ansi_strip (fn);
			size_t len = strlen (fn);

			if (!len) {
				buf++;
				break;
			}
			buf += len + 1;
			if (buf >= buf_end) {
				goto beach;
			}
			const ut8 *nbuf = r_uleb128 (buf, buf_end - buf, &id_idx, NULL);
			if (!buf || buf == nbuf || nbuf >= buf_end) {
				goto beach;
			}
			buf = nbuf;
			nbuf = r_uleb128 (buf, buf_end - buf, &mod_time, NULL);
			if (!buf || buf == nbuf || nbuf >= buf_end) {
				goto beach;
			}
			buf = nbuf;
			nbuf = r_uleb128 (buf, buf_end - buf, &file_len, NULL);
			if (!buf || buf == nbuf || nbuf >= buf_end) {
				goto beach;
			}
			buf = nbuf;

			if (i) {
				char *include_dir = NULL;
				char *include_dir_alloc = NULL; // track allocated memory
				if (id_idx > 0) {
					include_dir_alloc = sdb_array_get (sdb, "includedirs", id_idx - 1, 0);
					include_dir = include_dir_alloc;
					if (include_dir && include_dir[0] != '/') {
						// Look up comp_dir for this specific compilation unit
						const char *comp_dir = NULL;
						if (bf->dwarf_metadata.comp_dirs) {
							comp_dir = ht_up_find (bf->dwarf_metadata.comp_dirs, debug_line_offset, NULL);
						}
						if (!comp_dir) {
							comp_dir = bf->dwarf_metadata.comp_dir;
						}
						if (comp_dir) {
							include_dir = r_str_newf ("%s/%s", comp_dir, include_dir);
							free (include_dir_alloc);
							include_dir_alloc = include_dir;
						}
					}
				} else {
					// id_idx == 0: use comp_dir directly as include_dir
					if (bf->dwarf_metadata.comp_dirs) {
						const char *cd = ht_up_find (bf->dwarf_metadata.comp_dirs, debug_line_offset, NULL);
						if (cd) {
							include_dir_alloc = strdup (cd);
						}
					}
					if (!include_dir_alloc) {
						include_dir_alloc = bf->dwarf_metadata.comp_dir? strdup (bf->dwarf_metadata.comp_dir) : NULL;
					}
					if (!include_dir_alloc) {
						include_dir_alloc = strdup ("./");
					}
					include_dir = include_dir_alloc;
				}

				if (hdr->file_names) {
					hdr->file_names[count].name = r_str_newf ("%s/%s", r_str_get (include_dir), fn);
					hdr->file_names[count].id_idx = id_idx;
					hdr->file_names[count].mod_time = mod_time;
					hdr->file_names[count].file_len = file_len;
				}
				free (include_dir_alloc);
			}
			count++;
			if (mode == R_MODE_PRINT && i) {
				print ("  %d     %" PFMT64d "       %" PFMT64d "         %" PFMT64d "          %s\n",
					entry_index++,
					id_idx,
					mod_time,
					file_len,
					fn);
			}
		}
		if (i == 0) {
			hdr->file_names = calloc (sizeof (file_entry), count);
			if (!hdr->file_names) {
				R_LOG_ERROR ("Cannot calloc %d", count);
				break;
			}
			hdr->file_names_count = count;
			buf = tmp_buf;
			count = 1;
		}
	}
	if (mode == R_MODE_PRINT) {
		print ("\n");
	}

beach:
	free (fn);
	sdb_free (sdb);

	return buf;
}

static const char *get_section_string(RBinFile *bf, RBinSection *section, size_t offset) {
	if (!bf || !section) {
		return NULL;
	}
	const ut8 *data = get_section_bytes (bf, section);
	size_t len = section->bytes.len;
	if (!data || offset >= len) {
		return NULL;
	}
	if (!memchr (data + offset, 0, len - offset)) {
		return NULL;
	}

	return (const char *) (data + offset);
}

static const ut8 *dwarf_read_index(const ut8 *buf, const ut8 *buf_end, bool be, ut8 size, ut64 *value) {
	R_RETURN_VAL_IF_FAIL (buf && buf_end && value && buf <= buf_end, NULL);
	if (size > (size_t)(buf_end - buf)) {
		return NULL;
	}
	switch (size) {
	case 1:
		*value = buf[0];
		break;
	case 2:
		*value = r_read_ble16 (buf, be);
		break;
	case 3:
		*value = r_read_ble24 (buf, be);
		break;
	case 4:
		*value = r_read_ble32 (buf, be);
		break;
	case 8:
		*value = r_read_ble64 (buf, be);
		break;
	default:
		return NULL;
	}
	return buf + size;
}

static const ut8 *dwarf_read_uleb_index(const ut8 *buf, const ut8 *buf_end, ut64 *value) {
	R_RETURN_VAL_IF_FAIL (buf && buf_end && value && buf < buf_end, NULL);
	const char *error = NULL;
	const ut8 *next = r_uleb128 (buf, buf_end - buf, value, &error);
	return next && next > buf && !error? next: NULL;
}

static const ut8 *dwarf_read_sleb(const ut8 *buf, const ut8 *buf_end, st64 *value) {
	R_RETURN_VAL_IF_FAIL (buf && buf_end && value && buf < buf_end, NULL);
	size_t available = buf_end - buf;
	size_t i;
	for (i = 0; i < available && i < 10; i++) {
		ut8 byte = buf[i];
		if (!(byte & 0x80)) {
			if (i == 9 && byte != 0 && byte != 0x7f) {
				return NULL;
			}
			const ut8 *next = r_leb128 (buf, i + 1, value);
			return next == buf + i + 1? next: NULL;
		}
	}
	return NULL;
}

static bool dwarf_relocate_address(RBinFile *bf, ut64 address, ut64 *relocated) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && relocated, false);
	*relocated = address;
	if (!address) {
		return true;
	}
	const st64 shift = bf->bo->baddr_shift;
	if (shift >= 0) {
		ut64 value;
		if (!r_add_overflow (address, (ut64)shift, &value)) {
			*relocated = value;
		}
		return true;
	}
	const ut64 magnitude = 0 - (ut64)shift;
	if (address >= magnitude) {
		*relocated = address - magnitude;
	}
	return true;
}

static bool dwarf_is_zero_padding(const ut8 *buf, const ut8 *buf_end) {
	if (!buf || !buf_end || buf >= buf_end) {
		return false;
	}
	for (; buf < buf_end; buf++) {
		if (*buf) {
			return false;
		}
	}
	return true;
}

static bool dwarf_is_breaked(RBin *bin) {
	return bin && bin->consb.is_breaked && bin->consb.is_breaked (bin->consb.cons);
}

typedef struct entry_descriptor {
	ut64 type;
	ut64 form;
} entry_descriptor;

#define MAX_V5_DESCRIPTORS 7

typedef struct entry_formatv5 {
	int ndesc;
	entry_descriptor descs[MAX_V5_DESCRIPTORS];
} entry_formatv5;

// Parse v5 directory/file content description into ent.
static const ut8 *parse_line_entryv5(const ut8 *buf, const ut8 *buf_end, entry_formatv5 *ent) {
	if (ent == NULL) {
		return NULL;
	}

	ut8 nform = READ8 (buf);
	if (nform >= MAX_V5_DESCRIPTORS) {
		R_LOG_DEBUG ("Too many entry formats: %d >= %d", nform, MAX_V5_DESCRIPTORS);
		return NULL;
	}
	ent->ndesc = 0;
	int i;
	for (i = 0; i < nform; i++) {
		entry_descriptor *e = &ent->descs[i];
		const ut8 *nbuf = r_uleb128 (buf, buf_end - buf, &e->type, NULL);
		if (!nbuf || buf == nbuf) {
			return NULL;
		}

		buf = nbuf;
		nbuf = r_uleb128 (buf, buf_end - buf, &e->form, NULL);
		if (!nbuf || buf == nbuf) {
			return NULL;
		}
		buf = nbuf;
		ent->ndesc++;
	}
	return buf;
}

static const ut8 *ut64_form_value(RBin *bin, entry_descriptor desc, const ut8 *buf, const ut8 *buf_end, ut64 *val) {
	const bool be = r_bin_is_big_endian (bin);
	const ut8 *nbuf = NULL;
	ut64 data = 0;

	switch (desc.form) {
	case DW_FORM_udata:
		nbuf = r_uleb128 (buf, buf_end - buf, &data, NULL);
		if (!nbuf || nbuf == buf) {
			return NULL;
		}
		*val = data;
		return nbuf;
	case DW_FORM_data1:
		if (buf + 1 >= buf_end) {
			return NULL;
		}
		*val = buf[0];
		buf += 1;
		return buf;
	case DW_FORM_data2:
		if (buf + 2 >= buf_end) {
			return NULL;
		}
		*val = r_read_ble16 (buf, be);
		buf += 2;
		return buf;
	case DW_FORM_data4:
		if (buf + 4 >= buf_end) {
			return NULL;
		}
		*val = r_read_ble32 (buf, be);
		buf += 4;
		return buf;
	case DW_FORM_data8:
		if (buf + 8 >= buf_end) {
			return NULL;
		}
		*val = r_read_ble64 (buf, be);
		buf += 8;
		return buf;
	default:
		R_LOG_DEBUG ("Expected data form but got: %#x", desc.form);
		return NULL;
	}
}

static const ut8 *str_form_value(RBinFile *bf, entry_descriptor desc, const ut8 *buf, const ut8 *buf_end, bool is_64bit, const char **ret_name) {
	RBin *bin = bf? bf->rbin: NULL;
	ut64 section_offset = 0;
	RBinSection *section = NULL;
	if (!bin) {
		return NULL;
	}

	switch (desc.form) {
	case DW_FORM_line_strp:
		section_offset = dwarf_read_offset (bin, is_64bit, &buf, buf_end);
		section = get_section (bf, DWARF_SN_LINE_STR);
		*ret_name = section? get_section_string (bf, section, section_offset): NULL;
		return buf;
	case DW_FORM_strp:
		section_offset = dwarf_read_offset (bin, is_64bit, &buf, buf_end);
		section = get_section (bf, DWARF_SN_STR);
		*ret_name = section? get_section_string (bf, section, section_offset): NULL;
		return buf;
	case DW_FORM_strp_sup:
		// TODO: handle this properly
		dwarf_read_offset (bin, is_64bit, &buf, buf_end);
		return buf;
	case DW_FORM_string:
		// TODO: find a way to test this case.
		if (buf == NULL || buf >= buf_end) {
			return NULL;
		}
		size_t available = buf_end - buf;
		size_t len = R_MIN (DWARF_STRING_MAX, available);
		size_t slen = r_str_nlen ((const char *)buf, (int)len);
		if (slen >= len) {
			return NULL;
		}
		*ret_name = (const char *)buf;
		buf += slen + 1;
		return buf;
	default:
		R_LOG_DEBUG ("Expected form type string but got: %#x", desc.form);
		return NULL;
	}
}

static const ut8 *data16_form_value(entry_descriptor desc, const ut8 *buf, const ut8 *buf_end, ut8 val[16]) {
	if (desc.form != DW_FORM_data16 || buf + 16 >= buf_end) {
		R_LOG_DEBUG ("Expected form type data16 but got: %#x", desc.form);
		return NULL;
	}
	memcpy (val, buf, 16);
	buf += 16;
	return buf;
}

// TODO DWARF 5 line header parsing, very different from ver. 4
// Because this function needs ability to parse a lot of FORMS just like debug info
// I'll complete this function after completing debug_info parsing and merging
// for the meanwhile I am skipping the space.
static const ut8 *parse_line_header_source_dwarf5(RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, Sdb *s, int mode, PrintfCallback print) {
	RBin *bin = bf? bf->rbin: NULL;
	if (!bin) {
		return NULL;
	}
	if (mode == R_MODE_PRINT) {
		print (" The Directory Table:\n");
	}

	entry_formatv5 dir_form = { 0 };
	buf = parse_line_entryv5 (buf, buf_end, &dir_form);
	if (buf == NULL) {
		R_LOG_DEBUG ("Invalid uleb128 for dwarf directory entry format");
		return NULL;
	}
	if (dir_form.ndesc <= 0) {
		R_LOG_DEBUG ("Invalid number of descriptors for directory table");
		return NULL;
	}

	ut64 ndir_entry = 0;
	const ut8 *nbuf = r_uleb128 (buf, buf_end - buf, &ndir_entry, NULL);
	if (!nbuf || nbuf == buf) {
		R_LOG_DEBUG ("Invalid uleb128 for dwarf directory count");
		return NULL;
	}
	ut64 i, j;
	if ((int)ndir_entry != -1) {
		buf = nbuf;
		for (i = 0; i < ndir_entry; i++) {
			for (j = 0; j < dir_form.ndesc; j++) {
				entry_descriptor desc = dir_form.descs[j];
				const char *name = NULL;

				switch (desc.type) {
				case DW_LNCT_path:
					buf = str_form_value (bf, desc, buf, buf_end, hdr->is_64bit, &name);
					if (buf == NULL || name == NULL) {
						R_LOG_DEBUG ("Invalid description (%#x) for directory %d %d", desc.form, i, ndir_entry);
						return NULL;
					}
					add_sdb_include_dir (s, name, i);
					break;
				default:
					R_LOG_DEBUG ("Invalid description type (%#x)", desc.type);
					// TODO: Skip this value instead of failing?
					return NULL;
				}
			}
			if (mode == R_MODE_PRINT) {
				print ("  %" PFMT64u "     %s\n", i, sdb_array_get (s, "includedirs", i, 0));
			}
		}
	}

	if (mode == R_MODE_PRINT) {
		print ("\n");
		print (" The File Name Table:\n");
		print ("  Entry Dir     Time      Size       MD5                              Name\n");
	}

	entry_formatv5 file_form = { 0 };
	buf = parse_line_entryv5 (buf, buf_end, &file_form);
	if (buf == NULL) {
		R_LOG_DEBUG ("Invalid uleb128 for dwarf file entry format");
		return NULL;
	}
	if (file_form.ndesc <= 0) {
		R_LOG_DEBUG ("Invalid number of descriptors for file table");
		return NULL;
	}

	ut64 nfile_entry = 0;
	nbuf = r_uleb128 (buf, buf_end - buf, &nfile_entry, NULL);
	if (!nbuf || nbuf == buf) {
		R_LOG_DEBUG ("Invalid uleb128 for dwarf file count");
		return NULL;
	}
	buf = nbuf;

	hdr->file_names = calloc (sizeof (file_entry), nfile_entry);
	if (hdr->file_names == NULL) {
		return NULL;
	}
	hdr->file_names_count = nfile_entry;

	for (i = 0; i < nfile_entry; i++) {
		file_entry *file = &hdr->file_names[i];
		for (j = 0; j < file_form.ndesc; j++) {
			entry_descriptor desc = file_form.descs[j];
			const char *name = NULL;
			ut64 data = 0;

			switch (desc.type) {
			case DW_LNCT_path:
				buf = str_form_value (bf, desc, buf, buf_end, hdr->is_64bit, &name);
				if (buf == NULL || name == NULL) {
					R_LOG_DEBUG ("Invalid description (%#x) for file path", desc.form);
					return NULL;
				}
				file->name = strdup (name);
				break;
			case DW_LNCT_timestamp:
				buf = ut64_form_value (bin, desc, buf, buf_end, &data);
				if (buf == NULL) {
					R_LOG_DEBUG ("Invalid description (%#x,%#x) for file timestamp", desc.type, desc.form);
					return NULL;
				}
				file->mod_time = data;
				break;
			case DW_LNCT_directory_index:
				buf = ut64_form_value (bin, desc, buf, buf_end, &data);
				if (buf == NULL) {
					R_LOG_DEBUG ("Invalid description (%#x,%#x) for file dir index", desc.type, desc.form);
					return NULL;
				}
				if (file->name == NULL) {
					break;
				}
				file->id_idx = data;

				// prepend directory to the file name
				char *dir = sdb_array_get (s, "includedirs", file->id_idx, 0);
				const char *filename = file->name;
				if (dir == NULL || !strcmp (filename, dir)) {
					free (dir);
					break;
				}

				bool isabs = r_file_is_abspath (dir);
				if (file->id_idx == 0 || isabs) {
					file->name = r_str_newf ("%s/%s", dir, filename);
					free ((char *)filename);
				} else {
					char *comp_unit_dir = sdb_array_get (s, "includedirs", 0, 0);
					if (comp_unit_dir == NULL || !strcmp (filename, comp_unit_dir)) {
						free (comp_unit_dir);
						free (dir);
						break;
					}
					char *tmp = r_str_newf ("%s/%s/%s",
						comp_unit_dir,
						dir,
						filename);
					file->name = tmp;
					free ((char *)filename);
					free (comp_unit_dir);
				}
				free (dir);
				break;
			case DW_LNCT_size:
				buf = ut64_form_value (bin, desc, buf, buf_end, &data);
				if (buf == NULL) {
					R_LOG_DEBUG ("Invalid description (%#x,%#x) for file size", desc.type, desc.form);
					return NULL;
				}
				file->file_len = data;
				break;
			case DW_LNCT_MD5:
				buf = data16_form_value (desc, buf, buf_end, file->md5sum);
				if (buf == NULL) {
					R_LOG_DEBUG ("Invalid description (%#x,%#x) for file checksum", desc.type, desc.form);
					return NULL;
				}
				file->has_checksum = true;
				break;
			default:
				R_LOG_DEBUG ("Invalid or unsupported DW line number content type %#x", desc.type);
				return NULL;
			}
		}
		if (mode == R_MODE_PRINT) {
			// number of hexes chars in a md5 checksum plus NULL
			char sumstr[33];

			memset (sumstr, ' ', sizeof (sumstr));
			sumstr[32] = '\0';

			if (file->has_checksum) {
				int i;
				ut8 *p = &file->md5sum[0];
				static const char *hex = "0123456789abcdef";

				for (i = 0; i < 16; i++) {
					sumstr[i * 2] = hex[(p[i] >> 4) & 0x0f];
					sumstr[i * 2 + 1] = hex[p[i] & 0x0f];
				}
			}
			print ("  %" PFMT64u "     %" PFMT32d "       %" PFMT32d "         %" PFMT32d "          %s %s\n",
				i + 1,
				file->id_idx,
				file->mod_time,
				file->file_len,
				sumstr,
				file->name);
		}
	}

	if (mode == R_MODE_PRINT) {
		print ("\n");
	}

	sdb_free (s);
	return buf;
}

static const ut8 *parse_line_header(RBin *bin, RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, int mode, PrintfCallback print, int debug_line_offset) {
	R_RETURN_VAL_IF_FAIL (hdr && bf && buf, NULL);

	const bool be = r_bin_is_big_endian (bin);
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

	hdr->header_length = dwarf_read_offset (bin, hdr->is_64bit, &buf, buf_end);
	if (!buf) {
		return NULL;
	}
	if (buf_end - buf < 8) {
		return NULL;
	}
	hdr->min_inst_len = READ8 (buf);
	if (hdr->version >= 4) {
		hdr->max_ops_per_inst = READ8 (buf);
	}
	hdr->default_is_stmt = READ8 (buf);
	hdr->line_base = (int8_t)READ8 (buf);
	hdr->line_range = READ8 (buf);
	hdr->opcode_base = READ8 (buf);

	hdr->file_names_count = 0;
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
			hdr->std_opcode_lengths[i] = READ8 (buf);
			if (mode == R_MODE_PRINT) {
				print ("  Opcode %u has %d arg\n", (int)i, hdr->std_opcode_lengths[i]);
			}
		}
		if (mode == R_MODE_PRINT) {
			print ("\n");
		}
	} else {
		hdr->std_opcode_lengths = NULL;
	}

	// XXX dat leaks
	Sdb *sdb = sdb_new (NULL, NULL, 0);
	if (!sdb) {
		return NULL;
	}

	if (hdr->version < 5) {
		buf = parse_line_header_source (bin, bf, buf, buf_end, hdr, sdb, mode, print, debug_line_offset);
	} else {
		buf = parse_line_header_source_dwarf5 (bf, buf, buf_end, hdr, sdb, mode, print);
	}
	R_FREE (hdr->std_opcode_lengths);

	return buf;
}

#define DWARF_ADDRLINE_STORE_LIMIT (16 * 1024 * 1024)

static bool dwarf_line_store_is_large(RBinFile *bf) {
	RBinSection *section = get_section (bf, DWARF_SN_LINE);
	return section && section->size > DWARF_ADDRLINE_STORE_LIMIT;
}

static inline void add_sdb_addrline(RBinFile *bf, ut64 addr, const char *file, ut64 line, ut64 column, int mode, PrintfCallback print) {
	if (R_STR_ISEMPTY (file)) {
		return;
	}

	const char *p = r_str_rchr (file, NULL, '/');
	if (p) {
		p++;
	} else {
		p = file;
	}
	// includedirs and properly check full paths
	switch (mode) {
	case 1:
	case 'r':
	case '*': {
		// sanitize filename to prevent r2 script injection via embedded newlines
		char *sp = strdup (p);
		r_str_sanitize (sp);
#if R2_590
		/// XXX CL must take filename as last argument to support spaces imho
		print ("'CL %s|%d|%d 0x%08" PFMT64x "\n", sp, (int)line, (int)column, addr);
#else
		if (column) {
			print ("'CL %s:%d:%d 0x%08" PFMT64x "\n", sp, (int)line, (int)column, addr);
		} else if (line > 0) {
			print ("'CL %s:%d 0x%08" PFMT64x "\n", sp, (int)line, addr);
		}
#endif
		free (sp);
		break;
		}
	}
	if (mode == R_MODE_PRINT && dwarf_line_store_is_large (bf)) {
		return;
	}
	bf->addrline.al_add (&bf->addrline, addr, file, NULL, line, column);
}

static const ut8 *parse_ext_opcode(RBin *bin, const ut8 *obuf, size_t len, const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs, int mode) {
	R_RETURN_VAL_IF_FAIL (bin && bin->cur && obuf && hdr && regs, NULL);

	const bool be = r_bin_is_big_endian (bin);
	PrintfCallback print = bin->cb_printf;
	ut64 addr;
	const ut8 *buf = obuf;
	st64 op_len;
	RBinFile *binfile = bin->cur;
	RBinObject *o = binfile->bo;
	ut32 addr_size = o && o->info && o->info->bits? o->info->bits / 8: 4;
	const char *filename;

	const ut8 *buf_end = buf + len;
	buf = r_leb128 (buf, len, &op_len);
	if (buf >= buf_end) {
		return NULL;
	}

	ut8 opcode = *buf++;

	if (mode == R_MODE_PRINT) {
		print ("  Extended opcode %d: ", opcode);
	}

	switch (opcode) {
	case DW_LNE_end_sequence:
		regs->end_sequence = true;

		if (binfile && hdr->file_names) {
			int fnidx = regs->file;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline (binfile, regs->address, hdr->file_names[fnidx].name, regs->line, regs->column, mode, print);
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
		if (o->baddr && o->baddr != UT64_MAX && addr < o->baddr) {
			addr += o->baddr;
		}
		regs->address = addr;
		if (mode == R_MODE_PRINT) {
			print ("set Address to 0x%" PFMT64x "\n", addr);
		}
		break;
	case DW_LNE_define_file:
		filename = (const char *)buf;
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
			print ("set Discriminator to %" PFMT64d "\n", addr);
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
	const RBin *bin, const ut8 *obuf, size_t len, const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs, ut8 opcode, int mode) {

	R_RETURN_VAL_IF_FAIL (bin && obuf && hdr && regs, NULL);

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
	int line_increment = hdr->line_base + (adj_opcode % hdr->line_range);
	regs->line += line_increment;
	if (mode == R_MODE_PRINT) {
		print ("  Special opcode %d: ", adj_opcode);
		print ("advance Address by %" PFMT64d " to 0x%" PFMT64x " and Line by %d to %" PFMT64d "\n",
			advance_adr,
			regs->address,
			line_increment,
			regs->line);
	}
	if (binfile && hdr->file_names) {
		int idx = regs->file;
		if (idx >= 0 && idx < hdr->file_names_count) {
			add_sdb_addrline (binfile, regs->address, hdr->file_names[idx].name, regs->line, regs->column, mode, print);
		}
	}
	regs->basic_block = false;
	regs->prologue_end = false;
	regs->epilogue_begin = false;
	regs->discriminator = 0;

	return buf;
}

static const ut8 *parse_std_opcode(RBin *bin, const ut8 *obuf, size_t len, const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs, ut8 opcode, int mode) {
	R_RETURN_VAL_IF_FAIL (bin && bin->cur && obuf && hdr && regs, NULL);
	bool be = r_bin_is_big_endian (bin);

	PrintfCallback print = bin->cb_printf;
	RBinFile *binfile = bin->cur;
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;
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
		if (binfile && hdr->file_names) {
			int fnidx = regs->file;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline (binfile,
					regs->address,
					hdr->file_names[fnidx].name,
					regs->line,
					regs->column,
					mode,
					print);
			}
		}
		regs->basic_block = false;
		break;
	case DW_LNS_advance_pc:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		regs->address += addr * hdr->min_inst_len;
		if (mode == R_MODE_PRINT) {
			print ("Advance PC by %" PFMT64d " to 0x%" PFMT64x "\n",
				addr * hdr->min_inst_len,
				regs->address);
		}
		break;
	case DW_LNS_advance_line:
		buf = r_leb128 (buf, buf_end - buf, &sbuf);
		regs->line += sbuf;
		if (mode == R_MODE_PRINT) {
			print ("Advance line by %" PFMT64d ", to %" PFMT64d "\n", sbuf, regs->line);
		}
		break;
	case DW_LNS_set_file:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		if (mode == R_MODE_PRINT) {
			print ("Set file to %" PFMT64d "\n", addr);
		}
		regs->file = addr;
		break;
	case DW_LNS_set_column:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		if (mode == R_MODE_PRINT) {
			print ("Set column to %" PFMT64d "\n", addr);
		}
		regs->column = addr;
		break;
	case DW_LNS_negate_stmt:
		regs->is_stmt = regs->is_stmt? false: true;
		if (mode == R_MODE_PRINT) {
			print ("Set is_stmt to %d\n", regs->is_stmt);
		}
		break;
	case DW_LNS_set_basic_block:
		if (mode == R_MODE_PRINT) {
			print ("set_basic_block\n");
		}
		regs->basic_block = true;
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
			print ("Advance PC by constant %" PFMT64d " to 0x%" PFMT64x "\n",
				op_advance,
				regs->address);
		}
		break;
	case DW_LNS_fixed_advance_pc:
		operand = READ16 (buf);
		regs->address += operand;
		if (mode == R_MODE_PRINT) {
			print ("Fixed advance pc to %" PFMT64d "\n", regs->address);
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

static void line_header_fini(RBinDwarfLineHeader *hdr) {
	if (!hdr) {
		return;
	}
	if (hdr->file_names) {
		size_t i;
		for (i = 0; i < hdr->file_names_count; i++) {
			free ((char *)hdr->file_names[i].name);
		}
		R_FREE (hdr->file_names);
	}
	R_FREE (hdr->std_opcode_lengths);
	R_FREE (hdr->include_directories);
	hdr->file_names_count = 0;
}

static void set_regs_default(const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs) {
	regs->address = 0;
	regs->file = 1;
	regs->line = 1;
	regs->column = 0;
	regs->is_stmt = hdr->default_is_stmt;
	regs->basic_block = false;
	regs->end_sequence = false;
	regs->prologue_end = false;
	regs->epilogue_begin = false;
	regs->isa = 0;
}

// Passing bin should be unnecessary (after we stop printing inside bin_dwarf)
static size_t parse_opcodes(RBin *bin, const ut8 *obuf, size_t len, const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs, int mode) {
	R_RETURN_VAL_IF_FAIL (bin && obuf, 0);
	ut8 opcode, ext_opcode;

	if (len < 8) {
		return 0;
	}
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;

	while (buf && buf + 1 < buf_end && !dwarf_is_breaked (bin)) {
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
		len = (size_t) (buf_end - buf);
	}
	if (mode == R_MODE_PRINT) {
		bin->cb_printf ("\n"); // formatting of the output
	}
	return (size_t)buf? (buf - obuf): 0; // number of bytes we've moved by
}

static void free_comp_dir_entry(HtUPKv *kv) {
	free (kv->value);
}

static bool parse_line_raw(RBin *a, const ut8 *obuf, ut64 len, int mode) {
	R_RETURN_VAL_IF_FAIL (a && obuf, false);
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
	while (buf && buf + 4 < buf_end && !dwarf_is_breaked (a)) {
		// How much did we read from the compilation unit
		size_t bytes_read = 0;
		// calculate how much we've read by parsing header
		// because header unit_length includes itself
		buf_size = buf_end - buf;

		tmpbuf = buf;

		// Offset from start of the .debug_line section, equal to DW_AT_stmt_list
		// from the dwarf standard.
		int debug_line_offset = buf - obuf;
		buf = parse_line_header (a, a->cur, buf, buf_end, &hdr, mode, print, debug_line_offset);
		if (!buf) {
			line_header_fini (&hdr);
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
		if (bytes_read >= buf_size) {
			if (mode == R_MODE_PRINT) {
				print (" Line table is present, but no lines present\n");
			}
			buf = tmpbuf + buf_size;
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
			if (dwarf_is_breaked (a)) {
				line_header_fini (&hdr);
				return true;
			}
			bytes_read += tmp_read;
			buf += tmp_read; // Move in the buffer forward
		} while (bytes_read < buf_size && tmp_read != 0 && !dwarf_is_breaked (a)); // if nothing is read -> error, exit

		if (!tmp_read) {
			line_header_fini (&hdr);
			return false;
		}
		line_header_fini (&hdr);
	}
	return true;
}

static void line_files_add(RList *files, HtPP *seen, const char *file) {
	if (R_STR_ISEMPTY (file)) {
		return;
	}
	bool found = false;
	ht_pp_find (seen, file, &found);
	if (found) {
		return;
	}
	char *dup = strdup (file);
	if (!dup) {
		return;
	}
	if (!ht_pp_insert (seen, file, (void *)(size_t)1)) {
		free (dup);
		return;
	}
	r_list_append (files, dup);
}

R_API RList *r_bin_dwarf_parse_line_files(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = get_section (bf, DWARF_SN_LINE);
	if (!section) {
		return NULL;
	}
	const ut8 *obuf = get_section_bytes (bf, section);
	if (!obuf || section->bytes.len < 1) {
		return NULL;
	}
	RList *files = r_list_newf (free);
	HtPP *seen = ht_pp_new0 ();
	if (!files || !seen) {
		r_list_free (files);
		ht_pp_free (seen);
		return NULL;
	}
	RBin *bin = bf->rbin;
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + section->bytes.len;
	while (buf && buf + 4 < buf_end) {
		const ut8 *unit_start = buf;
		RBinDwarfLineHeader hdr = { 0 };
		int debug_line_offset = buf - obuf;
		buf = parse_line_header (bin, bf, buf, buf_end, &hdr, R_MODE_SET, bin->cb_printf, debug_line_offset);
		if (!buf) {
			line_header_fini (&hdr);
			break;
		}
		size_t i;
		for (i = 0; i < hdr.file_names_count; i++) {
			line_files_add (files, seen, hdr.file_names[i].name);
		}
		size_t len_size = hdr.is_64bit? 12: 4;
		size_t remaining = buf_end - unit_start;
		if (remaining < len_size || hdr.unit_length > remaining - len_size) {
			line_header_fini (&hdr);
			break;
		}
		const ut8 *unit_end = unit_start + len_size + hdr.unit_length;
		line_header_fini (&hdr);
		if (unit_end <= unit_start || unit_end > buf_end) {
			break;
		}
		buf = unit_end;
	}
	ht_pp_free (seen);
	return files;
}

static int parse_aranges_raw(RBin *bin, const ut8 *obuf, int len, int mode) {
	PrintfCallback print = bin->cb_printf;
	bool be = r_bin_is_big_endian (bin);
	ut32 length, offset;
	ut16 version;
	ut32 debug_info_offset;
	ut8 address_size, segment_size;
	const ut8 *buf = obuf;
	int idx = 0;

	if (!buf || len < 4) {
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
		print ("Version %d\n", version);
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
		ut64 n = (offset - (idx % offset)) % offset;
		if ((idx + n) >= len) {
			return false;
		}
		buf += n;
		idx += n;
	}

	while ((buf - obuf) < len) {
		ut64 adr, length;
		if ((idx + 8) >= len) {
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

static bool init_debug_info(RBinDwarfDebugInfo *inf) {
	if (!inf) {
		return false;
	}
	inf->comp_units = RVecDwarfCompUnit_new ();
	if (!inf->comp_units) {
		return false;
	}

	return true;
}

static bool init_die(RArena *arena, RBinDwarfDie *die, ut64 abbr_code, size_t attr_count) {
	if (!die) {
		return false;
	}
	if (attr_count) {
		die->attr_values = RVecDwarfAttrValue_new ();
		if (!die->attr_values) {
			return false;
		}
		if (!RVecDwarfAttrValue_reserve (die->attr_values, attr_count)) {
			RVecDwarfAttrValue_free (die->attr_values);
			die->attr_values = NULL;
			return false;
		}
	} else {
		die->attr_values = NULL;
	}
	die->abbrev_code = abbr_code;
	return true;
}

static bool init_comp_unit(RBinDwarfCompUnit *cu) {
	if (!cu) {
		return false;
	}
	cu->dies = RVecDwarfDie_new ();
	if (!cu->dies) {
		return false;
	}
	return true;
}

static bool init_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	ad->defs = RVecDwarfAttrDef_new ();
	if (!ad->defs) {
		return false;
	}
	return true;
}

static void print_abbrev_section(RVecDwarfAbbrevDecl *da, PrintfCallback print) {
	if (!da) {
		return;
	}

	RBinDwarfAbbrevDecl *decl;
	R_VEC_FOREACH (da, decl) {
		int declstag = decl->tag;
		print ("   %-4" PFMT64d " ", decl->code);
		if (declstag >= 0 && declstag < DW_TAG_LAST) {
			print ("  %-25s ", dwarf_tag_name_encodings[declstag]);
		}
		print ("[%s]", decl->has_children? "has children": "no children");
		print (" (0x%" PFMT64x ")\n", decl->offset);

		RBinDwarfAttrDef *def;
		R_VEC_FOREACH (decl->defs, def) {
			ut64 attr_name = def->attr_name;
			ut64 attr_form = def->attr_form;
			if (is_printable_attr (attr_name) && is_printable_form (attr_form)) {
				print ("    %-30s %-30s\n",
					dwarf_attr_encodings[attr_name],
					dwarf_attr_form_encodings[attr_form]);
			}
		}
	}
}

R_API void r_bin_dwarf_free_debug_abbrev(RVecDwarfAbbrevDecl *da) {
	RVecDwarfAbbrevDecl_free (da);
}

static void attr_value_fini(RBinDwarfAttrValue *value) {
	if (!value) {
		return;
	}
	// Only DW_FORM_block2 allocates block.data with r_mem_dup.
	// Other block forms point into the section buffer.
	if (value->attr_form == DW_FORM_block2) {
		free ((void *)value->block.data);
	}
}

static void dwarf_die_fini(RBinDwarfDie *die) {
	if (!die || !die->attr_values) {
		return;
	}
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		attr_value_fini (value);
	}
	RVecDwarfAttrValue_free (die->attr_values);
	die->attr_values = NULL;
}

static void dwarf_comp_unit_fini(RBinDwarfCompUnit *unit) {
	if (!unit || !unit->dies) {
		return;
	}
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		dwarf_die_fini (die);
	}
	RVecDwarfDie_free (unit->dies);
	unit->dies = NULL;
}

R_API void r_bin_dwarf_free_debug_info(RBinDwarfDebugInfo *inf) {
	if (!inf) {
		return;
	}

	RBinDwarfCompUnit *unit;
	R_VEC_FOREACH (inf->comp_units, unit) {
		dwarf_comp_unit_fini (unit);
	}
	RVecDwarfCompUnit_free (inf->comp_units);

	ht_up_free (inf->lookup_table);
	free (inf);
}

static void print_attr_value(const RBinDwarfAttrValue *val, PrintfCallback print) {
	size_t i;
	R_RETURN_IF_FAIL (val);

	switch (val->attr_form) {
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_exprloc:
		print ("%" PFMT64u " byte block:", val->block.length);
		for (i = 0; i < val->block.length; i++) {
			print (" 0x%02x", val->block.data[i]);
		}
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_data16:
		print ("%" PFMT64u "", val->uconstant);
		if (val->attr_name == DW_AT_language) {
			if (is_printable_lang (val->uconstant)) {
				print ("   (%s)", dwarf_langs[val->uconstant]);
			} else {
				print ("   (unknown language)");
			}
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
		print ("%" PFMT64d, val->sconstant);
		break;
	case DW_FORM_udata:
		print ("%" PFMT64u, val->uconstant);
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
		print ("<0x%" PFMT64x ">", val->reference);
		break;
	case DW_FORM_flag_present:
		print ("1");
		break;
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
		if (val->kind == DW_AT_KIND_STRING_INDEX) {
			print ("(unresolved string index: 0x%" PFMT64x ")", val->string.offset);
			break;
		}
		// fall through
	case DW_FORM_line_strp:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
		print ("(indirect string, offset: 0x%" PFMT64x "): %s",
			val->string.offset,
			r_str_get_fail (val->string.content, "(null)"));
		break;
	case DW_FORM_addr:
	case DW_FORM_addrx:
	case DW_FORM_addrx1:
	case DW_FORM_addrx2:
	case DW_FORM_addrx3:
	case DW_FORM_addrx4:
		if (val->kind == DW_AT_KIND_ADDRESS_INDEX) {
			print ("<unresolved address index: 0x%" PFMT64x ">", val->address);
			break;
		}
		// fall through
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		print ("0x%" PFMT64x, val->address);
		break;
	case DW_FORM_implicit_const:
		print ("0x%" PFMT64x, val->uconstant);
		break;
	default:
		print ("Unknown attr value form %" PFMT64d "\n", val->attr_form);
		break;
	};
}

static void print_comp_unit_header(const RBinDwarfCompUnit *unit, PrintfCallback print) {
	R_RETURN_IF_FAIL (unit);
	print ("\n");
	print ("  Compilation Unit @ offset 0x%" PFMT64x ":\n", unit->offset);
	print ("   Length:        0x%" PFMT64x "\n", unit->hdr.length);
	print ("   Version:       %d\n", unit->hdr.version);
	print ("   Abbrev Offset: 0x%" PFMT64x "\n", unit->hdr.abbrev_offset);
	print ("   Pointer Size:  %d\n", unit->hdr.address_size);
	if (is_printable_unit_type (unit->hdr.unit_type)) {
		print ("   Unit Type:     %s\n", dwarf_unit_types[unit->hdr.unit_type]);
	}
	print ("\n");
}

static void print_die(const RBinDwarfDie *die, PrintfCallback print) {
	R_RETURN_IF_FAIL (die);
	print ("<0x%" PFMT64x ">: Abbrev Number: %-4" PFMT64u " ", die->offset, die->abbrev_code);
	if (is_printable_tag (die->tag)) {
		print ("(%s)\n", dwarf_tag_name_encodings[die->tag]);
	} else {
		print ("(Unknown abbrev tag)\n");
	}
	if (!die->abbrev_code || !die->attr_values) {
		return;
	}
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		if (!value->attr_name) {
			continue;
		}
		if (is_printable_attr (value->attr_name)) {
			print ("     %-25s : ", dwarf_attr_encodings[value->attr_name]);
		} else {
			print ("     AT_UNKWN [0x%-3" PFMT64x "]\t : ", value->attr_name);
		}
		print_attr_value (value, print);
		print ("\n");
	}
}

static void print_comp_unit(const RBinDwarfCompUnit *unit, PrintfCallback print) {
	R_RETURN_IF_FAIL (unit && unit->dies);
	print_comp_unit_header (unit, print);
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		print_die (die, print);
	}
}

static void print_debug_info(const RBinDwarfDebugInfo *inf, PrintfCallback print) {
	R_RETURN_IF_FAIL (inf);
	RBinDwarfCompUnit *unit;
	R_VEC_FOREACH (inf->comp_units, unit) {
		print_comp_unit (unit, print);
	}
}

static const ut8 *fill_block_data(const ut8 *buf, const ut8 *buf_end, RBinDwarfBlock *block) {
	const size_t available = buf_end - buf;
	if (available < block->length) {
		R_LOG_WARN ("not enough to fill block: have %d but need %d", available, block->length);
		block->length = 0;
		block->data = NULL;
		return NULL;
	}
	block->data = buf;
	return buf + block->length;
}

#if 0
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
#endif
static const ut8 *parse_attr_value(RBinFile *bf, const ut8 *obuf, int obuf_len, RBinDwarfAttrDef *def, RBinDwarfAttrValue *value, const RBinDwarfCompUnitHdr *hdr) {
	R_RETURN_VAL_IF_FAIL (bf && def && value && hdr && obuf, NULL);
	RBin *bin = bf->rbin;

	value->attr_form = def->attr_form;
	value->attr_name = def->attr_name;
	value->block.data = NULL;
	value->string.content = NULL;
	value->string.offset = 0;

	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + obuf_len;

	if (obuf_len < 1) {
		return NULL;
	}

	const bool be = r_bin_is_big_endian (bin);

	// https://www.dwarfstd.org/doc/DWARF4.pdf#page=161http://www.dwarfstd.org/doc/DWARF4.pdf#page=161&zoom=100,0,560zoom=100,0,560
	switch (def->attr_form) {
	case DW_FORM_addr:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = dwarf_read_index (buf, buf_end, be, hdr->address_size, &value->address);
		if (!buf) {
			R_LOG_WARN ("DWARF: Unexpected pointer size: %u", (unsigned)hdr->address_size);
			return NULL;
		}
		if (!dwarf_relocate_address (bf, value->address, &value->address)) {
			return NULL;
		}
		break;
	case DW_FORM_data1:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->uconstant);
		break;
	case DW_FORM_data2:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_index (buf, buf_end, be, 2, &value->uconstant);
		break;
	case DW_FORM_data4:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->uconstant);
		break;
	case DW_FORM_data8:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_index (buf, buf_end, be, 8, &value->uconstant);
		break;
	case DW_FORM_data16: // TODO Fix this, right now I just read the data, but I need to make storage for it
		value->kind = DW_AT_KIND_CONSTANT;
		if ((size_t)(buf_end - buf) < 16) {
			return NULL;
		}
		value->uconstant = r_read_ble64 (buf + 8, be);
		buf += 16;
		break;
	case DW_FORM_sdata:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_sleb (buf, buf_end, &value->sconstant);
		break;
	case DW_FORM_udata:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->uconstant);
		break;
	case DW_FORM_string:
		value->kind = DW_AT_KIND_STRING;
		size_t available = buf_end - buf;
		if (available < 1 || available > ST32_MAX) {
			return NULL;
		}
		size_t slen = r_str_nlen ((const char *)buf, (int)available);
		if (slen >= available) {
			return NULL;
		}
		if (slen > 0) {
			// go programs contain multibyte chars in the symbol names and strings we dont want to strip them here
			value->string.content = (const char *)buf;
		} else {
			value->string.content = NULL;
		}
		buf += slen + 1;
		break;
	case DW_FORM_block1:
		value->kind = DW_AT_KIND_BLOCK;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->block.length);
		if (!buf) {
			return NULL;
		}
		if (value->block.length > 0) {
			size_t available = buf_end - buf;
			if (value->block.length <= available) {
				value->block.data = buf;
				buf += value->block.length;
			} else {
				R_LOG_WARN ("not enough to fill block1: have %zu but need %zu", available, value->block.length);
				return NULL;
			}
		} else {
			value->block.data = NULL;
		}
		break;
	case DW_FORM_block2:
		value->kind = DW_AT_KIND_BLOCK;
		ut64 block2_length;
		buf = dwarf_read_index (buf, buf_end, be, 2, &block2_length);
		if (!buf || block2_length > SIZE_MAX) {
			return NULL;
		}
		size_t len = (size_t)block2_length;
		if (len > 0) {
			size_t len_buf = buf_end - buf;
			if (len > len_buf) {
				return NULL;
			}
			value->block.data = r_mem_dup (buf, len);
			if (!value->block.data) {
				return NULL;
			}
			buf += len;
			value->block.length = len;
		} else {
			value->block.length = 0;
		}
		break;
	case DW_FORM_block4:
		value->kind = DW_AT_KIND_BLOCK;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->block.length);
		if (!buf) {
			return NULL;
		}
		if (value->block.length > 0) {
			size_t available = buf_end - buf;
			if (value->block.length <= available) {
				value->block.data = buf;
				buf += value->block.length;
			} else {
				R_LOG_WARN ("not enough to fill block4: have %zu but need %zu", available, value->block.length);
				return NULL;
			}
		} else {
			value->block.data = NULL;
		}
		break;
	case DW_FORM_block: // variable length ULEB128
		value->kind = DW_AT_KIND_BLOCK;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->block.length);
		if (!buf) {
			return NULL;
		}
		if (value->block.length > 0) {
			size_t available = buf_end - buf;
			if (value->block.length <= available) {
				value->block.data = buf;
				buf += value->block.length;
			} else {
				R_LOG_WARN ("not enough to fill block: have %zu but need %zu", available, value->block.length);
				return NULL;
			}
		} else {
			value->block.data = NULL;
		}
		break;
	case DW_FORM_flag:
		value->kind = DW_AT_KIND_FLAG;
		ut64 flag;
		buf = dwarf_read_index (buf, buf_end, be, 1, &flag);
		if (!buf) {
			return NULL;
		}
		value->flag = (ut8)flag;
		break;
	// offset in .debug_str
	case DW_FORM_strp:
	case DW_FORM_line_strp:
		value->kind = DW_AT_KIND_STRING;
		buf = dwarf_read_index (buf, buf_end, be, hdr->is_64bit? 8: 4,
			&value->string.offset);
		if (!buf || value->string.offset > SIZE_MAX) {
			return NULL;
		}
		RBinSection *section = (def->attr_form == DW_FORM_strp)
			? get_section (bf, DWARF_SN_STR)
			: get_section (bf, DWARF_SN_LINE_STR);
		const char *str = section? get_section_string (bf, section, (size_t)value->string.offset): NULL;
		value->string.content = str;
		break;
	// offset in .debug_info
	case DW_FORM_ref_addr:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, hdr->is_64bit? 8: 4, &value->reference);
		break;
	// This type of reference is an offset from the first byte of the compilation
	// header for the compilation unit containing the reference
	case DW_FORM_ref1:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_ref2:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 2, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_ref4:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_ref8:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 8, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_ref_udata:
		value->kind = DW_AT_KIND_REFERENCE;
		// uleb128 is enough to fit into ut64?
		buf = dwarf_read_uleb_index (buf, buf_end, &value->reference);
		if (!buf || value->reference > UT64_MAX - hdr->unit_offset) {
			return NULL;
		}
		value->reference += hdr->unit_offset;
		break;
	// offset in a section other than .debug_info or .debug_str
	case DW_FORM_sec_offset:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, hdr->is_64bit? 8: 4, &value->reference);
		break;
	case DW_FORM_exprloc:
		value->kind = DW_AT_KIND_BLOCK;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->block.length);
		if (!buf) {
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
		buf = dwarf_read_index (buf, buf_end, be, 8, &value->reference);
		break;
	// Index into .debug_str_offsets. Resolve after the CU base attributes are known.
	case DW_FORM_strx:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->string.offset);
		break;
	case DW_FORM_strx1:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->string.offset);
		break;
	case DW_FORM_strx2:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 2, &value->string.offset);
		break;
	case DW_FORM_strx3:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 3, &value->string.offset);
		break;
	case DW_FORM_strx4:
		value->kind = DW_AT_KIND_STRING_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->string.offset);
		break;
	case DW_FORM_implicit_const:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = def->special;
		break;
	/*  addrx* forms : The index is relative to the value of the
		DW_AT_addr_base attribute of the associated compilation unit.
	index into an array of addresses in the .debug_addr section.*/
	case DW_FORM_addrx:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->address);
		break;
	case DW_FORM_addrx1:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value->address);
		break;
	case DW_FORM_addrx2:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 2, &value->address);
		break;
	case DW_FORM_addrx3:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 3, &value->address);
		break;
	case DW_FORM_addrx4:
		value->kind = DW_AT_KIND_ADDRESS_INDEX;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->address);
		break;
	case DW_FORM_strp_sup: // offset in a section .debug_line_str
		value->kind = DW_AT_KIND_STRING;
		buf = dwarf_read_index (buf, buf_end, be, hdr->is_64bit? 8: 4,
			&value->string.offset);
		// if (debug_str && value->string.offset < debug_line_str_len) {
		// 	value->string.content =
		// 		strdupsts
		break;
	// offset in the supplementary object file
	case DW_FORM_ref_sup4:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 4, &value->reference);
		break;
	case DW_FORM_ref_sup8:
		value->kind = DW_AT_KIND_REFERENCE;
		buf = dwarf_read_index (buf, buf_end, be, 8, &value->reference);
		break;
	// An index into the .debug_loc
	case DW_FORM_loclistx:
		value->kind = DW_AT_KIND_LOCLISTPTR;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->reference);
		break;
		// An index into the .debug_rnglists
	case DW_FORM_rnglistx:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = dwarf_read_uleb_index (buf, buf_end, &value->address);
		break;
	case 0:
		value->uconstant = 0;
		return NULL;
		// TODO: handle DW_FORM_indirect
	default:
		R_LOG_WARN ("Unknown DW_FORM 0x%02" PFMT64x, def->attr_form);
		value->uconstant = 0;
		return NULL;
	}
	if (!buf || buf > buf_end) {
		return NULL;
	}
	return buf;
}

static bool dwarf_form_is_strx(ut64 form) {
	return form == DW_FORM_strx || (form >= DW_FORM_strx1 && form <= DW_FORM_strx4);
}

static bool dwarf_form_is_addrx(ut64 form) {
	return form == DW_FORM_addrx || (form >= DW_FORM_addrx1 && form <= DW_FORM_addrx4);
}

static bool dwarf_index_entry_offset(ut64 base, ut64 index, ut8 entry_size, size_t section_size, size_t *entry_offset) {
	R_RETURN_VAL_IF_FAIL (entry_offset, false);
	if (!entry_size || index > (UT64_MAX - base) / entry_size) {
		return false;
	}
	ut64 offset = base + index * entry_size;
	if (offset > SIZE_MAX || offset > section_size || entry_size > section_size - (size_t)offset) {
		return false;
	}
	*entry_offset = (size_t)offset;
	return true;
}

static bool dwarf_index_contribution_end(const ut8 *data, size_t size, bool be, ut64 base, bool is_64bit, bool is_address_table, ut8 address_size, size_t *contribution_end) {
	R_RETURN_VAL_IF_FAIL (data && contribution_end, false);
	const size_t header_size = is_64bit? 16: 8;
	if (base > SIZE_MAX || base < header_size || (size_t)base > size) {
		return false;
	}
	size_t header = (size_t)base - header_size;
	if (header > size || header_size > size - header) {
		return false;
	}
	ut64 length;
	size_t length_size;
	size_t fields_offset;
	if (is_64bit) {
		if (r_read_ble32 (data + header, be) != DWARF_INIT_LEN_64) {
			return false;
		}
		length = r_read_ble64 (data + header + 4, be);
		length_size = 12;
		fields_offset = header + 12;
	} else {
		length = r_read_ble32 (data + header, be);
		if (length == DWARF_INIT_LEN_64) {
			return false;
		}
		length_size = 4;
		fields_offset = header + 4;
	}
	if (length > SIZE_MAX || (size_t)length > size - header - length_size) {
		return false;
	}
	size_t end = header + length_size + (size_t)length;
	if (r_read_ble16 (data + fields_offset, be) != 5) {
		return false;
	}
	if (is_address_table) {
		if (data[fields_offset + 2] != address_size || data[fields_offset + 3] != 0) {
			return false;
		}
	} else if (r_read_ble16 (data + fields_offset + 2, be) != 0) {
		return false;
	}
	if ((size_t)base > end) {
		return false;
	}
	*contribution_end = end;
	return true;
}

static bool dwarf_string_offsets_contribution(const ut8 *data, size_t section_size, bool be, ut64 contribution_offset, ut64 contribution_size, ut64 *base, size_t *end, ut8 *entry_size) {
	R_RETURN_VAL_IF_FAIL (data && base && end && entry_size, false);
	if (contribution_offset > SIZE_MAX || contribution_size > SIZE_MAX
		|| contribution_offset > section_size
		|| contribution_size > section_size - (size_t)contribution_offset
		|| contribution_size < 4) {
		return false;
	}
	size_t start = (size_t)contribution_offset;
	size_t limit = start + (size_t)contribution_size;
	bool is_64bit = r_read_ble32 (data + start, be) == DWARF_INIT_LEN_64;
	*base = contribution_offset + (is_64bit? 16: 8);
	*entry_size = is_64bit? 8: 4;
	if (!dwarf_index_contribution_end (data, limit, be, *base,
			is_64bit, false, 0, end)) {
		return false;
	}
	return *end == limit || dwarf_is_zero_padding (data + *end, data + limit);
}

static bool dwarf_string_offsets_base(const ut8 *data, size_t section_size, bool be, ut64 base, size_t *end, ut8 *entry_size) {
	R_RETURN_VAL_IF_FAIL (data && end && entry_size, false);
	if (base > SIZE_MAX || base > section_size) {
		return false;
	}
	if (base >= 16 && r_read_ble32 (data + (size_t)base - 16, be) == DWARF_INIT_LEN_64
		&& dwarf_index_contribution_end (data, section_size, be, base,
			true, false, 0, end)) {
		*entry_size = 8;
		return true;
	}
	if (dwarf_index_contribution_end (data, section_size, be, base,
			false, false, 0, end)) {
		*entry_size = 4;
		return true;
	}
	return false;
}

static bool dwarf_address_base(const ut8 *data, size_t section_size, bool be,
		ut64 base, ut8 address_size, size_t *end) {
	R_RETURN_VAL_IF_FAIL (data && end, false);
	if (base > SIZE_MAX || base > section_size) {
		return false;
	}
	if (base >= 16 && r_read_ble32 (data + (size_t)base - 16, be) == DWARF_INIT_LEN_64
		&& dwarf_index_contribution_end (data, section_size, be, base,
			true, true, address_size, end)) {
		return true;
	}
	return dwarf_index_contribution_end (data, section_size, be, base,
		false, true, address_size, end);
}

static bool dwarf_comp_unit_index_bases(const RBinDwarfCompUnit *unit, bool need_str, bool need_addr, ut64 *str_base, bool *has_str_base, ut64 *addr_base, bool *has_addr_base) {
	R_RETURN_VAL_IF_FAIL (unit && unit->dies && str_base && has_str_base
		&& addr_base && has_addr_base, false);
	*has_str_base = false;
	*has_addr_base = false;
	if (!need_str && !need_addr) {
		return true;
	}
	RBinDwarfDie *root = RVecDwarfDie_at (unit->dies, 0);
	if (!root || !root->attr_values || (root->tag != DW_TAG_compile_unit
			&& root->tag != DW_TAG_partial_unit && root->tag != DW_TAG_type_unit
			&& root->tag != DW_TAG_skeleton_unit)) {
		return false;
	}
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (root->attr_values, value) {
		if (value->attr_name == DW_AT_str_offsets_base) {
			if (*has_str_base || value->attr_form != DW_FORM_sec_offset
				|| value->kind != DW_AT_KIND_REFERENCE) {
				return false;
			}
			*has_str_base = true;
			*str_base = value->reference;
		} else if (value->attr_name == DW_AT_addr_base) {
			if (*has_addr_base || value->attr_form != DW_FORM_sec_offset
				|| value->kind != DW_AT_KIND_REFERENCE) {
				return false;
			}
			*has_addr_base = true;
			*addr_base = value->reference;
		}
	}
	return true;
}

typedef enum {
	DWARF_INDEX_RESOLUTION_OK,
	DWARF_INDEX_RESOLUTION_UNAVAILABLE,
	DWARF_INDEX_RESOLUTION_MALFORMED,
} DwarfIndexResolution;

static bool dwarf_is_split_unit(const RBinDwarfCompUnit *unit) {
	return unit && (unit->hdr.unit_type == DW_UT_split_compile
		|| unit->hdr.unit_type == DW_UT_split_type);
}

typedef struct {
	RBinFile *bf;
	RBinDwarfCompUnit *unit;
	bool be;
	bool has_str_base;
	bool has_addr_base;
	ut64 str_base;
	ut64 addr_base;
	DwarfIndexResolution str_status;
	RBinSection *str_offsets_section;
	RBinSection *str_section;
	const ut8 *str_offsets;
	ut8 str_offset_size;
	size_t str_offsets_end;
	DwarfIndexResolution addr_status;
	RBinSection *addr_section;
	const ut8 *addr;
	size_t addr_end;
} DwarfIndexResolver;

static DwarfIndexResolution dwarf_index_resolver_init_str(DwarfIndexResolver *resolver) {
	resolver->str_status = DWARF_INDEX_RESOLUTION_MALFORMED;
	resolver->str_offsets_section = get_section (resolver->bf, DWARF_SN_STR_OFFSETS);
	resolver->str_section = get_section (resolver->bf, DWARF_SN_STR);
	resolver->str_offsets = resolver->str_offsets_section
		? get_section_bytes (resolver->bf, resolver->str_offsets_section): NULL;
	if (!resolver->str_offsets || !resolver->str_section
		|| !get_section_bytes (resolver->bf, resolver->str_section)) {
		resolver->str_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
		return resolver->str_status;
	}
	if (resolver->has_str_base) {
		if (!dwarf_string_offsets_base (resolver->str_offsets,
				resolver->str_offsets_section->bytes.len, resolver->be,
				resolver->str_base, &resolver->str_offsets_end,
				&resolver->str_offset_size)) {
			return resolver->str_status;
		}
	} else if (!dwarf_is_split_unit (resolver->unit)) {
		return resolver->str_status;
	} else {
		if (!dwarf_string_offsets_contribution (resolver->str_offsets,
				resolver->str_offsets_section->bytes.len, resolver->be, 0,
				resolver->str_offsets_section->bytes.len, &resolver->str_base,
				&resolver->str_offsets_end, &resolver->str_offset_size)) {
			resolver->str_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
			return resolver->str_status;
		}
	}
	resolver->str_status = DWARF_INDEX_RESOLUTION_OK;
	return resolver->str_status;
}

static DwarfIndexResolution dwarf_index_resolver_init_addr(DwarfIndexResolver *resolver) {
	resolver->addr_status = DWARF_INDEX_RESOLUTION_MALFORMED;
	resolver->addr_section = get_section (resolver->bf, DWARF_SN_ADDR);
	resolver->addr = resolver->addr_section
		? get_section_bytes (resolver->bf, resolver->addr_section): NULL;
	if (!resolver->addr) {
		resolver->addr_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
		return resolver->addr_status;
	}
	if (!resolver->has_addr_base) {
		if (!dwarf_is_split_unit (resolver->unit)) {
			return resolver->addr_status;
		}
		resolver->addr_status = DWARF_INDEX_RESOLUTION_UNAVAILABLE;
		return resolver->addr_status;
	}
	if (!dwarf_address_base (resolver->addr,
			resolver->addr_section->bytes.len, resolver->be,
			resolver->addr_base, resolver->unit->hdr.address_size,
			&resolver->addr_end)) {
		return resolver->addr_status;
	}
	resolver->addr_status = DWARF_INDEX_RESOLUTION_OK;
	return resolver->addr_status;
}

static DwarfIndexResolution dwarf_index_resolver_resolve_die(DwarfIndexResolver *resolver, RBinDwarfDie *die) {
	R_RETURN_VAL_IF_FAIL (resolver && resolver->bf && resolver->unit && die,
		DWARF_INDEX_RESOLUTION_MALFORMED);
	DwarfIndexResolution result = DWARF_INDEX_RESOLUTION_OK;
	if (!die->attr_values) {
		return result;
	}
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		size_t entry_offset;
		if (dwarf_form_is_strx (value->attr_form)
			&& value->kind == DW_AT_KIND_STRING_INDEX) {
			DwarfIndexResolution status = resolver->str_status;
			if (status == DWARF_INDEX_RESOLUTION_MALFORMED) {
				return status;
			}
			if (status == DWARF_INDEX_RESOLUTION_UNAVAILABLE) {
				result = status;
				continue;
			}
			if (!dwarf_index_entry_offset (resolver->str_base,
					value->string.offset, resolver->str_offset_size,
					resolver->str_offsets_end, &entry_offset)) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			ut64 string_offset = resolver->str_offset_size == 8
				? r_read_ble64 (resolver->str_offsets + entry_offset, resolver->be)
				: r_read_ble32 (resolver->str_offsets + entry_offset, resolver->be);
			if (string_offset > SIZE_MAX) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			const char *content = get_section_string (resolver->bf,
				resolver->str_section, (size_t)string_offset);
			if (!content) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			value->string.offset = string_offset;
			value->string.content = content;
			value->kind = DW_AT_KIND_STRING;
		} else if (dwarf_form_is_addrx (value->attr_form)
			&& value->kind == DW_AT_KIND_ADDRESS_INDEX) {
			DwarfIndexResolution status = resolver->addr_status;
			if (status == DWARF_INDEX_RESOLUTION_MALFORMED) {
				return status;
			}
			if (status == DWARF_INDEX_RESOLUTION_UNAVAILABLE) {
				result = status;
				continue;
			}
			if (!dwarf_index_entry_offset (resolver->addr_base, value->address,
					resolver->unit->hdr.address_size, resolver->addr_end,
					&entry_offset)) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			ut64 address;
			if (!dwarf_read_index (resolver->addr + entry_offset,
					resolver->addr + resolver->addr_end, resolver->be,
					resolver->unit->hdr.address_size, &address)
				|| !dwarf_relocate_address (resolver->bf, address,
					&value->address)) {
				return DWARF_INDEX_RESOLUTION_MALFORMED;
			}
			value->kind = DW_AT_KIND_ADDRESS;
		}
	}
	return result;
}

static DwarfIndexResolution dwarf_resolve_comp_unit_indexes(RBinFile *bf, RBinDwarfCompUnit *unit) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && unit && unit->dies,
		DWARF_INDEX_RESOLUTION_MALFORMED);
	DwarfIndexResolver resolver = {
		.bf = bf,
		.unit = unit,
		.be = r_bin_is_big_endian (bf->rbin),
		.str_status = DWARF_INDEX_RESOLUTION_OK,
		.addr_status = DWARF_INDEX_RESOLUTION_OK,
	};
	bool need_str = false;
	bool need_addr = false;
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		if (!die->attr_values) {
			continue;
		}
		RBinDwarfAttrValue *value;
		R_VEC_FOREACH (die->attr_values, value) {
			need_str |= dwarf_form_is_strx (value->attr_form)
				&& value->kind == DW_AT_KIND_STRING_INDEX;
			need_addr |= dwarf_form_is_addrx (value->attr_form)
				&& value->kind == DW_AT_KIND_ADDRESS_INDEX;
		}
	}
	if (!need_str && !need_addr) {
		return DWARF_INDEX_RESOLUTION_OK;
	}
	if (!dwarf_comp_unit_index_bases (unit, need_str, need_addr,
			&resolver.str_base, &resolver.has_str_base,
			&resolver.addr_base, &resolver.has_addr_base)) {
		return DWARF_INDEX_RESOLUTION_MALFORMED;
	}
	if (need_str && dwarf_index_resolver_init_str (&resolver)
			== DWARF_INDEX_RESOLUTION_MALFORMED) {
		return DWARF_INDEX_RESOLUTION_MALFORMED;
	}
	if (need_addr && dwarf_index_resolver_init_addr (&resolver)
			== DWARF_INDEX_RESOLUTION_MALFORMED) {
		return DWARF_INDEX_RESOLUTION_MALFORMED;
	}
	DwarfIndexResolution result = DWARF_INDEX_RESOLUTION_OK;
	R_VEC_FOREACH (unit->dies, die) {
		DwarfIndexResolution status = dwarf_index_resolver_resolve_die (&resolver, die);
		if (status == DWARF_INDEX_RESOLUTION_MALFORMED) {
			return status;
		}
		if (status == DWARF_INDEX_RESOLUTION_UNAVAILABLE) {
			result = status;
		}
	}
	return result;
}

static void dwarf_metadata_set_comp_dir(RBinFile *bf, ut64 debug_line_offset, bool has_debug_line_offset, const char *comp_dir);

static void dwarf_comp_unit_save_comp_dir(RBinFile *bf, RBinDwarfCompUnit *unit) {
	R_RETURN_IF_FAIL (bf && unit && unit->dies);
	RBinDwarfDie *root = RVecDwarfDie_at (unit->dies, 0);
	if (!root || !root->attr_values) {
		return;
	}
	const char *comp_dir = NULL;
	ut64 debug_line_offset = 0;
	bool has_debug_line_offset = false;
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (root->attr_values, value) {
		if (value->attr_name == DW_AT_comp_dir && value->kind == DW_AT_KIND_STRING) {
			comp_dir = value->string.content;
		} else if (value->attr_name == DW_AT_stmt_list
			&& (value->kind == DW_AT_KIND_REFERENCE
				|| value->attr_form == DW_FORM_data4
				|| value->attr_form == DW_FORM_data8)) {
			debug_line_offset = value->reference;
			has_debug_line_offset = true;
		}
	}
	if (!comp_dir) {
		return;
	}
	dwarf_metadata_set_comp_dir (bf, debug_line_offset,
		has_debug_line_offset, comp_dir);
}

#if 0
* @brief
*
* @param buf Start of the DIE data
* @param buf_end
* @param abbrev Abbreviation of the DIE
* @param hdr Unit header
* @param die DIE to store the parsed info into
* @return const ut8* Updated buffer
#endif
static const ut8 *parse_die(RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfAbbrevDecl *abbrev, RBinDwarfCompUnitHdr *hdr, RBinDwarfDie *die) {
	if (!buf || !buf_end || buf > buf_end) {
		return NULL;
	}
	RBinDwarfAttrDef *def;
	R_VEC_FOREACH (abbrev->defs, def) {
		if (!def->attr_name && !def->attr_form) {
			break;
		}
		RBinDwarfAttrValue value = { 0 };
		const ut8 *nbuf = parse_attr_value (bf, buf, buf_end - buf, def, &value, hdr);
		if (!nbuf) {
			attr_value_fini (&value);
			return NULL;
		}
		buf = nbuf;

		if (die->attr_values) {
			RVecDwarfAttrValue_push_back (die->attr_values, &value);
		} else {
			attr_value_fini (&value);
		}
	}
	return buf;
}

#if 0
* @brief Reads throught comp_unit buffer and parses all its DIEntries
*
* @param sdb
* @param buf_start Start of the compilation unit data
* @param buf_end End of the compilation unit data
* @param unit Unit to store the newly parsed information
* @param abbrevs Parsed abbrev section info of *all* abbreviations
* @param first_abbr_idx index for first abbrev of the current comp unit in abbrev array
* @param be big endian flag
*
* @return const ut8* Update buffer
#endif
static const ut8 *parse_comp_unit_mode(RBinFile *bf, const ut8 *buf_start, const ut8 *buf_end, RBinDwarfCompUnit *unit, const RVecDwarfAbbrevDecl *abbrevs, size_t first_abbr_idx, PrintfCallback print) {
	const ut8 *buf = buf_start;
	size_t abbrevs_count = RVecDwarfAbbrevDecl_length (abbrevs);
	int child_depth = 0;
	bool has_root = false;
	while (buf && buf < buf_end && buf >= buf_start) {
		if (dwarf_is_breaked (bf->rbin)) {
			return NULL;
		}
		RBinDwarfDie die = { 0 };
		// add header size to the offset;
		die.offset = buf - buf_start + unit->hdr.header_size + unit->offset;
		die.offset += unit->hdr.is_64bit? 12: 4;

		// DIE starts with ULEB128 with the abbreviation code
		ut64 abbr_code = 0;
		buf = dwarf_read_uleb_index (buf, buf_end, &abbr_code);

		if (abbr_code > abbrevs_count || !buf) { // something invalid
			return NULL;
		}
		if (buf == buf_end && abbr_code) {
			return NULL;
		}

		// there can be "null" entries that have abbr_code == 0
		if (!abbr_code) {
			if (!has_root || child_depth <= 0) {
				return NULL;
			}
			RVecDwarfDie_push_back (unit->dies, &die);
			child_depth--;
			continue;
		}
		if (has_root && child_depth <= 0) {
			return NULL;
		}
		if (abbr_code > UT64_MAX - first_abbr_idx) {
			return NULL;
		}
		ut64 abbr_idx = first_abbr_idx + abbr_code;
		if (abbrevs_count < abbr_idx) {
			return NULL;
		}

		RBinDwarfAbbrevDecl *abbrev = RVecDwarfAbbrevDecl_at (abbrevs, abbr_idx - 1);
		if (!abbrev || !abbrev->defs) {
			return NULL;
		}

		size_t attr_count = RVecDwarfAttrDef_length (abbrev->defs);
		if (attr_count > 0) {
			RBinDwarfAttrDef *last = RVecDwarfAttrDef_at (abbrev->defs, attr_count - 1);
			if (last && !last->attr_name && !last->attr_form) {
				attr_count--;
			}
		}
		if (!init_die (bf->arena, &die, abbr_code, attr_count)) {
			return NULL; // error
		}
		die.tag = abbrev->tag;
		die.has_children = abbrev->has_children;

		buf = parse_die (bf, buf, buf_end, abbrev, &unit->hdr, &die);
		if (!buf) {
			dwarf_die_fini (&die);
			return NULL;
		}
		bool has_children = die.has_children;
		RVecDwarfDie_push_back (unit->dies, &die);
		has_root = true;
		if (has_children) {
			child_depth++;
		}
	}
	if (buf != buf_end || !has_root || child_depth != 0) {
		return NULL;
	}
	if (dwarf_resolve_comp_unit_indexes (bf, unit)
			== DWARF_INDEX_RESOLUTION_MALFORMED) {
		return NULL;
	}
	dwarf_comp_unit_save_comp_dir (bf, unit);
	if (print) {
		print_comp_unit_header (unit, print);
		RBinDwarfDie *die;
		R_VEC_FOREACH (unit->dies, die) {
			print_die (die, print);
		}
	}
	return buf;
}

static const ut8 *parse_comp_unit(RBinFile *bf, const ut8 *buf_start, const ut8 *buf_end, RBinDwarfCompUnit *unit, const RVecDwarfAbbrevDecl *abbrevs, size_t first_abbr_idx) {
	return parse_comp_unit_mode (bf, buf_start, buf_end, unit, abbrevs,
		first_abbr_idx, NULL);
}

static const ut8 *print_comp_unit_stream(RBinFile *bf, const ut8 *buf_start, const ut8 *buf_end, RBinDwarfCompUnit *unit, const RVecDwarfAbbrevDecl *abbrevs, size_t first_abbr_idx, PrintfCallback print) {
	R_RETURN_VAL_IF_FAIL (print, NULL);
	return parse_comp_unit_mode (bf, buf_start, buf_end, unit, abbrevs,
		first_abbr_idx, print);
}

static bool dwarf_supported_address_size(ut8 address_size) {
	switch (address_size) {
	case 1:
	case 2:
	case 3:
	case 4:
	case 8:
		return true;
	}
	return false;
}

#if 0
* @brief Reads all information about compilation unit header
*
* @param buf Start of the buffer
* @param buf_end Upper bound of the buffer
* @param unit Unit to read information into
* @return ut8* Advanced position in a buffer
#endif
static const ut8 *info_comp_unit_read_hdr(RBin *bin, const ut8 *buf, const ut8 *buf_end, RBinDwarfCompUnitHdr *hdr) {
	// 32-bit vs 64-bit dwarf formats
	// https://www.dwarfstd.org/doc/Dwarf3.pdf section 7.4
	R_RETURN_VAL_IF_FAIL (bin && buf && buf_end && hdr && buf <= buf_end, NULL);
	bool be = r_bin_is_big_endian (bin);
	buf = dwarf_read_index (buf, buf_end, be, 4, &hdr->length);
	if (!buf) {
		return NULL;
	}
	if (hdr->length == (ut32)DWARF_INIT_LEN_64) { // then its 64bit
		buf = dwarf_read_index (buf, buf_end, be, 8, &hdr->length);
		if (!buf) {
			return NULL;
		}
		hdr->is_64bit = true;
	}
	const ut8 *tmp = buf; // to calculate header size
	ut64 value;
	buf = dwarf_read_index (buf, buf_end, be, 2, &value);
	if (!buf) {
		return NULL;
	}
	hdr->version = (ut16)value;
	if (hdr->version == 5) {
		buf = dwarf_read_index (buf, buf_end, be, 1, &value);
		if (!buf) {
			return NULL;
		}
		hdr->unit_type = (ut8)value;
		buf = dwarf_read_index (buf, buf_end, be, 1, &value);
		if (!buf) {
			return NULL;
		}
		hdr->address_size = (ut8)value;
		ut8 offset_size = hdr->is_64bit? 8: 4;
		buf = dwarf_read_index (buf, buf_end, be, offset_size, &hdr->abbrev_offset);
		if (!buf) {
			return NULL;
		}

		if (hdr->unit_type == DW_UT_skeleton || hdr->unit_type == DW_UT_split_compile) {
			buf = dwarf_read_index (buf, buf_end, be, 8, &value);
			if (!buf) {
				return NULL;
			}
			hdr->dwo_id = value;
		} else if (hdr->unit_type == DW_UT_type || hdr->unit_type == DW_UT_split_type) {
			buf = dwarf_read_index (buf, buf_end, be, 8, &hdr->type_sig);
			if (!buf) {
				return NULL;
			}
			buf = dwarf_read_index (buf, buf_end, be, offset_size, &hdr->type_offset);
			if (!buf) {
				return NULL;
			}
		}
	} else {
		ut8 offset_size = hdr->is_64bit? 8: 4;
		buf = dwarf_read_index (buf, buf_end, be, offset_size, &hdr->abbrev_offset);
		if (!buf) {
			return NULL;
		}
		buf = dwarf_read_index (buf, buf_end, be, 1, &value);
		if (!buf) {
			return NULL;
		}
		hdr->address_size = (ut8)value;
	}
	hdr->header_size = buf - tmp; // header size excluding length field
	return buf;
}

static void dwarf_metadata_set_comp_dir(RBinFile *bf, ut64 debug_line_offset, bool has_debug_line_offset, const char *comp_dir) {
	if (!bf || !comp_dir) {
		return;
	}
	char *dir = strdup (comp_dir);
	if (!dir) {
		return;
	}
	if (has_debug_line_offset) {
		if (!bf->dwarf_metadata.comp_dirs) {
			bf->dwarf_metadata.comp_dirs = ht_up_new (NULL, free_comp_dir_entry, NULL);
			if (!bf->dwarf_metadata.comp_dirs) {
				free (dir);
				return;
			}
		}
		if (!ht_up_update (bf->dwarf_metadata.comp_dirs, debug_line_offset, dir)) {
			free (dir);
		}
		return;
	}
	free (bf->dwarf_metadata.comp_dir);
	bf->dwarf_metadata.comp_dir = dir;
}

typedef bool (*DwarfRootCallback)(RBinFile *bf, const RBinDwarfCompUnit *unit, void *user);

static bool dwarf_parse_root_die(RBinFile *bf, const ut8 *buf, const ut8 *unit_end, RBinDwarfCompUnit *unit, const RVecDwarfAbbrevDecl *decls, size_t first_abbr_idx) {
	R_RETURN_VAL_IF_FAIL (bf && buf && unit_end && unit && unit->dies && decls
		&& buf < unit_end, false);
	size_t abbrevs_count = RVecDwarfAbbrevDecl_length (decls);
	ut64 abbr_code = 0;
	const ut8 *attrs = dwarf_read_uleb_index (buf, unit_end, &abbr_code);
	if (!attrs || !abbr_code || abbr_code > UT64_MAX - first_abbr_idx) {
		return false;
	}
	ut64 abbr_idx = first_abbr_idx + abbr_code;
	if (!abbr_idx || abbr_idx > abbrevs_count) {
		return false;
	}
	RBinDwarfAbbrevDecl *abbrev = RVecDwarfAbbrevDecl_at (decls, abbr_idx - 1);
	if (!abbrev || (abbrev->tag != DW_TAG_compile_unit
			&& abbrev->tag != DW_TAG_partial_unit
			&& abbrev->tag != DW_TAG_type_unit
			&& abbrev->tag != DW_TAG_skeleton_unit)) {
		return false;
	}
	size_t attr_count = RVecDwarfAttrDef_length (abbrev->defs);
	if (attr_count) {
		RBinDwarfAttrDef *last = RVecDwarfAttrDef_at (abbrev->defs, attr_count - 1);
		if (last && !last->attr_name && !last->attr_form) {
			attr_count--;
		}
	}
	RBinDwarfDie die = { 0 };
	if (!init_die (bf->arena, &die, abbr_code, attr_count)) {
		return false;
	}
	die.offset = unit->offset + (unit->hdr.is_64bit? 12: 4)
		+ unit->hdr.header_size;
	die.tag = abbrev->tag;
	die.has_children = abbrev->has_children;
	if (!parse_die (bf, attrs, unit_end, abbrev, &unit->hdr, &die)) {
		dwarf_die_fini (&die);
		return false;
	}
	RVecDwarfDie_push_back (unit->dies, &die);
	if (dwarf_resolve_comp_unit_indexes (bf, unit)
		== DWARF_INDEX_RESOLUTION_MALFORMED) {
		return false;
	}
	dwarf_comp_unit_save_comp_dir (bf, unit);
	return true;
}

static bool dwarf_foreach_root(RBinFile *bf, RVecDwarfAbbrevDecl *decls, DwarfRootCallback callback, void *user) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && decls, false);
	RBinSection *section = get_section (bf, DWARF_SN_INFO);
	const ut8 *data = section? get_section_bytes (bf, section): NULL;
	if (!data || !section->bytes.len) {
		return false;
	}
	const ut8 *buf = data;
	const ut8 *end = data + section->bytes.len;
	size_t abbrevs_count = RVecDwarfAbbrevDecl_length (decls);
	while (buf < end && !dwarf_is_breaked (bf->rbin)) {
		if (dwarf_is_zero_padding (buf, end)) {
			return true;
		}
		RBinDwarfCompUnit unit = { 0 };
		if (!init_comp_unit (&unit)) {
			return false;
		}
		const ut8 *unit_start = buf;
		unit.offset = unit_start - data;
		unit.hdr.unit_offset = unit.offset;
		buf = info_comp_unit_read_hdr (bf->rbin, buf, end, &unit.hdr);
		size_t len_size = unit.hdr.is_64bit? 12: 4;
		size_t remaining = end - unit_start;
		if (!buf || remaining < len_size || unit.hdr.length < unit.hdr.header_size
			|| unit.hdr.length > remaining - len_size) {
			// The next unit boundary is unknown, so keep only the units visited so far.
			dwarf_comp_unit_fini (&unit);
			return true;
		}
		const ut8 *unit_end = unit_start + len_size + unit.hdr.length;
		if (!dwarf_supported_address_size (unit.hdr.address_size)) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		RBinDwarfAbbrevDecl key = { .offset = unit.hdr.abbrev_offset };
		RBinDwarfAbbrevDecl *abbrev_start = bsearch (&key, decls->_start,
			abbrevs_count, sizeof (key), abbrev_cmp);
		if (!abbrev_start || !dwarf_parse_root_die (bf, buf, unit_end, &unit,
				decls, abbrev_start - decls->_start)) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		if (callback && !callback (bf, &unit, user)) {
			dwarf_comp_unit_fini (&unit);
			return false;
		}
		dwarf_comp_unit_fini (&unit);
		buf = unit_end;
	}
	return buf == end && !dwarf_is_breaked (bf->rbin);
}

R_API bool r_bin_dwarf_parse_comp_dirs(RBinFile *bf, RVecDwarfAbbrevDecl *decls) {
	return dwarf_foreach_root (bf, decls, NULL, NULL);
}

static const char *attr_value_string(const RBinDwarfAttrValue *value) {
	if (!value || value->kind != DW_AT_KIND_STRING) {
		return NULL;
	}
	switch (value->attr_form) {
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_strp:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
	case DW_FORM_string:
		return value->string.content;
	default:
		return NULL;
	}
}

typedef struct {
	RList *files;
	HtPP *seen;
} DwarfSourceFilesContext;

static bool dwarf_collect_source_file(RBinFile *bf, const RBinDwarfCompUnit *unit, void *user) {
	(void)bf;
	DwarfSourceFilesContext *ctx = user;
	R_RETURN_VAL_IF_FAIL (ctx && ctx->files && ctx->seen && unit && unit->dies, false);
	RBinDwarfDie *root = RVecDwarfDie_at (unit->dies, 0);
	if (!root || !root->attr_values) {
		return true;
	}
	const char *comp_dir = NULL;
	const char *name = NULL;
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (root->attr_values, value) {
		const char *string_value = attr_value_string (value);
		if (value->attr_name == DW_AT_comp_dir && string_value) {
			comp_dir = string_value;
		} else if (value->attr_name == DW_AT_name && string_value) {
			name = string_value;
		}
	}
	if (!name) {
		return true;
	}
	char *path = (r_file_is_abspath (name) || !comp_dir)
		? strdup (name): r_str_newf ("%s/%s", comp_dir, name);
	line_files_add (ctx->files, ctx->seen, path);
	free (path);
	return true;
}

R_API RList *r_bin_dwarf_parse_comp_unit_files(RBinFile *bf, RVecDwarfAbbrevDecl *decls) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && decls, NULL);
	RList *files = r_list_newf (free);
	HtPP *seen = ht_pp_new0 ();
	if (!files || !seen) {
		r_list_free (files);
		ht_pp_free (seen);
		return NULL;
	}
	DwarfSourceFilesContext ctx = {
		.files = files,
		.seen = seen,
	};
	if (!dwarf_foreach_root (bf, decls, dwarf_collect_source_file, &ctx)) {
		r_list_free (files);
		ht_pp_free (seen);
		return NULL;
	}
	ht_pp_free (seen);
	return files;
}

R_API bool r_bin_dwarf_print_info(RBinFile *bf, RVecDwarfAbbrevDecl *decls) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin && decls, false);
	RBinSection *section = get_section (bf, DWARF_SN_INFO);
	if (!section) {
		return false;
	}
	const ut8 *obuf = get_section_bytes (bf, section);
	if (!obuf || section->bytes.len < 1 || section->bytes.len > (UT32_MAX >> 1)) {
		return false;
	}
	RBin *bin = bf->rbin;
	PrintfCallback print = bin->cb_printf;
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + section->bytes.len;
	size_t abbrevs_count = RVecDwarfAbbrevDecl_length (decls);
	bool result = false;
	while (buf && buf < buf_end && !dwarf_is_breaked (bin)) {
		if (dwarf_is_zero_padding (buf, buf_end)) {
			buf = buf_end;
			break;
		}
		RBinDwarfCompUnit unit = { 0 };
		if (!init_comp_unit (&unit)) {
			goto cleanup;
		}
		const ut8 *unit_start = buf;
		unit.offset = unit_start - obuf;
		unit.hdr.unit_offset = unit.offset;
		buf = info_comp_unit_read_hdr (bin, buf, buf_end, &unit.hdr);
		if (!buf || buf > buf_end) {
			dwarf_comp_unit_fini (&unit);
			goto cleanup;
		}
		size_t len_size = unit.hdr.is_64bit? 12: 4;
		size_t remaining = buf_end - unit_start;
		if (remaining < len_size || unit.hdr.length < unit.hdr.header_size
			|| unit.hdr.length > remaining - len_size) {
			dwarf_comp_unit_fini (&unit);
			goto cleanup;
		}
		const ut8 *unit_end = unit_start + len_size + unit.hdr.length;
		if (!dwarf_supported_address_size (unit.hdr.address_size)) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		RBinDwarfAbbrevDecl key = { .offset = unit.hdr.abbrev_offset };
		RBinDwarfAbbrevDecl *abbrev_start = bsearch (&key, decls->_start, abbrevs_count, sizeof (key), abbrev_cmp);
		if (!abbrev_start) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		size_t first_abbr_idx = abbrev_start - decls->_start;
		if (!print_comp_unit_stream (bf, buf, unit_end, &unit, decls,
				first_abbr_idx, print)) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		dwarf_comp_unit_fini (&unit);
		buf = unit_end;
	}
	result = buf == buf_end && !dwarf_is_breaked (bin);
cleanup:
	return result;
}

#if 0
* @brief Parses whole .debug_info section
*
* @param sdb Sdb to store line related information into
* @param da Parsed Abbreviations
* @param obuf .debug_info section buffer start
* @param len length of the section buffer
* @param be big endian flag
* @return R_API* parse_info_raw Parsed information
#endif
static RBinDwarfDebugInfo *parse_info_raw(RBinFile *bf, RVecDwarfAbbrevDecl *decls, const ut8 *obuf, size_t len) {
	R_RETURN_VAL_IF_FAIL (bf && decls && obuf, false);
	RBin *bin = bf->rbin;
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;
	RBinDwarfDebugInfo *info = R_NEW0 (RBinDwarfDebugInfo);
	if (!init_debug_info (info)) {
		goto cleanup;
	}

	while (buf < buf_end) {
		if (dwarf_is_zero_padding (buf, buf_end)) {
			break;
		}
		RBinDwarfCompUnit unit = { 0 };
		if (!init_comp_unit (&unit)) {
			goto cleanup;
		}
		const ut8 *unit_start = buf;
		unit.offset = buf - obuf;
		// small redundancy, because it was easiest solution at a time
		unit.hdr.unit_offset = buf - obuf;

		buf = info_comp_unit_read_hdr (bin, buf, buf_end, &unit.hdr);
		size_t len_size = unit.hdr.is_64bit? 12: 4;
		size_t remaining = buf_end - unit_start;
		if (!buf || remaining < len_size || unit.hdr.length < unit.hdr.header_size
			|| unit.hdr.length > remaining - len_size) {
			R_LOG_WARN ("Invalid DWARF compilation unit header at 0x%" PFMT64x, unit.offset);
			dwarf_comp_unit_fini (&unit);
			break;
		}
		const ut8 *unit_end = unit_start + len_size + unit.hdr.length;
		if (!dwarf_supported_address_size (unit.hdr.address_size)) {
			R_LOG_WARN ("Unsupported DWARF address size %u in compilation unit at 0x%" PFMT64x,
				(unsigned)unit.hdr.address_size, unit.offset);
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}

		// find abbrev start for current comp unit
		// we could also do naive, ((char *)da->decls) + abbrev_offset,
		// but this is more bulletproof to invalid DWARF
		RBinDwarfAbbrevDecl key = { .offset = unit.hdr.abbrev_offset };
		RBinDwarfAbbrevDecl *abbrev_start = bsearch (&key, decls->_start, RVecDwarfAbbrevDecl_length (decls), sizeof (key), abbrev_cmp);
		if (!abbrev_start) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		// They point to the same array object, so should be def. behaviour
		size_t first_abbr_idx = abbrev_start - decls->_start;

		buf = parse_comp_unit (bf, buf, unit_end, &unit, decls, first_abbr_idx);
		if (!buf) {
			dwarf_comp_unit_fini (&unit);
			buf = unit_end;
			continue;
		}
		buf = unit_end;

		RVecDwarfCompUnit_push_back (info->comp_units, &unit);
	}
	return info;
cleanup:
	r_bin_dwarf_free_debug_info (info);
	return NULL;
}

static RVecDwarfAbbrevDecl *parse_abbrev_raw(const ut8 *obuf, size_t len) {
	const ut8 *buf = obuf, *buf_end = obuf + len;

	// XXX - Set a suitable value here.
	if (!obuf || len < 3) {
		return NULL;
	}

	RVecDwarfAbbrevDecl *da = RVecDwarfAbbrevDecl_new ();

	while (buf && (buf + 1 < buf_end)) {
		size_t offset = buf - obuf;
		ut64 tmp;
		buf = r_uleb128 (buf, (size_t) (buf_end - buf), &tmp, NULL);
		if (!buf || !tmp || buf >= buf_end) {
			continue;
		}

		RBinDwarfAbbrevDecl decl = { 0 };
		if (!init_abbrev_decl (&decl)) {
			RVecDwarfAbbrevDecl_free (da);
			return NULL;
		}

		decl.code = tmp;
		buf = r_uleb128 (buf, (size_t) (buf_end - buf), &tmp, NULL);
		decl.tag = tmp;

		decl.offset = offset;
		if (buf >= buf_end) {
			RVecDwarfAttrDef_free (decl.defs);
			continue;
		}
		decl.has_children = READ8 (buf);
		ut64 attr_code, attr_form;
		do {
			RBinDwarfAttrDef def = { 0 };
			st64 special;

			buf = r_uleb128 (buf, (size_t) (buf_end - buf), &attr_code, NULL);
			if (buf >= buf_end) {
				RVecDwarfAttrDef_free (decl.defs);
				goto out_while;
			}
			buf = r_uleb128 (buf, (size_t) (buf_end - buf), &attr_form, NULL);
			if (buf >= buf_end) {
				RVecDwarfAttrDef_free (decl.defs);
				goto out_while;
			}
			// https://www.dwarfstd.org/doc/DWARF5.pdf#page=225
			if (attr_form == DW_FORM_implicit_const) {
				buf = r_leb128 (buf, (size_t) (buf_end - buf), &special);
				def.special = special;
			}
			def.attr_name = attr_code;
			def.attr_form = attr_form;

			RVecDwarfAttrDef_push_back (decl.defs, &def);
		} while (attr_code && attr_form);

		RVecDwarfAbbrevDecl_push_back (da, &decl);
	}
out_while:
	return da;
}

static const char *getstr(RBinDwarfAttrValue *val) {
	switch (val->attr_form) {
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_strp:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
	case DW_FORM_string:
		return val->string.content;
	}
	return NULL;
}

static ut64 getint(RBinDwarfAttrValue *val) {
	switch (val->attr_form) {
	case DW_FORM_addr:
	case DW_FORM_addrx:
	case DW_FORM_addrx1:
	case DW_FORM_addrx2:
	case DW_FORM_addrx3:
	case DW_FORM_addrx4:
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		return val->address;
	case DW_FORM_implicit_const:
		return val->uconstant;
	}
	return 0;
}

#if 0
* @brief Parses .debug_info section
*
* @param da Parsed abbreviations
* @param bin
* @param mode R_MODE_PRINT to print
* @return RBinDwarfDebugInfo* Parsed information, NULL if error
#endif

R_API RBinDwarfDebugInfo *r_bin_dwarf_parse_info(RBinFile *bf, RVecDwarfAbbrevDecl *da, int mode) {
	R_RETURN_VAL_IF_FAIL (da && bf, NULL);
	RBin *bin = bf->rbin;
	RBinSection *section = get_section (bf, DWARF_SN_INFO);

	if (!bin || !section) {
		return NULL;
	}
	/* Read and possibly decompress the .debug_info section */
	const ut8 *buf = get_section_bytes (bf, section);
	if (!buf || section->size < 1 || section->size > (UT32_MAX >> 1)) {
		return NULL;
	}
	RBinDwarfDebugInfo *info = parse_info_raw (bf, da, buf, section->bytes.len);
	if (!info) {
		return NULL;
	}
	if (mode == R_MODE_PRINT) {
		print_debug_info (info, bin->cb_printf);
	}

	// TODO: load compilation units
	// TODO: only necessary when we have no srcline inf
	// TODO: add a command to enumerate the ranges for all the compilation units
	// TODO: idu? -> 0x00001600 0x0001840 entry.S
	RBinDwarfCompUnit *unit;
	R_VEC_FOREACH (info->comp_units, unit) {
		RBinDwarfDie *die;
		R_VEC_FOREACH (unit->dies, die) {
			const char *name = NULL;
			const char *path = NULL;
			ut64 low = 0;

			if (!die->attr_values) {
				continue;
			}
			RBinDwarfAttrValue *v;
			R_VEC_FOREACH (die->attr_values, v) {
				int n = v->attr_name;
				switch (n) {
				case DW_AT_name:
					name = getstr (v);
					break;
				case DW_AT_comp_dir:
					path = getstr (v);
					break;
				case DW_AT_low_pc:
					low = getint (v);
					break;
				case DW_AT_high_pc:
					// hig = getint (v);
					break;
				}
			}
			if (path && name) {
				// printf ("0x%08"PFMT64x" %s %s\n", low, path, name);
				char *abspath = (*name != '/')? r_str_newf ("%s/%s", path, name): strdup (name);
				// TODO: add compilation unit callback here
				bf->addrline.al_add_cu (&bf->addrline, low + 1, abspath, NULL, 0, 0);
				free (abspath);
			}
		}
	}

	// build hashtable after whole parsing because of possible relocations
	size_t dies_count = 0;
	R_VEC_FOREACH (info->comp_units, unit) {
		RBinDwarfDie *die;
		R_VEC_FOREACH (unit->dies, die) {
			dies_count += 1;
		}
	}

	info->lookup_table = ht_up_new_size (dies_count + dies_count / 3, NULL, NULL, NULL);
	R_VEC_FOREACH (info->comp_units, unit) {
		RBinDwarfDie *die;
		R_VEC_FOREACH (unit->dies, die) {
			ht_up_insert (info->lookup_table, die->offset, die); // optimization for further processing}
		}
	}

	return info;
}

static void row_free(void *p) {
	free (p);
}

static bool cb(void *user, const RBinAddrline *item) {
	RList *list = (RList *)user;
	RBinAddrline *row = R_NEW0 (RBinAddrline);
	if (row) {
		row->addr = item->addr;
		row->line = item->line;
		row->column = item->column;
		row->file = item->file;
		row->path = item->path;
		r_list_append (list, row);
	}
	return true;
}

R_API RList *r_bin_dwarf_parse_line(RBinFile *bf, int mode) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RList *list = NULL;
	RBinSection *section = get_section (bf, DWARF_SN_LINE);
	if (bf && section) {
		/* Read and possibly decompress the .debug_line section */
		const ut8 *buf = get_section_bytes (bf, section);
		if (!buf || section->bytes.len < 1) {
			return NULL;
		}
		list = r_list_newf (row_free);
		/* parse the line number program */
		parse_line_raw (bf->rbin, buf, section->bytes.len, mode);
		if (bf->addrline.used) {
			RBinAddrLineStore *als = &bf->addrline;
			als->al_foreach (als, cb, list);
		}
	}
	return list;
}

R_API void r_bin_dwarf_parse_aranges(RBinFile *bf, int mode) {
	RBinSection *section = get_section (bf, DWARF_SN_ARANGES);
	if (bf && section) {
		/* Read and possibly decompress the .debug_aranges section */
		const ut8 *buf = get_section_bytes (bf, section);
		if (!buf || section->bytes.len < 1 || section->bytes.len > ST32_MAX) {
			return;
		}
		parse_aranges_raw (bf->rbin, buf, section->bytes.len, mode);
	}
}

R_API RVecDwarfAbbrevDecl *r_bin_dwarf_parse_abbrev(RBinFile *bf, int mode) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = get_section (bf, DWARF_SN_ABBREV);
	if (!bf || !section) {
		return NULL;
	}
	const ut8 *buf = get_section_bytes (bf, section);
	if (!buf) {
		return NULL;
	}
	RVecDwarfAbbrevDecl *abbrevs = parse_abbrev_raw (buf, section->bytes.len);
	if (mode == R_MODE_PRINT && abbrevs) {
		print_abbrev_section (abbrevs, bf->rbin->cb_printf);
	}
	return abbrevs;
}

static inline ut64 get_max_offset(size_t addr_size) {
	switch (addr_size) {
	case 1: return UT8_MAX;
	case 2: return UT16_MAX;
	case 4: return UT32_MAX;
	case 8: return UT64_MAX;
	}
	return 0;
}

static inline RBinDwarfLocList *create_loc_list(ut64 offset) {
	RBinDwarfLocList *list = R_NEW0 (RBinDwarfLocList);
	list->list = r_list_new ();
	list->offset = offset;
	return list;
}

static inline RBinDwarfLocRange *create_loc_range(ut64 start, ut64 end, RBinDwarfBlock *block) {
	RBinDwarfLocRange *range = R_NEW0 (RBinDwarfLocRange);
	range->start = start;
	range->end = end;
	range->expression = block;
	return range;
}

static void parse_loc_raw(RBin *bin, HtUP /*<offset, List *<LocListEntry>*/ *loc_table, const ut8 *buf, size_t len, size_t addr_size) {
	const bool be = r_bin_is_big_endian (bin);
	/* GNU has their own extensions GNU locviews that we can't parse */
	const ut8 *const buf_start = buf;
	const ut8 *buf_end = buf + len;
	/* for recognizing Base address entry */
	const ut64 max_offset = get_max_offset (addr_size);

	ut64 address_base = 0; /* remember base of the loclist */
	ut64 list_offset = 0;

	RBinDwarfLocList *loc_list = NULL;
	RBinDwarfLocRange *range = NULL;
	while (buf && buf < buf_end) {
		/* Check if we have at least enough bytes to read two addresses */
		if (buf + 2 * addr_size > buf_end) {
			break;
		}
		ut64 start_addr = dwarf_read_address (bin, addr_size, &buf, buf_end);
		ut64 end_addr = dwarf_read_address (bin, addr_size, &buf, buf_end);

		if (start_addr == 0 && end_addr == 0) { /* end of list entry: 0, 0 */
			if (loc_list) {
				ht_up_insert (loc_table, loc_list->offset, loc_list);
				list_offset = buf - buf_start;
				loc_list = NULL;
			}
			address_base = 0;
			continue;
		}
		if (start_addr == max_offset && end_addr != max_offset) {
			/* base address, DWARF2 doesn't have this type of entry, these entries shouldn't
			be in the list, they are just informational entries for further parsing (address_base) */
			address_base = end_addr;
		} else { /* location list entry: */
			if (!loc_list) {
				loc_list = create_loc_list (list_offset);
			}
			/* Check if we have at least the 2-byte block length field */
			if (buf + 2 > buf_end) {
				break;
			}
			/* TODO in future parse expressions to better structure in dwarf.c and not in dwarf_process.c */
			RBinDwarfBlock *block = R_NEW0 (RBinDwarfBlock);
			block->length = READ16 (buf);
			if (block->length > 0) {
				size_t available = buf_end - buf;
				if (block->length <= available) {
					block->data = buf;
					buf += block->length;
				} else {
					/* Block extends past section end, truncate it */
					block->data = buf;
					block->length = available;
					buf = buf_end;
				}
			} else {
				block->data = NULL;
			}
			range = create_loc_range (start_addr + address_base, end_addr + address_base, block);
			r_list_append (loc_list->list, range);
			range = NULL;
		}
	}
	/* If the section ended without a terminating 0,0 entry, make sure to insert
	 * any pending loc_list into the lookup table so it can be freed later. */
	if (loc_list) {
		ht_up_insert (loc_table, loc_list->offset, loc_list);
		loc_list = NULL;
	}
}

#if 0
* @brief Parses out the .debug_loc section into a table that maps each list as
*        offset of a list -> LocationList
*
* @param bin
* @param addr_size machine address size used in executable (necessary for parsing)
* @return R_API*
#endif
R_API HtUP /*<offset, RBinDwarfLocList*/ *r_bin_dwarf_parse_loc(RBinFile *bf, int addr_size) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = get_section (bf, DWARF_SN_LOC);
	if (!bf || !section) {
		return NULL;
	}
	/* The standarparse_loc_raw_frame, not sure why is that */
	const ut8 *buf = get_section_bytes (bf, section);
	if (!buf) {
		return NULL;
	}
	/* set the endianity global [HOTFIX] */
	HtUP /*<offset, RBinDwarfLocList*/ *loc_table = ht_up_new0 ();
	if (!loc_table) {
		return NULL;
	}
	parse_loc_raw (bf->rbin, loc_table, buf, section->bytes.len, addr_size);
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

R_API char *r_bin_dwarf_print_loc(HtUP /*<offset, RBinDwarfLocList*/ *loc_table, int addr_size) {
	R_RETURN_VAL_IF_FAIL (loc_table, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "\nContents of the .debug_loc section:\n");
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
			r_strbuf_appendf (sb, "0x%" PFMT64x " 0x%" PFMT64x " 0x%" PFMT64x "\n", base_offset, range->start, range->end);
			base_offset += addr_size * 2;
			if (range->expression) {
				base_offset += 2 + range->expression->length; /* 2 bytes for expr length */
			}
		}
		r_strbuf_appendf (sb, "0x%" PFMT64x " <End of list>\n", base_offset);
	}
	r_strbuf_append (sb, "\n");
	r_list_free (sort_list);
	return r_strbuf_drain (sb);
}

R_API bool r_bin_dwarf_print_loc_stream(RBinFile *bf, int addr_size) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, false);
	RBinSection *section = get_section (bf, DWARF_SN_LOC);
	if (!section) {
		return false;
	}
	const ut8 *buf = get_section_bytes (bf, section);
	if (!buf || section->bytes.len < 1) {
		return false;
	}
	RBin *bin = bf->rbin;
	const bool be = r_bin_is_big_endian (bin);
	const ut8 *const buf_start = buf;
	const ut8 *buf_end = buf + section->bytes.len;
	const ut64 max_offset = get_max_offset (addr_size);
	PrintfCallback print = bin->cb_printf;
	ut64 address_base = 0;
	ut64 list_offset = 0;
	ut64 base_offset = 0;
	bool have_list = false;

	print ("\nContents of the .debug_loc section:\n");
	while (buf && buf < buf_end && !dwarf_is_breaked (bin)) {
		if (buf + 2 * addr_size > buf_end) {
			break;
		}
		ut64 start_addr = dwarf_read_address (bin, addr_size, &buf, buf_end);
		ut64 end_addr = dwarf_read_address (bin, addr_size, &buf, buf_end);
		if (start_addr == 0 && end_addr == 0) {
			if (have_list) {
				print ("0x%" PFMT64x " <End of list>\n", base_offset);
			}
			list_offset = buf - buf_start;
			address_base = 0;
			have_list = false;
			continue;
		}
		if (start_addr == max_offset && end_addr != max_offset) {
			address_base = end_addr;
			continue;
		}
		if (buf + 2 > buf_end) {
			break;
		}
		ut64 block_len = READ16 (buf);
		if (block_len > (ut64)(buf_end - buf)) {
			block_len = buf_end - buf;
		}
		buf += block_len;
		if (!have_list) {
			base_offset = list_offset;
			have_list = true;
		}
		print ("0x%" PFMT64x " 0x%" PFMT64x " 0x%" PFMT64x "\n",
			base_offset, start_addr + address_base, end_addr + address_base);
		base_offset += addr_size * 2 + 2 + block_len;
	}
	if (dwarf_is_breaked (bin)) {
		print ("\n");
		return false;
	}
	if (have_list) {
		print ("0x%" PFMT64x " <End of list>\n", base_offset);
	}
	print ("\n");
	return true;
}

static bool free_loc_list(void *user, const ut64 key, const void *value) {
	RBinDwarfLocList *loc_list = (RBinDwarfLocList *)value;
	if (loc_list && loc_list->list) {
		RBinDwarfLocRange *range;
		RListIter *iter;
		r_list_foreach (loc_list->list, iter, range) {
			if (range) {
				free (range->expression);
				free (range);
			}
		}
		r_list_free (loc_list->list);
	}
	free (loc_list);
	return true;
}

R_API void r_bin_dwarf_free_loc(HtUP /*<offset, RBinDwarfLocList*>*/ *loc_table) {
	if (loc_table) {
		ht_up_foreach (loc_table, free_loc_list, NULL);
		ht_up_free (loc_table);
	}
}

/* Itanium C++ ABI LSDA (language specific data area) parser. This is the
 * layout of the gcc_except_tab sections referenced by eh_frame or by the
 * mach0 compact unwind info, with every field using the DW_EH_PE pointer
 * encodings from the DWARF exception headers. */

#define DW_EH_PE_OMIT 0xff
#define DW_EH_PE_ABSPTR 0x00
#define DW_EH_PE_ULEB128 0x01
#define DW_EH_PE_UDATA2 0x02
#define DW_EH_PE_UDATA4 0x03
#define DW_EH_PE_UDATA8 0x04
#define DW_EH_PE_SLEB128 0x09
#define DW_EH_PE_SDATA2 0x0a
#define DW_EH_PE_SDATA4 0x0b
#define DW_EH_PE_SDATA8 0x0c
#define DW_EH_PE_PCREL 0x10
#define DW_EH_PE_TEXTREL 0x20
#define DW_EH_PE_DATAREL 0x30
#define DW_EH_PE_FUNCREL 0x40
#define DW_EH_PE_INDIRECT 0x80

typedef struct {
	const ut8 *buf;
	const ut8 *p;
	const ut8 *end;
	ut64 vaddr; // vaddr of buf[0]
	ut64 baddr;
	ut64 fcn_addr;
	int bits;
	bool be;
} EhReader;

// read_*_leb128 never reads past end, so checking the size is enough
static bool eh_uleb(EhReader *r, ut64 *value) {
	size_t size = read_u64_leb128 (r->p, r->end, value);
	if (!size) {
		return false;
	}
	r->p += size;
	return true;
}

static bool eh_sleb(EhReader *r, st64 *value) {
	size_t size = read_i64_leb128 (r->p, r->end, value);
	if (!size) {
		return false;
	}
	r->p += size;
	return true;
}

static bool eh_encoded(EhReader *r, ut8 encoding, ut64 *value, bool apply_base) {
	if (encoding == DW_EH_PE_OMIT || r->p >= r->end) {
		return false;
	}
	const ut64 field_addr = r->vaddr + (r->p - r->buf);
	ut64 raw = 0;
	st64 signed_raw = 0;
	size_t size = 0;
	switch (encoding & 0x0f) {
	case DW_EH_PE_ABSPTR:
		size = r->bits / 8;
		if (size != 4 && size != 8) {
			return false;
		}
		break;
	case DW_EH_PE_ULEB128:
		if (!eh_uleb (r, &raw)) {
			return false;
		}
		goto encoded_value;
	case DW_EH_PE_UDATA2:
	case DW_EH_PE_SDATA2:
		size = 2;
		break;
	case DW_EH_PE_UDATA4:
	case DW_EH_PE_SDATA4:
		size = 4;
		break;
	case DW_EH_PE_UDATA8:
	case DW_EH_PE_SDATA8:
		size = 8;
		break;
	case DW_EH_PE_SLEB128:
		if (!eh_sleb (r, &signed_raw)) {
			return false;
		}
		raw = signed_raw;
		goto encoded_value;
	default:
		return false;
	}
	if ((size_t)(r->end - r->p) < size) {
		return false;
	}
	raw = r_read_ble (r->p, r->be, size * 8);
	if ((encoding & 0x0f) >= DW_EH_PE_SLEB128) {
		switch (size) {
		case 2: signed_raw = (st16)raw; break;
		case 4: signed_raw = (st32)raw; break;
		case 8: signed_raw = (st64)raw; break;
		}
		raw = signed_raw;
	}
	r->p += size;

encoded_value:
	if (apply_base && raw) {
		switch (encoding & 0x70) {
		case DW_EH_PE_PCREL:
			raw += field_addr;
			break;
		case DW_EH_PE_TEXTREL:
		case DW_EH_PE_DATAREL:
			raw += r->baddr;
			break;
		case DW_EH_PE_FUNCREL:
			raw += r->fcn_addr;
			break;
		}
	}
	*value = raw;
	return true;
}

static size_t eh_encoding_size(ut8 encoding, int bits) {
	switch (encoding & 0x0f) {
	case DW_EH_PE_ABSPTR: return bits / 8;
	case DW_EH_PE_UDATA2:
	case DW_EH_PE_SDATA2: return 2;
	case DW_EH_PE_UDATA4:
	case DW_EH_PE_SDATA4: return 4;
	case DW_EH_PE_UDATA8:
	case DW_EH_PE_SDATA8: return 8;
	default: return 0;
	}
}

// resolve the name of a typeinfo address through the relocs or the symbols
static char *eh_type_name(RBinFile *bf, ut64 type_addr) {
	const char *name = NULL;
	RBinReloc *reloc = r_bin_reloc_at (bf->bo->relocs, type_addr, 1);
	if (reloc) {
		if (reloc->import && reloc->import->name) {
			name = r_bin_name_tostring (reloc->import->name);
		} else if (reloc->symbol && reloc->symbol->name) {
			name = r_bin_name_tostring (reloc->symbol->name);
		}
	}
	if (!name) {
		RBinSymbol *symbol;
		R_VEC_FOREACH (&bf->bo->symbols_vec, symbol) {
			if (symbol->vaddr == type_addr && symbol->name) {
				name = r_bin_name_tostring (symbol->name);
				break;
			}
		}
	}
	if (!name) {
		return NULL;
	}
	char *demangled = r_bin_demangle (bf, "cxx", name, type_addr, false);
	if (!demangled) {
		return NULL;
	}
	const char *prefix = "typeinfo for ";
	if (r_str_startswith (demangled, prefix)) {
		char *type = strdup (demangled + strlen (prefix));
		free (demangled);
		return type;
	}
	return demangled;
}

static char *eh_read_type(RBinFile *bf, const EhReader *lsda,
		const ut8 *type_table, ut8 encoding, st64 type_filter, bool *catch_all) {
	*catch_all = false;
	if (type_filter <= 0 || !type_table) {
		return NULL;
	}
	size_t entry_size = eh_encoding_size (encoding, lsda->bits);
	if (!entry_size || (ut64)type_filter > (ut64)(type_table - lsda->buf) / entry_size) {
		return NULL;
	}
	EhReader entry = *lsda;
	entry.p = type_table - (type_filter * entry_size);
	ut64 type_addr;
	if (!eh_encoded (&entry, encoding, &type_addr, true)) {
		return NULL;
	}
	if (!type_addr) {
		*catch_all = true;
		return NULL;
	}
	return eh_type_name (bf, type_addr);
}

static void eh_add_action(RBinFile *bf, RList *result, const EhReader *lsda,
		const ut8 *action_table, const ut8 *type_table, ut8 type_encoding, ut64 action,
		ut64 source, ut64 from, ut64 to, ut64 handler) {
	if (!action) {
		RBinTrycatch *tc = r_bin_trycatch_new (source, from, to, handler, 0);
		if (tc) {
			tc->kind = R_BIN_TRYCATCH_CLEANUP;
			r_list_append (result, tc);
		}
		return;
	}
	if (!action_table) {
		return;
	}
	const ut64 table_offset = action_table - lsda->buf;
	const ut64 lsda_size = lsda->end - lsda->buf;
	if (action - 1 >= lsda_size - table_offset) {
		return;
	}
	const ut8 *record = action_table + (action - 1);
	// the depth limit keeps cyclic next-record chains from looping forever
	size_t depth;
	for (depth = 0; depth < 64; depth++) {
		EhReader action_reader = *lsda;
		action_reader.p = record;
		st64 type_filter;
		if (!eh_sleb (&action_reader, &type_filter)) {
			break;
		}
		const ut8 *next_field = action_reader.p;
		st64 next;
		if (!eh_sleb (&action_reader, &next)) {
			break;
		}
		RBinTrycatch *tc = r_bin_trycatch_new (source, from, to, handler, 0);
		if (!tc) {
			break;
		}
		tc->kind = type_filter < 0? R_BIN_TRYCATCH_FILTER: R_BIN_TRYCATCH_CATCH;
		tc->type_filter = type_filter;
		tc->type = eh_read_type (bf, lsda, type_table, type_encoding,
			type_filter, &tc->catch_all);
		r_list_append (result, tc);
		if (!next) {
			break;
		}
		// the offset is relative to the field holding it and may be negative
		const ut64 target = (ut64)(next_field - lsda->buf) + (ut64)next;
		if (target < table_offset || target >= lsda_size) {
			break;
		}
		record = lsda->buf + target;
	}
}

R_IPI void r_bin_dwarf_parse_lsda(RBinFile *bf, RList *result, ut64 fcn_addr, ut64 lsda_addr) {
	R_RETURN_IF_FAIL (bf && bf->bo && result);
	RBinSection *section = r_bin_get_section_at (bf->bo, lsda_addr, true);
	if (!section || section->size > ST32_MAX) {
		return;
	}
	const ut8 *bytes = get_section_bytes (bf, section);
	if (!bytes) {
		return;
	}
	const ut64 section_vaddr = bf->bo->baddr_shift + section->vaddr;
	const ut64 offset = lsda_addr - section_vaddr;
	if (offset >= section->bytes.len) {
		return;
	}
	RBinInfo *info = bf->bo->info;
	EhReader r = {
		.buf = bytes,
		.p = bytes + offset,
		.end = bytes + section->bytes.len,
		.vaddr = section_vaddr,
		.baddr = bf->bo->baddr_shift + bf->bo->baddr,
		.fcn_addr = fcn_addr,
		.bits = (info && info->bits)? info->bits: 64,
		.be = info? info->big_endian: false,
	};
	ut8 lp_encoding = *r.p++;
	ut64 lpstart = fcn_addr;
	if (lp_encoding != DW_EH_PE_OMIT && !eh_encoded (&r, lp_encoding, &lpstart, true)) {
		return;
	}
	if (r.p >= r.end) {
		return;
	}
	ut8 type_encoding = *r.p++;
	const ut8 *type_table = NULL;
	if (type_encoding != DW_EH_PE_OMIT) {
		ut64 type_offset;
		if (!eh_uleb (&r, &type_offset) || type_offset > (ut64)(r.end - r.p)) {
			return;
		}
		type_table = r.p + type_offset;
	}
	if (r.p >= r.end) {
		return;
	}
	ut8 callsite_encoding = *r.p++;
	ut64 callsite_size;
	if (!eh_uleb (&r, &callsite_size) || callsite_size > (ut64)(r.end - r.p)) {
		return;
	}
	const ut8 *callsite_end = r.p + callsite_size;
	const ut8 *action_table = callsite_end;
	while (r.p < callsite_end) {
		ut64 start, length, landing_pad, action;
		if (!eh_encoded (&r, callsite_encoding, &start, false)
				|| !eh_encoded (&r, callsite_encoding, &length, false)
				|| !eh_encoded (&r, callsite_encoding, &landing_pad, false)
				|| !eh_uleb (&r, &action) || r.p > callsite_end) {
			break;
		}
		// start and length are relative to the function, only the landing pad is lpstart-based
		if (!landing_pad || landing_pad > UT64_MAX - lpstart) {
			continue;
		}
		if (start > UT64_MAX - fcn_addr || length > UT64_MAX - fcn_addr - start) {
			continue;
		}
		eh_add_action (bf, result, &r, action_table, type_table, type_encoding,
			action, fcn_addr, fcn_addr + start, fcn_addr + start + length,
			lpstart + landing_pad);
	}
}

/* eh_frame CIE parser, only extracts the pointer encodings needed to locate
 * the LSDA of each FDE. */

typedef struct {
	ut8 fde_encoding;
	ut8 lsda_encoding;
	bool has_augmentation_data;
	int bits; // address size, honoring the one given by the version 4 CIEs
} EhCie;

static bool eh_parse_cie(const EhReader *section_reader, const ut8 *record, const ut8 *record_end, EhCie *cie) {
	EhReader r = *section_reader;
	r.p = record;
	r.end = record_end;
	cie->fde_encoding = DW_EH_PE_ABSPTR;
	cie->lsda_encoding = DW_EH_PE_OMIT;
	cie->has_augmentation_data = false;
	cie->bits = section_reader->bits;
	if (r.p >= r.end) {
		return false;
	}
	const ut8 version = *r.p++;
	// version 2 was never used and anything newer than 5 is unknown
	if (version != 1 && (version < 3 || version > 5)) {
		return false;
	}
	const ut8 *augmentation = r.p;
	const ut8 *nul = memchr (augmentation, 0, r.end - augmentation);
	if (!nul) {
		return false;
	}
	r.p = nul + 1;
	if (version >= 4) {
		if (r.end - r.p < 2) {
			return false;
		}
		const ut8 address_size = *r.p++;
		if (address_size != 4 && address_size != 8) {
			return false;
		}
		cie->bits = address_size * 8;
		r.bits = cie->bits;
		const ut8 segment_size = *r.p++;
		if (segment_size) {
			return false;
		}
	}
	if (augmentation[0] == 'e' && augmentation[1] == 'h') {
		ut64 ignored;
		if (!eh_encoded (&r, DW_EH_PE_ABSPTR, &ignored, false)) {
			return false;
		}
	}
	ut64 ignored_u;
	st64 ignored_s;
	if (!eh_uleb (&r, &ignored_u) || !eh_sleb (&r, &ignored_s)) {
		return false;
	}
	if (version == 1) {
		if (r.p >= r.end) {
			return false;
		}
		r.p++; // return address register
	} else if (!eh_uleb (&r, &ignored_u)) {
		return false;
	}
	if (augmentation[0] != 'z') {
		return true;
	}
	cie->has_augmentation_data = true;
	ut64 augmentation_size;
	if (!eh_uleb (&r, &augmentation_size) || augmentation_size > (ut64)(r.end - r.p)) {
		return false;
	}
	r.end = r.p + augmentation_size;
	const ut8 *a;
	for (a = augmentation + 1; *a; a++) {
		switch (*a) {
		case 'L':
			if (r.p >= r.end) {
				return false;
			}
			cie->lsda_encoding = *r.p++;
			break;
		case 'P':
			if (r.p >= r.end) {
				return false;
			}
			{
				const ut8 encoding = *r.p++;
				ut64 ignored;
				if (!eh_encoded (&r, encoding & ~DW_EH_PE_INDIRECT, &ignored, true)) {
					return false;
				}
			}
			break;
		case 'R':
			if (r.p >= r.end) {
				return false;
			}
			cie->fde_encoding = *r.p++;
			break;
		// flags taking no augmentation data: signal frame, b-key and mte frames
		case 'S':
		case 'B':
		case 'G':
			break;
		default:
			return false;
		}
	}
	return true;
}

// decode the header of an eh_frame record, returns false on a terminator or a truncated entry
static bool eh_record_header(const EhReader *r, ut64 offset, ut64 *length, ut64 *length_size, ut64 *id_size) {
	const ut64 section_size = r->end - r->buf;
	if (offset + 4 > section_size) {
		return false;
	}
	const ut8 *entry = r->buf + offset;
	ut64 len = r_read_ble32 (entry, r->be);
	*length_size = 4;
	*id_size = 4;
	if (len == UT32_MAX) { // 64 bit dwarf format
		if (offset + 12 > section_size) {
			return false;
		}
		len = r_read_ble64 (entry + 4, r->be);
		*length_size = 12;
		*id_size = 8;
	}
	// a zero length marks the end of the section
	if (len < *id_size || len > section_size - offset - *length_size) {
		return false;
	}
	*length = len;
	return true;
}

// resolve the lsda pointer held in the augmentation data of one fde
static void eh_parse_fde(RBinFile *bf, RList *result, const EhReader *section_reader,
		const EhCie *cie, const ut8 *record, const ut8 *record_end, HtUP *seen) {
	if (!cie->has_augmentation_data || cie->lsda_encoding == DW_EH_PE_OMIT) {
		return;
	}
	// the indirect flag asks for a dereference that can't be done from the section bytes
	if ((cie->fde_encoding | cie->lsda_encoding) & DW_EH_PE_INDIRECT) {
		return;
	}
	EhReader r = *section_reader;
	r.p = record;
	r.end = record_end;
	r.bits = cie->bits;
	ut64 fcn_addr, range, augmentation_size, lsda;
	if (!eh_encoded (&r, cie->fde_encoding, &fcn_addr, true)
			|| !eh_encoded (&r, cie->fde_encoding & 0x0f, &range, false)
			|| !eh_uleb (&r, &augmentation_size)
			|| augmentation_size > (ut64)(r.end - r.p)) {
		return;
	}
	r.fcn_addr = fcn_addr;
	r.end = r.p + augmentation_size;
	if (!eh_encoded (&r, cie->lsda_encoding, &lsda, true) || !lsda) {
		return;
	}
	// every lsda describes a single function, so parse each one just once
	if (!ht_up_insert (seen, lsda, (void *)(size_t)1)) {
		return;
	}
	r_bin_dwarf_parse_lsda (bf, result, fcn_addr, lsda);
}

// walk the FDEs in the eh_frame section parsing the LSDA referenced by each one
R_IPI void r_bin_dwarf_parse_eh_frame(RBinFile *bf, RList *result) {
	R_RETURN_IF_FAIL (bf && bf->bo && result);
	RBinSection *section = NULL, *s;
	R_VEC_FOREACH (&bf->bo->sections_vec, s) {
		if (!s->is_segment && s->name && r_str_endswith (s->name, ".eh_frame")) {
			section = s;
			break;
		}
	}
	if (!section || section->size < 8 || section->size > ST32_MAX) {
		return;
	}
	const ut8 *bytes = get_section_bytes (bf, section);
	if (!bytes || section->bytes.len < 8) {
		return;
	}
	RBinInfo *info = bf->bo->info;
	EhReader section_reader = {
		.buf = bytes,
		.end = bytes + section->bytes.len,
		.vaddr = bf->bo->baddr_shift + section->vaddr,
		.baddr = bf->bo->baddr_shift + bf->bo->baddr,
		.bits = (info && info->bits)? info->bits: 64,
		.be = info? info->big_endian: false,
	};
	HtUP *seen = ht_up_new0 ();
	if (!seen) {
		return;
	}
	// most objects share a single CIE, so caching the last one avoids reparsing it
	EhCie cie = {0};
	ut64 cached_cie = UT64_MAX;
	bool cie_ok = false;
	ut64 offset = 0;
	ut64 length, length_size, id_size;
	while (eh_record_header (&section_reader, offset, &length, &length_size, &id_size)) {
		const ut64 next_offset = offset + length_size + length;
		const ut8 *id_field = bytes + offset + length_size;
		// a zero id marks a CIE, FDEs hold the relative offset to their CIE
		const ut64 cie_pointer = r_read_ble (id_field, section_reader.be, id_size * 8);
		if (!cie_pointer || cie_pointer > (ut64)(id_field - bytes)) {
			offset = next_offset;
			continue;
		}
		const ut64 cie_offset = (id_field - bytes) - cie_pointer;
		if (cie_offset != cached_cie) {
			ut64 cie_length, cie_length_size, cie_id_size;
			cached_cie = cie_offset;
			cie_ok = false;
			if (eh_record_header (&section_reader, cie_offset, &cie_length, &cie_length_size, &cie_id_size)) {
				const ut8 *cie_entry = bytes + cie_offset;
				// the pointed record must be a CIE, so its id must be zero
				if (!r_read_ble (cie_entry + cie_length_size, section_reader.be, cie_id_size * 8)) {
					cie_ok = eh_parse_cie (&section_reader, cie_entry + cie_length_size + cie_id_size,
						cie_entry + cie_length_size + cie_length, &cie);
				}
			}
		}
		if (cie_ok) {
			eh_parse_fde (bf, result, &section_reader, &cie,
				id_field + id_size, bytes + next_offset, seen);
		}
		offset = next_offset;
	}
	ht_up_free (seen);
}
