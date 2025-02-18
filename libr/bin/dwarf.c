/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include <r_core.h>
#include "format/elf/elf.h"

#define READ8(buf)                                                \
	(((buf) + sizeof (ut8) < buf_end) ? ((ut8 *)buf)[0] : 0); \
	(buf) += sizeof (ut8)
#define READ16(buf)                                                            \
	(((buf) + sizeof (ut16) < buf_end) ? r_read_ble16 (buf, be) : 0); \
	(buf) += sizeof (ut16)
#define READ32(buf)                                                            \
	(((buf) + sizeof (ut32) < buf_end) ? r_read_ble32 (buf, be) : 0); \
	(buf) += sizeof (ut32)
#define READ64(buf)                                                            \
	(((buf) + sizeof (ut64) < buf_end) ? r_read_ble64 (buf, be) : 0); \
	(buf) += sizeof (ut64)

#define READ_BUF(x,y) if (idx+sizeof (y)>=len) { return false;} \
	(x)=*(y*)buf; idx+=sizeof (y);buf+=sizeof (y)

#define READ_BUF64(x) if (idx + sizeof (ut64)>=len) { return false;} \
	(x)=r_read_ble64 (buf, be); idx+=sizeof (ut64);buf+=sizeof (ut64)
#define READ_BUF32(x) if (idx + sizeof (ut32)>=len) { return false;} \
	(x)=r_read_ble32 (buf, be); idx+=sizeof (ut32);buf+=sizeof (ut32)
#define READ_BUF16(x) if (idx + sizeof (ut16)>=len) { return false;} \
	(x)=r_read_ble16 (buf, be); idx+=sizeof (ut16);buf+=sizeof (ut16)

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


static R_TH_LOCAL RBinObject *lastObject = NULL;
static R_TH_LOCAL RBinSection *lastSection[DWARF_SN_MAX] = {NULL};

static void dwarf_cache_reset(void) {
	lastObject = NULL;
	int i;
	for (i = 0; i < DWARF_SN_MAX; i++) {
		lastSection[i] = NULL;
	}
}

// 1 of 20s spent in this non-mnemonized function
static RBinSection *getsection(RBin *bin, int sn) {
	R_RETURN_VAL_IF_FAIL (sn >= 0 && sn < DWARF_SN_MAX, NULL);
	RListIter *iter;
	RBinSection *section = NULL;
	RBinObject *o = R_UNWRAP3 (bin, cur, bo);
	if (o != lastObject) {
		dwarf_cache_reset ();
		lastObject = o;
	}
	char const *rclass = R_UNWRAP3 (o, info, rclass);
	if (R_LIKELY (o && o->sections)) {
		/* XXX: xcoff64 specific hack */
		const char * const *name_tab = rclass && !strcmp (o->info->rclass, "xcoff64")
			? dwarf_sn_xcoff64
			: dwarf_sn_elf;
		const char *name_str = name_tab[sn];
		if (!name_str) {
			return NULL;
		}
		if (lastSection[sn]) {
			RBinSection *ls = lastSection[sn];
			const char *lsn = ls->name;
			if (strstr (lsn , name_str)) {
				if (r_str_startswith (lsn, ".debug_") && R_BIN_ELF_SCN_IS_COMPRESSED (ls->flags))  {
					R_LOG_WARN ("Compressed dwarf sections not yet supported");
					return NULL;
				}
				if (strstr (lsn, "zdebug")) {
					R_LOG_WARN ("Compressed dwarf sections not yet supported");
					return NULL;
				}
				return ls;
			}
		}
		r_list_foreach (o->sections, iter, section) {
			if (strstr (section->name, name_str)) {
				if (r_str_startswith (section->name, ".debug_") && R_BIN_ELF_SCN_IS_COMPRESSED (section->flags))  {
					R_LOG_WARN ("Compressed dwarf sections not yet supported");
					return NULL;
				}
				if (strstr (section->name, "zdebug")) {
					R_LOG_WARN ("Compressed dwarf sections not yet supported");
					return NULL;
				}
				lastSection[sn] = section;
				return section;
			}
		}
	}
	return NULL;
}

// XXX this is not optimal. we can use rbuf apis everywhere and avoid boundary checks and full section reads
static ut8 *get_section_bytes(RBin *bin, int sect_name, size_t *len) {
	R_RETURN_VAL_IF_FAIL (bin && len, NULL);
	RBinSection *section = getsection (bin, sect_name);
	if (!section || !bin->cur) {
		return NULL;
	}
	RBinFile *binfile = bin->cur;
	if (section->size > binfile->size) {
		return NULL;
	}
	*len = section->size;
	ut8 *buf = calloc (1, *len);
	if (R_LIKELY (buf)) {
		r_buf_read_at (binfile->buf, section->paddr, buf, *len);
	}
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

/**
 * @brief Reads 64/32 bit unsigned based on format
 *
 * @param is_64bit Format of the comp unit
 * @param buf Pointer to the buffer to read from, to update after read
 * @param buf_end To check the boundary /for READ macro/
 * @return ut64 Read value
 */
static inline ut64 dwarf_read_offset(bool is_64bit, const ut8 **buf, const ut8 *buf_end, bool be) {
	ut64 result;
	if (!buf || !*buf || !buf_end) {
		return 0;
	}
	if (is_64bit) {
		if (*buf + 8 >= buf_end) {
			return 0;
		}
		result = READ64 (*buf);
	} else {
		if (*buf + 4 >= buf_end) {
			return 0;
		}
		result = (ut64)READ32 (*buf);
	}
	return result;
}

static inline ut64 dwarf_read_address(size_t size, const ut8 **buf, const ut8 *buf_end, bool be) {
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

static void line_header_fini(RBinDwarfLineHeader *hdr) {
	if (hdr) {
		size_t i;
		if (hdr->file_names) {
			for (i = 0; i < hdr->file_names_count; i ++) {
				free (hdr->file_names[i].name);
			}
			free (hdr->file_names);
		}
		free (hdr->std_opcode_lengths);
	}
}

static char *get_compilation_directory_key(int debug_line_offset) {
	if (debug_line_offset < 0) {
		return NULL;
	}
	return r_str_newf ("DW_AT_comp_dir%d", debug_line_offset);
}

// Parses source file header of DWARF version <= 4
static const ut8 *parse_line_header_source(RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, Sdb *sdb, int mode, PrintfCallback print, int debug_line_offset) {
	int i = 0;
	size_t count = 1;
	const ut8 *tmp_buf = NULL;
	char *fn = NULL;

	if (mode == R_MODE_PRINT) {
		print (" The Directory Table:\n");
	}
	while (buf <= buf_end) {
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
	if (mode == R_MODE_PRINT) {
		print ("\n");
		print (" The File Name Table:\n");
		print ("  Entry Dir     Time      Size       Name\n");
	}
	int entry_index = 1; // used for printing information

	for (i = 0; i < 2; i++) {
		while (buf + 1 < buf_end) {
			size_t maxlen = R_MIN ((size_t) (buf_end - buf - 1), 0xfff);
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
				if (id_idx > 0) {
					include_dir = sdb_array_get (sdb, "includedirs", id_idx - 1, 0);
					if (include_dir && include_dir[0] != '/') {
						char *comp_dir_key = get_compilation_directory_key (debug_line_offset);
						const char *k = comp_dir_key? comp_dir_key: "DW_AT_comp_dir";
						const char *comp_dir = sdb_const_get (bf->sdb_addrinfo, k, 0);
						if (comp_dir) {
							include_dir = r_str_newf ("%s/%s", comp_dir, include_dir);
						}
						free (comp_dir_key);
					} else {
						// XXX
					}
				} else {
					char *comp_dir_key = get_compilation_directory_key (debug_line_offset);
					if (comp_dir_key) {
						include_dir = sdb_get (bf->sdb_addrinfo, comp_dir_key, 0);
					} else {
						include_dir = sdb_get (bf->sdb_addrinfo, "DW_AT_comp_dir", 0);
					}
					if (!include_dir) {
						include_dir = strdup ("./");
					}
					free (comp_dir_key);
				}

				if (hdr->file_names) {
					hdr->file_names[count].name = r_str_newf ("%s/%s", r_str_get (include_dir), fn);
					hdr->file_names[count].id_idx = id_idx;
					hdr->file_names[count].mod_time = mod_time;
					hdr->file_names[count].file_len = file_len;
					// TODO: add_files (bf, hdr->file_names[count].name);
					// eprintf ("ADP %s\n", hdr->file_names[count].name);
				}
				R_FREE (include_dir);
			}
			count++;
			if (mode == R_MODE_PRINT && i) {
				print ("  %d     %" PFMT64d "       %" PFMT64d "         %" PFMT64d "          %s\n",
						entry_index++, id_idx, mod_time, file_len, fn);
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

static char *get_section_string(RBin *bin, RBinSection * section, size_t offset) {
	ut8 str[32], str2[128], str3[2048];
	RBinFile *bf = bin ? bin->cur: NULL;
	if (!section || (section->paddr + offset + 2) > bf->size) {
		return NULL;
	}
	size_t len = R_MIN (section->size - offset, sizeof (str) - 1);
	str[len] = 0;
	r_buf_read_at (bf->buf, section->paddr + offset, str, len);
	if (r_str_nlen ((const char *)str, len) != len) {
		// eprintf ("%d\n", r_str_nlen (str, len));
		return r_str_ndup ((const char *)str, sizeof (str));
	}
	len = R_MIN (section->size - offset, sizeof (str2) - 1);
	str2[len] = 0;
	r_buf_read_at (bf->buf, section->paddr + offset, str2, len);
	if (r_str_nlen ((const char *)str2, len) != len) {
		// eprintf ("%d\n", r_str_nlen (str2, len));
		return r_str_ndup ((const char *)str2, sizeof (str2));
	}
	len = R_MIN (section->size - offset, sizeof (str3) - 1);
	str3[len] = 0;
	// memset (str3, 0, len + 1);
	r_buf_read_at (bf->buf, section->paddr + offset, str3, len);
	if (r_str_nlen ((const char *)str3, len) != len) {
		// eprintf ("%d\n", r_str_nlen (str2, len));
		return r_str_ndup ((const char *)str3, sizeof (str3));
	}
	char *res = r_str_ndup ((const char *)str3, sizeof (str3));
	R_LOG_DEBUG ("Truncated corrupted section name: %s", res);
	return res;
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
		R_LOG_WARN ("Too many entry formats: %d >= %d", nform, MAX_V5_DESCRIPTORS);
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
};

static const ut8 *ut64_form_value(entry_descriptor desc, const ut8 *buf, const ut8 *buf_end, ut64 *val, bool be) {
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

static const ut8 *str_form_value(entry_descriptor desc, RBin *bin, const ut8 *buf, const ut8 *buf_end, char **v, bool be, bool is_64bit) {
	const size_t maxlen = 0xfff;
	char *name = NULL;
	ut64 section_offset = 0;
	RBinSection *section = NULL;

	switch (desc.form) {
	case DW_FORM_line_strp:
		section_offset = dwarf_read_offset (is_64bit, &buf, buf_end, be);
		section = getsection (bin, DWARF_SN_LINE_STR);
		name = get_section_string (bin, section, section_offset);
		if (name == NULL) {
			return NULL;
		}
		r_str_ansi_strip (name);
		r_str_replace_ch (name, '\n', 0, true);
		r_str_replace_ch (name, '\t', 0, true);
		*v = name;
		return buf;
	case DW_FORM_strp:
		section_offset = dwarf_read_offset (is_64bit, &buf, buf_end, be);
		section = getsection (bin, DWARF_SN_STR);
		name = get_section_string (bin, section, section_offset);
		if (name == NULL) {
			return NULL;
		}
		r_str_ansi_strip (name);
		r_str_replace_ch (name, '\n', 0, true);
		r_str_replace_ch (name, '\t', 0, true);
		*v = name;
		return buf;
	case DW_FORM_strp_sup:
		// TODO: handle this properly
		dwarf_read_offset (is_64bit, &buf, buf_end, be);
		return buf;
	case DW_FORM_string:
		// TODO: find a way to test this case.
		if (buf == NULL || buf >= buf_end) {
			return NULL;
		}
		const int len = R_MIN (maxlen, (buf_end - buf));
		if (len < 0) {
			return NULL;
		}
		*v = r_str_ndup ((const char *)buf, len);
		buf += len + 1;
		return buf;
	default:
		R_LOG_DEBUG ("Expected form type string but got: %#x", desc.form);
		return NULL;
	}
};

static const ut8 *data16_form_value(entry_descriptor desc, const ut8 *buf, const ut8 *buf_end, ut8 val[16]) {
	if (desc.form != DW_FORM_data16) {
		R_LOG_DEBUG ("Expected form type data16 but got: %#x", desc.form);
		return NULL;
	}
	if (buf + 16 >= buf_end) {
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
static const ut8 *parse_line_header_source_dwarf5(RBin *bin, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, Sdb *s, int mode, PrintfCallback print, bool be) {
	if (mode == R_MODE_PRINT) {
		print (" The Directory Table:\n");
	}

	entry_formatv5 dir_form = {0};
	buf = parse_line_entryv5 (buf, buf_end, &dir_form);
	if (buf == NULL) {
		R_LOG_WARN ("Invalid uleb128 for dwarf directory entry format");
		return NULL;
	}
	if (dir_form.ndesc <= 0) {
		R_LOG_WARN ("Invalid number of descriptors for directory table");
		return NULL;
	}

	ut64 ndir_entry = 0;
	const ut8 *nbuf = r_uleb128 (buf, buf_end - buf, &ndir_entry, NULL);
	if (!nbuf || nbuf == buf) {
		R_LOG_WARN ("Invalid uleb128 for dwarf directory count");
		return NULL;
	}
	ut64 i, j;
	if ((int)ndir_entry != -1) {
		buf = nbuf;
		for (i = 0; i < ndir_entry; i++) {
			for (j = 0; j < dir_form.ndesc; j++) {
				entry_descriptor desc = dir_form.descs[j];
				char *name = NULL;

				switch (desc.type) {
				case DW_LNCT_path:
					buf = str_form_value (desc, bin, buf, buf_end, &name, be, hdr->is_64bit);
					if (buf == NULL || name == NULL) {
						R_LOG_WARN ("Invalid description (%#x) for directory %d %d", desc.form, i, ndir_entry);
						return NULL;
					}
					add_sdb_include_dir (s, name, i);
					free (name);
					break;
				default:
					R_LOG_WARN ("Invalid description type (%#x)", desc.type);
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

	entry_formatv5 file_form = {0};
	buf = parse_line_entryv5 (buf, buf_end, &file_form);
	if (buf == NULL) {
		R_LOG_WARN ("Invalid uleb128 for dwarf file entry format");
		return NULL;
	}
	if (file_form.ndesc <= 0) {
		R_LOG_WARN ("Invalid number of descriptors for file table");
		return NULL;
	}

	ut64 nfile_entry = 0;
	nbuf = r_uleb128 (buf, buf_end - buf, &nfile_entry, NULL);
	if (!nbuf || nbuf == buf) {
		R_LOG_WARN ("Invalid uleb128 for dwarf file count");
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
			char *name = NULL;
			ut64 data = 0;

			switch (desc.type) {
			case DW_LNCT_path:
				buf = str_form_value (desc, bin, buf, buf_end, &name, be, hdr->is_64bit);
				if (buf == NULL || name == NULL) {
					R_LOG_WARN ("Invalid description (%#x) for file path", desc.form);
					return NULL;
				}
				file->name = name;
				break;
			case DW_LNCT_timestamp:
				buf = ut64_form_value (desc, buf, buf_end, &data, be);
				if (buf == NULL) {
					R_LOG_WARN ("Invalid description (%#x,%#x) for file timestamp", desc.type, desc.form);
					return NULL;
				}
				file->mod_time = data;
				break;
			case DW_LNCT_directory_index:
				buf = ut64_form_value (desc, buf, buf_end, &data, be);
				if (buf == NULL) {
					R_LOG_WARN ("Invalid description (%#x,%#x) for file dir index", desc.type, desc.form);
					return NULL;
				}
				if (file->name == NULL) {
					break;
				}
				file->id_idx = data;

				// prepend directory to the file name
				char *dir = sdb_array_get (s, "includedirs", file->id_idx, 0);
				char *filename = file->name;
				if (dir == NULL || !strcmp (filename, dir)) {
					break;
				}

				bool isabs = r_file_is_abspath (dir);
				if (file->id_idx == 0 || isabs) {
					file->name = r_str_newf ("%s/%s", dir, filename);
					free (filename);
				} else {
					char *comp_unit_dir = sdb_array_get (s, "includedirs", 0, 0);
					if (comp_unit_dir == NULL || !strcmp (filename, comp_unit_dir)) {
						break;
					}
					char *tmp = r_str_newf ("%s/%s/%s",
								comp_unit_dir, dir, filename);
					file->name = tmp;
					free (filename);
				}
				break;
			case DW_LNCT_size:
				buf = ut64_form_value (desc, buf, buf_end, &data, be);
				if (buf == NULL) {
					R_LOG_WARN ("Invalid description (%#x,%#x) for file size", desc.type, desc.form);
					return NULL;
				}
				file->file_len = data;
				break;
			case DW_LNCT_MD5:
				buf = data16_form_value (desc, buf, buf_end, file->md5sum);
				if (buf == NULL) {
					R_LOG_WARN ("Invalid description (%#x,%#x) for file checksum", desc.type, desc.form);
					return NULL;
				}
				file->has_checksum = true;
				break;
			default:
				R_LOG_ERROR ("Invalid or unsupported DW line number content type %#x", desc.type);
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
			       i + 1, file->id_idx, file->mod_time, file->file_len, sumstr, file->name);
		}
	}

	if (mode == R_MODE_PRINT) {
		print ("\n");
	}

	sdb_free (s);
	return buf;
}

static const ut8 *parse_line_header(RBin *bin, RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, int mode, PrintfCallback print, int debug_line_offset, bool be) {
	R_RETURN_VAL_IF_FAIL (hdr && bf && buf, NULL);

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

	hdr->header_length = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);
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
	hdr->line_base = (int8_t) READ8 (buf);
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
		buf = parse_line_header_source (bf, buf, buf_end, hdr, sdb, mode, print, debug_line_offset);
	} else {
		buf = parse_line_header_source_dwarf5 (bin, buf, buf_end, hdr, sdb, mode, print, be);
	}

	return buf;
}

static inline void add_sdb_addrline(RBinFile *bf, ut64 addr, const char *file, ut64 line, ut64 column, int mode, PrintfCallback print) {
	Sdb *s = bf->sdb_addrinfo;
	if (!s || R_STR_ISEMPTY (file)) {
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
	case '*':
#if R2_590
		/// XXX CL must take filename as last argument to support spaces imho
		print ("'CL %s|%d|%d 0x%08"PFMT64x"\n", p, (int)line, (int)column, addr);
#else
		if (column) {
			print ("'CL %s:%d:%d 0x%08"PFMT64x"\n", p, (int)line, (int)column, addr);
		} else if (line > 0) {
			print ("'CL %s:%d 0x%08"PFMT64x"\n", p, (int)line, addr);
		}
#endif
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
#if 0
	char offset[SDB_NUM_BUFSZ];
	char *offset_ptr;
	char *fileline = (column > 0)
		? r_str_newf ("%s|%"PFMT64d"|%"PFMT64d, p, line, column)
		: r_str_newf ("%s|%"PFMT64d, p, line);
	r_str_ansi_strip (fileline);
	r_str_replace_ch (fileline, '\n', 0, true);
	r_str_replace_ch (fileline, '\t', 0, true);
	offset_ptr = sdb_itoa (addr, 16, offset, sizeof (offset));
	sdb_add (s, offset_ptr, fileline, 0);
	sdb_add (s, fileline, offset_ptr, 0);
	free (fileline);
#else
	RBinDbgItem item = {
		.addr = addr,
		.file = file,
		.line = line,
		.column = column,
	};
	bf->addrline.al_add (&bf->addrline, item);
#endif
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
	ut32 addr_size = o && o->info && o->info->bits ? o->info->bits / 8 : 4;
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

		if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
			int fnidx = regs->file;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline (binfile, regs->address,
						hdr->file_names[fnidx].name,
						regs->line, regs->column, mode, print);
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
	int line_increment =  hdr->line_base + (adj_opcode % hdr->line_range);
	regs->line += line_increment;
	if (mode == R_MODE_PRINT) {
		print ("  Special opcode %d: ", adj_opcode);
		print ("advance Address by %"PFMT64d " to 0x%"PFMT64x" and Line by %d to %"PFMT64d"\n",
			advance_adr, regs->address, line_increment, regs->line);
	}
	if (binfile && hdr->file_names) {
		int idx = regs->file;
		if (idx >= 0 && idx < hdr->file_names_count) {
			add_sdb_addrline (binfile, regs->address,
					hdr->file_names[idx].name,
					regs->line, regs->column, mode, print);
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
		if (binfile && hdr->file_names) {
			int fnidx = regs->file;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline (binfile,
					regs->address,
					hdr->file_names[fnidx].name,
					regs->line, regs->column, mode, print);
			}
		}
		regs->basic_block = false;
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
		buf = r_leb128 (buf, buf_end - buf, &sbuf);
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
		regs->is_stmt = regs->is_stmt ? false: true;
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
	return (size_t) buf? (buf - obuf): 0; // number of bytes we've moved by
}

static bool parse_line_raw(RBin *a, const ut8 *obuf, ut64 len, int mode, bool be) {
	R_RETURN_VAL_IF_FAIL (a && obuf, false);
	PrintfCallback print = a->cb_printf;

	if (mode == R_MODE_PRINT) {
		print ("Raw dump of debug contents of section .debug_line:\n\n");
	}
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;
	const ut8 *tmpbuf = NULL;

	RBinDwarfLineHeader hdr = {0};
	ut64 buf_size;

	// each iteration we read one header AKA comp. unit
	while (buf <= buf_end) {
		// How much did we read from the compilation unit
		size_t bytes_read = 0;
		// calculate how much we've read by parsing header
		// because header unit_length includes itself
		buf_size = buf_end - buf;

		tmpbuf = buf;

		// Offset from start of the .debug_line section, equal to DW_AT_stmt_list
		// from the dwarf standard.
		int debug_line_offset = buf - obuf;
		buf = parse_line_header (a, a->cur, buf, buf_end, &hdr, mode, print, debug_line_offset, be);
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
		ut64 n = (((ut64) (size_t)buf / offset) + 1) * offset - ((ut64)(size_t)buf);
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
	inf->comp_units = calloc (sizeof (RBinDwarfCompUnit), DEBUG_INFO_CAPACITY);
	if (!inf->comp_units) {
		return false;
	}
	inf->lookup_table = ht_up_new0 ();
	inf->capacity = DEBUG_INFO_CAPACITY;
	inf->count = 0;
	return true;
}

static bool init_die(RBinDwarfDie *die, ut64 abbr_code, ut64 attr_count) {
	if (!die) {
		return false;
	}
	if (attr_count) {
		die->attr_values = calloc (sizeof (RBinDwarfAttrValue), attr_count);
		if (!die->attr_values) {
			return false;
		}
	} else {
		die->attr_values = NULL;
	}
	die->abbrev_code = abbr_code;
	die->capacity = attr_count;
	die->count = 0;
	return true;
}

static bool init_comp_unit(RBinDwarfCompUnit *cu) {
	if (!cu) {
		return false;
	}
	cu->dies = calloc (sizeof (RBinDwarfDie), COMP_UNIT_CAPACITY);
	if (!cu->dies) {
		return false;
	}
	cu->capacity = COMP_UNIT_CAPACITY;
	cu->count = 0;
	return true;
}

static int expand_cu(RBinDwarfCompUnit *cu) {
	if (!cu || cu->capacity == 0 || cu->capacity != cu->count) {
		return false;
	}
	RBinDwarfDie *tmp = (RBinDwarfDie *)realloc (cu->dies, cu->capacity * 2 * sizeof (RBinDwarfDie));
	if (tmp) {
		memset ((ut8 *)tmp + cu->capacity * sizeof (RBinDwarfDie),
				0, cu->capacity * sizeof (RBinDwarfDie));
		cu->dies = tmp;
		cu->capacity *= 2;
		return true;
	}
	return false;
}

static bool init_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	ad->defs = calloc (sizeof (RBinDwarfAttrDef), ABBREV_DECL_CAP);
	if (ad->defs) {
		ad->capacity = ABBREV_DECL_CAP;
		ad->count = 0;
		return true;
	}
	return false;
}

static void expand_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	if (!ad || !ad->capacity || ad->capacity != ad->count) {
		return;
	}
	RBinDwarfAttrDef *tmp = (RBinDwarfAttrDef *)realloc (ad->defs,
		ad->capacity * 2 * sizeof (RBinDwarfAttrDef));
	if (tmp) {
		// Set the area in the buffer past the length to 0
		memset ((ut8 *)tmp + ad->capacity * sizeof (RBinDwarfAttrDef),
			0, ad->capacity * sizeof (RBinDwarfAttrDef));
		ad->defs = tmp;
		ad->capacity *= 2;
	}
}

static bool init_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	if (!da) {
		return false;
	}
	da->decls = calloc (sizeof (RBinDwarfAbbrevDecl), DEBUG_ABBREV_CAP);
	if (!da->decls) {
		return false;
	}
	da->capacity = DEBUG_ABBREV_CAP;
	da->count = 0;
	return true;
}

static bool expand_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	if (!da || da->capacity == 0 || da->capacity != da->count) {
		return false;
	}
	RBinDwarfAbbrevDecl *tmp = (RBinDwarfAbbrevDecl *)realloc (da->decls,
		da->capacity * 2 * sizeof (RBinDwarfAbbrevDecl));
	if (!tmp) {
		return false;
	}
	memset ((ut8 *)tmp + da->capacity * sizeof (RBinDwarfAbbrevDecl),
		0, da->capacity * sizeof (RBinDwarfAbbrevDecl));
	da->decls = tmp;
	da->capacity *= 2;
	return true;
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
		if (declstag >= 0 && declstag < DW_TAG_LAST) {
			print ("  %-25s ", dwarf_tag_name_encodings[declstag]);
		}
		print ("[%s]", da->decls[i].has_children ?
				"has children" : "no children");
		print (" (0x%"PFMT64x")\n", da->decls[i].offset);

		if (da->decls[i].defs) {
			for (j = 0; j < da->decls[i].count; j++) {
				attr_name = da->decls[i].defs[j].attr_name;
				attr_form = da->decls[i].defs[j].attr_form;
				if (is_printable_attr (attr_name) && is_printable_form (attr_form)) {
					print ("    %-30s %-30s\n",
							dwarf_attr_encodings[attr_name],
							dwarf_attr_form_encodings[attr_form]);
				}
			}
		}
	}
}

R_API void r_bin_dwarf_free_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	if (da) {
		size_t i;
		for (i = 0; i < da->count; i++) {
			R_FREE (da->decls[i].defs);
		}
		R_FREE (da->decls);
		free (da);
	}
}

static void free_attr_value(RBinDwarfAttrValue *val) {
	// TODO adjust to new forms, now we're leaking
	if (!val) {
		return;
	}
	switch (val->attr_form) {
	case DW_FORM_strp:
	case DW_FORM_string:
	case DW_FORM_line_strp:
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
	if (die) {
		size_t i;
		for (i = 0; i < die->count; i++) {
			free_attr_value (&die->attr_values[i]);
		}
		R_FREE (die->attr_values);
	}
}

static void free_comp_unit(RBinDwarfCompUnit *cu) {
	if (cu) {
		size_t i;
		for (i = 0; i < cu->count; i++) {
			if (cu->dies) {
				free_die (&cu->dies[i]);
			}
		}
		R_FREE (cu->dies);
	}
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
		print ("%"PFMT64d, val->sconstant);
		break;
	case DW_FORM_udata:
		print ("%"PFMT64u, val->uconstant);
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
	case DW_FORM_line_strp:
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
		print ("0x%"PFMT64x, val->address);
		break;
	case DW_FORM_implicit_const:
		print ("0x%"PFMT64x, val->uconstant);
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

	R_RETURN_IF_FAIL (inf);

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
	if (block->length < 1) {
		block->length = 0;
		return NULL;
	}
	if (!buf) {
		R_LOG_WARN ("no data to fill the block");
		block->length = 0;
		return NULL;
	}
	int len = buf_end - buf;
	len = R_MIN (len, block->length);
	if (len < 1) {
		R_LOG_WARN ("truncated block data %d %d", len, block->length);
		block->length = 0;
		return NULL;
	}
	block->data = calloc (sizeof (ut8), len + 1);
	if (R_LIKELY (block->data)) {
		memcpy (block->data, buf, len);
		block->data[len] = 0;
		buf += len;
	}
	if (len != block->length) {
		R_LOG_WARN ("truncated dwarf block");
	}
	block->length = len;
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
static const ut8 *parse_attr_value(RBin *bin, const ut8 *obuf, int obuf_len, RBinDwarfAttrDef *def, RBinDwarfAttrValue *value, const RBinDwarfCompUnitHdr *hdr, bool be) {
	R_RETURN_VAL_IF_FAIL (def && value && hdr && obuf, NULL);

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
			R_LOG_WARN ("DWARF: Unexpected pointer size: %u", (unsigned)hdr->address_size);
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
		if (*buf) {
			char *name = r_str_ndup ((const char *)buf, buf_end - buf);
			r_str_ansi_strip (name);
			r_str_replace_ch (name, '\n', 0, true);
			r_str_replace_ch (name, '\t', 0, true);
			value->string.content = name;
		} else {
			value->string.content = NULL;
		}
		if (value->string.content) {
			buf += strlen (value->string.content) + 1;
		}
		break;
	case DW_FORM_block1:
		value->kind = DW_AT_KIND_BLOCK;
		value->block.length = READ8 (buf);
		buf = fill_block_data (buf, buf_end, &value->block);
		break;
	case DW_FORM_block2:
		value->kind = DW_AT_KIND_BLOCK;
		size_t len = READ16 (buf);
		if (len > 0) {
			size_t len_buf = buf_end - buf;
			size_t datalen = R_MIN (len, len_buf);
			value->block.data = r_mem_dup (buf, datalen);
			buf += datalen;
			value->block.length = datalen;
		} else {
			value->block.length = 0;
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
		buf = fill_block_data (buf, buf_end, &value->block);
		break;
	case DW_FORM_flag:
		value->kind = DW_AT_KIND_FLAG;
		value->flag = READ8 (buf);
		break;
	// offset in .debug_str
	case DW_FORM_strp:
	case DW_FORM_line_strp:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);
		// int section_name = def->attr_form == DW_FORM_strp? DWARF_SN_STR: DWARF_SN_LINE_STR;
		RBinSection *section = (def->attr_form == DW_FORM_strp)
			? getsection (bin, DWARF_SN_STR) : getsection (bin, DWARF_SN_LINE_STR);
		char *str = get_section_string (bin, section, value->string.offset);
		if (str) {
			r_str_ansi_strip (str);
			r_str_replace_ch (str, '\n', 0, true);
			r_str_replace_ch (str, '\t', 0, true);
			value->string.content = str;
		} else {
			value->string.content = NULL;
		}
		break;
	// offset in .debug_info
	case DW_FORM_ref_addr:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);
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
		value->reference = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);
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
		// I need to add 3byte endianness free read here TODO
		value->kind = DW_AT_KIND_ADDRESS;
		buf += 3;
		break;
	case DW_FORM_addrx4:
		value->kind = DW_AT_KIND_ADDRESS;
		value->address = READ32 (buf);
		break;
	case DW_FORM_strp_sup: // offset in a section .debug_line_str
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);
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
		value->reference = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);
		break;
	 // An index into the .debug_rnglists
	case DW_FORM_rnglistx:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = r_uleb128 (buf, buf_end - buf, &value->address, NULL);
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
static const ut8 *parse_die(RBin *bin, const ut8 *buf, const ut8 *buf_end, RBinDwarfAbbrevDecl *abbrev, RBinDwarfCompUnitHdr *hdr, RBinDwarfDie *die, Sdb *sdb, bool be) {
	size_t i;
	int debug_line_offset = -1;
	char *comp_dir = NULL; // name of the compilation directory
	char *comp_dir_key = NULL;
	if (!buf || !buf_end || buf > buf_end) {
		return NULL;
	}
	for (i = 0; i < die->count; i++) {
		memset (&die->attr_values[i], 0, sizeof (RBinDwarfDie));
	}
	if (abbrev->count) {
		for (i = 0; i < abbrev->count && i < die->capacity; i++) {
			memset (&die->attr_values[i], 0, sizeof (die->attr_values[i]));
			// debug_str_len = r_str_nlen (debug_str, buf_end - buf);
			const ut8 *nbuf = parse_attr_value (bin, buf, buf_end - buf,
				&abbrev->defs[i], &die->attr_values[i], hdr, be);
			if (!nbuf) {
				break;
			}
			buf = nbuf;
			RBinDwarfAttrValue *attribute = &die->attr_values[i];

			bool is_string = (attribute->attr_form == DW_FORM_strp || attribute->attr_form == DW_FORM_string ||
				attribute->attr_form == DW_FORM_line_strp);
			bool is_valid_string_form = is_string && attribute->string.content;
			if (attribute->attr_name == DW_AT_stmt_list) {
				debug_line_offset = attribute->reference;
			}
			if (attribute->attr_name == DW_AT_comp_dir && is_valid_string_form) {
				comp_dir = strdup (attribute->string.content);
				r_str_ansi_strip (comp_dir);
				r_str_replace_ch (comp_dir, '\n', 0, true);
				r_str_replace_ch (comp_dir, '\t', 0, true);
			}
			die->count++;
		}
	}
	comp_dir_key = get_compilation_directory_key (debug_line_offset);
	if (!comp_dir_key) {
		sdb_set_owned (sdb, "DW_AT_comp_dir", comp_dir, 0);
	} else {
		sdb_set_owned (sdb, comp_dir_key, comp_dir, 0);
	}

	free (comp_dir_key);
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
static const ut8 *parse_comp_unit(RBin *bin, RBinDwarfDebugInfo *info, Sdb *sdb, const ut8 *buf_start, const ut8 *buf_end, RBinDwarfCompUnit *unit, const RBinDwarfDebugAbbrev *abbrevs, size_t first_abbr_idx, bool be) {
	const ut8 *buf = buf_start;
	const ut8 *theoric_buf_end = buf_start + unit->hdr.length - unit->hdr.header_size;
	if (theoric_buf_end < buf_end) {
		buf_end = theoric_buf_end;
	}

	while (buf && buf < buf_end && buf >= buf_start) {
		if (unit->count && unit->capacity == unit->count) {
			if (!expand_cu (unit)) {
				break;
			}
		}
		RBinDwarfDie *die = &unit->dies[unit->count];
		// add header size to the offset;
		die->offset = buf - buf_start + unit->hdr.header_size + unit->offset;
		die->offset += unit->hdr.is_64bit ? 12 : 4;

		// DIE starts with ULEB128 with the abbreviation code
		ut64 abbr_code = 0;
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

		if (!init_die (die, abbr_code, abbrev->count)) {
			return NULL; // error
		}
		die->tag = abbrev->tag;
		die->has_children = abbrev->has_children;

		buf = parse_die (bin, buf, buf_end, abbrev, &unit->hdr, die, sdb, be);
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
static const ut8 *info_comp_unit_read_hdr(const ut8 *buf, const ut8 *buf_end, RBinDwarfCompUnitHdr *hdr, bool be) {
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
		hdr->abbrev_offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);

		if (hdr->unit_type == DW_UT_skeleton || hdr->unit_type == DW_UT_split_compile) {
			hdr->dwo_id = READ8 (buf);
		} else if (hdr->unit_type == DW_UT_type || hdr->unit_type == DW_UT_split_type) {
			hdr->type_sig = READ64 (buf);
			hdr->type_offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);
		}
	} else {
		hdr->abbrev_offset = dwarf_read_offset (hdr->is_64bit, &buf, buf_end, be);
		hdr->address_size = READ8 (buf);
	}
	hdr->header_size = buf - tmp; // header size excluding length field
	return buf;
}

static bool expand_info(RBinDwarfDebugInfo *info) {
	R_RETURN_VAL_IF_FAIL (info && info->capacity == info->count, -1);
	RBinDwarfCompUnit *tmp = realloc (info->comp_units,
		info->capacity * 2 * sizeof (RBinDwarfCompUnit));
	if (!tmp) {
		return false;
	}
	memset ((ut8 *)tmp + info->capacity * sizeof (RBinDwarfCompUnit),
		0, info->capacity * sizeof (RBinDwarfCompUnit));
	info->comp_units = tmp;
	info->capacity *= 2;
	return true;
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
static RBinDwarfDebugInfo *parse_info_raw(RBin *bin, Sdb *sdb, RBinDwarfDebugAbbrev *da, const ut8 *obuf, size_t len, bool be) {
	R_RETURN_VAL_IF_FAIL (da && sdb && obuf, false);

	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;
	RBinDwarfDebugInfo *info = R_NEW0 (RBinDwarfDebugInfo);
	if (!init_debug_info (info)) {
		goto cleanup;
	}
	int unit_idx = 0;

	while (buf < buf_end) {
		if (info->count >= info->capacity) {
			if (!expand_info (info)) {
				break;
			}
		}

		RBinDwarfCompUnit *unit = &info->comp_units[unit_idx];
		if (!init_comp_unit (unit)) {
			unit_idx--;
			goto cleanup;
		}
		info->count++;

		unit->offset = buf - obuf;
		// small redundancy, because it was easiest solution at a time
		unit->hdr.unit_offset = buf - obuf;

		buf = info_comp_unit_read_hdr (buf, buf_end, &unit->hdr, be);

		if (unit->hdr.length > len) {
			goto cleanup;
		}

		if (da->decls->count >= da->capacity) {
			R_LOG_WARN ("malformed dwarf have not enough buckets for decls");
		}
		R_WARN_IF_FAIL (da->count <= da->capacity);

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

		buf = parse_comp_unit (bin, info, sdb, buf, buf_end, unit, da, first_abbr_idx, be);
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
	if (!init_debug_abbrev (da)) {
		return NULL;
	}

	while (buf && (buf + 1 < buf_end)) {
		offset = buf - obuf;
		buf = r_uleb128 (buf, (size_t)(buf_end-buf), &tmp, NULL);
		if (!buf || !tmp || buf >= buf_end) {
			continue;
		}
		if (da->count == da->capacity) {
			if (!expand_debug_abbrev (da)) {
				break;
			}
		}
		tmpdecl = &da->decls[da->count];
		if (!init_abbrev_decl (tmpdecl)) {
			break;
		}

		tmpdecl->code = tmp;
		buf = r_uleb128 (buf, (size_t)(buf_end - buf), &tmp, NULL);
		tmpdecl->tag = tmp;

		tmpdecl->offset = offset;
		if (buf >= buf_end) {
			break;
		}
		has_children = READ8 (buf);
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
/**
 * @brief Parses .debug_info section
 *
 * @param da Parsed abbreviations
 * @param bin
 * @param mode R_MODE_PRINT to print
 * @return RBinDwarfDebugInfo* Parsed information, NULL if error
 */
R_API RBinDwarfDebugInfo *r_bin_dwarf_parse_info(RBin *bin, RBinDwarfDebugAbbrev *da, int mode) {
	R_RETURN_VAL_IF_FAIL (da && bin, NULL);
	RBinDwarfDebugInfo *info = NULL;
	RBinSection *section = getsection (bin, DWARF_SN_INFO);
	RBinFile *bf = bin->cur;

	ut64 debug_str_len = 0;
	ut8 *debug_str_buf = NULL;

	const bool be = r_bin_is_big_endian (bin);
	if (bf && section) {
		RBinSection *debug_str = getsection (bin, DWARF_SN_STR);
		if (debug_str) {
			debug_str_len = debug_str->size;
			debug_str_buf = calloc (1, debug_str_len + 1);
			if (!debug_str_buf) {
				goto cleanup;
			}
			st64 ret = r_buf_read_at (bf->buf, debug_str->paddr, debug_str_buf, debug_str_len);
			if (ret != debug_str_len) {
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
		if (!r_buf_read_at (bf->buf, section->paddr, buf, len)) {
			free (buf);
			goto cleanup;
		}
		/* set the endianity global [HOTFIX] */
		info = parse_info_raw (bin, bf->sdb_addrinfo, da, buf, len, be);
		if (mode == R_MODE_PRINT && info) {
			print_debug_info (info, bin->cb_printf);
		} else if (info) {
			// TODO: load compilation units
			// TODO: only necessary when we have no srcline inf
			// TODO: add a command to enumerate the ranges for all the compilation units
			// TODO: idu? -> 0x00001600 0x0001840 entry.S
			size_t i, j, k;
			RBinDwarfDie *dies;
			RBinDwarfAttrValue *values;
			for (i = 0; i < info->count; i++) {
				dies = info->comp_units[i].dies;
				for (j = 0; j < info->comp_units[i].count; j++) {
					values = dies[j].attr_values;
					const char *name = NULL;
					const char *path = NULL;
					ut64 low = 0;
					// unused ut64 hig = 0;
					for (k = 0; k < dies[j].count; k++) {
						int n = values[k].attr_name;
						RBinDwarfAttrValue *v = &values[k];
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
						RBinDbgItem item = {
							.addr = low + 1, // XXX this low is wrong, we must add compilation units not addrline
							.file = abspath,
							.line = 0,
							.column = 0,
						};
						// TODO: add compilation unit callback here
						bf->addrline.al_add_cu (&bf->addrline, item);
						free (abspath);
					}
				}
			}
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

static RBinDbgItem *row_new(ut64 addr, const char *file, int line, int col) {
	R_RETURN_VAL_IF_FAIL (file, NULL);
	RBinDbgItem *row = R_NEW0 (RBinDbgItem);
	row->file = strdup (file);
	row->addr = addr;
	row->line = line;
	row->column = col;
	return row;
}

static void row_free(void *p) {
	if (p) {
		RBinDbgItem *row = (RBinDbgItem *)p;
		r_bin_dbgitem_free (row);
	}
}

static bool cb(void *user, RBinDbgItem *item) {
	RList *list = (RList *)user;
	RBinDbgItem *row = row_new (item->addr, item->file, item->line, item->column);
	if (row) {
		r_list_append (list, row);
	}
	return true;
}

R_API RList *r_bin_dwarf_parse_line(RBin *bin, int mode) {
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	RList *list = NULL;
	dwarf_cache_reset ();
	const bool be = r_bin_is_big_endian (bin);
	RBinSection *section = getsection (bin, DWARF_SN_LINE);
	RBinFile *bf = bin->cur;
	if (bf && section) {
		int len = section->size;
		if (len < 1) {
			return NULL;
		}
		ut8 *buf = calloc (1, len + 1);
		if (!buf) {
			return NULL;
		}
		int ret = r_buf_read_at (bf->buf, section->paddr, buf, len);
		if (ret != len) {
			free (buf);
			return NULL;
		}
		list = r_list_newf (row_free);
		/* set the endianity global [HOTFIX] */
		// Actually parse the section
		parse_line_raw (bin, buf, len, mode, be);
		if (bin->cur && bin->cur->addrline.used) {
			RBinAddrLineStore *als = &bin->cur->addrline;
			als->al_foreach (als, cb, list);
		}
		free (buf);
	}
	return list;
}

R_API void r_bin_dwarf_parse_aranges(RBin *bin, int mode) {
	RBinSection *section = getsection (bin, DWARF_SN_ARANGES);
	RBinFile *bf = bin ? bin->cur: NULL;
	if (bf && section) {
		size_t len = section->size;
		if (len < 1 || len > ST32_MAX) {
			return;
		}
		ut8 *buf = calloc (1, len);
		if (!buf) {
			return;
		}
		if (!r_buf_read_at (bf ->buf, section->paddr, buf, len)) {
			free (buf);
			return;
		}
		/* set the endianity global [HOTFIX] */
		parse_aranges_raw (bin, buf, len, mode);
		free (buf);
	}
}

R_API RBinDwarfDebugAbbrev *r_bin_dwarf_parse_abbrev(RBin *bin, int mode) {
	size_t len = 0;
	dwarf_cache_reset ();
	ut8 *buf = get_section_bytes (bin, DWARF_SN_ABBREV, &len);
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
	case 1: return UT8_MAX;
	case 2: return UT16_MAX;
	case 4: return UT32_MAX;
	case 8: return UT64_MAX;
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
	if (loc_list) {
		r_list_foreach (loc_list->list, iter, range) {
			free (range->expression->data);
			free (range->expression);
			free (range);
		}
		r_list_free (loc_list->list);
		free (loc_list);
	}
}

static void parse_loc_raw(HtUP/*<offset, List *<LocListEntry>*/ *loc_table, const ut8 *buf, size_t len, size_t addr_size, bool be) {
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
		ut64 start_addr = dwarf_read_address (addr_size, &buf, buf_end, be);
		ut64 end_addr = dwarf_read_address (addr_size, &buf, buf_end, be);

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
	free_loc_table_list (loc_list);
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
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	/* The standarparse_loc_raw_frame, not sure why is that */
	size_t len = 0;
	const bool be = r_bin_is_big_endian (bin);
	ut8 *buf = get_section_bytes (bin, DWARF_SN_LOC, &len);
	if (!buf) {
		return NULL;
	}
	/* set the endianity global [HOTFIX] */
	HtUP /*<offset, RBinDwarfLocList*/ *loc_table = ht_up_new0 ();
	if (!loc_table) {
		free (buf);
		return NULL;
	}
	parse_loc_raw (loc_table, buf, len, addr_size, be);
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
	R_RETURN_IF_FAIL (loc_table && print);
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
	if (loc_table) {
		loc_table->opt.freefn = free_loc_table_entry;
		ht_up_free (loc_table);
	}
}
