/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"

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

R_API R_OWNED char *r_bin_dwarf_print_abbrev(const RVecDwarfAbbrevDecl *da) {
	R_RETURN_VAL_IF_FAIL (da, NULL);
	RStrBuf *sb = r_strbuf_new (NULL);

	RBinDwarfAbbrevDecl *decl;
	R_VEC_FOREACH (da, decl) {
		int declstag = decl->tag;
		r_strbuf_appendf (sb, "   %-4" PFMT64d " ", decl->code);
		if (declstag >= 0 && declstag < DW_TAG_LAST) {
			r_strbuf_appendf (sb, "  %-25s ", dwarf_tag_name_encodings[declstag]);
		}
		r_strbuf_appendf (sb, "[%s]", decl->has_children? "has children": "no children");
		r_strbuf_appendf (sb, " (0x%" PFMT64x ")\n", decl->offset);

		RBinDwarfAttrDef *def;
		R_VEC_FOREACH (decl->defs, def) {
			ut64 attr_name = def->attr_name;
			ut64 attr_form = def->attr_form;
			if (is_printable_attr (attr_name) && is_printable_form (attr_form)) {
				r_strbuf_appendf (sb, "    %-30s %-30s\n",
					dwarf_attr_encodings[attr_name],
					dwarf_attr_form_encodings[attr_form]);
			}
		}
	}
	return r_strbuf_drain (sb);
}

static void print_attr_value(const RBinDwarfAttrValue *val, RStrBuf *sb) {
	size_t i;
	R_RETURN_IF_FAIL (val);

	switch (val->attr_form) {
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_exprloc:
		r_strbuf_appendf (sb, "%" PFMT64u " byte block:", val->block.length);
		for (i = 0; i < val->block.length; i++) {
			r_strbuf_appendf (sb, " 0x%02x", val->block.data[i]);
		}
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_data16:
		r_strbuf_appendf (sb, "%" PFMT64u, val->uconstant);
		if (val->attr_name == DW_AT_language) {
			if (is_printable_lang (val->uconstant)) {
				r_strbuf_appendf (sb, "   (%s)", dwarf_langs[val->uconstant]);
			} else {
				r_strbuf_append (sb, "   (unknown language)");
			}
		}
		break;
	case DW_FORM_string:
		if (val->string.content) {
			r_strbuf_append (sb, val->string.content);
		} else {
			r_strbuf_append (sb, "No string found");
		}
		break;
	case DW_FORM_flag:
		r_strbuf_appendf (sb, "%u", val->flag);
		break;
	case DW_FORM_sdata:
		r_strbuf_appendf (sb, "%" PFMT64d, val->sconstant);
		break;
	case DW_FORM_udata:
		r_strbuf_appendf (sb, "%" PFMT64u, val->uconstant);
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
		r_strbuf_appendf (sb, "<0x%" PFMT64x ">", val->reference);
		break;
	case DW_FORM_flag_present:
		r_strbuf_append (sb, "1");
		break;
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
		if (val->kind == DW_AT_KIND_STRING_INDEX) {
			r_strbuf_appendf (sb, "(unresolved string index: 0x%" PFMT64x ")", val->string.offset);
			break;
		}
		// fall through
	case DW_FORM_line_strp:
	case DW_FORM_strp_sup:
	case DW_FORM_strp:
		r_strbuf_appendf (sb, "(indirect string, offset: 0x%" PFMT64x "): %s",
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
			r_strbuf_appendf (sb, "<unresolved address index: 0x%" PFMT64x ">", val->address);
			break;
		}
		// fall through
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		r_strbuf_appendf (sb, "0x%" PFMT64x, val->address);
		break;
	case DW_FORM_implicit_const:
		r_strbuf_appendf (sb, "0x%" PFMT64x, val->uconstant);
		break;
	default:
		r_strbuf_appendf (sb, "Unknown attr value form %" PFMT64d "\n", val->attr_form);
		break;
	};
}

static void print_comp_unit_header(const RBinDwarfCompUnit *unit, RStrBuf *sb) {
	R_RETURN_IF_FAIL (unit);
	r_strbuf_append (sb, "\n");
	r_strbuf_appendf (sb, "  Compilation Unit @ offset 0x%" PFMT64x ":\n", unit->offset);
	r_strbuf_appendf (sb, "   Length:        0x%" PFMT64x "\n", unit->hdr.length);
	r_strbuf_appendf (sb, "   Version:       %d\n", unit->hdr.version);
	r_strbuf_appendf (sb, "   Abbrev Offset: 0x%" PFMT64x "\n", unit->hdr.abbrev_offset);
	r_strbuf_appendf (sb, "   Pointer Size:  %d\n", unit->hdr.address_size);
	if (is_printable_unit_type (unit->hdr.unit_type)) {
		r_strbuf_appendf (sb, "   Unit Type:     %s\n", dwarf_unit_types[unit->hdr.unit_type]);
	}
	r_strbuf_append (sb, "\n");
}

static void print_die(const RBinDwarfDie *die, RStrBuf *sb) {
	R_RETURN_IF_FAIL (die);
	r_strbuf_appendf (sb, "<0x%" PFMT64x ">: Abbrev Number: %-4" PFMT64u " ", die->offset, die->abbrev_code);
	if (is_printable_tag (die->tag)) {
		r_strbuf_appendf (sb, "(%s)\n", dwarf_tag_name_encodings[die->tag]);
	} else {
		r_strbuf_append (sb, "(Unknown abbrev tag)\n");
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
			r_strbuf_appendf (sb, "     %-25s : ", dwarf_attr_encodings[value->attr_name]);
		} else {
			r_strbuf_appendf (sb, "     AT_UNKWN [0x%-3" PFMT64x "]\t : ", value->attr_name);
		}
		print_attr_value (value, sb);
		r_strbuf_append (sb, "\n");
	}
}

R_IPI void dwarf_print_comp_unit(const RBinDwarfCompUnit *unit, RStrBuf *sb) {
	R_RETURN_IF_FAIL (unit && unit->dies);
	print_comp_unit_header (unit, sb);
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		print_die (die, sb);
	}
}
