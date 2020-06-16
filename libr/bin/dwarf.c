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

#define READ(x,y) (((x) + sizeof (y) < buf_end)? *((y*)(x)): 0); (x) += sizeof (y)
#define READ8(x) (((x) + sizeof (ut8) < buf_end)? ((ut8*)x)[0]: 0); (x) += sizeof (ut8)
#define READ16(x) (((x) + sizeof (ut16) < buf_end)? r_read_ble16(x,0): 0); (x) += sizeof (ut16)
#define READ32(x) (((x) + sizeof (ut32) < buf_end)? r_read_ble32(x,0): 0); (x) += sizeof (ut32)
#define READ64(x) (((x) + sizeof (ut64) < buf_end)? r_read_ble64(x,0): 0); (x) += sizeof (ut64)

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
	[DW_TAG_template_alias] = "DW_TAG_template_alias",
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
	[DW_AT_data_big_offset] = "DW_AT_data_big_offset",
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
	[DW_AT_GNU_all_tail_call_sites] = "DW_AT_GNU_all_tail_call_sites",
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

static inline bool is_printable_attr(ut64 attr_code) {
	return ((attr_code <= DW_AT_loclists_base && attr_code >= DW_AT_sibling) || 
			attr_code == DW_AT_GNU_all_tail_call_sites);
}

static inline bool is_printable_form(ut64 form_code) {
	return (form_code <= DW_FORM_addrx4 && form_code >= DW_FORM_addr);
}

static inline bool is_printable_tag(ut64 attr_code) {
	return (attr_code <= DW_TAG_LAST);
}


static int add_sdb_include_dir(Sdb *s, const char *incl, int idx) {
	if (!s || !incl) {
		return false;
	}
	return sdb_array_set (s, "includedirs", idx, incl, 0);
}

static void r_bin_dwarf_header_fini(RBinDwarfLineHeader *hdr) {
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
	RBinDwarfLineHeader *hdr, FILE *f, Sdb *sdb, int mode) {
	int i = 0;
	size_t count;
	const ut8 *tmp_buf = NULL;

	if (f) {
		fprintf (f, " The Directory Table:\n");
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
		if (f) {
			fprintf (f, "  %d     %s\n", i + 1, str);
		}
		add_sdb_include_dir (sdb, str, i);
		free (str);
		i++;
		buf += len + 1;
	}

	tmp_buf = buf;
	count = 0;
	if (f) {
		fprintf (f, "\n");
		fprintf (f, " The File Name Table:\n");
		fprintf (f, "  Entry Dir     Time      Size       Name\n");
	}
	int entry_index = 1; // used for printing information

	for (i = 0; i < 2; i++) {
		while (buf + 1 < buf_end) {
			const char *filename = (const char *)buf;
			size_t maxlen = R_MIN ((size_t) (buf_end - buf - 1), 0xfff);
			ut64 id_idx, mod_time, file_len;
			size_t namelen, len = r_str_nlen (filename, maxlen);

			if (!len) {
				buf++;
				break;
			}
			buf += len + 1;
			if (buf >= buf_end) {
				buf = NULL;
				goto beach;
			}
			buf = r_uleb128 (buf, buf_end - buf, &id_idx);
			if (buf >= buf_end) {
				buf = NULL;
				goto beach;
			}
			buf = r_uleb128 (buf, buf_end - buf, &mod_time);
			if (buf >= buf_end) {
				buf = NULL;
				goto beach;
			}
			buf = r_uleb128 (buf, buf_end - buf, &file_len);
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

				namelen = len + (include_dir ? strlen (include_dir) : 0) + 8;

				if (hdr->file_names) {
					hdr->file_names[count].name = r_str_newf("%s/%s", include_dir ? include_dir : "", filename);
					hdr->file_names[count].id_idx = id_idx;
					hdr->file_names[count].mod_time = mod_time;
					hdr->file_names[count].file_len = file_len;
				}
				free (comp_dir);
				free (pinclude_dir);
			}
			count++;
			if (f && i) {
				fprintf (f, "  %d     %" PFMT64d "       %" PFMT64d "         %" PFMT64d "          %s\n", entry_index++, id_idx, mod_time, file_len, filename);
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
	if (f) {
		fprintf (f, "\n");
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
	RBinDwarfLineHeader *hdr, FILE *f, Sdb *sdb, int mode) {
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
	RBinDwarfLineHeader *hdr, FILE *f, int mode) {
	
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

	if (hdr->is_64bit) {
		hdr->header_length = READ64 (buf);
	} else {
		hdr->header_length = READ32 (buf);
	}
	ut8 *tmp_buf = buf; // So I can skip parsing DWARF 5 headres for now

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

	if (f) {
		fprintf (f, " Header information:\n");
		fprintf (f, "  Length:                             %" PFMT64u "\n", hdr->unit_length);
		fprintf (f, "  DWARF Version:                      %d\n", hdr->version);
		fprintf (f, "  Header Length:                      %" PFMT64d "\n", hdr->header_length);
		fprintf (f, "  Minimum Instruction Length:         %d\n", hdr->min_inst_len);
		fprintf (f, "  Maximum Operations per Instruction: %d\n", hdr->max_ops_per_inst);
		fprintf (f, "  Initial value of 'is_stmt':         %d\n", hdr->default_is_stmt);
		fprintf (f, "  Line Base:                          %d\n", hdr->line_base);
		fprintf (f, "  Line Range:                         %d\n", hdr->line_range);
		fprintf (f, "  Opcode Base:                        %d\n", hdr->opcode_base);
		fprintf (f, "\n");
	}

	if (hdr->opcode_base > 0) {
		hdr->std_opcode_lengths = calloc (sizeof (ut8), hdr->opcode_base);

		if (f) {
			fprintf (f, " Opcodes:\n");
		}
		for (int i = 1; i <= hdr->opcode_base - 1; i++) {
			if (buf + 2 > buf_end) {
				break;
			}
			hdr->std_opcode_lengths[i] = READ (buf, ut8);
			if (f) {
				fprintf (f, "  Opcode %d has %d arg\n", i, hdr->std_opcode_lengths[i]);
			}
		}
		if (f) {
			fprintf (f, "\n");
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
		buf = parse_line_header_source (bf, buf, buf_end, hdr, f, sdb, mode);
	} else { // because Version 5 source files are very different
		buf = parse_line_header_source_dwarf5 (bf, buf, buf_end, hdr, f, sdb, mode);
	}

	return buf;
}

static inline void add_sdb_addrline(Sdb *s, ut64 addr, const char *file, ut64 line, FILE *f, int mode) {
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
		if (!f) {
			f = stdout;
		}
		fprintf (f, "CL %s:%d 0x%08"PFMT64x"\n", p, (int)line, addr);
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

static const ut8* r_bin_dwarf_parse_ext_opcode(const RBin *a, const ut8 *obuf,
		size_t len, const RBinDwarfLineHeader *hdr,
		RBinDwarfSMRegisters *regs, FILE *f, int mode) {
	// XXX - list is an unused parameter.
	const ut8 *buf;
	const ut8 *buf_end;
	ut8 opcode;
	ut64 addr;
	buf = obuf;
	st64 op_len;
	RBinFile *binfile = a ? a->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	ut32 addr_size = o && o->info && o->info->bits ? o->info->bits / 8 : 4;
	const char *filename;

	if (!binfile || !obuf || !hdr || !regs) {
		return NULL;
	}

	buf_end = buf + len;
	buf = r_leb128 (buf, len, &op_len);
	if (buf >= buf_end) {
		return NULL;
	}

	opcode = *buf++;

	if (f) {
		fprintf (f, "  Extended opcode %d: ", opcode);
	}

	switch (opcode) {
	case DW_LNE_end_sequence:
		regs->end_sequence = DWARF_TRUE;

		if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
			int fnidx = regs->file - 1;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline(binfile->sdb_addrinfo, regs->address,
						hdr->file_names[fnidx].name, regs->line, f, mode);
			}
		}

		if (f) {
			fprintf (f, "End of Sequence\n");
		}
		break;
	case DW_LNE_set_address:
		if (addr_size == 8) {
			addr = READ64 (buf);
		} else {
			addr = READ32 (buf);
		}
		regs->address = addr;
		if (f) {
			fprintf (f, "set Address to 0x%"PFMT64x"\n", addr);
		}
		break;
	case DW_LNE_define_file:
		filename = (const char*)buf;

		if (f) {
			fprintf (f, "define_file\n");
			fprintf (f, "filename %s\n", filename);
		}

		buf += (strlen (filename) + 1);
		ut64 dir_idx;
		ut64 ignore;
		if (buf + 1 < buf_end) {
			buf = r_uleb128 (buf, buf_end - buf, &dir_idx);
		}
		if (buf + 1 < buf_end) {
			buf = r_uleb128 (buf, buf_end - buf, &ignore);
		}
		if (buf + 1 < buf_end) {
			buf = r_uleb128 (buf, buf_end - buf, &ignore);
		}
		break;
	case DW_LNE_set_discriminator:
		buf = r_uleb128 (buf, buf_end - buf, &addr);
		if (f) {
			fprintf (f, "set Discriminator to %"PFMT64d"\n", addr);
		}
		regs->discriminator = addr;
		break;
	default:
		if (f) {
			fprintf (f, "Unexpected ext opcode %d\n", opcode);
			buf = NULL;
		}
		break;
	}

	return buf;
}

static const ut8* r_bin_dwarf_parse_spec_opcode(
		const RBin *a, const ut8 *obuf, size_t len,
		const RBinDwarfLineHeader *hdr,
		RBinDwarfSMRegisters *regs,
		ut8 opcode, FILE *f, int mode) {
	// XXX - list is not used
	const ut8 *buf = obuf;
	ut8 adj_opcode = 0;
	ut64 advance_adr;
	RBinFile *binfile = a ? a->cur : NULL;

	if (!obuf || !hdr || !regs) {
		return NULL;
	}

	adj_opcode = opcode - hdr->opcode_base;
	if (!hdr->line_range) {
		// line line-range information. move away
		return NULL;
	}
	advance_adr = adj_opcode / hdr->line_range;
	regs->address += advance_adr;
	int line_increment =  hdr->line_base + (adj_opcode % hdr->line_range);
	regs->line += line_increment;
	if (f) {
		fprintf (f, "  Special opcode %d: ", adj_opcode);
		fprintf (f, "advance Address by %"PFMT64d" to 0x%"PFMT64x" and Line by %d to %"PFMT64d"\n",
			advance_adr, regs->address, line_increment, regs->line);
	}
	if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
		int idx = regs->file -1;
		if (idx >= 0 && idx < hdr->file_names_count) {
			add_sdb_addrline (binfile->sdb_addrinfo, regs->address,
					hdr->file_names[idx].name,
					regs->line, f, mode);
		}
	}
	regs->basic_block = DWARF_FALSE;
	regs->prologue_end = DWARF_FALSE;
	regs->epilogue_begin = DWARF_FALSE;
	regs->discriminator = 0;

	return buf;
}

static const ut8* r_bin_dwarf_parse_std_opcode(
		const RBin *a, const ut8 *obuf, size_t len,
		const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs,
		ut8 opcode, FILE *f, int mode) {
	const ut8* buf = obuf;
	const ut8* buf_end = obuf + len;
	ut64 addr = 0LL;
	st64 sbuf;
	ut8 adj_opcode;
	ut64 op_advance;
	ut16 operand;
	RBinFile *binfile = a ? a->cur : NULL;

	if (!binfile || !hdr || !regs || !obuf) {
		return NULL;
	}

	if (f) {
		fprintf (f, "  "); // formatting
	}
	switch (opcode) {
	case DW_LNS_copy:
		if (f) {
			fprintf (f, "Copy\n");
		}
		if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
			int fnidx = regs->file - 1;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline (binfile->sdb_addrinfo,
					regs->address,
					hdr->file_names[fnidx].name,
					regs->line, f, mode);
			}
		}
		regs->basic_block = DWARF_FALSE;
		break;
	case DW_LNS_advance_pc:
		buf = r_uleb128 (buf, buf_end - buf, &addr);
		regs->address += addr * hdr->min_inst_len;
		if (f) {
			fprintf (f, "Advance PC by %"PFMT64d" to 0x%"PFMT64x"\n",
				addr * hdr->min_inst_len, regs->address);
		}
		break;
	case DW_LNS_advance_line:
		buf = r_leb128(buf, buf_end - buf, &sbuf);
		regs->line += sbuf;
		if (f) {
			fprintf (f, "Advance line by %"PFMT64d", to %"PFMT64d"\n", sbuf, regs->line);
		}
		break;
	case DW_LNS_set_file:
		buf = r_uleb128 (buf, buf_end - buf, &addr);
		if (f) {
			fprintf (f, "Set file to %"PFMT64d"\n", addr);
		}
		regs->file = addr;
		break;
	case DW_LNS_set_column:
		buf = r_uleb128 (buf, buf_end - buf, &addr);
		if (f) {
			fprintf (f, "Set column to %"PFMT64d"\n", addr);
		}
		regs->column = addr;
		break;
	case DW_LNS_negate_stmt:
		regs->is_stmt = regs->is_stmt ? DWARF_FALSE : DWARF_TRUE;
		if (f) {
			fprintf (f, "Set is_stmt to %d\n", regs->is_stmt);
		}
		break;
	case DW_LNS_set_basic_block:
		if (f) {
			fprintf (f, "set_basic_block\n");
		}
		regs->basic_block = DWARF_TRUE;
		break;
	case DW_LNS_const_add_pc:
		adj_opcode = 255 - hdr->opcode_base;
		if (hdr->line_range > 0) {
			op_advance = adj_opcode / hdr->line_range;
		} else {
			op_advance = 0;
		}
		regs->address += op_advance;
		if (f) {
			fprintf (f, "Advance PC by constant %"PFMT64d" to 0x%"PFMT64x"\n",
				op_advance, regs->address);
		}
		break;
	case DW_LNS_fixed_advance_pc:
		operand = READ16 (buf);
		regs->address += operand;
		if (f) {
			fprintf (f,"Fixed advance pc to %"PFMT64d"\n", regs->address);
		}
		break;
	case DW_LNS_set_prologue_end:
		regs->prologue_end = ~0;
		if (f) {
			fprintf (f, "set_prologue_end\n");
		}
		break;
	case DW_LNS_set_epilogue_begin:
		regs->epilogue_begin = ~0;
		if (f) {
			fprintf (f, "set_epilogue_begin\n");
		}
		break;
	case DW_LNS_set_isa:
		buf = r_uleb128 (buf, buf_end - buf, &addr);
		regs->isa = addr;
		if (f) {
			fprintf (f, "set_isa\n");
		}
		break;
	default:
		if (f) {
			fprintf (f, "Unexpected std opcode %d\n", opcode);
		}
		break;
	}
	return buf;
}

static void r_bin_dwarf_set_regs_default(const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs) {
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

static size_t r_bin_dwarf_parse_opcodes(const RBin *a, const ut8 *obuf,
		size_t len, const RBinDwarfLineHeader *hdr,
		RBinDwarfSMRegisters *regs, FILE *f, int mode) {
	const ut8 *buf, *buf_end;
	ut8 opcode, ext_opcode;

	if (!a || !obuf || len < 8) {
		return 0;
	}
	buf = obuf;
	buf_end = obuf + len;

	while (buf && buf + 1 < buf_end) {
		opcode = *buf++;
		len--;
		if (!opcode) {
			ext_opcode = *buf;
			buf = r_bin_dwarf_parse_ext_opcode (a, buf, len, hdr, regs, f, mode);
			if (!buf || ext_opcode == DW_LNE_end_sequence) {
				r_bin_dwarf_set_regs_default (hdr, regs); // end_sequence should reset regs to default
				break;
			}
		} else if (opcode >= hdr->opcode_base) {
			buf = r_bin_dwarf_parse_spec_opcode (a, buf, len, hdr, regs, opcode, f, mode);
		} else {
			buf = r_bin_dwarf_parse_std_opcode (a, buf, len, hdr, regs, opcode, f, mode);
		}
		len = (int)(buf_end - buf);
	}
	if (f) {
		fprintf (f, "\n"); // formatting of the output
	}
	return (size_t) (buf - obuf); // number of bytes we've moved by
}

static int parse_line_raw(const RBin *a, const ut8 *obuf,
				       ut64 len, int mode) {
	RBinFile *binfile = a ? a->cur : NULL;
	if (!binfile || !obuf) {
		return false;
	}
	FILE *f = NULL;
	if (mode == R_MODE_PRINT) {
		f = stdout;
		fprintf (f, "Raw dump of debug contents of section .debug_line:\n\n");
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
		buf = parse_line_header (a->cur, buf, buf_end, &hdr, f, mode);
		if (!buf) {
			return false;
		}

		if (f) {
			fprintf (f, " Line Number Statements:\n");
		}
		bytes_read = buf - tmpbuf;

		RBinDwarfSMRegisters regs;
		r_bin_dwarf_set_regs_default (&hdr, &regs);

		// If there is more bytes in the buffer than size of the header
		// It means that there has to be another header/comp.unit
		if (buf_size > hdr.unit_length) {
			buf_size = hdr.unit_length + (hdr.is_64bit * 8 + 4); // we dif against bytes_read, but
				// unit_length doesn't account unit_length field
		}
		// this deals with a case that there is compilation unit with any line information
		if (buf_size == bytes_read) {
			if (f) {
				fprintf (f, " Line table is present, but no lines present\n");
			}
			r_bin_dwarf_header_fini (&hdr);
			continue;
		}
		if (buf_size > (buf_end - buf) + bytes_read || buf > buf_end) {
			r_bin_dwarf_header_fini (&hdr);
			return false;
		}
		// we read the whole compilation unit (that might be composed of more sequences)
		do {
			// reads one whole sequence
			size_t tmp_read = r_bin_dwarf_parse_opcodes (a, buf, buf_size, &hdr, &regs, f, mode);
			bytes_read += tmp_read;
			buf += tmp_read; // Move in the buffer forward
		} while (bytes_read < buf_size);

		r_bin_dwarf_header_fini (&hdr);
	}
	return true;
}

#define READ_BUF(x,y) if (idx+sizeof(y)>=len) { return false;} \
	(x)=*(y*)buf; idx+=sizeof(y);buf+=sizeof(y)

#define READ_BUF64(x) if (idx+sizeof(ut64)>=len) { return false;} \
	(x)=r_read_ble64(buf, 0); idx+=sizeof(ut64);buf+=sizeof(ut64)
#define READ_BUF32(x) if (idx+sizeof(ut32)>=len) { return false;} \
	(x)=r_read_ble32(buf, 0); idx+=sizeof(ut32);buf+=sizeof(ut32)
#define READ_BUF16(x) if (idx+sizeof(ut16)>=len) { return false;} \
	(x)=r_read_ble16(buf, 0); idx+=sizeof(ut16);buf+=sizeof(ut16)

R_API int r_bin_dwarf_parse_aranges_raw(const ut8 *obuf, int len, FILE *f) {
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
	if (f) {
		printf("parse_aranges\n");
		printf("length 0x%x\n", length);
	}

	if (idx + 12 >= len) {
		return false;
	}

	READ_BUF16 (version);
	if (f) {
		printf("Version %d\n", version);
	}

	READ_BUF32 (debug_info_offset);
	if (f) {
		fprintf (f, "Debug info offset %d\n", debug_info_offset);
	}

	READ_BUF (address_size, ut8);
	if (f) {
		fprintf (f, "address size %d\n", (int)address_size);
	}

	READ_BUF (segment_size, ut8);
	if (f) {
		fprintf (f, "segment size %d\n", (int)segment_size);
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
		if (f) {
			printf ("length 0x%" PFMT64x " address 0x%" PFMT64x "\n", length, adr);
		}
	}

	return 0;
}

static int r_bin_dwarf_init_debug_info(RBinDwarfDebugInfo *inf) {
	if (!inf) {
		return -1;
	}
	inf->comp_units = calloc (sizeof (RBinDwarfCompUnit), DEBUG_INFO_CAPACITY);

	// XXX - should we be using error codes?
	if (!inf->comp_units) {
		return -ENOMEM;
	}

	inf->capacity = DEBUG_INFO_CAPACITY;
	inf->length = 0;

	return true;
}

static int r_bin_dwarf_init_die(RBinDwarfDIE *die) {
	if (!die) {
		return -EINVAL;
	}
	die->attr_values = calloc (sizeof (RBinDwarfAttrValue), 8);
	if (!die->attr_values) {
		return -ENOMEM;
	}
	die->capacity = 8;
	die->length = 0;
	return 0;
}

static int r_bin_dwarf_expand_die(RBinDwarfDIE* die) {
	RBinDwarfAttrValue *tmp = NULL;
	if (!die || die->capacity == 0) {
		return -EINVAL;
	}
	if (die->capacity != die->length) {
		return -EINVAL;
	}
	tmp = (RBinDwarfAttrValue*)realloc (die->attr_values,
			die->capacity * 2 * sizeof (RBinDwarfAttrValue));
	if (!tmp) {
		return -ENOMEM;
	}
	memset ((ut8*)tmp + die->capacity * sizeof (RBinDwarfAttrValue),
			0, die->capacity * sizeof (RBinDwarfAttrValue));
	die->attr_values = tmp;
	die->capacity *= 2;
	return 0;
}

static int r_bin_dwarf_init_comp_unit(RBinDwarfCompUnit *cu) {
	if (!cu) {
		return -EINVAL;
	}
	cu->dies = calloc (sizeof (RBinDwarfDIE), COMP_UNIT_CAPACITY);
	if (!cu->dies) {
		return -ENOMEM;
	}
	cu->capacity = COMP_UNIT_CAPACITY;
	cu->length = 0;
	return 0;
}

static int r_bin_dwarf_expand_cu(RBinDwarfCompUnit *cu) {
	RBinDwarfDIE *tmp;

	if (!cu || cu->capacity == 0 || cu->capacity != cu->length) {
		return -EINVAL;
	}

	tmp = (RBinDwarfDIE *)realloc (cu->dies,
		cu->capacity * 2 * sizeof (RBinDwarfDIE));
	if (!tmp) {
		return -ENOMEM;
	}

	memset ((ut8 *)tmp + cu->capacity * sizeof (RBinDwarfDIE),
		0, cu->capacity * sizeof (RBinDwarfDIE));
	cu->dies = tmp;
	cu->capacity *= 2;

	return 0;
}

static int r_bin_dwarf_init_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	if (!ad) {
		return -EINVAL;
	}
	ad->defs = calloc (sizeof (RBinDwarfAttrDef), ABBREV_DECL_CAP);

	if (!ad->defs) {
		return -ENOMEM;
	}

	ad->capacity = ABBREV_DECL_CAP;
	ad->length = 0;

	return 0;
}

static int r_bin_dwarf_expand_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	RBinDwarfAttrDef *tmp;

	if (!ad || !ad->capacity || ad->capacity != ad->length) {
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

static int r_bin_dwarf_init_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	if (!da) {
		return -EINVAL;
	}
	da->decls = calloc (sizeof (RBinDwarfAbbrevDecl), DEBUG_ABBREV_CAP);
	if (!da->decls) {
		return -ENOMEM;
	}
	da->capacity = DEBUG_ABBREV_CAP;
	da->length = 0;

	return 0;
}

static int r_bin_dwarf_expand_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	RBinDwarfAbbrevDecl *tmp;

	if (!da || da->capacity == 0 || da->capacity != da->length) {
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

static void print_abbrev_section(FILE *f, RBinDwarfDebugAbbrev *da) {
	size_t i, j;
	ut64 attr_name, attr_form;

	if (!f || !da) {
		return;
	}
	for (i = 0; i < da->length; i++) {
		int declstag = da->decls[i].tag;
		fprintf (f, "   %-4"PFMT64d" ", da->decls[i].code);
		if (declstag>=0 && declstag < DW_TAG_LAST) {
			fprintf (f, "  %-25s ", dwarf_tag_name_encodings[declstag]);
		}
		fprintf (f, "[%s]", da->decls[i].has_children ?
				"has children" : "no children");
		fprintf (f, " (0x%"PFMT64x")\n", da->decls[i].offset);

		if (da->decls[i].defs) {
			for (j = 0; j < da->decls[i].length; j++) {
				attr_name = da->decls[i].defs[j].attr_name;
				attr_form = da->decls[i].defs[j].attr_form;
				if (is_printable_attr(attr_name) && is_printable_form(attr_form)) {
					fprintf (f, "    %-30s %-30s\n",
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
	for (i = 0; i < da->length; i++) {
		R_FREE (da->decls[i].defs);
	}
	R_FREE (da->decls);
}

static void r_bin_dwarf_free_attr_value(RBinDwarfAttrValue *val) {
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

static void r_bin_dwarf_free_die(RBinDwarfDIE *die) {
	size_t i;
	if (!die) {
		return;
	}
	for (i = 0; i < die->length; i++) {
		r_bin_dwarf_free_attr_value (&die->attr_values[i]);
	}
	R_FREE (die->attr_values);
}

static void r_bin_dwarf_free_comp_unit(RBinDwarfCompUnit *cu) {
	size_t i;
	if (!cu) {
		return;
	}
	for (i = 0; i < cu->length; i++) {
		if (cu->dies) {
			r_bin_dwarf_free_die (&cu->dies[i]);
		}
	}
	R_FREE (cu->dies);
}

R_API void r_bin_dwarf_free_debug_info(RBinDwarfDebugInfo *inf) {
	size_t i;
	if (!inf) {
		return;
	}
	for (i = 0; i < inf->length; i++) {
		r_bin_dwarf_free_comp_unit (&inf->comp_units[i]);
	}
	R_FREE (inf->comp_units);
	free(inf);
}

static void r_bin_dwarf_dump_attr_value(const RBinDwarfAttrValue *val, FILE *f) {
	size_t i;
	if (!val || !f) {
		return;
	}
	switch (val->attr_form) {
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_exprloc:
		fprintf (f, "%"PFMT64u" byte block:", val->block.length);
		for (i = 0; i < val->block.length; i++) {
			fprintf (f, "0x%02x", val->block.data[i]);
		}
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_data16:
		fprintf (f, "%"PFMT64u"", val->data);
		if (val->attr_name == DW_AT_language) {
			fprintf (f, "   (%s)", dwarf_langs[val->data]);
		}
		break;
	case DW_FORM_strp:
		fprintf (f, "(indirect string, offset: 0x%"PFMT64x"): ",
				val->string.offset);
	case DW_FORM_string:
		if (val->string.content) {
			fprintf (f, "%s", val->string.content);
		} else {
			fprintf (f, "No string found");
		}
		break;
	case DW_FORM_flag:
		fprintf (f, "%u", val->flag);
		break;
	case DW_FORM_sdata:
		fprintf (f, "%"PFMT64d"", val->sdata);
		break;
	case DW_FORM_udata:
		fprintf (f, "%"PFMT64u"", val->data);
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
		fprintf (f, "<0x%"PFMT64x">", val->reference);
		break;
	case DW_FORM_flag_present:
		fprintf (f, "1");
		break;
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_ptr:
	case DW_FORM_strp_sup:
		fprintf (f, "(indirect string, offset: 0x%"PFMT64x"): ",
			val->string.offset);
		break;
	case DW_FORM_addr:
	case DW_FORM_addrx:
	case DW_FORM_addrx1:
	case DW_FORM_addrx2:
	case DW_FORM_addrx3:
	case DW_FORM_addrx4:
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		fprintf (f, "0x%"PFMT64x"", val->address);
		break;
	case DW_FORM_implicit_const:
		fprintf (f, "0x%"PFMT64d"", val->sdata);
		break;
	default:
		fprintf (f, "Unknown attr value form %"PFMT64d"\n", val->attr_form);
		break;
	};
}

static void r_bin_dwarf_dump_debug_info(FILE *f, const RBinDwarfDebugInfo *inf) {
	size_t i, j, k;
	RBinDwarfDIE *dies;
	RBinDwarfAttrValue *values;
	if (!inf || !f) {
		return;
	}

	for (i = 0; i < inf->length; i++) {
		fprintf (f, "\n");
		fprintf (f, "  Compilation Unit @ offset 0x%" PFMT64x ":\n", inf->comp_units[i].offset);
		fprintf (f, "   Length:        0x%" PFMT64x "\n", inf->comp_units[i].hdr.length);
		fprintf (f, "   Version:       %d\n", inf->comp_units[i].hdr.version);
		fprintf (f, "   Abbrev Offset: 0x%" PFMT64x "\n", inf->comp_units[i].hdr.abbrev_offset);
		fprintf (f, "   Pointer Size:  %d\n", inf->comp_units[i].hdr.address_size);
		fprintf (f, "\n");

		dies = inf->comp_units[i].dies;

		for (j = 0; j < inf->comp_units[i].length; j++) {
			fprintf (f, "    Abbrev Number: %-4" PFMT64u " ", dies[j].abbrev_code);

			if (is_printable_tag (dies[j].tag)) {
				fprintf (f, "(%s)\n", dwarf_tag_name_encodings[dies[j].tag]);
			} else {
				fprintf (f, "(Unknown abbrev tag)\n");
			}

			if (!dies[j].abbrev_code) {
				continue;
			}
			values = dies[j].attr_values;

			for (k = 0; k < dies[j].length; k++) {
				if (!values[k].attr_name) {
					continue;
				}
				if (is_printable_attr (values[k].attr_name)) {
					fprintf (f, "     %-25s : ", dwarf_attr_encodings[values[k].attr_name]);
				} else {
					fprintf (f, "     AT_UNKWN [0x%-3" PFMT64x "]\t : ", values[k].attr_name);
				}
				r_bin_dwarf_dump_attr_value (&values[k], f);
				fprintf (f, "\n");
			}
		}
	}
}

static const ut8 *r_bin_dwarf_parse_attr_value(const ut8 *obuf, int obuf_len,
		RBinDwarfAttrDef *spec, RBinDwarfAttrValue *value,
		const RBinDwarfCompUnitHdr *hdr,
		const ut8 *debug_str, size_t debug_str_len) {
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + obuf_len;
	size_t j;

	if (!spec || !value || !hdr || !obuf || obuf_len < 1) {
		return NULL;
	}
	value->attr_form = spec->attr_form;
	value->attr_name = spec->attr_name;
	value->block.data = NULL;
	value->string.content = NULL;
	value->string.offset = 0;

	switch (spec->attr_form) {
	case DW_FORM_addr:
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
		value->data = READ8 (buf);
		break;
	case DW_FORM_data2:
		value->data = READ16 (buf);
		break;
	case DW_FORM_data4:
		value->data = READ32 (buf);
		break;
	case DW_FORM_data8:
		value->data = READ64 (buf);
		break;
	case DW_FORM_data16: // Fix this, right now I just read the data, but I need to make storage for it
		value->data = READ64 (buf);
		value->data = READ64 (buf);
		break;
	case DW_FORM_sdata:
		buf = r_leb128 (buf, buf_end - buf, &value->sdata);
		break;
	case DW_FORM_udata:
		buf = r_uleb128 (buf, buf_end - buf, &value->data);
		break;
	case DW_FORM_string:
		value->string.content = *buf ? strdup ((const char *)buf) : NULL;
		buf += (strlen ((const char *)buf) + 1);
		break;
	case DW_FORM_block1:
		value->block.length = READ8 (buf);
		value->block.data = calloc (sizeof (ut8), value->block.length + 1);
		if (!value->block.data) {
			return NULL;
		}
		if (value->block.data) {
			for (j = 0; j < value->block.length; j++) {
				value->block.data[j] = READ (buf, ut8);
			}
		}
		break;
	case DW_FORM_block2:
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
		value->block.length = READ32 (buf);
		if (value->block.length > 0) {
			ut8 *data = calloc (sizeof (ut8), value->block.length);
			if (!data) {
				return NULL;
			}
			for (j = 0; j < value->block.length; j++) {
				data[j] = READ (buf, ut8);
			}
			value->block.data = data;
		}
		break;
	case DW_FORM_block: // variable length ULEB128
		buf = r_uleb128 (buf, buf_end - buf, &value->block.length);
		if (!buf || buf >= buf_end) {
			return NULL;
		}
		value->block.data = calloc (sizeof (ut8), value->block.length);
		if (value->block.data) {
			for (j = 0; j < value->block.length; j++) {
				value->block.data[j] = READ (buf, ut8);
			}
		}
		break;
	case DW_FORM_flag:
		value->flag = READ (buf, ut8);
		break;
	case DW_FORM_strp: // offset in .debug_str
		// this offset can be 64bit, based on dwarf format
		if (hdr->is_64bit) {
			value->string.offset = READ64 (buf);
		} else {
			value->string.offset = READ32 (buf);
		}
		if (debug_str && value->string.offset < debug_str_len) {
			// TODO does it make sense to duplicate the
			value->string.content = strdup (
				(const char *)(debug_str +
					value->string.offset));
		} else {
			value->string.content = NULL;
		}
		break;
	case DW_FORM_ref_addr: // offset in .debug_info
		// This is 4 or 8 bytes depending where it refers to
		// http://www.dwarfstd.org/doc/Dwarf3.pdf page 128
		/*
	 For references from one shared object or
	static executable file to another, the relocation and identification of the target object must be
	performed by the consumer. In the 32-bit DWARF format, this offset is a 4-byte unsigned
	value; in the 64-bit DWARF format, it is an 8-byte unsigned value
	*/
		if (hdr->is_64bit) {
			value->reference = READ64 (buf);
		} else {
			value->reference = READ32 (buf);
		}
		break;
	// This type of reference is an offset from the first byte of the compilation
	// header for the compilation unit containing the reference
	case DW_FORM_ref1:
		value->reference = hdr->unit_offset + READ8 (buf);
		break;
	case DW_FORM_ref2:
		value->reference = hdr->unit_offset + READ16 (buf);
		break;
	case DW_FORM_ref4:
		value->reference = hdr->unit_offset + READ32 (buf);
		break;
	case DW_FORM_ref8:
		value->reference = hdr->unit_offset + READ64 (buf);
		break;
	case DW_FORM_ref_udata:
		// uleb128 is enough to fit into ut64?
		buf = r_uleb128 (buf, buf_end - buf, &value->reference);
		value->reference += hdr->unit_offset;
		break;
	case DW_FORM_sec_offset: // offset in a section other than .debug_info or .debug_str
		if (hdr->is_64bit) {
			value->reference = READ64 (buf);
		} else {
			value->reference = READ32 (buf);
		}
		break;
	case DW_FORM_exprloc:
		buf = r_uleb128 (buf, buf_end - buf, &value->block.length);
		if (!buf || buf >= buf_end) {
			return NULL;
		}
		value->block.data = calloc (sizeof (ut8), value->block.length);
		if (value->block.data) {
			for (j = 0; j < value->block.length; j++) {
				value->block.data[j] = READ (buf, ut8);
			}
		}
		break;
	case DW_FORM_flag_present: // this means that the flag is present, nothing is read
		value->flag = true;
		break;
	case DW_FORM_ref_sig8:
		value->reference = READ64 (buf);
		break;
	case DW_FORM_strx: // offset into .debug_line_str section, can't parse the section now, so we just skip
		buf = r_uleb128 (buf, buf_end - buf, &value->string.offset);
		break;
	case DW_FORM_strx1:
		value->string.offset = READ8 (buf);
		break;
	case DW_FORM_strx2:
		value->string.offset = READ16 (buf);
		break;
	case DW_FORM_strx3: // Add 3 byte int read
		buf += 3;
		break;
	case DW_FORM_strx4:
		value->string.offset = READ32 (buf);
		break;
	case DW_FORM_implicit_const:
		value->sdata = spec->special;
		break;
	/*  This refers to addrx* forms
		The index is relative to the value of the
		DW_AT_addr_base attribute of the associated compilation unit.
	*/
	case DW_FORM_addrx: // index into an array of addresses in the .debug_addr section.
		buf = r_uleb128 (buf, buf_end - buf, &value->address);
		break;
	case DW_FORM_addrx1:
		value->address = READ8 (buf);
		break;
	case DW_FORM_addrx2:
		value->address = READ16 (buf);
		break;
	case DW_FORM_addrx3: // I need to add 3byte endianess free read here TODO
		buf += 3;
		break;
	case DW_FORM_addrx4:
		value->address = READ32 (buf);
		break;
	case DW_FORM_line_ptr: // offset in a section .debug_line_str
		if (hdr->is_64bit) {
			value->reference = READ64 (buf);
		} else {
			value->reference = READ32 (buf);
		}
		break;
	case DW_FORM_strp_sup: // offset in a section .debug_line_str
		if (hdr->is_64bit) {
			value->string.offset = READ64 (buf);
		} else {
			value->string.offset = READ32 (buf);
		}
		break;
	case DW_FORM_ref_sup4: // offset in the supplementary object file
		value->reference = READ32 (buf);
		break;
	case DW_FORM_ref_sup8: // offset in the supplementary object file
		value->reference = READ64 (buf);
		break;
	case DW_FORM_loclistx: // An index into the .debug_loclists
		buf = r_uleb128 (buf, buf_end - buf, &value->address);
		break;
	case DW_FORM_rnglistx: // An index into the .debug_rnglists
		buf = r_uleb128 (buf, buf_end - buf, &value->address);
		break;
	default:
		eprintf ("Unknown DW_FORM 0x%02" PFMT64x "\n", spec->attr_form);
		value->data = 0;
		return NULL;
	}
	return buf;
}
/**
 * @brief 
 * 
 * @param s  Sdb
 * @param buf_start
 * @param buf_end // buffer end for the comp unit
 * @param unit 
 * @param abbrevs
 * @param offset Offset index to the start of the abbreviations for current comp unit
 * @param debug_str Start of the debug_string table
 * @param debug_str_len  Length of the debug_string table
 * @return const ut8* Shifted obuf
 */
static const ut8 *r_bin_dwarf_parse_comp_unit(Sdb *sdb, const ut8 *buf_start,
		RBinDwarfCompUnit *unit, const RBinDwarfDebugAbbrev *abbrevs,
		size_t offset, const ut8 *debug_str, size_t debug_str_len) {
	const ut8 *buf = buf_start;
	const ut8* buf_end = buf_start + unit->hdr.length - unit->hdr.header_size;
	ut64 abbr_code;
	size_t i;

	while (buf && buf < buf_end && buf >= buf_start) {
		if (unit->length && unit->capacity == unit->length) { 
			r_bin_dwarf_expand_cu (unit);
		}
		// DIE starts with ULEB128 with the abbreviation code
		buf = r_uleb128 (buf, buf_end - buf, &abbr_code);

		RBinDwarfDIE *curr_die = &unit->dies[unit->length];
		r_bin_dwarf_init_die (curr_die);
		curr_die->abbrev_code = abbr_code;

		if (abbr_code > abbrevs->length || !buf || buf >= buf_end) { 
			unit->length++;
			return buf; // we finished, return the buffer to parse next compilation units
		}

		// there can be "null" entries for alignment padding purposes
		// such entries have abbr_code == 0
		if (!abbr_code) {
			unit->length++;
			continue;
		}
		abbr_code += offset;

		RBinDwarfAbbrevDecl *curr_abbr = &abbrevs->decls[abbr_code - 1];
		curr_die->tag = curr_abbr->tag;


		if (abbrevs->capacity < abbr_code) {
			return NULL;
		}
		// reads all attribute valeus based on abbreviation
		for (i = 0; i < curr_abbr->length - 1; i++) {
			if (curr_die->length == curr_die->capacity) {
				r_bin_dwarf_expand_die (curr_die);
			}
			if (i >= curr_die->capacity || i >= curr_abbr->capacity) {
				eprintf ("Warning: malformed dwarf attribute capacity doesn't match length\n");
				break;
			}
			memset (&curr_die->attr_values[i], 0, sizeof (curr_die->attr_values[i]));
			
			buf = r_bin_dwarf_parse_attr_value (buf, buf_end - buf,
					&curr_abbr->defs[i],
					&curr_die->attr_values[i],
					&unit->hdr, debug_str, debug_str_len);

			bool is_string_form = curr_die->attr_values[i].attr_form == DW_FORM_strp || 
								curr_die->attr_values[i].attr_form == DW_FORM_string;
			// TODO  does this have a purpose anymore?
			// Or atleast it needs to rework becase there will be 
			// more comp units -> more comp dirs and only the last one will be kept
			if (curr_die->attr_values[i].attr_name == DW_AT_comp_dir  && 
				is_string_form &&
				curr_die->attr_values[i].string.content) {
				const char *name = curr_die->attr_values[i].string.content;
				if ((size_t)name > 1024) { // solve some null derefs
					sdb_set (sdb, "DW_AT_comp_dir", name, 0);
				} else {
					eprintf ("Invalid string pointer at %p\n", name);
				}
			}
			curr_die->length++;
		}
		unit->length++;
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

	// hdr.length is supposed to be smaller than 0xffffff00, should we check that?
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

		if (hdr->is_64bit) {
			hdr->abbrev_offset = READ64 (buf);
		} else {
			hdr->abbrev_offset = READ32 (buf);
		}

		if (hdr->unit_type == DW_UT_skeleton || hdr->unit_type == DW_UT_split_compile) {
			hdr->dwo_id = READ8 (buf);
		} else if (hdr->unit_type == DW_UT_type || hdr->unit_type == DW_UT_split_type) {
			hdr->type_sig = READ64 (buf);

			if (hdr->is_64bit) {
				hdr->type_offset = READ64 (buf);
			} else {
				hdr->type_offset = READ32 (buf);
			}
		}
	} else {
		if (hdr->is_64bit) {
			hdr->abbrev_offset = READ64 (buf);
		} else {
			hdr->abbrev_offset = READ32 (buf);
		}
		hdr->address_size = READ8 (buf);
	}
	hdr->header_size = buf - tmp; // header size excluding length field
	return buf;
}
static int expand_info(RBinDwarfDebugInfo *info) {
	r_return_val_if_fail (info && info->capacity == info->length, EXIT_FAILURE);

	RBinDwarfCompUnit *tmp;
	tmp = realloc (info->comp_units, info->capacity * 2 * sizeof (RBinDwarfCompUnit));

	if (!tmp) {
		return -ENOMEM;
	}
	memset ((ut8 *)tmp + info->capacity * sizeof (RBinDwarfCompUnit),
		0, info->capacity * sizeof (RBinDwarfCompUnit));

	info->comp_units = tmp;
	info->capacity *= 2;

	return 0;
}

R_API RBinDwarfDebugInfo *r_bin_dwarf_parse_info_raw(Sdb *sdb, RBinDwarfDebugAbbrev *da,
		const ut8 *obuf, size_t len,
		const ut8 *debug_str, size_t debug_str_len, int mode) {

	r_return_val_if_fail(da && sdb && obuf, false);

	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;
	const ut8 *buf_tmp;

	RBinDwarfDebugInfo *info = calloc(1, sizeof (RBinDwarfDebugInfo));
	if (!info) {
		return NULL;
	}
	if (r_bin_dwarf_init_debug_info (info) < 0) {
		goto cleanup;
	}
	size_t k, offset = 0;
	int curr_unit_idx = 0;

	while (buf < buf_end) {
		if (info->length >= info->capacity) {
			if (expand_info (info)) {
				break;
			}
		}

		RBinDwarfCompUnit *curr_unit = &info->comp_units[curr_unit_idx];
		if (r_bin_dwarf_init_comp_unit (curr_unit) < 0) {
			curr_unit_idx--;
			goto cleanup;
		}
		info->length++;

		curr_unit->offset = buf - obuf;
		curr_unit->hdr.unit_offset = buf - obuf;
		buf_tmp = buf;
		buf = info_comp_unit_read_hdr (buf, buf_end, &curr_unit->hdr);

		if (curr_unit->hdr.length > len) {
			goto cleanup;
		}

		if (da->decls->length >= da->capacity) {
			eprintf ("WARNING: malformed dwarf have not enough buckets for decls.\n");
		}

		const int k_max = R_MIN (da->capacity, da->length);

		// linear search for current abbreviation index, fix this because this shouldn't be necessary
		for (k = 0; k < k_max; k++) {
			if (da->decls[k].offset == curr_unit->hdr.abbrev_offset) {
				offset = k;
				break;
			}
		}

		buf = r_bin_dwarf_parse_comp_unit (sdb, buf, curr_unit, da, offset, debug_str, debug_str_len);

		if (!buf) {
			goto cleanup;
		}

		curr_unit_idx++;
	}

	if (mode == R_MODE_PRINT) {
		r_bin_dwarf_dump_debug_info (stdout, info);
	}

	return info;

cleanup:
	r_bin_dwarf_free_debug_info (info);
	return NULL;
}

static RBinDwarfDebugAbbrev *r_bin_dwarf_parse_abbrev_raw(const ut8 *obuf, size_t len, int mode) {
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

	r_bin_dwarf_init_debug_abbrev (da);

	while (buf && buf+1 < buf_end) {
		offset = buf - obuf;
		buf = r_uleb128 (buf, (size_t)(buf_end-buf), &tmp);
		if (!buf || !tmp || buf >= buf_end) {
			continue;
		}
		if (da->length == da->capacity) {
			r_bin_dwarf_expand_debug_abbrev(da);
		}
		tmpdecl = &da->decls[da->length];
		r_bin_dwarf_init_abbrev_decl (tmpdecl);

		tmpdecl->code = tmp;
		buf = r_uleb128 (buf, (size_t)(buf_end-buf), &tmp);
		tmpdecl->tag = tmp;
 
		tmpdecl->offset = offset;
		if (buf >= buf_end) {
			break;
		}
		has_children = READ (buf, ut8);
		tmpdecl->has_children = has_children;
		do {
			if (tmpdecl->length == tmpdecl->capacity) {
				r_bin_dwarf_expand_abbrev_decl (tmpdecl);
			}
			buf = r_uleb128 (buf, (size_t)(buf_end - buf), &attr_code);
			if (buf >= buf_end) {
				break;
			}
			buf = r_uleb128 (buf, (size_t)(buf_end - buf), &attr_form);
			if (attr_form == DW_FORM_implicit_const) {
				buf = r_leb128 (buf, (size_t)(buf_end - buf), &special);
				tmpdecl->defs[tmpdecl->length].special = special;
			}
			tmpdecl->defs[tmpdecl->length].attr_name = attr_code;
			tmpdecl->defs[tmpdecl->length].attr_form = attr_form;
			tmpdecl->length++;
		} while (attr_code && attr_form);

		da->length++;
	}

	if (mode == R_MODE_PRINT) {
		print_abbrev_section (stdout, da);
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


R_API RBinDwarfDebugInfo *r_bin_dwarf_parse_info(RBinDwarfDebugAbbrev *da, RBin *a, int mode) {
	ut8 *buf, *debug_str_buf = 0;
	int len, ret, debug_str_len = 0;
	RBinDwarfDebugInfo *result = NULL;
	RBinSection *debug_str;
	RBinSection *section = getsection (a, "debug_info");
	RBinFile *binfile = a ? a->cur: NULL;

	if (binfile && section) {
		debug_str = getsection (a, "debug_str");
		if (debug_str) {
			debug_str_len = debug_str->size;
			debug_str_buf = calloc (1, debug_str_len + 1);
			ret = r_buf_read_at (binfile->buf, debug_str->paddr,
					     debug_str_buf, debug_str_len);
			if (!ret) {
				free (debug_str_buf);
				return NULL;
			}
		}

		len = section->size;
		if (len > (UT32_MAX >> 1) || len < 1) {
			free (debug_str_buf);
			return NULL;
		}
		buf = calloc (1, len);
		if (!buf) {
			free (debug_str_buf);
			return NULL;
		}
		if (!r_buf_read_at (binfile->buf, section->paddr, buf, len)) {
			free (debug_str_buf);
			free (buf);
			return NULL;
		}
		result = r_bin_dwarf_parse_info_raw (binfile->sdb_addrinfo, da, buf, len,
				debug_str_buf, debug_str_len, mode);
		free (debug_str_buf);
		free (buf);
		return result;
	}
	return NULL;
}

static RBinDwarfRow *r_bin_dwarf_row_new(ut64 addr, const char *file, int line, int col) {
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

static void r_bin_dwarf_row_free(void *p) {
	RBinDwarfRow *row = (RBinDwarfRow*)p;
	free (row->file);
	free (row);
}

R_API RList *r_bin_dwarf_parse_line(RBin *a, int mode) {
	ut8 *buf;
	RList *list = NULL;
	int len, ret;
	RBinSection *section = getsection (a, "debug_line");
	RBinFile *binfile = a ? a->cur: NULL;
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
		list = r_list_newf (r_bin_dwarf_row_free); // always return empty list wtf
		if (!list) {
			free (buf);
			return NULL;
		}
		// Actually parse the section
		parse_line_raw (a, buf, len, mode);
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
					row = r_bin_dwarf_row_new (addr, file, line, 0);
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

R_API RList *r_bin_dwarf_parse_aranges(RBin *a, int mode) {
	ut8 *buf;
	int ret;
	size_t len;
	RBinSection *section = getsection (a, "debug_aranges");
	RBinFile *binfile = a ? a->cur: NULL;

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
		if (mode == R_MODE_PRINT) {
			r_bin_dwarf_parse_aranges_raw (buf, len, stdout);
		} else {
			r_bin_dwarf_parse_aranges_raw (buf, len, DBGFD);
		}
		free (buf);
	}
	return NULL;
}

R_API RBinDwarfDebugAbbrev *r_bin_dwarf_parse_abbrev(RBin *a, int mode) {
	ut8 *buf;
	size_t len;
	RBinSection *section = getsection (a, "debug_abbrev");
	RBinDwarfDebugAbbrev *da = NULL;
	RBinFile *binfile = a ? a->cur: NULL;
	if (!section || !binfile) {
		return NULL;
	}
	if (section->size > binfile->size) {
		return NULL;
	}
	len = section->size;
	buf = calloc (1,len);
	r_buf_read_at (binfile->buf, section->paddr, buf, len);
	da = r_bin_dwarf_parse_abbrev_raw (buf, len, mode);
	free (buf);
	return da;
}
