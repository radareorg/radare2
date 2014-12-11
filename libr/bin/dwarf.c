/* radare - LGPL - Copyright 2012-2014 - pancake, Fedor Sakharov */

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

#define READ(x,y) *((y*)x); x += sizeof (y)

static const char *dwarf_tag_name_encodings[] = {
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
	[DW_TAG_volatile_type] = "DW_TAG_volatile_type"
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
	[DW_AT_containing_type] = "DW_AT_containig_type",
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
	[DW_AT_vtable_elem_location] = "DW_AT_vtable_elem_location"
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
	[DW_FORM_indirect] = "DW_FORM_indirect"
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
};

static int add_sdb_include_dir(Sdb *s, const char *incl, int idx) {
	if (!s || !incl)
		return R_FALSE;
	return sdb_array_set (s, "includedirs", idx, incl, 0);
}

static const ut8 *r_bin_dwarf_parse_lnp_header (
		RBinFile *bf, const ut8 *buf, const ut8 *buf_end,
		RBinDwarfLNPHeader *hdr, FILE *f, int mode)
{
	int i;
	Sdb *s;
	size_t count;
	const ut8 *tmp_buf = NULL;

	if (!hdr || !bf || !buf) return NULL;

	hdr->unit_length.part1 = READ (buf, ut32);
	if (hdr->unit_length.part1 == DWARF_INIT_LEN_64) {
		hdr->unit_length.part2 = READ (buf, ut32);
	}

	s = sdb_new (NULL, NULL, 0);

	hdr->version = READ (buf, ut16);

	if (hdr->unit_length.part1 == DWARF_INIT_LEN_64) {
		hdr->header_length = READ (buf, ut64);
	} else {
		hdr->header_length = READ (buf, ut32);
	}

	if (buf_end-buf < 8) return NULL;
	hdr->min_inst_len = READ (buf, ut8);
	//hdr->max_ops_per_inst = READ (buf, ut8);
	hdr->file_names = NULL;
	hdr->default_is_stmt = READ (buf, ut8);
	hdr->line_base = READ (buf, char);
	hdr->line_range = READ (buf, ut8);
	hdr->opcode_base = READ (buf, ut8);

	if (f) {
		fprintf(f, "DWARF LINE HEADER\n");
		fprintf(f, "  total_length: %d\n", hdr->unit_length.part1);
		fprintf(f, "  version: %d\n", hdr->version);
		fprintf(f, "  header_length: : %"PFMT64d"\n", hdr->header_length);
		fprintf(f, "  mininstlen: %d\n", hdr->min_inst_len);
		fprintf(f, "  is_stmt: %d\n", hdr->default_is_stmt);
		fprintf(f, "  line_base: %d\n", hdr->line_base);
		fprintf(f, "  line_range: %d\n", hdr->line_range);
		fprintf(f, "  opcode_base: %d\n", hdr->opcode_base);
	}

	hdr->std_opcode_lengths = calloc(sizeof(ut8), hdr->opcode_base);

	for (i = 1; i <= hdr->opcode_base - 1; i++) {
		hdr->std_opcode_lengths[i] = READ (buf, ut8);
		if (f) {
			fprintf(f, " op %d %d\n", i, hdr->std_opcode_lengths[i]);
		}
	}

	i = 0;
	while (buf+1 < buf_end) {
		int maxlen = R_MIN ((size_t)(buf_end-buf), 0xfff);
		int len = r_str_nlen((const char*)buf, maxlen);
		if (len<1 || len >= 0xfff) {
			buf += 1;
			break;
		}
		if (f) {
			fprintf(f, "INCLUDEDIR (%s)\n", buf);
		}
		add_sdb_include_dir (s, (const char *)buf, i);
		i++;
		buf += len + 1;
	}

	tmp_buf = buf;
	count = 0;
	for (i = 0; i < 2; i++) {
		while (buf+1<buf_end) {
			const char *filename = (const char *)buf;
			ut64 id_idx, mod_time, file_len;
			size_t namelen, len = r_str_nlen (filename, (size_t)(buf_end-buf));

			if (!len) {
				buf++;
				break;
			}
			buf += len + 1;
			if (buf>=buf_end) { buf = NULL; goto beach; }
			buf = r_uleb128 (buf, buf_end-buf, &id_idx);
			if (buf>=buf_end) { buf = NULL; goto beach; }
			buf = r_uleb128 (buf, buf_end-buf, &mod_time);
			if (buf>=buf_end) { buf = NULL; goto beach; }
			buf = r_uleb128 (buf, buf_end-buf, &file_len);
			if (buf>=buf_end) { buf = NULL; goto beach; }

			if (i) {
				char *include_dir = NULL, *comp_dir = NULL;
				char *allocated_id = NULL;
				if (id_idx > 0) {
					include_dir = sdb_array_get (s, "includedirs", id_idx - 1, 0);

					if (include_dir && include_dir[0] != '/') {
						comp_dir = sdb_get (bf->sdb_addrinfo, "DW_AT_comp_dir", 0);
						if (comp_dir) {
							allocated_id = calloc(1,strlen(comp_dir) +
									strlen(include_dir) + 8);
							snprintf(allocated_id, strlen(comp_dir) + strlen(include_dir) + 8,
									"%s/%s/", comp_dir, include_dir);
							include_dir = allocated_id;
						}
					}
				} else {
					include_dir = sdb_get (bf->sdb_addrinfo, "DW_AT_comp_dir", 0);
					if (!include_dir)
						include_dir = "./";
				}

				namelen = len + (include_dir?strlen (include_dir):0) + 8;

				if (hdr->file_names) {
					hdr->file_names[count].name = calloc (sizeof(char), namelen);
					snprintf (hdr->file_names[count].name, namelen - 1,
						"%s/%s", include_dir, filename);
					hdr->file_names[count].name[namelen - 1] = '\0';
					if (allocated_id)
						free (allocated_id);
					hdr->file_names[count].id_idx = id_idx;
					hdr->file_names[count].mod_time = mod_time;
					hdr->file_names[count].file_len = file_len;
				}
			}
			count++;
			if (f && i) {
				fprintf (f, "FILE (%s)\n", filename);
				fprintf (f, "| dir idx %"PFMT64d"\n", id_idx);
				fprintf (f, "| lastmod %"PFMT64d"\n", mod_time);
				fprintf (f, "| filelen %"PFMT64d"\n", file_len);
			}
		}
		if (i == 0) {
			if (count>0) {
				hdr->file_names = calloc(sizeof(file_entry), count);
			} else {
				hdr->file_names = NULL;
			}
			hdr->file_names_count = count;
			buf = tmp_buf;
			count = 0;
		}
	}

beach:
	sdb_free (s);

	return buf;
}

static inline void add_sdb_addrline(Sdb *s, ut64 addr, const char *file, ut64 line, FILE *f, int mode) {
	const char *p;
	char fileline[128];
	char offset[64];
	char *offset_ptr;

	if (!s || !file)
		return;
	p = r_str_rchr (file, NULL, '/');
	if (p) p++; else p = file;
	// includedirs and properly check full paths
	switch (mode) {
	case 1:
	case 'r':
	case '*':
		if (!f) f = stdout;
		fprintf (f, "CL %s:%d 0x%08"PFMT64x"\n", p, (int)line, addr);
		break;
	}
	if (r_file_exists (file))
		p = file;
	snprintf (fileline, sizeof (fileline) - 1, "%s|%"PFMT64d, p, line);
	offset_ptr = sdb_itoa (addr, offset, 16);

	if (!sdb_add (s, offset_ptr, fileline, 0)) {
		sdb_set (s, offset_ptr, fileline, 0);
	}

	if (!sdb_add (s, fileline, offset_ptr, 0)) {
		sdb_set (s, fileline, offset_ptr, 0);
	}
}

static const ut8* r_bin_dwarf_parse_ext_opcode(const RBin *a, const ut8 *obuf,
		size_t len, const RBinDwarfLNPHeader *hdr,
		RBinDwarfSMRegisters *regs, FILE *f, int mode)
{
	// XXX - list is an unused parameter.
	const ut8 *buf;
	ut8 opcode;
	ut64 addr;
	buf = obuf;
	st64 op_len;
	RBinFile *binfile = a ? a->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	ut32 addr_size = o && o->info && o->info->bits ? o->info->bits / 8 : 4;
	const char *filename;

	if (!binfile || !obuf || !hdr || !regs) return NULL;

	buf = r_leb128 (buf, &op_len);
	opcode = *buf++;

	if (f) {
		fprintf (f, "Extended opcode %d: ", opcode);
	}

	switch (opcode) {
	case DW_LNE_end_sequence:
		regs->end_sequence = DWARF_TRUE;

		if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
			int fnidx = regs->file - 1;
			if (fnidx>=0 && fnidx<hdr->file_names_count) {
				add_sdb_addrline(binfile->sdb_addrinfo, regs->address,
						hdr->file_names[fnidx].name, regs->line, f, mode);
			}
		}

		if (f) {
			fprintf(f, "End of Sequence\n");
		}
		break;
	case DW_LNE_set_address:
		if (addr_size == 8) {
			addr = READ (buf, ut64);
		} else {
			addr = READ (buf, ut32);
		}

		regs->address = addr;

		if (f) {
			fprintf(f, "set Address to 0x%"PFMT64x"\n", addr);
		}
		break;
	case DW_LNE_define_file:
		filename = (const char*)buf;

		if (f) {
			fprintf(f, "define_file\n");
			fprintf(f, "filename %s\n", filename);
		}

		buf += (strlen (filename) + 1);
		ut64 dir_idx;
		buf = r_uleb128 (buf, ST32_MAX, &dir_idx);
		break;
	case DW_LNE_set_discriminator:
		buf = r_uleb128(buf, ST32_MAX, &addr);
		if (f) {
			fprintf(f, "set Discriminator to %"PFMT64d"\n", addr);
		}
		regs->discriminator = addr;
		break;
	default:
		if (f) {
			fprintf(f, "Unexpeced opcode %d\n", opcode);
		}
		break;
	}

	return buf;
}

static const ut8* r_bin_dwarf_parse_spec_opcode(
		const RBin *a, const ut8 *obuf, size_t len,
		const RBinDwarfLNPHeader *hdr,
		RBinDwarfSMRegisters *regs,
		ut8 opcode, FILE *f, int mode)
{
	// XXX - list is not used
	const ut8 *buf = obuf;
	ut8 adj_opcode = 0;
	ut64 advance_adr;
	RBinFile *binfile = a ? a->cur : NULL;

	if (!obuf || !hdr || !regs) return NULL;

	adj_opcode = opcode - hdr->opcode_base;
	if (!hdr->line_range) {
		eprintf ("Error r_bin_dwarf_parse_spec_opcode: hdr->line_range is 0\n");
		return NULL;
	}
	advance_adr = adj_opcode / hdr->line_range;
	regs->address += advance_adr;
	regs->line += hdr->line_base + (adj_opcode % hdr->line_range);
	if (f) {
		fprintf(f, "Special opcode %d: ", adj_opcode);
		fprintf(f, "advance Address by %"PFMT64d" to %"PFMT64x" and Line by %d to %"PFMT64d"\n",
			advance_adr, regs->address, hdr->line_base +
			(adj_opcode % hdr->line_range), regs->line);
	}
	if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
		int idx = regs->file -1;
		if (idx>=0 && idx<hdr->file_names_count) {
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
		const RBinDwarfLNPHeader *hdr, RBinDwarfSMRegisters *regs,
		ut8 opcode, FILE *f, int mode)
{
	const ut8* buf = obuf;
	ut64 addr = 0LL;
	st64 sbuf;
	ut8 adj_opcode;
	ut64 op_advance;
	ut16 operand;
	RBinFile *binfile = a ? a->cur : NULL;

	if (!binfile || !hdr || !regs || !obuf) return NULL;
	switch (opcode) {
	case DW_LNS_copy:
		if (f) {
			fprintf(f, "Copy\n");
		}

		if (binfile && binfile->sdb_addrinfo && hdr->file_names) {
			int fnidx = regs->file - 1;
			if (fnidx>=0 && fnidx<hdr->file_names_count) {
				add_sdb_addrline(binfile->sdb_addrinfo,
					regs->address,
					hdr->file_names[fnidx].name,
					regs->line, f, mode);
			}
		}
		regs->basic_block = DWARF_FALSE;
		break;
	case DW_LNS_advance_pc:
		buf = r_uleb128 (buf, ST32_MAX, &addr);
		regs->address += addr * hdr->min_inst_len;

		if (f) {
			fprintf(f, "Advance PC by %"PFMT64d" to 0x%"PFMT64x"\n",
				addr * hdr->min_inst_len, regs->address);
		}
		break;
	case DW_LNS_advance_line:
		buf = r_leb128(buf, &sbuf);
		regs->line += sbuf;
		if (f) {
			fprintf(f, "Advance line by %"PFMT64d", to %"PFMT64d"\n", sbuf, regs->line);
		}
		break;
	case DW_LNS_set_file:
		buf = r_uleb128 (buf, ST32_MAX, &addr);
		if (f) {
			fprintf(f, "Set file to %"PFMT64d"\n", addr);
		}
		regs->file = addr;
		break;
	case DW_LNS_set_column:
		buf = r_uleb128(buf, ST32_MAX, &addr);
		if (f) {
			fprintf(f, "Set column to %"PFMT64d"\n", addr);
		}
		regs->column = addr;
		break;
	case DW_LNS_negate_stmt:
		regs->is_stmt = regs->is_stmt ? DWARF_FALSE : DWARF_TRUE;
		if (f) {
			fprintf(f, "Set is_stmt to %d\n", regs->is_stmt);
		}
		break;
	case DW_LNS_set_basic_block:
		if (f) {
			fprintf(f, "set_basic_block\n");
		}
		regs->basic_block = DWARF_TRUE;
		break;
	case DW_LNS_const_add_pc:
		adj_opcode = 255 - hdr->opcode_base;
		op_advance = adj_opcode / hdr->line_range;
		regs->address += op_advance;
		if (f) {
			fprintf(f, "Advance PC by constant %"PFMT64d" to 0x%"PFMT64x"\n",
				op_advance, regs->address);
		}
		break;
	case DW_LNS_fixed_advance_pc:
		operand = READ (buf, ut16);
		regs->address += operand;
		if (f) {
			fprintf(f,"Fixed advance pc to %"PFMT64d"\n", regs->address);
		}
		break;
	case DW_LNS_set_prologue_end:
		regs->prologue_end = ~0;
		if (f) {
			fprintf(f, "set_prologue_end\n");
		}
		break;
	case DW_LNS_set_epilogue_begin:
		regs->epilogue_begin = ~0;
		if (f) {
			fprintf(f, "set_epilogue_begin\n");
		}
		break;
	case DW_LNS_set_isa:
		buf = r_uleb128(buf, ST32_MAX, &addr);
		regs->isa = addr;
		if (f) {
			fprintf(f, "set_isa\n");
		}
		break;
	default:
		if (f) {
			fprintf(f, "Unexpected opcode\n");
		}
		break;
	}
	return buf;
}

static const ut8* r_bin_dwarf_parse_opcodes (const RBin *a, const ut8 *obuf,
		size_t len, const RBinDwarfLNPHeader *hdr,
		RBinDwarfSMRegisters *regs, FILE *f, int mode) {
	const ut8 *buf, *buf_end;
	ut8 opcode, ext_opcode;

	if (!a || !obuf || len<8)
		return NULL;
	buf = obuf;
	buf_end = obuf + len;

	while (buf && buf < buf_end) {
		opcode = *buf++;
		len--;
		if (opcode == 0) {
			ext_opcode = *buf;
			buf = r_bin_dwarf_parse_ext_opcode (a, buf, len, hdr, regs, f, mode);
			if (ext_opcode == DW_LNE_end_sequence)
				break;
		} else if (opcode >= hdr->opcode_base) {
			buf = r_bin_dwarf_parse_spec_opcode (a, buf, len, hdr, regs, opcode, f, mode);
		} else {
			buf = r_bin_dwarf_parse_std_opcode (a, buf, len, hdr, regs, opcode, f, mode);
		}
		len = (int)(buf_end - buf);
	}

	return buf;
}

static void r_bin_dwarf_set_regs_default (const RBinDwarfLNPHeader *hdr,
		RBinDwarfSMRegisters *regs) {
	regs->address = 0;
	regs->file = 1;
	regs->line = 1;
	regs->column = 0;
	regs->is_stmt = hdr->default_is_stmt;
	regs->basic_block = DWARF_FALSE;
	regs->end_sequence = DWARF_FALSE;
}

R_API int r_bin_dwarf_parse_line_raw2(const RBin *a, const ut8 *obuf,
		size_t len, int mode) {
	RBinDwarfLNPHeader hdr;
	const ut8 *buf = NULL, *buf_tmp = NULL, *buf_end = NULL;
	RBinDwarfSMRegisters regs;
	int tmplen;
	FILE *f = NULL;
	RBinFile *binfile = a ? a->cur : NULL;

	if (!binfile || !obuf) return R_FALSE;

	if (mode == R_CORE_BIN_PRINT) {
		f = stdout;
	}

	buf = obuf;
	buf_end = obuf + len;
	while (buf+1 < buf_end) {
		buf_tmp = buf;
		buf = r_bin_dwarf_parse_lnp_header (a->cur, buf, buf_end, &hdr, f, mode);
		if (!buf) return R_FALSE;
		r_bin_dwarf_set_regs_default (&hdr, &regs);
		tmplen = R_MIN (len, 4+hdr.unit_length.part1);
		r_bin_dwarf_parse_opcodes (a, buf, tmplen, &hdr, &regs, f, mode);
		buf = buf_tmp + tmplen;
		len = (int)(buf_end - buf);
	}

	return R_TRUE;
}

R_API int r_bin_dwarf_parse_aranges_raw(const ut8 *obuf, int len, FILE *f) {
	ut32 length;
	ut16 version;
	ut32 debug_info_offset;
	ut8 address_size, segment_size;
	const ut8 *buf = obuf;
	int idx = 0;

	if (!obuf) return R_FALSE;

	length = *(ut32*)obuf;

	if (f) {
		printf("parse_aranges\n");
		printf("length 0x%x\n", length);
	}

	if (length >= 0xfffffff0) {
		if (idx+12>=len)
			return R_FALSE;
		idx += 12;
		buf += 4;
		buf += 8;
	} else {
		if (idx+4>=len)
			return R_FALSE;
		idx+=4;
		buf += 4;
	}

	if (idx+2>=len)
		return R_FALSE;
	version = *(ut16*)buf;
	buf += 2;
	idx += 2;

	if (f) printf("Version %d\n", version);

	if (idx+4>=len)
		return R_FALSE;
	debug_info_offset = *(ut32*)buf;

	if (f)  fprintf(f, "Debug info offset %d\n", debug_info_offset);

	buf += 4;
	idx += 4;

// ???
	address_size = *(ut8*)buf;

	if (f) fprintf(f, "address size %d\n", (int)address_size);

	buf += 1;

	segment_size = *(ut8*)buf;

	if (f) fprintf(f, "segment size %d\n", (int)segment_size);

	buf += 1;

	size_t offset = segment_size + address_size * 2;

	if (offset) {
		ut64 n = (((ut64) (size_t)buf / offset) + 1) * offset - ((ut64)(size_t)buf);
		if (idx+n>=len)
			return R_FALSE;
		buf += n;
		idx += n;
	} else {
	//	buf += 1;
	}

	while ((buf - obuf) < len) {
		ut64 adr, length;
		if ((idx+8)>=len)
			break;
		adr = *(ut64*)buf;
		buf += 8;
		idx += 8;
		length = *(ut64*)buf;
		buf += 8;
		idx += 8;
		if (f) printf("length 0x%"PFMT64x" address 0x%"PFMT64x"\n", length, adr);
	}

	return 0;
}

static int r_bin_dwarf_init_debug_info(RBinDwarfDebugInfo *inf) {
	if (!inf) return -1;
	inf->comp_units = calloc (sizeof(RBinDwarfCompUnit), DEBUG_INFO_CAPACITY);

	// XXX - should we be using error codes?
	if (!inf->comp_units) return -ENOMEM;

	inf->capacity = DEBUG_INFO_CAPACITY;
	inf->length = 0;

	return R_TRUE;
}

static int r_bin_dwarf_init_die(RBinDwarfDIE *die) {
	if (!die) return -EINVAL;
	die->attr_values = calloc(sizeof(RBinDwarfAttrValue), 8);

	if (!die->attr_values)
		return -ENOMEM;

	die->capacity = 8;
	die->length = 0;

	return 0;
}

static int r_bin_dwarf_expand_die(RBinDwarfDIE* die) {
	RBinDwarfAttrValue *tmp = NULL;
	if (!die || die->capacity == 0) return -EINVAL;

	if (die->capacity != die->length) return -EINVAL;

	tmp = (RBinDwarfAttrValue*)realloc(die->attr_values,
			die->capacity * 2 * sizeof(RBinDwarfAttrValue));

	if (!tmp)
		return -ENOMEM;

	die->attr_values = tmp;
	die->capacity *= 2;
	return 0;
}

static int r_bin_dwarf_init_comp_unit(RBinDwarfCompUnit *cu) {

	if (!cu) return -EINVAL;
	cu->dies = calloc(sizeof(RBinDwarfDIE), COMP_UNIT_CAPACITY);

	if (!cu->dies) return -ENOMEM;

	cu->capacity = COMP_UNIT_CAPACITY;
	cu->length = 0;

	return 0;
}

static int r_bin_dwarf_expand_cu(RBinDwarfCompUnit *cu) {
	RBinDwarfDIE *tmp;

	if (!cu || cu->capacity == 0 || cu->capacity != cu->length) return -EINVAL;

	tmp = (RBinDwarfDIE*)realloc(cu->dies,
			cu->capacity * 2 * sizeof(RBinDwarfDIE));

	if (!tmp) return -ENOMEM;

	cu->dies = tmp;
	cu->capacity *= 2;

	return 0;
}

static int r_bin_dwarf_init_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	if (!ad) return -EINVAL;
	ad->specs = calloc(sizeof(RBinDwarfAttrSpec), ABBREV_DECL_CAP);

	if (!ad->specs)
		return -ENOMEM;

	ad->capacity = ABBREV_DECL_CAP;
	ad->length = 0;

	return 0;
}

static int r_bin_dwarf_expand_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	RBinDwarfAttrSpec *tmp;

	if (!ad || ad->capacity==0 || ad->capacity != ad->length)
		return -EINVAL;

	tmp = (RBinDwarfAttrSpec*)realloc(ad->specs,
			ad->capacity * 2 * sizeof(RBinDwarfAttrSpec));

	if (!tmp)
		return -ENOMEM;

	ad->specs = tmp;
	ad->capacity *= 2;

	return 0;
}

static int r_bin_dwarf_init_debug_abbrev(RBinDwarfDebugAbbrev *da) {

	if (!da) return -EINVAL;
	da->decls = calloc(sizeof(RBinDwarfAbbrevDecl), DEBUG_ABBREV_CAP);

	if (!da->decls) return -ENOMEM;

	da->capacity = DEBUG_ABBREV_CAP;
	da->length = 0;

	return 0;
}

static int r_bin_dwarf_expand_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	RBinDwarfAbbrevDecl *tmp;

	if (!da || da->capacity == 0 || da->capacity != da->length)
		return -EINVAL;

	tmp = (RBinDwarfAbbrevDecl*)realloc(da->decls,
			da->capacity * 2 * sizeof(RBinDwarfAbbrevDecl));

	if (!tmp)
		return -ENOMEM;

	da->decls = tmp;
	da->capacity *= 2;

	return 0;
}

static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RBinDwarfDebugAbbrev *da) {
	size_t i, j;
	ut64 attr_name, attr_form;

	if (!f || !da) return;
	for (i = 0; i < da->length; i++) {
		int declstag = da->decls[i].tag;
		fprintf(f, "Abbreviation Code %"PFMT64d" ", da->decls[i].code);
		if (declstag>=0 && declstag < DW_TAG_LAST)
			fprintf(f, "Tag %s ", dwarf_tag_name_encodings[declstag]);
		fprintf(f, "[%s]\n", da->decls[i].has_children ?
				"has children" : "no children");
		fprintf(f, "Offset 0x%"PFMT64x"\n", da->decls[i].offset);

		for (j = 0; j < da->decls[i].length; j++) {
			attr_name = da->decls[i].specs[j].attr_name;
			attr_form = da->decls[i].specs[j].attr_form;
			if (attr_name && attr_form &&
				attr_name <= DW_AT_vtable_elem_location &&
				attr_form <= DW_FORM_indirect) {
					fprintf(f, "    %s %s\n",
						dwarf_attr_encodings[attr_name],
						dwarf_attr_form_encodings[attr_form]);
			}
		}
	}
}

R_API void r_bin_dwarf_free_debug_abbrev(RBinDwarfDebugAbbrev *da) {
	size_t i;

	if (!da) return;
	for (i = 0; i < da->length; i++)
		free(da->decls[i].specs);

	free (da->decls);
}

static void r_bin_dwarf_free_attr_value (RBinDwarfAttrValue *val) {
	if (!val) return;
	switch (val->form) {
	case DW_FORM_strp:
	case DW_FORM_string:
		if (val->encoding.str_struct.string) {
			free (val->encoding.str_struct.string);
		}
		break;
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
		if (val->encoding.block.data) {
			free (val->encoding.block.data);
		}
		break;
	default:
		break;
	};
}

static void r_bin_dwarf_free_die (RBinDwarfDIE *die) {
	size_t i;
	if (!die) return;
	for (i = 0; i < die->length; i++) {
		r_bin_dwarf_free_attr_value (&die->attr_values[i]);
	}
	free (die->attr_values);
}

static void r_bin_dwarf_free_comp_unit (RBinDwarfCompUnit *cu)
{
	size_t i;
	if (!cu) return;
	for (i = 0; i < cu->length; i++) {
		r_bin_dwarf_free_die (&cu->dies[i]);
	}

	free (cu->dies);
}

static void r_bin_dwarf_free_debug_info (RBinDwarfDebugInfo *inf)
{
	size_t i;
	if (!inf) return;
	for (i = 0; i < inf->length; i++) {
		r_bin_dwarf_free_comp_unit (&inf->comp_units[i]);
	}

	free (inf->comp_units);
}

static void r_bin_dwarf_dump_attr_value(const RBinDwarfAttrValue *val, FILE *f)
{
	size_t i;
	if (!val || !f) return;
	switch (val->form) {
	case DW_FORM_addr:
		fprintf(f, "0x%"PFMT64x"", val->encoding.address);
		break;
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
		fprintf (f, "%llu byte block:", val->encoding.block.length);
		for (i = 0; i < val->encoding.block.length; i++) {
			fprintf (f, "%02x", val->encoding.block.data[i]);
		}
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
		fprintf (f, "%llu", val->encoding.data);
		if (val->name == DW_AT_language) {
			fprintf (f, "   (%s)", dwarf_langs[val->encoding.data]);
		}
		break;
	case DW_FORM_strp:
		fprintf (f, "(indirect string, offset: 0x%"PFMT64x"): ",
				val->encoding.str_struct.offset);
	case DW_FORM_string:
		if (val->encoding.str_struct.string) {
			fprintf (f, "%s", val->encoding.str_struct.string);
		} else {
			fprintf (f, "No string found");
		}
		break;
	case DW_FORM_flag:
		fprintf (f, "%u", val->encoding.flag);
		break;
	case DW_FORM_sdata:
		fprintf (f, "%"PFMT64d"", val->encoding.sdata);
		break;
	case DW_FORM_udata:
		fprintf (f, "%llu", val->encoding.data);
		break;
	case DW_FORM_ref_addr:
		fprintf (f, "<0x%"PFMT64x">", val->encoding.reference);
		break;
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
		fprintf (f, "<0x%"PFMT64x">", val->encoding.reference);
		break;
	default:
		fprintf (f, "Unknown attr value form %"PFMT64d"\n", val->form);
	};
}

static void r_bin_dwarf_dump_debug_info (FILE *f, const RBinDwarfDebugInfo *inf) {
	size_t i, j, k;
	RBinDwarfDIE *dies;
	RBinDwarfAttrValue *values;
	if (!inf || !f) return;

	for (i = 0; i < inf->length; i++) {
		fprintf(f, "  Compilation Unit @ offset 0x%"PFMT64x":\n", inf->comp_units [i].offset);
		fprintf(f, "   Length:        0x%x\n", inf->comp_units [i].hdr.length);
		fprintf(f, "   Version:       %d\n", inf->comp_units [i].hdr.version);
		fprintf(f, "   Abbrev Offset: 0x%x\n", inf->comp_units [i].hdr.abbrev_offset);
		fprintf(f, "   Pointer Size:  %d\n", inf->comp_units [i].hdr.pointer_size);

		dies = inf->comp_units[i].dies;

		for (j = 0; j < inf->comp_units[i].length; j++) {
			fprintf(f, "    Abbrev Number: %llu ", dies[j].abbrev_code);

			if (dies[j].tag && dies[j].tag <= DW_TAG_volatile_type &&
				       dwarf_tag_name_encodings[dies[j].tag]) {
				fprintf(f, "(%s)\n", dwarf_tag_name_encodings[dies[j].tag]);
			} else {
				fprintf(f, "(Unknown abbrev tag)\n");
			}

			if (!dies[j].abbrev_code)
				continue;
			values = dies[j].attr_values;

			for (k = 0; k < dies[j].length; k++) {
				if (!values[k].name)
					continue;

				if (values[k].name < DW_AT_vtable_elem_location &&
						dwarf_attr_encodings[values[k].name]) {
					fprintf(f, "     %-18s : ", dwarf_attr_encodings[values[k].name]);
				} else {
					fprintf(f, "     TODO\t");
				}
				r_bin_dwarf_dump_attr_value (&values[k], f);
				fprintf(f, "\n");
			}
		}
	}
}

static const ut8 *r_bin_dwarf_parse_attr_value (const ut8 *obuf,
		RBinDwarfAttrSpec *spec, RBinDwarfAttrValue *value,
		const RBinDwarfCompUnitHdr *hdr,
		const ut8 *debug_str, size_t debug_str_len)
{
	const ut8 *buf = obuf;
	size_t j;

	if (!spec || !value || !hdr || !obuf) return NULL;
	value->form = spec->attr_form;
	value->name = spec->attr_name;

	switch (spec->attr_form) {
	case DW_FORM_addr:
		switch (hdr->pointer_size) {
		case 1:
			value->encoding.address = READ (buf, ut8);
			break;
		case 2:
			value->encoding.address = READ (buf, ut16);
			break;
		case 4:
			value->encoding.address = READ (buf, ut32);
			break;
		case 8:
			value->encoding.address = READ (buf, ut64);
			break;
		default:
			eprintf("DWARF: Unexpected pointer size: %u\n",
					(unsigned)hdr->pointer_size);
			return NULL;
		}
		break;

	case DW_FORM_block2:
		value->encoding.block.length = READ (buf, ut16);
		value->encoding.block.data = calloc(sizeof(ut8),
				value->encoding.block.length);

		for (j = 0; j < value->encoding.block.length; j++) {
			value->encoding.block.data[j] = READ (buf, ut8);
		}
		break;

	case DW_FORM_block4:
		value->encoding.block.length = READ (buf, ut32);
		value->encoding.block.data = calloc(sizeof(ut8),
				value->encoding.block.length);

		for (j = 0; j < value->encoding.block.length; j++) {
			value->encoding.block.data[j] = READ (buf, ut8);
		}
		break;

	case DW_FORM_data2:
		value->encoding.data = READ (buf, ut16);
		break;

	case DW_FORM_data4:
		value->encoding.data = READ (buf, ut32);
		break;

	case DW_FORM_data8:
		value->encoding.data = READ (buf, ut64);
		break;

	case DW_FORM_string:
		value->encoding.str_struct.string = strdup((const char*)buf);
		buf += (strlen((const char*)buf) + 1);
		break;

	case DW_FORM_block:
		buf = r_uleb128 (buf, ST32_MAX, &value->encoding.block.length);

		value->encoding.block.data = calloc(sizeof(ut8),
				value->encoding.block.length);

		for (j = 0; j < value->encoding.block.length; j++) {
			value->encoding.block.data[j] = READ (buf, ut8);
		}
		break;

	case DW_FORM_block1:
		value->encoding.block.length = READ (buf, ut8);

		value->encoding.block.data = calloc(sizeof(ut8),
				value->encoding.block.length);

		for (j = 0; j < value->encoding.block.length; j++) {
			value->encoding.block.data[j] = READ (buf, ut8);
		}
		break;

	case DW_FORM_flag:
		value->encoding.flag = READ (buf, ut8);
		break;

	case DW_FORM_sdata:
		buf = r_leb128 (buf, &value->encoding.sdata);
		break;

	case DW_FORM_strp:
		value->encoding.str_struct.offset = READ (buf, ut32);
		if (debug_str && value->encoding.str_struct.offset
				< debug_str_len) {
			value->encoding.str_struct.string = strdup (
				(const char *)(debug_str +
					value->encoding.str_struct.offset));
		} else {
			value->encoding.str_struct.string = NULL;
		}
		break;

	case DW_FORM_udata:
		buf = r_uleb128 (buf, ST32_MAX, &value->encoding.data);
		break;

	case DW_FORM_ref_addr:
		value->encoding.reference = READ (buf, ut64); // addr size of machine
		break;

	case DW_FORM_ref1:
		value->encoding.reference = READ (buf, ut8);
		break;

	case DW_FORM_ref2:
		value->encoding.reference = READ (buf, ut16);
		break;

	case DW_FORM_ref4:
		value->encoding.reference = READ (buf, ut32);
		break;

	case DW_FORM_ref8:
		value->encoding.reference = READ (buf, ut64);
		break;

	case DW_FORM_data1:
		value->encoding.data = READ (buf, ut8);
		break;

	default:
		return buf;
	}

	return buf;
}

static const ut8 *r_bin_dwarf_parse_comp_unit(Sdb *s, const ut8 *obuf,
		RBinDwarfCompUnit *cu, const RBinDwarfDebugAbbrev *da,
		size_t offset, const ut8 *debug_str, size_t debug_str_len)
{
	const ut8 *buf = obuf, *buf_end = obuf + (cu->hdr.length - 7);
	ut64 abbr_code;
	size_t i;

	while (buf < buf_end) {
		if (cu->length && cu->capacity == cu->length)
			r_bin_dwarf_expand_cu (cu);

		buf = r_uleb128 (buf, ST32_MAX, &abbr_code);

		if (abbr_code > da->length) {
			return NULL;
		}

		r_bin_dwarf_init_die (&cu->dies[cu->length]);

		if (!abbr_code) {
			cu->dies[cu->length].abbrev_code = 0;
			cu->length++;
			buf++;
			continue;
		}

		cu->dies[cu->length].abbrev_code = abbr_code;
		cu->dies[cu->length].tag = da->decls[abbr_code - 1].tag;
		abbr_code += offset;

		for (i = 0; i < da->decls[abbr_code - 1].length; i++) {
			if (cu->dies[cu->length].length ==
				cu->dies[cu->length].capacity)
				r_bin_dwarf_expand_die (&cu->dies[cu->length]);
			buf = r_bin_dwarf_parse_attr_value (buf,
					&da->decls[abbr_code - 1].specs[i],
					&cu->dies[cu->length].attr_values[i],
					&cu->hdr, debug_str, debug_str_len);

			if (cu->dies[cu->length].attr_values[i].name == DW_AT_comp_dir) {
				char *comp_dir =
					cu->dies[cu->length].attr_values[i].encoding.str_struct.string;

				if (s)
					sdb_add (s, "DW_AT_comp_dir", comp_dir, 0);
			}
			cu->dies[cu->length].length++;
		}

		cu->length++;
	}

	return buf;
}

R_API int r_bin_dwarf_parse_info_raw(Sdb *s, RBinDwarfDebugAbbrev *da,
		const ut8 *obuf, size_t len,
		const ut8 *debug_str, size_t debug_str_len, int mode)
{
	const ut8 *buf = obuf, *buf_end = obuf + len;
	size_t curr_unit = 0, k, offset = 0;

	RBinDwarfDebugInfo *inf = NULL, di;
	inf = &di;

	r_bin_dwarf_init_debug_info (inf);
	if (!da || !s || !obuf) return R_FALSE;
	while (buf < buf_end) {
		if (inf->length >= inf->capacity)
			break;

		r_bin_dwarf_init_comp_unit (&inf->comp_units[curr_unit]);

		inf->comp_units[curr_unit].offset = buf - obuf;
		inf->comp_units[curr_unit].hdr.length = READ (buf, ut32);
		inf->comp_units[curr_unit].hdr.version = READ (buf, ut16);

		if (inf->comp_units[curr_unit].hdr.version != 2) {
//			eprintf ("DWARF: version %d is not yet supported.\n",
//					inf->comp_units[curr_unit].hdr.version);
			return -1;
		}

		inf->comp_units[curr_unit].hdr.abbrev_offset = READ (buf, ut32);
		inf->comp_units[curr_unit].hdr.pointer_size = READ (buf, ut8);
		inf->length++;

		/* Linear search FIXME */
		for (k = 0; k < da->decls->length; k++) {
			if (da->decls[k].offset ==
				inf->comp_units[curr_unit].hdr.abbrev_offset) {
				offset = k;
				break;
			}
		}

		buf = r_bin_dwarf_parse_comp_unit(s, buf, &inf->comp_units[curr_unit],
				da, offset, debug_str, debug_str_len);

		if (!buf) {
			r_bin_dwarf_free_debug_info (inf);
			return R_FALSE;
		}

		curr_unit++;
	}

	if (mode == R_CORE_BIN_PRINT) {
		r_bin_dwarf_dump_debug_info (NULL, inf);
	}

	r_bin_dwarf_free_debug_info (inf);

	return R_TRUE;
}

static RBinDwarfDebugAbbrev *r_bin_dwarf_parse_abbrev_raw(const ut8 *obuf, size_t len, int mode) {
	const ut8 *buf = obuf, *buf_end = obuf + len;
	ut64 tmp, spec1, spec2, offset;
	ut8 has_children;
	RBinDwarfAbbrevDecl *tmpdecl;

	RBinDwarfDebugAbbrev *da = NULL;
	// XXX - Set a suitable value here.
	if (!obuf || len < 3) return da;
	
	da = R_NEW0(RBinDwarfDebugAbbrev);

	r_bin_dwarf_init_debug_abbrev (da);

	while (buf && buf+1 < buf_end) {
		offset = buf - obuf;
		buf = r_uleb128 (buf, (size_t)(buf_end-buf), &tmp);
		if (!buf || !tmp)
			continue;

		if (da->length == da->capacity)
			r_bin_dwarf_expand_debug_abbrev(da);

		tmpdecl = &da->decls[da->length];

		r_bin_dwarf_init_abbrev_decl(tmpdecl);

		tmpdecl->code = tmp;
		buf = r_uleb128 (buf, (size_t)(buf_end-buf), &tmp);
		tmpdecl->tag = tmp;

		tmpdecl->offset = offset;
		has_children = READ (buf, ut8);
		tmpdecl->has_children = has_children;
		do {
			if (tmpdecl->length == tmpdecl->capacity)
				r_bin_dwarf_expand_abbrev_decl(tmpdecl);

			buf = r_uleb128(buf, (size_t)(buf_end-buf), &spec1);
			buf = r_uleb128(buf, (size_t)(buf_end-buf), &spec2);

			tmpdecl->specs[tmpdecl->length].attr_name = spec1;
			tmpdecl->specs[tmpdecl->length].attr_form = spec2;

			tmpdecl->length++;
		} while (spec1 && spec2);

		da->length++;
	}

	if (mode == R_CORE_BIN_PRINT)
		dump_r_bin_dwarf_debug_abbrev(stdout, da);

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

R_API int r_bin_dwarf_parse_info(RBinDwarfDebugAbbrev *da, RBin *a, int mode) {
	ut8 *buf, *debug_str_buf = 0;
	int len, debug_str_len = 0, ret;
	RBinSection *debug_str;
	RBinSection *section = getsection (a, "debug_info");
	RBinFile *binfile = a ? a->cur: NULL;

	if (binfile && section) {
		debug_str = getsection (a, "debug_str");
		if (debug_str) {
			debug_str_len = debug_str->size;
			debug_str_buf = calloc (1, debug_str_len);
			ret = r_buf_read_at (binfile->buf, debug_str->paddr,
					debug_str_buf, debug_str_len);
			if (!ret) {
				free (debug_str_buf);
				return R_FALSE;
			}
		}

		len = section->size;
		if (len > (UT32_MAX>>1) || len <1) {
			free (debug_str_buf);
			return R_FALSE;
		}
		buf = calloc (1, len);
		ret = r_buf_read_at (binfile->buf, section->paddr, buf, len);

		if (!ret) {
			free (debug_str_buf);
			free (buf);
			return R_FALSE;
		}
		ret = r_bin_dwarf_parse_info_raw (binfile->sdb_addrinfo, da, buf, len,
				debug_str_buf, debug_str_len, mode);
		if (debug_str_buf) {
			free (debug_str_buf);
		}
		free (buf);
		return ret;
	}
	return R_FALSE;
}

R_API RList *r_bin_dwarf_parse_line(RBin *a, int mode) {
	ut8 *buf;
	int len, ret;
	RBinSection *section = getsection (a, "debug_line");
	RBinFile *binfile = a ? a->cur: NULL;
	if (binfile && section) {
		RList *list = r_list_new ();
		len = section->size;
		buf = calloc (1,len);
		ret = r_buf_read_at (binfile->buf, section->paddr, buf, len);
		if (!ret) {
			free (buf);
			return NULL;
		}
		r_bin_dwarf_parse_line_raw2 (a, buf, len, mode);
//sdb_query (binfile->sdb_addrinfo, "*");
		free (buf);
		return list;
	}
	return NULL;
}

R_API RList *r_bin_dwarf_parse_aranges(RBin *a, int mode) {
	ut8 *buf;
	int ret;
	size_t len;
	RBinSection *section = getsection (a, "debug_aranges");
	RBinFile *binfile = a ? a->cur: NULL;

	if (binfile && section) {
		len = section->size;
		if (len==0) return NULL;
		buf = calloc (1,len);
		ret = r_buf_read_at (binfile->buf, section->paddr, buf, len);

		if (!ret) {
			free (buf);
			return NULL;
		}

		if (mode == R_CORE_BIN_PRINT) {
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

	if (binfile && section) {
		len = section->size;
		buf = calloc (1,len);
		r_buf_read_at (binfile->buf, section->paddr, buf, len);
		da = r_bin_dwarf_parse_abbrev_raw (buf, len, mode);
		free (buf);
	}

	return da;
}
