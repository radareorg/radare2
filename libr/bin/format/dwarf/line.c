/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"

#define DWARF_STRING_MAX ((size_t)0xfff)

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

static int add_sdb_include_dir(Sdb *s, const char *incl, int idx) {
	if (!s || !incl) {
		return false;
	}
	return sdb_array_set (s, "includedirs", idx, incl, 0);
}

// Parses source file header of DWARF version <= 4
static const ut8 *parse_line_header_source(RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, Sdb *sdb, int mode, RStrBuf *sb, int debug_line_offset) {
	int i = 0;
	size_t count = 1;
	const ut8 *tmp_buf = NULL;
	char *fn = NULL;

	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, " The Directory Table:\n");
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
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "  %d     %s\n", i + 1, str);
		}
		add_sdb_include_dir (sdb, str, i);
		free (str);
		i++;
		buf += len + 1;
	}

	tmp_buf = buf;
	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, "\n");
		r_strbuf_append (sb, " The File Name Table:\n");
		r_strbuf_append (sb, "  Entry Dir     Time      Size       Name\n");
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
			if (sb && mode == R_MODE_PRINT && i) {
				r_strbuf_appendf (sb, "  %d     %" PFMT64d "       %" PFMT64d "         %" PFMT64d "          %s\n",
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
	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, "\n");
	}

beach:
	free (fn);
	sdb_free (sdb);

	return buf;
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
		section = dwarf_get_section (bf, DWARF_SN_LINE_STR);
		*ret_name = section? dwarf_get_section_string (bf, section, section_offset): NULL;
		return buf;
	case DW_FORM_strp:
		section_offset = dwarf_read_offset (bin, is_64bit, &buf, buf_end);
		section = dwarf_get_section (bf, DWARF_SN_STR);
		*ret_name = section? dwarf_get_section_string (bf, section, section_offset): NULL;
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
static const ut8 *parse_line_header_source_dwarf5(RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, Sdb *s, int mode, RStrBuf *sb) {
	RBin *bin = bf? bf->rbin: NULL;
	if (!bin) {
		return NULL;
	}
	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, " The Directory Table:\n");
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
			if (sb && mode == R_MODE_PRINT) {
				char *include_dir = sdb_array_get (s, "includedirs", i, 0);
				r_strbuf_appendf (sb, "  %" PFMT64u "     %s\n", i, include_dir);
				free (include_dir);
			}
		}
	}

	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, "\n");
		r_strbuf_append (sb, " The File Name Table:\n");
		r_strbuf_append (sb, "  Entry Dir     Time      Size       MD5                              Name\n");
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
		if (sb && mode == R_MODE_PRINT) {
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
			r_strbuf_appendf (sb, "  %" PFMT64u "     %" PFMT32d "       %" PFMT32d "         %" PFMT32d "          %s %s\n",
				i + 1,
				file->id_idx,
				file->mod_time,
				file->file_len,
				sumstr,
				file->name);
		}
	}

	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, "\n");
	}

	sdb_free (s);
	return buf;
}

static const ut8 *parse_line_header(RBin *bin, RBinFile *bf, const ut8 *buf, const ut8 *buf_end, RBinDwarfLineHeader *hdr, int mode, RStrBuf *sb, int debug_line_offset) {
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

	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, " Header information:\n");
		r_strbuf_appendf (sb, "  Length:                             %" PFMT64u "\n", hdr->unit_length);
		r_strbuf_appendf (sb, "  DWARF Version:                      %d\n", hdr->version);
		r_strbuf_appendf (sb, "  Header Length:                      %" PFMT64d "\n", hdr->header_length);
		r_strbuf_appendf (sb, "  Minimum Instruction Length:         %d\n", hdr->min_inst_len);
		r_strbuf_appendf (sb, "  Maximum Operations per Instruction: %d\n", hdr->max_ops_per_inst);
		r_strbuf_appendf (sb, "  Initial value of 'is_stmt':         %d\n", hdr->default_is_stmt);
		r_strbuf_appendf (sb, "  Line Base:                          %d\n", hdr->line_base);
		r_strbuf_appendf (sb, "  Line Range:                         %d\n", hdr->line_range);
		r_strbuf_appendf (sb, "  Opcode Base:                        %d\n\n", hdr->opcode_base);
	}

	if (hdr->opcode_base > 0) {
		hdr->std_opcode_lengths = calloc (sizeof (ut8), hdr->opcode_base);

		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, " Opcodes:\n");
		}
		size_t i;
		for (i = 1; i < hdr->opcode_base; i++) {
			if (buf + 2 > buf_end) {
				break;
			}
			hdr->std_opcode_lengths[i] = READ8 (buf);
			if (sb && mode == R_MODE_PRINT) {
				r_strbuf_appendf (sb, "  Opcode %u has %d arg\n", (int)i, hdr->std_opcode_lengths[i]);
			}
		}
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, "\n");
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
		buf = parse_line_header_source (bf, buf, buf_end, hdr, sdb, mode, sb, debug_line_offset);
	} else {
		buf = parse_line_header_source_dwarf5 (bf, buf, buf_end, hdr, sdb, mode, sb);
	}
	R_FREE (hdr->std_opcode_lengths);

	return buf;
}

#define DWARF_ADDRLINE_STORE_LIMIT (16 * 1024 * 1024)

static bool dwarf_line_store_is_large(RBinFile *bf) {
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_LINE);
	return section && section->size > DWARF_ADDRLINE_STORE_LIMIT;
}

static inline void add_sdb_addrline(RBinFile *bf, ut64 addr, const char *file, ut64 line, ut64 column, int mode, RStrBuf *sb) {
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
		if (!sb) {
			break;
		}
		// sanitize filename to prevent r2 script injection via embedded newlines
		char *sp = strdup (p);
		r_str_sanitize (sp);
#if R2_590
		/// XXX CL must take filename as last argument to support spaces imho
		r_strbuf_appendf (sb, "'CL %s|%d|%d 0x%08" PFMT64x "\n", sp, (int)line, (int)column, addr);
#else
		if (column) {
			r_strbuf_appendf (sb, "'CL %s:%d:%d 0x%08" PFMT64x "\n", sp, (int)line, (int)column, addr);
		} else if (line > 0) {
			r_strbuf_appendf (sb, "'CL %s:%d 0x%08" PFMT64x "\n", sp, (int)line, addr);
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

static const ut8 *parse_ext_opcode(RBin *bin, const ut8 *obuf, size_t len, const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs, int mode, RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (bin && bin->cur && obuf && hdr && regs, NULL);

	const bool be = r_bin_is_big_endian (bin);
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

	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_appendf (sb, "  Extended opcode %d: ", opcode);
	}

	switch (opcode) {
	case DW_LNE_end_sequence:
		regs->end_sequence = true;

		if (binfile && hdr->file_names) {
			int fnidx = regs->file;
			if (fnidx >= 0 && fnidx < hdr->file_names_count) {
				add_sdb_addrline (binfile, regs->address, hdr->file_names[fnidx].name, regs->line, regs->column, mode, sb);
			}
		}

		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, "End of Sequence\n");
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
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "set Address to 0x%" PFMT64x "\n", addr);
		}
		break;
	case DW_LNE_define_file:
		filename = (const char *)buf;
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, "define_file\n");
			r_strbuf_appendf (sb, "filename %s\n", filename);
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
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "set Discriminator to %" PFMT64d "\n", addr);
		}
		regs->discriminator = addr;
		break;
	default:
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Unexpected ext opcode %d\n", opcode);
		}
		buf = NULL;
		break;
	}

	return buf;
}

static const ut8 *parse_spec_opcode(const RBin *bin, const ut8 *obuf, size_t len, const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs, ut8 opcode, int mode, RStrBuf *sb) {

	R_RETURN_VAL_IF_FAIL (bin && obuf && hdr && regs, NULL);

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
	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_appendf (sb, "  Special opcode %d: ", adj_opcode);
		r_strbuf_appendf (sb, "advance Address by %" PFMT64d " to 0x%" PFMT64x " and Line by %d to %" PFMT64d "\n",
			advance_adr,
			regs->address,
			line_increment,
			regs->line);
	}
	if (binfile && hdr->file_names) {
		int idx = regs->file;
		if (idx >= 0 && idx < hdr->file_names_count) {
			add_sdb_addrline (binfile, regs->address, hdr->file_names[idx].name, regs->line, regs->column, mode, sb);
		}
	}
	regs->basic_block = false;
	regs->prologue_end = false;
	regs->epilogue_begin = false;
	regs->discriminator = 0;

	return buf;
}

static const ut8 *parse_std_opcode(RBin *bin, const ut8 *obuf, size_t len, const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs, ut8 opcode, int mode, RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (bin && bin->cur && obuf && hdr && regs, NULL);
	bool be = r_bin_is_big_endian (bin);

	RBinFile *binfile = bin->cur;
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;
	ut64 addr = 0LL;
	st64 sbuf;
	ut8 adj_opcode;
	ut64 op_advance;
	ut16 operand;

	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, "  "); // formatting
	}
	switch (opcode) {
	case DW_LNS_copy:
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, "Copy\n");
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
					sb);
			}
		}
		regs->basic_block = false;
		break;
	case DW_LNS_advance_pc:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		regs->address += addr * hdr->min_inst_len;
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Advance PC by %" PFMT64d " to 0x%" PFMT64x "\n",
				addr * hdr->min_inst_len,
				regs->address);
		}
		break;
	case DW_LNS_advance_line:
		buf = r_leb128 (buf, buf_end - buf, &sbuf);
		regs->line += sbuf;
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Advance line by %" PFMT64d ", to %" PFMT64d "\n", sbuf, regs->line);
		}
		break;
	case DW_LNS_set_file:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Set file to %" PFMT64d "\n", addr);
		}
		regs->file = addr;
		break;
	case DW_LNS_set_column:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Set column to %" PFMT64d "\n", addr);
		}
		regs->column = addr;
		break;
	case DW_LNS_negate_stmt:
		regs->is_stmt = regs->is_stmt? false: true;
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Set is_stmt to %d\n", regs->is_stmt);
		}
		break;
	case DW_LNS_set_basic_block:
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, "set_basic_block\n");
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
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Advance PC by constant %" PFMT64d " to 0x%" PFMT64x "\n",
				op_advance,
				regs->address);
		}
		break;
	case DW_LNS_fixed_advance_pc:
		operand = READ16 (buf);
		regs->address += operand;
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Fixed advance pc to %" PFMT64d "\n", regs->address);
		}
		break;
	case DW_LNS_set_prologue_end:
		regs->prologue_end = ~0;
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, "set_prologue_end\n");
		}
		break;
	case DW_LNS_set_epilogue_begin:
		regs->epilogue_begin = ~0;
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, "set_epilogue_begin\n");
		}
		break;
	case DW_LNS_set_isa:
		buf = r_uleb128 (buf, buf_end - buf, &addr, NULL);
		regs->isa = addr;
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, "set_isa\n");
		}
		break;
	default:
		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_appendf (sb, "Unexpected std opcode %d\n", opcode);
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

static size_t parse_opcodes(RBin *bin, const ut8 *obuf, size_t len, const RBinDwarfLineHeader *hdr, RBinDwarfSMRegisters *regs, int mode, RStrBuf *sb) {
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
			buf = parse_ext_opcode (bin, buf, len, hdr, regs, mode, sb);
			if (!buf || ext_opcode == DW_LNE_end_sequence) {
				set_regs_default (hdr, regs); // end_sequence should reset regs to default
				break;
			}
		} else if (opcode >= hdr->opcode_base) {
			buf = parse_spec_opcode (bin, buf, len, hdr, regs, opcode, mode, sb);
		} else {
			buf = parse_std_opcode (bin, buf, len, hdr, regs, opcode, mode, sb);
		}
		len = (size_t) (buf_end - buf);
	}
	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, "\n"); // formatting of the output
	}
	return (size_t)buf? (buf - obuf): 0; // number of bytes we've moved by
}

static bool parse_line_raw(RBin *a, const ut8 *obuf, ut64 len, int mode, RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (a && obuf, false);

	if (sb && mode == R_MODE_PRINT) {
		r_strbuf_append (sb, "Raw dump of debug contents of section .debug_line:\n\n");
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
		buf = parse_line_header (a, a->cur, buf, buf_end, &hdr, mode, sb, debug_line_offset);
		if (!buf) {
			line_header_fini (&hdr);
			return false;
		}

		if (sb && mode == R_MODE_PRINT) {
			r_strbuf_append (sb, " Line Number Statements:\n");
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
			if (sb && mode == R_MODE_PRINT) {
				r_strbuf_append (sb, " Line table is present, but no lines present\n");
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
			tmp_read = parse_opcodes (a, buf, buf_end - buf, &hdr, &regs, mode, sb);
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

R_IPI void dwarf_line_files_add(RList *files, HtPP *seen, const char *file) {
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
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_LINE);
	if (!section) {
		return NULL;
	}
	const ut8 *obuf = dwarf_get_section_bytes (bf, section);
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
		buf = parse_line_header (bin, bf, buf, buf_end, &hdr, R_MODE_SET, NULL, debug_line_offset);
		if (!buf) {
			line_header_fini (&hdr);
			break;
		}
		size_t i;
		for (i = 0; i < hdr.file_names_count; i++) {
			dwarf_line_files_add (files, seen, hdr.file_names[i].name);
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

R_API RList *r_bin_dwarf_parse_line(RBinFile *bf, int mode, char **text) {
	if (text) {
		*text = NULL;
	}
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RList *list = NULL;
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_LINE);
	if (bf && section) {
		/* Read and possibly decompress the .debug_line section */
		const ut8 *buf = dwarf_get_section_bytes (bf, section);
		if (!buf || section->bytes.len < 1) {
			return NULL;
		}
		list = r_list_newf (row_free);
		/* parse the line number program */
		RStrBuf *sb = text? r_strbuf_new (NULL): NULL;
		parse_line_raw (bf->rbin, buf, section->bytes.len, mode, sb);
		if (text) {
			*text = r_strbuf_drain (sb);
		}
		if (bf->addrline.used) {
			RBinAddrLineStore *als = &bf->addrline;
			als->al_foreach (als, cb, list);
		}
	}
	return list;
}
