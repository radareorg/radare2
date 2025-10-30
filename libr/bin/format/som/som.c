/* radare2 - LGPL - Copyright 2025 - pancake */

#define R_LOG_ORIGIN "bin.som"

#include "som.h"
#include <string.h>

// XXX this is a hack because we should be able to find out the interpreter from the dynamicloaderheader instead of this crap
static char *som_find_interpreter_path(RBuffer *b) {
	const char *pattern = "dld.sl";
	const ut64 size = r_buf_size (b);
	if (!size || size > (1ULL << 26)) {
		return NULL;
	}
	ut8 *tmp = malloc (size);
	if (!tmp) {
		return NULL;
	}
	if (r_buf_read_at (b, 0, tmp, size) != size) {
		free (tmp);
		return NULL;
	}
	char *res = NULL;
	const size_t pat_len = strlen (pattern);
	const ut8 *match = r_mem_mem (tmp, size, (const ut8 *)pattern, pat_len);
	if (match) {
		// scan backward to find the start of the string
		const ut8 *start = match;
		while (start > tmp && *(start - 1) != '\0') {
			start--;
		}
		size_t offset = start - tmp;
		size_t len = r_str_nlen ((const char *)start, size - offset);
		if (len > 0) {
			res = r_str_ndup ((const char *)start, len);
		}
	}
	free (tmp);
	return res;
}

static bool is_valid_magic(const uint8_t *buf) {
	uint16_t magic = r_read_be16 (buf + 2);
	switch (magic) {
	case SOM_MAGIC_RELOC:
	case SOM_MAGIC_EXEC:
	case SOM_MAGIC_SHARE:
	case SOM_MAGIC_SHMEM:
	case SOM_MAGIC_DEMAND:
	case SOM_MAGIC_DL:
	case SOM_MAGIC_SHL:
		return true; /* match found */
	default:
		return false; /* no match */
	}
}

R_IPI bool r_bin_som_check_buffer(RBuffer *b) {
	if (!b || r_buf_size (b) < 4) {
		return false;
	}
	ut8 buf[4];
	if (r_buf_read_at (b, 0, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	return is_valid_magic (buf);
}

static void read_string_table(RBuffer *b, ut64 location, ut32 size, char **strings) {
	if (location > 0 && size > 0) {
		char *data = malloc (size);
		if (data) {
			if (r_buf_read_at (b, location, (ut8 *)data, size) == size) {
				*strings = data;
			} else {
				free (data);
			}
		}
	}
}

static void parse_som_header(RSomFile *obj, RBuffer *b, const ut8 *header) {
	obj->hdr.system_id = r_read_be16 (header + 0);
	obj->hdr.magic = r_read_be16 (header + 2);
	obj->hdr.version_id = r_read_be32 (header + 4);
	obj->hdr.file_time.secs = r_read_be32 (header + 8);
	obj->hdr.file_time.nanosecs = r_read_be32 (header + 12);
	obj->hdr.entry_space = r_read_be32 (header + 16);
	obj->hdr.entry_subspace = r_read_be32 (header + 20);
	obj->hdr.entry_offset = r_read_be32 (header + 24);
	obj->hdr.aux_header_location = r_read_be32 (header + 28);
	obj->hdr.aux_header_size = r_read_be32 (header + 32);
	obj->hdr.som_length = r_read_be32 (header + 36);
	obj->hdr.presumed_dp = r_read_be32 (header + 40);
	obj->hdr.space_location = r_read_be32 (header + 44);
	obj->hdr.space_total = r_read_be32 (header + 48);
	obj->hdr.subspace_location = r_read_be32 (header + 52);
	obj->hdr.subspace_total = r_read_be32 (header + 56);
	obj->hdr.loader_fixup_location = r_read_be32 (header + 60);
	obj->hdr.loader_fixup_total = r_read_be32 (header + 64);
	obj->hdr.space_strings_location = r_read_be32 (header + 68);
	obj->hdr.space_strings_size = r_read_be32 (header + 72);
	obj->hdr.init_array_location = r_read_be32 (header + 76);
	obj->hdr.init_array_total = r_read_be32 (header + 80);
	obj->hdr.compiler_location = r_read_be32 (header + 84);
	obj->hdr.compiler_total = r_read_be32 (header + 88);
	obj->hdr.symbol_location = r_read_be32 (header + 92);
	obj->hdr.symbol_total = r_read_be32 (header + 96);
	obj->hdr.fixup_request_location = r_read_be32 (header + 100);
	obj->hdr.fixup_request_total = r_read_be32 (header + 104);
	obj->hdr.symbol_strings_location = r_read_be32 (header + 108);
	obj->hdr.symbol_strings_size = r_read_be32 (header + 112);
	obj->hdr.unloadable_sp_location = r_read_be32 (header + 116);
	obj->hdr.unloadable_sp_size = r_read_be32 (header + 120);
	obj->hdr.checksum = r_read_be32 (header + 124);
}

static RSomDlHeader *parse_dl_header(const ut8 *dl_header_data) {
	RSomDlHeader *dl_hdr = R_NEW0 (RSomDlHeader);
	dl_hdr->hdr_version = r_read_be32 (dl_header_data + 0);
	dl_hdr->ltptr_value = r_read_be32 (dl_header_data + 4);
	dl_hdr->shlib_list_loc = r_read_be32 (dl_header_data + 8);
	dl_hdr->shlib_list_count = r_read_be32 (dl_header_data + 12);
	dl_hdr->import_list_loc = r_read_be32 (dl_header_data + 16);
	dl_hdr->import_list_count = r_read_be32 (dl_header_data + 20);
	dl_hdr->hash_table_loc = r_read_be32 (dl_header_data + 24);
	dl_hdr->hash_table_size = r_read_be32 (dl_header_data + 28);
	dl_hdr->export_list_loc = r_read_be32 (dl_header_data + 32);
	dl_hdr->export_list_count = r_read_be32 (dl_header_data + 36);
	dl_hdr->string_table_loc = r_read_be32 (dl_header_data + 40);
	dl_hdr->string_table_size = r_read_be32 (dl_header_data + 44);
	dl_hdr->dreloc_loc = r_read_be32 (dl_header_data + 48);
	dl_hdr->dreloc_count = r_read_be32 (dl_header_data + 52);
	dl_hdr->dlt_loc = r_read_be32 (dl_header_data + 56);
	dl_hdr->plt_loc = r_read_be32 (dl_header_data + 60);
	dl_hdr->dlt_count = r_read_be32 (dl_header_data + 64);
	dl_hdr->plt_count = r_read_be32 (dl_header_data + 68);
	dl_hdr->highwater_mark = r_read_be16 (dl_header_data + 72);
	dl_hdr->flags = r_read_be16 (dl_header_data + 74);
	dl_hdr->export_ext_loc = r_read_be32 (dl_header_data + 76);
	dl_hdr->module_loc = r_read_be32 (dl_header_data + 80);
	dl_hdr->module_count = r_read_be32 (dl_header_data + 84);
	dl_hdr->elaborator = r_read_be32 (dl_header_data + 88);
	dl_hdr->initializer = r_read_be32 (dl_header_data + 92);
	dl_hdr->embedded_path = r_read_be32 (dl_header_data + 96);
	dl_hdr->initializer_count = r_read_be32 (dl_header_data + 100);
	dl_hdr->tdsize = r_read_be32 (dl_header_data + 104);
	dl_hdr->fastbind_list_loc = r_read_be32 (dl_header_data + 108);
	return dl_hdr;
}

R_IPI void *r_bin_som_load_buffer(RBinFile *bf, RBuffer *b, ut64 laddr, Sdb *s) {
	if (!b || !r_bin_som_check_buffer (b)) {
		return NULL;
	}
	ut8 header[128];
	if (r_buf_read_at (b, 0, header, sizeof (header)) != sizeof (header)) {
		return NULL;
	}
	RSomFile *obj = R_NEW0 (RSomFile);
	obj->buf = r_buf_ref (b);
	obj->baddr = laddr? laddr: SOM_BADDR;
	parse_som_header (obj, b, header);

	// Parse string tables
	read_string_table (b, obj->hdr.space_strings_location, obj->hdr.space_strings_size, &obj->space_strings);
	read_string_table (b, obj->hdr.symbol_strings_location, obj->hdr.symbol_strings_size, &obj->symbol_strings);

	// Parse spaces
	if (obj->hdr.space_total > 0 && obj->hdr.space_total < 1024) {
		obj->spaces = r_list_newf (free);
		size_t i;
		for (i = 0; i < obj->hdr.space_total; i++) {
			ut8 space_data[32];
			ut64 offset = obj->hdr.space_location + i * 32;
			if (r_buf_read_at (b, offset, space_data, sizeof (space_data)) != sizeof (space_data)) {
				break;
			}
			RSomSpace *space = R_NEW0 (RSomSpace);
			space->name = r_read_be32 (space_data + 0);
			space->flags = r_read_be32 (space_data + 4);
			space->space_number = r_read_be32 (space_data + 8);
			space->subspace_index = r_read_be32 (space_data + 12);
			space->subspace_quantity = r_read_be32 (space_data + 16);
			r_list_append (obj->spaces, space);
		}
	}

	// Parse subspaces
	if (obj->hdr.subspace_total > 0 && obj->hdr.subspace_total < 4096) {
		obj->subspaces = r_list_newf (free);
		size_t i;
		ut8 subspace_data[40];
		for (i = 0; i < obj->hdr.subspace_total; i++) {
			ut64 offset = obj->hdr.subspace_location + i * 40;
			if (r_buf_read_at (b, offset, subspace_data, sizeof (subspace_data)) != sizeof (subspace_data)) {
				break;
			}
			RSomSubspace *subspace = R_NEW0 (RSomSubspace);
			subspace->space_index = r_read_be32 (subspace_data + 0);
			subspace->flags = r_read_be32 (subspace_data + 4);
			subspace->file_loc_init_value = r_read_be32 (subspace_data + 8);
			subspace->initialization_length = r_read_be32 (subspace_data + 12);
			subspace->subspace_start = r_read_be32 (subspace_data + 16);
			subspace->subspace_length = r_read_be32 (subspace_data + 20);
			subspace->alignment = r_read_be32 (subspace_data + 24);
			subspace->name = r_read_be32 (subspace_data + 28);
			subspace->fixup_request_index = r_read_be32 (subspace_data + 32);
			subspace->fixup_request_quantity = r_read_be32 (subspace_data + 36);
			r_list_append (obj->subspaces, subspace);
		}
	}

	// Parse dynamic loader header stored in $SHLIB_INFO$ subspace
	obj->dl_hdr = NULL;
	obj->shlibs = NULL;
	obj->imports = NULL;
	obj->dl_strings = NULL;
	obj->interp = NULL;
	if (obj->subspaces && obj->space_strings) {
		RSomSubspace *dl_subspace = NULL;
		RListIter *iter;
		RSomSubspace *subspace;
		const size_t dl_name_len = strlen ("$SHLIB_INFO$");
		r_list_foreach (obj->subspaces, iter, subspace) {
			if (subspace->name < obj->hdr.space_strings_size) {
				const char *name = obj->space_strings + subspace->name;
				size_t name_len = strnlen (name, obj->hdr.space_strings_size - subspace->name);
				if (name_len == dl_name_len && !strncmp (name, "$SHLIB_INFO$", dl_name_len)) {
					dl_subspace = subspace;
					break;
				}
			}
		}
		if (dl_subspace) {
			const ut64 dl_base = dl_subspace->file_loc_init_value;
			const ut64 dl_limit = dl_base + dl_subspace->initialization_length;
			ut8 dl_header_data[0x70];
			if (dl_subspace->initialization_length >= sizeof (dl_header_data) && r_buf_read_at (b, dl_base, dl_header_data, sizeof (dl_header_data)) == sizeof (dl_header_data)) {
				obj->dl_hdr = parse_dl_header (dl_header_data);
			}
			if (obj->dl_hdr) {
				if (obj->dl_hdr->string_table_size > 0 && obj->dl_hdr->string_table_loc < dl_subspace->initialization_length) {
					const ut64 str_off = dl_base + obj->dl_hdr->string_table_loc;
					const ut64 max_len = dl_limit > str_off? dl_limit - str_off: 0;
					const ut64 wanted = obj->dl_hdr->string_table_size;
					const ut32 str_len = (ut32)R_MIN (wanted, max_len);
					if (str_len > 0) {
						read_string_table (b, str_off, str_len, &obj->dl_strings);
					}
				}
				if (obj->dl_hdr->shlib_list_count > 0 && obj->dl_hdr->shlib_list_count < 1024 && obj->dl_hdr->shlib_list_loc < dl_subspace->initialization_length) {
					const ut64 list_off = dl_base + obj->dl_hdr->shlib_list_loc;
					const ut64 available = dl_limit > list_off? dl_limit - list_off: 0;
					const ut64 max_entries = available / 8;
					const ut32 count = (ut32)R_MIN ((ut64)obj->dl_hdr->shlib_list_count, max_entries);
					if (count > 0) {
						obj->shlibs = r_list_newf (free);
						ut32 i;
						// we start by 1 because the first is the embedded program name
						for (i = 1; i < count; i++) {
							ut8 shlib_data[8];
							const ut64 entry_off = list_off + (ut64)i * sizeof (shlib_data);
							if (r_buf_read_at (b, entry_off, shlib_data, sizeof (shlib_data)) != sizeof (shlib_data)) {
								break;
							}
							RSomShlibListEntry *shlib = R_NEW0 (RSomShlibListEntry);
							shlib->shlib_name = r_read_be32 (shlib_data + 0);
							ut8 bitfield = shlib_data[4];
							shlib->reserved1 = (bitfield >> 2) & 0x3f;
							shlib->internal_name = (bitfield >> 1) & 0x1;
							shlib->dash_l_reference = bitfield & 0x1;
							shlib->bind = shlib_data[5];
							shlib->highwater_mark = r_read_be16 (shlib_data + 6);
							r_list_append (obj->shlibs, shlib);
						}
					}
				}
				if (obj->dl_hdr->import_list_count > 0 && obj->dl_hdr->import_list_count < 1024 && obj->dl_hdr->import_list_loc < dl_subspace->initialization_length) {
					const ut64 list_off = dl_base + obj->dl_hdr->import_list_loc;
					const ut64 available = dl_limit > list_off? dl_limit - list_off: 0;
					const ut64 max_entries = available / 8;
					const ut32 count = (ut32)R_MIN ((ut64)obj->dl_hdr->import_list_count, max_entries);
					if (count > 0) {
						obj->imports = r_list_newf (free);
						ut32 i;
						for (i = 0; i < count; i++) {
							ut8 import_data[8];
							const ut64 entry_off = list_off + (ut64)i * sizeof (import_data);
							if (r_buf_read_at (b, entry_off, import_data, sizeof (import_data)) != sizeof (import_data)) {
								break;
							}
							RSomImportListEntry *import_entry = R_NEW0 (RSomImportListEntry);
							import_entry->import_name = r_read_be32 (import_data + 0);
							import_entry->import_type = import_data[4];
							import_entry->import_qualifier = import_data[5];
							import_entry->reserved = r_read_be16 (import_data + 6);
							r_list_append (obj->imports, import_entry);
						}
					}
				}
			}
			if (obj->dl_strings) {
				if (obj->dl_hdr->embedded_path < obj->dl_hdr->string_table_size) {
					const ut32 off = obj->dl_hdr->embedded_path;
					const size_t max_len = obj->dl_hdr->string_table_size - off;
					const char *embedded = obj->dl_strings + off;
					size_t len = r_str_nlen (embedded, max_len);
					char *en = r_str_ndup (embedded, len);
					R_LOG_INFO ("EmbeddedName: %s", en);
					// embedded name is the program name aka argv[0]
				}
			}
		}
	}
	obj->interp = som_find_interpreter_path (obj->buf);

	// Parse symbols
	if (obj->hdr.symbol_total > 0 && obj->hdr.symbol_total < 65536) {
		obj->symbols = r_list_newf (free);
		size_t i;
		for (i = 0; i < obj->hdr.symbol_total; i++) {
			ut8 sym_data[16];
			ut64 offset = obj->hdr.symbol_location + i * 16;
			if (r_buf_read_at (b, offset, sym_data, sizeof (sym_data)) != sizeof (sym_data)) {
				break;
			}
			RSomSymbol *sym = R_NEW0 (RSomSymbol);
			sym->name = r_read_be32 (sym_data + 0);
			sym->qualifier_name = r_read_be32 (sym_data + 4);
			sym->symbol_value = r_read_be32 (sym_data + 8);
			sym->symbol_type = sym_data[12];
			sym->symbol_scope = sym_data[13];
			sym->check_sum = sym_data[14];
			sym->flags = sym_data[15];
			r_list_append (obj->symbols, sym);
		}
	}

	return obj;
}

R_IPI void r_bin_som_free_buffer(void *bf_o) {
	r_bin_som_free ((RSomFile *)bf_o);
}

static RBinAddr *get_entry(RSomFile *obj) {
	if (!obj || !obj->spaces || obj->hdr.entry_space >= r_list_length (obj->spaces)) {
		return NULL;
	}
	RSomSpace *space = r_list_get_n (obj->spaces, obj->hdr.entry_space);
	if (!space || !obj->subspaces || obj->hdr.entry_subspace >= r_list_length (obj->subspaces)) {
		return NULL;
	}
	RSomSubspace *subspace = r_list_get_n (obj->subspaces, obj->hdr.entry_subspace);
	if (!subspace) {
		return NULL;
	}
	RBinAddr *addr = R_NEW0 (RBinAddr);
	addr->paddr = subspace->file_loc_init_value + obj->hdr.entry_offset;
	const ut64 baddr = obj->baddr;
	addr->vaddr = addr->paddr + baddr;
	addr->bits = 32;
	return addr;
}

R_IPI RList *r_bin_som_get_sections(void *o) {
	RSomFile *obj = (RSomFile *)o;
	if (!obj || !obj->subspaces) {
		return NULL;
	}
	RList *list = r_list_newf (free);
	RListIter *iter;
	RSomSubspace *subspace;
	const ut64 baddr = obj->baddr;
	r_list_foreach (obj->subspaces, iter, subspace) {
		RBinSection *s = R_NEW0 (RBinSection);
		if (obj->space_strings && subspace->name < obj->hdr.space_strings_size) {
			const char *name_str = obj->space_strings + subspace->name;
			size_t len = strnlen (name_str, obj->hdr.space_strings_size - subspace->name);
			s->name = r_str_ndup (name_str, len);
		} else {
			s->name = r_str_newf ("subspace_%d", subspace->name);
		}
		s->paddr = subspace->file_loc_init_value;
		s->vaddr = subspace->subspace_start + baddr;
		s->size = subspace->subspace_length;
		s->vsize = subspace->subspace_length;
		s->perm = R_PERM_RWX;
		s->is_data = ! (subspace->flags & SOM_SUBSPACE_CODE_ONLY);
		s->perm = s->is_data? R_PERM_RX: R_PERM_RWX;
		if (s->vsize > 0) {
			s->add = (subspace->flags & SOM_SUBSPACE_IS_LOADABLE) != 0;
		} else {
			s->is_segment = false;
		}
		// s->is_segment = (subspace->flags & SOM_SUBSPACE_IS_LOADABLE) != 0;
		r_list_append (list, s);
	}
	return list;
}

R_IPI RList *r_bin_som_get_symbols(void *o) {
	RSomFile *obj = (RSomFile *)o;
	if (!obj || !obj->symbols) {
		return NULL;
	}
	RList *list = r_list_newf (free);
	RListIter *iter;
	RSomSymbol *sym;
	r_list_foreach (obj->symbols, iter, sym) {
		RBinSymbol *bs = R_NEW0 (RBinSymbol);
		if (obj->symbol_strings && sym->name < obj->hdr.symbol_strings_size) {
			const char *name_str = obj->symbol_strings + sym->name;
			size_t len = strnlen (name_str, obj->hdr.symbol_strings_size - sym->name);
			bs->name = r_bin_name_new (r_str_ndup (name_str, len));
		} else {
			bs->name = r_bin_name_new (r_str_newf ("sym_%d", sym->name));
		}
		bs->paddr = sym->symbol_value;
		bs->vaddr = sym->symbol_value + obj->baddr;
		bs->size = 0;
		bs->ordinal = 0;
		bs->bind = (sym->symbol_scope == 1)? "LOCAL": "GLOBAL";
		ut32 sym_type = sym->symbol_type;
		switch (sym_type) {
		case ST_CODE:
		case ST_PRI_PROG:
		case ST_SEC_PROG:
		case ST_ENTRY:
			bs->type = "FUNC";
			break;
		case ST_DATA:
		case ST_STORAGE:
			bs->type = "OBJECT";
			break;
		default:
			bs->type = "NOTYPE";
			break;
		}
		r_list_append (list, bs);
	}
	return list;
}

static char *somtype(uint32_t magic) {
	// TODO: maybe be more precise here and return the actual type
	switch (magic) {
	case SOM_MAGIC_EXEC:
		return "EXEC";
	case SOM_MAGIC_RELOC:
		return "REL";
	case SOM_MAGIC_SHARE:
	case SOM_MAGIC_SHMEM:
	case SOM_MAGIC_DEMAND:
	case SOM_MAGIC_DL:
	case SOM_MAGIC_SHL:
		return "DYN";
	}
	return "SOM";
}

R_IPI RBinInfo *r_bin_som_get_info(void *o) {
	RSomFile *obj = (RSomFile *)o;
	RBinInfo *info = R_NEW0 (RBinInfo);
	info->file = strdup ("som");
	if (obj->hdr.system_id == 2) {
		if (obj->hdr.version_id == 1) {
			info->os = strdup ("hpux10");
			info->arch = strdup ("m68k");
		} else if (obj->hdr.version_id == 2) {
			info->os = strdup ("hpux11");
			info->arch = strdup ("hppa");
		} else {
			info->os = strdup ("hpux");
			info->arch = strdup ("hppa");
		}
	} else {
		info->os = strdup ("hpux");
		info->arch = strdup ("hppa");
	}
	info->type = strdup (somtype (obj->hdr.magic));
	info->bits = 32;
	info->big_endian = true;
	info->has_va = true;
	if (obj->interp) {
		info->intrp = strdup (obj->interp);
	}
	return info;
}

R_IPI ut64 r_bin_som_get_baddr(void *o) {
	RSomFile *obj = (RSomFile *)o;
	return obj->baddr;
}

R_IPI ut64 r_bin_som_get_size(void *o) {
	RSomFile *obj = (RSomFile *)o;
	return obj? obj->hdr.som_length: 0;
}

R_IPI RList *r_bin_som_get_imports(void *o) {
	RSomFile *obj = (RSomFile *)o;
	if (!obj || !obj->imports || !obj->dl_strings) {
		return NULL;
	}
	RList *list = r_list_newf (free);
	RListIter *iter;
	RSomImportListEntry *import_entry;
	r_list_foreach (obj->imports, iter, import_entry) {
		RBinImport *imp = R_NEW0 (RBinImport);
		if (import_entry->import_name == -1) {
			continue;
		}
		const char *name;
		if (obj->dl_strings && import_entry->import_name < obj->dl_hdr->string_table_size) {
			const char *name_str = obj->dl_strings + import_entry->import_name;
			size_t len = strnlen (name_str, obj->dl_hdr->string_table_size - import_entry->import_name);
			name = r_str_ndup (name_str, len);
		} else {
			name = r_str_newf ("import_%d", import_entry->import_name);
		}
		imp->name = r_bin_name_new (name);
		imp->bind = "GLOBAL"; // assume global
		switch (import_entry->import_type) {
		case 0: // data
			imp->type = "OBJECT";
			break;
		case 1: // code
			imp->type = "FUNC";
			break;
		default:
			imp->type = "NOTYPE";
			break;
		}
		imp->ordinal = 0;
		r_list_append (list, imp);
	}
	return list;
}

R_IPI RList *r_bin_som_get_libs(void *o) {
	RSomFile *obj = (RSomFile *)o;
	if (!obj || !obj->shlibs || !obj->dl_strings) {
		return NULL;
	}
	RList *list = r_list_newf (free);
	RListIter *iter;
	RSomShlibListEntry *shlib;
	r_list_foreach (obj->shlibs, iter, shlib) {
		char *name = NULL;
		if (obj->dl_strings && shlib->shlib_name < obj->dl_hdr->string_table_size) {
			const char *name_str = obj->dl_strings + shlib->shlib_name;
			size_t len = strnlen (name_str, obj->dl_hdr->string_table_size - shlib->shlib_name);
			name = r_str_ndup (name_str, len);
		} else {
			name = r_str_newf ("sl_%d", shlib->shlib_name);
		}
		r_list_append (list, name);
	}
	return list;
}

R_IPI RList *r_bin_som_get_relocs(void *o) {
	// TODO: not yet implemented
	return NULL;
}

R_IPI RList *r_bin_som_get_entries(void *o) {
	RSomFile *obj = (RSomFile *)o;
	RBinAddr *entry = get_entry (obj);
	if (entry) {
		RList *list = r_list_newf (free);
		r_list_append (list, entry);
		return list;
	}
	return NULL;
}

void r_bin_som_free(RSomFile *obj) {
	if (!obj) {
		return;
	}
	r_list_free (obj->spaces);
	r_list_free (obj->subspaces);
	r_list_free (obj->symbols);
	r_list_free (obj->shlibs);
	r_list_free (obj->imports);
	free (obj->space_strings);
	free (obj->symbol_strings);
	free (obj->dl_strings);
	free (obj->interp);
	free (obj->dl_hdr);
	r_buf_free (obj->buf);
	R_FREE (obj);
}
