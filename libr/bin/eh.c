/* radare - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>

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

typedef struct {
	const ut8 *buf;
	const ut8 *p;
	const ut8 *end;
	ut64 vaddr;
	ut64 baddr;
	ut64 function;
	int bits;
	bool big_endian;
} EhReader;

typedef struct {
	ut8 fde_encoding;
	ut8 lsda_encoding;
	bool has_augmentation_data;
} EhCie;

static bool eh_uleb(EhReader *r, ut64 *value) {
	if (r->p >= r->end) {
		return false;
	}
	size_t size = read_u64_leb128 (r->p, r->end, value);
	if (!size || size > (size_t)(r->end - r->p)) {
		return false;
	}
	r->p += size;
	return true;
}

static bool eh_sleb(EhReader *r, st64 *value) {
	if (r->p >= r->end) {
		return false;
	}
	size_t size = read_i64_leb128 (r->p, r->end, value);
	if (!size || size > (size_t)(r->end - r->p)) {
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
	raw = r_read_ble (r->p, r->big_endian, size * 8);
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
			raw += r->function;
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

static RBinSection *eh_section_named(RBinFile *bf, const char *name) {
	RBinSection *section;
	R_VEC_FOREACH (&bf->bo->sections_vec, section) {
		if (section->name && r_str_endswith (section->name, name)) {
			return section;
		}
	}
	return NULL;
}

static RBinSection *eh_section_at(RBinFile *bf, ut64 vaddr) {
	RBinSection *section;
	R_VEC_FOREACH (&bf->bo->sections_vec, section) {
		if (vaddr >= section->vaddr && vaddr - section->vaddr < section->size) {
			return section;
		}
	}
	return NULL;
}

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

static char *eh_read_type(RBinFile *bf, const EhReader *lsda, const ut8 *type_table,
		ut8 encoding, st64 type_filter, bool *catch_all) {
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
	if (action > (ut64)(lsda->end - action_table)) {
		return;
	}
	const ut8 *record = action_table + action - 1;
	for (size_t depth = 0; record >= action_table && record < lsda->end && depth < 64; depth++) {
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
		st64 next_index = (next_field - action_table) + next;
		if (next_index < 0 || (ut64)next_index >= (ut64)(lsda->end - action_table)) {
			break;
		}
		record = action_table + next_index;
	}
}

R_API void r_bin_trycatch_parse_itanium_lsda(RBinFile *bf, RList *result,
		ut64 source, ut64 lsda_addr) {
	R_RETURN_IF_FAIL (bf && bf->bo && result);
	RBinSection *section = eh_section_at (bf, lsda_addr);
	if (!section || section->size > ST32_MAX) {
		return;
	}
	ut64 section_offset = lsda_addr - section->vaddr;
	ut64 bytes_size = section->size - section_offset;
	if (!bytes_size || bytes_size > ST32_MAX) {
		return;
	}
	ut8 *bytes = malloc (bytes_size);
	if (!bytes || r_buf_read_at (bf->buf, section->paddr + section_offset,
			bytes, bytes_size) != bytes_size) {
		free (bytes);
		return;
	}
	RBinInfo *info = bf->bo->info;
	EhReader r = {
		.buf = bytes,
		.p = bytes,
		.end = bytes + bytes_size,
		.vaddr = lsda_addr,
		.baddr = bf->bo->baddr,
		.function = source,
		.bits = info? info->bits: R_SYS_BITS,
		.big_endian = info? info->big_endian: false,
	};
	ut8 lp_encoding = *r.p++;
	ut64 lpstart = source;
	if (lp_encoding != DW_EH_PE_OMIT && !eh_encoded (&r, lp_encoding, &lpstart, true)) {
		free (bytes);
		return;
	}
	if (r.p >= r.end) {
		free (bytes);
		return;
	}
	ut8 type_encoding = *r.p++;
	const ut8 *type_table = NULL;
	if (type_encoding != DW_EH_PE_OMIT) {
		ut64 type_offset;
		if (!eh_uleb (&r, &type_offset) || type_offset > (ut64)(r.end - r.p)) {
			free (bytes);
			return;
		}
		type_table = r.p + type_offset;
	}
	if (r.p >= r.end) {
		free (bytes);
		return;
	}
	ut8 callsite_encoding = *r.p++;
	ut64 callsite_size;
	if (!eh_uleb (&r, &callsite_size) || callsite_size > (ut64)(r.end - r.p)) {
		free (bytes);
		return;
	}
	const ut8 *callsite_end = r.p + callsite_size;
	const ut8 *action_table = callsite_end;
	while (r.p < callsite_end) {
		ut64 start;
		ut64 length;
		ut64 landing_pad;
		ut64 action;
		if (!eh_encoded (&r, callsite_encoding, &start, false)
				|| !eh_encoded (&r, callsite_encoding, &length, false)
				|| !eh_encoded (&r, callsite_encoding, &landing_pad, false)
				|| !eh_uleb (&r, &action) || r.p > callsite_end) {
			break;
		}
		if (landing_pad && start <= UT64_MAX - lpstart && length <= UT64_MAX - start - lpstart) {
			eh_add_action (bf, result, &r, action_table, type_table, type_encoding,
				action, source, lpstart + start, lpstart + start + length,
				lpstart + landing_pad);
		}
	}
	free (bytes);
}

static bool eh_parse_cie(const EhReader *section_reader, const ut8 *record,
		const ut8 *record_end, EhCie *cie) {
	EhReader r = *section_reader;
	r.p = record;
	r.end = record_end;
	cie->fde_encoding = DW_EH_PE_ABSPTR;
	cie->lsda_encoding = DW_EH_PE_OMIT;
	cie->has_augmentation_data = false;
	if (r.p >= r.end) {
		return false;
	}
	ut8 version = *r.p++;
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
		r.bits = *r.p++ * 8;
		ut8 segment_size = *r.p++;
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
		r.p++;
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
	for (const ut8 *a = augmentation + 1; *a; a++) {
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
				ut8 encoding = *r.p++;
				ut64 ignored;
				if (!eh_encoded (&r, encoding, &ignored, true)) {
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
		case 'S':
			break;
		default:
			return false;
		}
	}
	return true;
}

R_API RList *r_bin_trycatch_from_eh_frame(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RList *result = r_list_newf ((RListFree)r_bin_trycatch_free);
	if (!result) {
		return NULL;
	}
	RBinSection *section = eh_section_named (bf, ".eh_frame");
	if (!section || section->size < 8 || section->size > ST32_MAX) {
		return result;
	}
	ut8 *bytes = malloc (section->size);
	if (!bytes || r_buf_read_at (bf->buf, section->paddr, bytes, section->size) != section->size) {
		free (bytes);
		return result;
	}
	RBinInfo *info = bf->bo->info;
	EhReader section_reader = {
		.buf = bytes,
		.end = bytes + section->size,
		.vaddr = section->vaddr,
		.baddr = bf->bo->baddr,
		.bits = info? info->bits: R_SYS_BITS,
		.big_endian = info? info->big_endian: false,
	};
	ut64 offset = 0;
	while (offset + 4 <= section->size) {
		const ut8 *entry = bytes + offset;
		ut64 length = r_read_ble32 (entry, section_reader.big_endian);
		size_t length_size = 4;
		size_t id_size = 4;
		if (!length) {
			break;
		}
		if (length == UT32_MAX) {
			if (offset + 12 > section->size) {
				break;
			}
			length = r_read_ble64 (entry + 4, section_reader.big_endian);
			length_size = 12;
			id_size = 8;
		}
		if (length < id_size || length > section->size - offset - length_size) {
			break;
		}
		const ut8 *id_field = entry + length_size;
		const ut8 *record = id_field + id_size;
		const ut8 *record_end = entry + length_size + length;
		ut64 cie_pointer = r_read_ble (id_field, section_reader.big_endian, id_size * 8);
		if (cie_pointer) {
			ut64 id_offset = id_field - bytes;
			if (cie_pointer <= id_offset) {
				const ut8 *cie_entry = id_field - cie_pointer;
				ut64 cie_offset = cie_entry - bytes;
				if (cie_offset + 4 > section->size) {
					offset += length_size + length;
					continue;
				}
				ut64 cie_length = r_read_ble32 (cie_entry, section_reader.big_endian);
				size_t cie_length_size = 4;
				size_t cie_id_size = 4;
				if (cie_length == UT32_MAX && cie_offset + 12 <= section->size) {
					cie_length = r_read_ble64 (cie_entry + 4, section_reader.big_endian);
					cie_length_size = 12;
					cie_id_size = 8;
				}
				if (cie_length < cie_id_size
						|| cie_length > section->size - cie_offset - cie_length_size
						|| r_read_ble (cie_entry + cie_length_size,
							section_reader.big_endian, cie_id_size * 8)) {
					offset += length_size + length;
					continue;
				}
				const ut8 *cie_record = cie_entry + cie_length_size + cie_id_size;
				const ut8 *cie_end = cie_entry + cie_length_size + cie_length;
				EhCie cie;
				if (cie_end <= section_reader.end
						&& eh_parse_cie (&section_reader, cie_record, cie_end, &cie)) {
					EhReader fde = section_reader;
					fde.p = record;
					fde.end = record_end;
					ut64 source;
					ut64 range;
					if (eh_encoded (&fde, cie.fde_encoding, &source, true)
							&& eh_encoded (&fde, cie.fde_encoding & 0x0f, &range, false)) {
						fde.function = source;
						if (cie.has_augmentation_data) {
							ut64 augmentation_size;
							if (eh_uleb (&fde, &augmentation_size)
									&& augmentation_size <= (ut64)(fde.end - fde.p)
									&& cie.lsda_encoding != DW_EH_PE_OMIT) {
								const ut8 *augmentation_end = fde.p + augmentation_size;
								fde.end = augmentation_end;
								ut64 lsda;
								if (eh_encoded (&fde, cie.lsda_encoding, &lsda, true) && lsda) {
									r_bin_trycatch_parse_itanium_lsda (bf, result, source, lsda);
								}
							}
						}
					}
				}
			}
		}
		offset += length_size + length;
	}
	free (bytes);
	return result;
}
