/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"
#include "../../i/private.h"

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
		RBinSymbol *symbol = r_bin_object_get_symbol_at (bf->bo, type_addr);
		if (symbol && symbol->vaddr == type_addr && symbol->name) {
			name = r_bin_name_tostring (symbol->name);
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

static void eh_add_action(RBinFile *bf, RVecRBinTrycatch *result, const EhReader *lsda,
		const ut8 *action_table, const ut8 *type_table, ut8 type_encoding, ut64 action,
		ut64 source, ut64 from, ut64 to, ut64 handler) {
	if (!action) {
		RBinTrycatch *tc = r_bin_trycatch_add (result, source, from, to, handler, 0);
		if (tc) {
			tc->kind = R_BIN_TRYCATCH_CLEANUP;
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
		RBinTrycatch *tc = r_bin_trycatch_add (result, source, from, to, handler, 0);
		if (!tc) {
			break;
		}
		tc->kind = type_filter < 0? R_BIN_TRYCATCH_FILTER: R_BIN_TRYCATCH_CATCH;
		tc->type_filter = type_filter;
		tc->type = eh_read_type (bf, lsda, type_table, type_encoding,
			type_filter, &tc->catch_all);
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

R_IPI void r_bin_dwarf_parse_lsda(RBinFile *bf, RVecRBinTrycatch *result, ut64 fcn_addr, ut64 lsda_addr) {
	R_RETURN_IF_FAIL (bf && bf->bo && result);
	RBinSection *section = r_bin_get_section_at (bf->bo, lsda_addr, true);
	if (!section || section->size > ST32_MAX) {
		return;
	}
	const ut8 *bytes = dwarf_get_section_bytes (bf, section);
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
static void eh_parse_fde(RBinFile *bf, RVecRBinTrycatch *result, const EhReader *section_reader,
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
R_IPI void r_bin_dwarf_parse_eh_frame(RBinFile *bf, RVecRBinTrycatch *result) {
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
	const ut8 *bytes = dwarf_get_section_bytes (bf, section);
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
