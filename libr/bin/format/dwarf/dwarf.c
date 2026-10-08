/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "../elf/elf.h"
#include "dwarf.h"

static const char *dwarf_sn_elf[DWARF_SN_MAX] = {
	[DWARF_SN_ABBREV] = "debug_abbrev",
	[DWARF_SN_INFO] = "debug_info",
	[DWARF_SN_FRAME] = "debug_frame",
	[DWARF_SN_LINE] = "debug_line",
	[DWARF_SN_LOC] = "debug_loc",
	[DWARF_SN_LOCLISTS] = "debug_loclists",
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

R_IPI RBinSection *dwarf_get_section(RBinFile *bf, int sn) {
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
				if (sn == DWARF_SN_LOC && strstr (section->name, "debug_loclists")) {
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
R_IPI const ut8 *dwarf_get_section_bytes(RBinFile *bf, RBinSection *section) {
	if (section->bytes.len && section->bytes.ptr) {
		return section->bytes.ptr;
	}

	if (!bf->buf || section->paddr > bf->size || section->size > bf->size - section->paddr) {
		return NULL;
	}
	/* Handle compressed DWARF sections (.zdebug_* or SHF_COMPRESSED) */
	RBinInfo *info = bf->bo->info;
	const bool is_elf = info && info->rclass && r_str_startswith (info->rclass, "elf");
	const bool compressed = (section->name && strstr (section->name, "zdebug"))
		|| (is_elf && R_BIN_ELF_SCN_IS_COMPRESSED (section->flags));
	if (compressed) {
		if (!is_elf) {
			return NULL;
		}
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
		bool is64 = r_buf_read8_at (bf->buf, EI_CLASS) == ELFCLASS64;
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

R_IPI const char *dwarf_get_section_string(RBinFile *bf, RBinSection *section, size_t offset) {
	if (!bf || !section) {
		return NULL;
	}
	const ut8 *data = dwarf_get_section_bytes (bf, section);
	size_t len = section->bytes.len;
	if (!data || offset >= len) {
		return NULL;
	}
	if (!memchr (data + offset, 0, len - offset)) {
		return NULL;
	}

	return (const char *) (data + offset);
}

R_IPI const ut8 *dwarf_read_index(const ut8 *buf, const ut8 *buf_end, bool be, ut8 size, ut64 *value) {
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

R_IPI const ut8 *dwarf_read_uleb_index(const ut8 *buf, const ut8 *buf_end, ut64 *value) {
	R_RETURN_VAL_IF_FAIL (buf && buf_end && value && buf < buf_end, NULL);
	const char *error = NULL;
	const ut8 *next = r_uleb128 (buf, buf_end - buf, value, &error);
	return next && next > buf && !error? next: NULL;
}

R_IPI bool dwarf_relocate_address(RBinFile *bf, ut64 address, ut64 *relocated) {
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

R_IPI bool dwarf_is_zero_padding(const ut8 *buf, const ut8 *buf_end) {
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

R_IPI bool dwarf_is_breaked(RBin *bin) {
	return bin && bin->consb.is_breaked && bin->consb.is_breaked (bin->consb.cons);
}
