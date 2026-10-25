/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "../elf/elf.h"
#include "dwarf.h"
#include "../../i/private.h"

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
				if (sn == DWARF_SN_LINE && strstr (section->name, "debug_line_str")) {
					continue;
				}
				/* accept matching section, including compressed or zdebug variants */
				return section;
			}
		}
	}
	return NULL;
}

static bool dwarf_is_elf(RBinFile *bf) {
	RBinInfo *info = bf->bo->info;
	return info && info->rclass && r_str_startswith (info->rclass, "elf");
}

// .zdebug_* or SHF_COMPRESSED sections
static bool dwarf_section_is_compressed(RBinSection *section, bool is_elf) {
	return (section->name && strstr (section->name, "zdebug"))
		|| (is_elf && R_BIN_ELF_SCN_IS_COMPRESSED (section->flags));
}

// size of the line table as parsed, read from the compression header without inflating
R_API ut64 r_bin_dwarf_line_size(RBinFile *bf, const char **section_name) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, 0);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_LINE);
	if (!section) {
		return 0;
	}
	if (section_name) {
		*section_name = section->name;
	}
	const bool is_elf = dwarf_is_elf (bf);
	if (is_elf && dwarf_section_is_compressed (section, is_elf)) {
		const bool is64 = r_buf_read8_at (bf->buf, EI_CLASS) == ELFCLASS64;
		const bool be = r_bin_is_big_endian (bf->rbin);
		const ut64 at = r_bin_file_get_buffer_offset (bf, section->paddr);
		return is64? r_buf_read_ble64_at (bf->buf, at + 8, be): r_buf_read_ble32_at (bf->buf, at + 4, be);
	}
	return section->size;
}

// this function caches full section data in section->bytes
// compiler generated debug sections inflate 2-10x, a run of identical bytes about 1000x
#define DWARF_MAX_INFLATE_RATIO 64

// inflate an ELF compressed section, NULL when invalid or a decompression bomb
static ut8 *dwarf_inflate(RBinFile *bf, RBinSection *section, ut64 offset, int *dst_len) {
	const ut64 raw_size = section->size;
	const bool is64 = r_buf_read8_at (bf->buf, EI_CLASS) == ELFCLASS64;
	const size_t header_size = is64? 24: 12;
	if (raw_size <= header_size || raw_size > ST32_MAX) {
		return NULL;
	}
	ut8 *rawbuf = calloc (1, raw_size);
	if (!rawbuf || r_buf_read_at (bf->buf, offset, rawbuf, raw_size) != raw_size) {
		free (rawbuf);
		return NULL;
	}
	const bool be = r_bin_is_big_endian (bf->rbin);
	// Elf64_Chdr: type, reserved, size, align. Elf32_Chdr: type, size, align. Only zlib (1)
	const ut32 ch_type = r_read_ble32 (rawbuf, be);
	const ut64 ch_size = is64? r_read_ble64 (rawbuf + 8, be): r_read_ble32 (rawbuf + 4, be);
	ut8 *decomp = (ch_type == 1)? r_inflate (rawbuf + header_size, (int)(raw_size - header_size), NULL, dst_len): NULL;
	free (rawbuf);
	if (decomp && (ut64)*dst_len / DWARF_MAX_INFLATE_RATIO > raw_size) {
		R_LOG_WARN ("DWARF: ignoring %s, %" PFMT64u " bytes inflate to %d", r_str_get (section->name), raw_size, *dst_len);
		R_FREE (decomp);
	} else if (decomp && (ut64)*dst_len != ch_size) {
		R_LOG_WARN ("DWARF: decompressed %d bytes, expected %" PFMT64u, *dst_len, ch_size);
		// the header states the size, size guards rely on it
		*dst_len = (int)R_MIN ((ut64)*dst_len, ch_size);
	}
	return decomp;
}

// this function caches full section data in section->bytes, an empty slice marks a failed inflate
R_IPI const ut8 *dwarf_get_section_bytes(RBinFile *bf, RBinSection *section) {
	if (section->bytes.ptr) {
		return section->bytes.len? section->bytes.ptr: NULL;
	}
	ut64 offset = r_bin_file_get_buffer_offset (bf, section->paddr);
	if (!bf->buf || offset > r_buf_size (bf->buf) || section->size > r_buf_size (bf->buf) - offset) {
		return NULL;
	}
	const bool is_elf = dwarf_is_elf (bf);
	if (dwarf_section_is_compressed (section, is_elf)) {
		int dst_len = 0;
		ut8 *decomp = is_elf? dwarf_inflate (bf, section, offset, &dst_len): NULL;
		if (!decomp) {
			// inflating again on every lookup would be as expensive as the first time
			static const ut8 failed = 0;
			section->bytes = r_slice (&failed, 0);
			return NULL;
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
		r_buf_read_at (bf->buf, offset, buf, section->size);
	}
	section->bytes = r_slice (buf, section->size);

	return buf;
}

// names reach terminals and generated r2 scripts, control characters never belong in them
static inline bool dwarf_is_ctrl(ut8 ch) {
	return ch < ' ' || ch == 0x7f;
}

R_IPI char *dwarf_string_filter(char *s) {
	char *p;
	for (p = s; p && *p; p++) {
		if (dwarf_is_ctrl (*p)) {
			*p = '_';
		}
	}
	return s;
}

// filters the string in place and returns its terminator, NULL when unterminated
R_IPI const ut8 *dwarf_string_end(const ut8 *s, const ut8 *end) {
	ut8 *p = (ut8 *)s;
	for (; p < end && *p; p++) {
		if (dwarf_is_ctrl (*p)) {
			*p = '_';
		}
	}
	return p < end? p: NULL;
}

// string sections are filtered once when cached, 1:1 so merged string tails stay valid
R_IPI const ut8 *dwarf_get_section_strings(RBinFile *bf, RBinSection *section) {
	const bool cached = section->bytes.ptr;
	ut8 *data = (ut8 *)dwarf_get_section_bytes (bf, section);
	if (data && !cached) {
		size_t i;
		for (i = 0; i < section->bytes.len; i++) {
			if (data[i] && dwarf_is_ctrl (data[i])) {
				data[i] = '_';
			}
		}
	}
	return data;
}

R_IPI const char *dwarf_get_section_string(RBinFile *bf, RBinSection *section, size_t offset) {
	if (!bf || !section) {
		return NULL;
	}
	const ut8 *data = dwarf_get_section_strings (bf, section);
	size_t len = section->bytes.len;
	if (!data || offset >= len) {
		return NULL;
	}
	// one string can be referenced by every DIE and each reference copies it again
	if (!memchr (data + offset, 0, R_MIN (len - offset, DWARF_STRING_MAX))) {
		return NULL;
	}
	return (const char *)(data + offset);
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
