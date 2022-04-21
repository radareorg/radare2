/* radare - LGPL - Copyright 2020 - mrmacete */

#include <r_types.h>
#include <r_util.h>
#include <r_hash.h>
#include "coresymbolication.h"

#define R_CS_EL_OFF_SEGS 0x58
#define R_CS_EL_SIZE_SEG 0x20
#define R_CS_EL_SIZE_SECT_64 0x18
#define R_CS_EL_SIZE_SECT_32 0x10
#define R_CS_EL_SIZE_SYM 0x18
#define R_CS_EL_SIZE_LSYM 0x24
#define R_CS_EL_SIZE_LINFO 0x14

static RCoreSymCacheElementHdr *r_coresym_cache_element_header_new(RBuffer *buf, size_t off, int bits) {
	RCoreSymCacheElementHdr *hdr = R_NEW0 (RCoreSymCacheElementHdr);
	if (hdr && r_buf_fread_at (buf, off, (ut8 *)hdr, "13i16c5i", 1) == sizeof (RCoreSymCacheElementHdr)) {
		return hdr;
	}
	free (hdr);
	return NULL;
}

static void r_coresym_cache_element_segment_fini(RCoreSymCacheElementSegment *seg) {
	if (seg) {
		free (seg->name);
	}
}

static void r_coresym_cache_element_section_fini(RCoreSymCacheElementSection *sec) {
	if (sec) {
		free (sec->name);
	}
}

static void r_coresym_cache_element_flc_fini(RCoreSymCacheElementFLC *flc) {
	if (flc) {
		free (flc->file);
	}
}

static void r_coresym_cache_element_symbol_fini(RCoreSymCacheElementSymbol *sym) {
	if (sym) {
		free (sym->name);
		free (sym->mangled_name);
	}
}

static void r_coresym_cache_element_lined_symbol_fini(RCoreSymCacheElementLinedSymbol *sym) {
	if (sym) {
		r_coresym_cache_element_symbol_fini (&sym->sym);
		r_coresym_cache_element_flc_fini (&sym->flc);
	}
}

static void r_coresym_cache_element_line_info_fini(RCoreSymCacheElementLineInfo *line) {
	if (line) {
		r_coresym_cache_element_flc_fini (&line->flc);
	}
}

void r_coresym_cache_element_free(RCoreSymCacheElement *element) {
	if (!element) {
		return;
	}
	size_t i;
	if (element->segments) {
		for (i = 0; i < element->hdr->n_segments; i++) {
			r_coresym_cache_element_segment_fini (&element->segments[i]);
		}
	}
	if (element->sections) {
		for (i = 0; i < element->hdr->n_sections; i++) {
			r_coresym_cache_element_section_fini (&element->sections[i]);
		}
	}
	if (element->symbols) {
		for (i = 0; i < element->hdr->n_symbols; i++) {
			r_coresym_cache_element_symbol_fini (&element->symbols[i]);
		}
	}
	if (element->lined_symbols) {
		for (i = 0; i < element->hdr->n_lined_symbols; i++) {
			r_coresym_cache_element_lined_symbol_fini (&element->lined_symbols[i]);
		}
	}
	if (element->line_info) {
		for (i = 0; i < element->hdr->n_line_info; i++) {
			r_coresym_cache_element_line_info_fini (&element->line_info[i]);
		}
	}
	free (element->segments);
	free (element->sections);
	free (element->symbols);
	free (element->lined_symbols);
	free (element->line_info);
	free (element->hdr);
	free (element->file_name);
	free (element->binary_version);
	free (element);
}

ut64 r_coresym_cache_element_pa2va(RCoreSymCacheElement *element, ut64 pa) {
	size_t i;
	for (i = 0; i < element->hdr->n_segments; i++) {
		RCoreSymCacheElementSegment *seg = &element->segments[i];
		if (seg->size == 0) {
			continue;
		}
		if (seg->paddr < pa && pa < seg->paddr + seg->size) {
			return pa - seg->paddr + seg->vaddr;
		}
	}
	return pa;
}

static void meta_add_fileline(RBinFile *bf, ut64 vaddr, ut32 size, RCoreSymCacheElementFLC *flc) {
	Sdb *s = bf->sdb_addrinfo;
	if (!s) {
		return;
	}
	char aoffset[64];
	ut64 cursor = vaddr;
	ut64 end = cursor + R_MAX (size, 1);
	char *fileline = r_str_newf ("%s:%d", flc->file, flc->line);
	while (cursor < end) {
		char *aoffsetptr = sdb_itoa (cursor, aoffset, 16);
		if (!aoffsetptr) {
			break;
		}
		sdb_set (s, aoffsetptr, fileline, 0);
		sdb_set (s, fileline, aoffsetptr, 0);
		cursor += 2;
	}
	free (fileline);
}

static char *str_dup_safe(const ut8 *b, const ut8 *str, const ut8 *end) {
	if (str >= b && str < end) {
		int len = r_str_nlen ((const char *)str, end - str);
		if (len) {
			return r_str_ndup ((const char *)str, len);
		}
	}
	return NULL;
}

static char *str_dup_safe_fixed(const ut8 *b, const ut8 *str, ut64 len, const ut8 *end) {
	if (str >= b && str + len < end) {
		char *result = calloc (1, len + 1);
		if (result) {
			r_str_ncpy (result, (const char *)str, len);
			return result;
		}
	}
	return NULL;
}

RCoreSymCacheElement *r_coresym_cache_element_new(RBinFile *bf, RBuffer *buf, ut64 off, int bits, char * file_name) {
	RCoreSymCacheElement *result = NULL;
	ut8 *b = NULL;
	RCoreSymCacheElementHdr *hdr = r_coresym_cache_element_header_new (buf, off, bits);
	if (!hdr) {
		return NULL;
	}
	if (hdr->version != 1) {
		eprintf ("Unsupported CoreSymbolication cache version (%d)\n", hdr->version);
		goto beach;
	}
	if (hdr->size == 0 || hdr->size > r_buf_size (buf) - off) {
		eprintf ("Corrupted CoreSymbolication header: size out of bounds (0x%x)\n", hdr->size);
		goto beach;
	}
	result = R_NEW0 (RCoreSymCacheElement);
	if (!result) {
		goto beach;
	}
	result->hdr = hdr;
	b = malloc (hdr->size);
	if (!b) {
		goto beach;
	}
	if (r_buf_read_at (buf, off, b, hdr->size) != hdr->size) {
		goto beach;
	}
	ut8 *end = b + hdr->size;
	if (file_name) {
		result->file_name = file_name;
	} else if (hdr->file_name_off) {
		result->file_name = str_dup_safe (b, b + (size_t)hdr->file_name_off, end);
	}
	if (hdr->version_off) {
		result->binary_version = str_dup_safe (b, b + (size_t)hdr->version_off, end);
	}
	const size_t word_size = bits / 8;
	const ut64 start_of_sections = (ut64)hdr->n_segments * R_CS_EL_SIZE_SEG + R_CS_EL_OFF_SEGS;
	const ut64 sect_size = (bits == 32) ? R_CS_EL_SIZE_SECT_32 : R_CS_EL_SIZE_SECT_64;
	const ut64 start_of_symbols = start_of_sections + (ut64)hdr->n_sections * sect_size;
	const ut64 start_of_lined_symbols = start_of_symbols + (ut64)hdr->n_symbols * R_CS_EL_SIZE_SYM;
	const ut64 start_of_line_info = start_of_lined_symbols + (ut64)hdr->n_lined_symbols * R_CS_EL_SIZE_LSYM;
	const ut64 start_of_unknown_pairs = start_of_line_info + (ut64)hdr->n_line_info * R_CS_EL_SIZE_LINFO;
	const ut64 start_of_strings = start_of_unknown_pairs + (ut64)hdr->n_symbols * 8;

	ut64 page_zero_size = 0;
	size_t page_zero_idx = 0;
	if (UT32_MUL_OVFCHK (hdr->n_segments, sizeof (RCoreSymCacheElementSegment))) {
		goto beach;
	} else if (UT32_MUL_OVFCHK (hdr->n_sections, sizeof (RCoreSymCacheElementSection))) {
		goto beach;
	} else if (UT32_MUL_OVFCHK (hdr->n_symbols, sizeof (RCoreSymCacheElementSymbol))) {
		goto beach;
	} else if (UT32_MUL_OVFCHK (hdr->n_lined_symbols, sizeof (RCoreSymCacheElementLinedSymbol))) {
		goto beach;
	} else if (UT32_MUL_OVFCHK (hdr->n_line_info, sizeof (RCoreSymCacheElementLineInfo))) {
		goto beach;
	}
	if (hdr->n_segments > 0) {
		result->segments = R_NEWS0 (RCoreSymCacheElementSegment, hdr->n_segments);
		if (!result->segments) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + R_CS_EL_OFF_SEGS;
		for (i = 0; i < hdr->n_segments && cursor + sizeof (RCoreSymCacheElementSegment) < end; i++) {
			RCoreSymCacheElementSegment *seg = &result->segments[i];
			seg->paddr = seg->vaddr = r_read_le64 (cursor);
			cursor += 8;
			if (cursor >= end) {
				break;
			}
			seg->size = seg->vsize = r_read_le64 (cursor);
			cursor += 8;
			if (cursor >= end) {
				break;
			}
			seg->name = str_dup_safe_fixed (b, cursor, 16, end);
			cursor += 16;
			if (!seg->name) {
				continue;
			}

			if (!strcmp (seg->name, "__PAGEZERO")) {
				page_zero_size = seg->size;
				page_zero_idx = i;
				seg->paddr = seg->vaddr = 0;
				seg->size = 0;
			}
		}
		for (i = 0; i < hdr->n_segments && page_zero_size > 0; i++) {
			if (i == page_zero_idx) {
				continue;
			}
			RCoreSymCacheElementSegment *seg = &result->segments[i];
			if (seg->vaddr < page_zero_size) {
				seg->vaddr += page_zero_size;
			}
		}
	}
	bool relative_to_strings = false;
	ut8* string_origin;
	if (hdr->n_sections > 0) {
		result->sections = R_NEWS0 (RCoreSymCacheElementSection, hdr->n_sections);
		if (!result->sections) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_sections;
		for (i = 0; i < hdr->n_sections && cursor < end; i++) {
			ut8 *sect_start = cursor;
			RCoreSymCacheElementSection *sect = &result->sections[i];
			if (cursor + (word_size * 4) > end) {
				goto beach;
			}
			sect->vaddr = sect->paddr = r_read_ble (cursor, false, bits);
			if (sect->vaddr < page_zero_size) {
				sect->vaddr += page_zero_size;
			}
			cursor += word_size;
			if (cursor + word_size >= end) {
				break;
			}
			sect->size = r_read_ble (cursor, false, bits);
			cursor += word_size;
			if (cursor + word_size >= end) {
				break;
			}
			ut64 sect_name_off = r_read_ble (cursor, false, bits);
			if (!i && !sect_name_off) {
				relative_to_strings = true;
			}
			cursor += word_size;
			if (bits == 32) {
				cursor += word_size;
			}
			string_origin = relative_to_strings? b + start_of_strings : sect_start;
			if (sect_name_off < (ut64)(size_t)(end - string_origin)) {
				sect->name = str_dup_safe (b, string_origin + sect_name_off, end);
			} else {
				sect->name = strdup ("");
			}
		}
	}
	if (hdr->n_symbols) {
		result->symbols = R_NEWS0 (RCoreSymCacheElementSymbol, hdr->n_symbols);
		if (!result->symbols) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_symbols;
		for (i = 0; i < hdr->n_symbols && cursor + R_CS_EL_SIZE_SYM <= end; i++) {
			RCoreSymCacheElementSymbol *sym = &result->symbols[i];
			sym->paddr = r_read_le32 (cursor);
			sym->size = r_read_le32 (cursor + 0x4);
			sym->unk1 = r_read_le32 (cursor + 0x8);
			size_t name_off = r_read_le32 (cursor + 0xc);
			size_t mangled_name_off = r_read_le32 (cursor + 0x10);
			sym->unk2 = (st32)r_read_le32 (cursor + 0x14);
			string_origin = relative_to_strings? b + start_of_strings : cursor;
			sym->name = str_dup_safe (b, string_origin + name_off, end);
			if (!sym->name) {
				cursor += R_CS_EL_SIZE_SYM;
				continue;
			}
			string_origin = relative_to_strings? b + start_of_strings : cursor;
			sym->mangled_name = str_dup_safe (b, string_origin + mangled_name_off, end);
			if (!sym->mangled_name) {
				cursor += R_CS_EL_SIZE_SYM;
				continue;
			}
			cursor += R_CS_EL_SIZE_SYM;
		}
	}
	if (hdr->n_lined_symbols) {
		result->lined_symbols = R_NEWS0 (RCoreSymCacheElementLinedSymbol, hdr->n_lined_symbols);
		if (!result->lined_symbols) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_lined_symbols;
		for (i = 0; i < hdr->n_lined_symbols && cursor + R_CS_EL_SIZE_LSYM <= end; i++) {
			RCoreSymCacheElementLinedSymbol *lsym = &result->lined_symbols[i];
			lsym->sym.paddr = r_read_le32 (cursor);
			lsym->sym.size = r_read_le32 (cursor + 0x4);
			lsym->sym.unk1 = r_read_le32 (cursor + 0x8);
			size_t name_off = r_read_le32 (cursor + 0xc);
			size_t mangled_name_off = r_read_le32 (cursor + 0x10);
			lsym->sym.unk2 = (st32)r_read_le32 (cursor + 0x14);
			size_t file_name_off = r_read_le32 (cursor + 0x18);
			lsym->flc.line = r_read_le32 (cursor + 0x1c);
			lsym->flc.col = r_read_le32 (cursor + 0x20);
			string_origin = relative_to_strings? b + start_of_strings : cursor;
			lsym->sym.name = str_dup_safe (b, string_origin + name_off, end);
			if (!lsym->sym.name) {
				cursor += R_CS_EL_SIZE_LSYM;
				continue;
			}
			string_origin = relative_to_strings? b + start_of_strings : cursor;
			lsym->sym.mangled_name = str_dup_safe (b, string_origin + mangled_name_off, end);
			if (!lsym->sym.mangled_name) {
				cursor += R_CS_EL_SIZE_LSYM;
				continue;
			}
			string_origin = relative_to_strings? b + start_of_strings : cursor;
			if (!string_origin) {
				cursor += R_CS_EL_SIZE_LSYM;
				continue;
			}
			lsym->flc.file = str_dup_safe (b, string_origin + file_name_off, end);
			if (!lsym->flc.file) {
				cursor += R_CS_EL_SIZE_LSYM;
				continue;
			}
			cursor += R_CS_EL_SIZE_LSYM;
			meta_add_fileline (bf, r_coresym_cache_element_pa2va (result, lsym->sym.paddr), lsym->sym.size, &lsym->flc);
		}
	}
	if (hdr->n_line_info) {
		result->line_info = R_NEWS0 (RCoreSymCacheElementLineInfo, hdr->n_line_info);
		if (!result->line_info) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_line_info;
		for (i = 0; i < hdr->n_line_info && cursor + R_CS_EL_SIZE_LINFO <= end; i++) {
			RCoreSymCacheElementLineInfo *info = &result->line_info[i];
			info->paddr = r_read_le32 (cursor);
			info->size = r_read_le32 (cursor + 4);
			size_t file_name_off = r_read_le32 (cursor + 8);
			info->flc.line = r_read_le32 (cursor + 0xc);
			info->flc.col = r_read_le32 (cursor + 0x10);
			string_origin = relative_to_strings? b + start_of_strings : cursor;
			info->flc.file = str_dup_safe (b, string_origin + file_name_off, end);
			if (!info->flc.file) {
				break;
			}
			cursor += R_CS_EL_SIZE_LINFO;
			meta_add_fileline (bf, r_coresym_cache_element_pa2va (result, info->paddr), info->size, &info->flc);
		}
	}

	/*
	 * TODO:
	 * Figure out the meaning of the 2 arrays of hdr->n_symbols
	 * 32-bit integers located at the end of line info.
	 * Those are the last info before the strings at the end.
	 */

beach:
	free (b);
	return result;
}

