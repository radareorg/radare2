/* radare - LGPL - Copyright 2020-2026 - mrmacete */

#include <r_util.h>
#include "coresymbolication.h"

#define R_CS_EL_OFF_SEGS 0x58
#define R_CS_EL_SIZE_SEG 0x20
#define R_CS_EL_SIZE_SECT_64 0x18
#define R_CS_EL_SIZE_SECT_32 0x10
#define R_CS_EL_SIZE_SYM 0x18
#define R_CS_EL_SIZE_LSYM 0x24
#define R_CS_EL_SIZE_LINFO 0x14
// address-line entries an element may add per byte of its size
#define R_CS_EL_LINES_PER_BYTE 4

static RCoreSymCacheElementHdr *r_coresym_cache_element_header_new(RBuffer *buf, size_t off, int bits) {
	(void)bits;
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
		if (pa >= seg->paddr && pa - seg->paddr < seg->size) {
			return seg->vaddr + (pa - seg->paddr);
		}
	}
	return pa;
}

// one entry per 2 bytes of the range, the sizes come from the file so the element bounds their total
static bool meta_add_fileline(RBinFile *bf, ut64 vaddr, ut32 size, RCoreSymCacheElementFLC *flc, ut64 *budget) {
	ut64 count = ((ut64)R_MAX (size, 1) + 1) / 2;
	const bool complete = count <= *budget;
	count = R_MIN (count, *budget);
	*budget -= count;
	ut64 i;
	for (i = 0; i < count; i++) {
		bf->addrline.al_add (&bf->addrline, vaddr + i * 2, flc->file, NULL, flc->line, 0);
	}
	return complete;
}

static char *str_dup_safe(const ut8 *b, const ut8 *origin, ut64 offset, const ut8 *end) {
	if (origin >= b && origin < end && offset < (ut64)(end - origin)) {
		const char *str = (const char *)origin + offset;
		int len = r_str_nlen (str, end - (const ut8 *)str);
		if (len > 0) {
			return r_str_ndup (str, len);
		}
	}
	return NULL;
}

static char *str_dup_safe_fixed(const ut8 *b, const ut8 *str, ut64 len, const ut8 *end) {
	if (str >= b && str <= end && len <= (size_t)(end - str)) {
		return r_str_ndup ((const char *)str, len);
	}
	return NULL;
}

RCoreSymCacheElement *r_coresym_cache_element_new(RBinFile *bf, RBuffer *buf, ut64 off, int bits, char *file_name) {
	if (bits != 32 && bits != 64) {
		return NULL;
	}
	RCoreSymCacheElementHdr *hdr = r_coresym_cache_element_header_new (buf, off, bits);
	if (!hdr) {
		return NULL;
	}
	if (hdr->version != 1 && hdr->version != 7) {
		R_LOG_ERROR ("Unsupported CoreSymbolication cache version (%d)", hdr->version);
		free (hdr);
		return NULL;
	}
	if (hdr->size == 0 || hdr->size > r_buf_size (buf) - off) {
		R_LOG_ERROR ("Corrupted CoreSymbolication header: size out of bounds (0x%x)", hdr->size);
		free (hdr);
		return NULL;
	}

	const size_t word_size = bits / 8;
	ut64 start_of_sections = (ut64)hdr->n_segments * R_CS_EL_SIZE_SEG + R_CS_EL_OFF_SEGS;
	if (hdr->p) {
		start_of_sections += 8;
	}
	const ut64 sect_size = (bits == 32) ? R_CS_EL_SIZE_SECT_32 : R_CS_EL_SIZE_SECT_64;
	const ut64 start_of_symbols = start_of_sections + (ut64)hdr->n_sections * sect_size;
	const ut64 start_of_lined_symbols = start_of_symbols + (ut64)hdr->n_symbols * R_CS_EL_SIZE_SYM;
	const ut64 start_of_line_info = start_of_lined_symbols + (ut64)hdr->n_lined_symbols * R_CS_EL_SIZE_LSYM;
	const ut64 start_of_unknown_pairs = start_of_line_info + (ut64)hdr->n_line_info * R_CS_EL_SIZE_LINFO;
	const ut64 start_of_strings = start_of_unknown_pairs + (ut64)hdr->n_symbols * 8;

	if (start_of_strings > hdr->size) {
		free (hdr);
		return NULL;
	}

	ut32 tmp;
	if (r_mul_overflow_ut32 (hdr->n_segments, sizeof (RCoreSymCacheElementSegment), &tmp) ||
	    r_mul_overflow_ut32 (hdr->n_sections, sizeof (RCoreSymCacheElementSection), &tmp) ||
	    r_mul_overflow_ut32 (hdr->n_symbols, sizeof (RCoreSymCacheElementSymbol), &tmp) ||
	    r_mul_overflow_ut32 (hdr->n_lined_symbols, sizeof (RCoreSymCacheElementLinedSymbol), &tmp) ||
	    r_mul_overflow_ut32 (hdr->n_line_info, sizeof (RCoreSymCacheElementLineInfo), &tmp)) {
		free (hdr);
		return NULL;
	}

	RCoreSymCacheElement *result = R_NEW0 (RCoreSymCacheElement);
	result->hdr = hdr;

	ut8 *b = malloc (hdr->size);
	if (!b) {
		goto beach;
	}
	if (r_buf_read_at (buf, off, b, hdr->size) != hdr->size) {
		goto beach;
	}
	ut8 *end = b + hdr->size;
	ut64 lines_budget = (ut64)hdr->size * R_CS_EL_LINES_PER_BYTE;
	bool lines_complete = true;

	if (hdr->file_name_off) {
		result->file_name = str_dup_safe (b, b, hdr->file_name_off, end);
	}
	if (hdr->version_off) {
		result->binary_version = str_dup_safe (b, b, hdr->version_off, end);
	}

	ut64 page_zero_size = 0;
	size_t page_zero_idx = 0;
	if (hdr->n_segments > 0) {
		result->segments = R_NEWS0 (RCoreSymCacheElementSegment, hdr->n_segments);
		if (!result->segments) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + R_CS_EL_OFF_SEGS;
		if (hdr->p) {
			cursor += 8;
		}
		for (i = 0; i < hdr->n_segments; i++, cursor += R_CS_EL_SIZE_SEG) {
			RCoreSymCacheElementSegment *seg = &result->segments[i];
			seg->paddr = seg->vaddr = r_read_le64 (cursor);
			seg->size = seg->vsize = r_read_le64 (cursor + 8);
			seg->name = str_dup_safe_fixed (b, cursor + 16, 16, end);
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
	bool relative_tostrings = false;
	ut8* string_origin;
	if (hdr->n_sections > 0) {
		result->sections = R_NEWS0 (RCoreSymCacheElementSection, hdr->n_sections);
		if (!result->sections) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_sections;
		for (i = 0; i < hdr->n_sections; i++, cursor += sect_size) {
			ut8 *sect_start = cursor;
			RCoreSymCacheElementSection *sect = &result->sections[i];
			sect->vaddr = sect->paddr = r_read_ble (cursor, false, bits);
			if (sect->vaddr < page_zero_size) {
				sect->vaddr += page_zero_size;
			}
			sect->size = r_read_ble (cursor + word_size, false, bits);
			ut64 sect_name_off = r_read_ble (cursor + word_size * 2, false, bits);
			if (!i && !sect_name_off) {
				relative_tostrings = true;
			}
			string_origin = relative_tostrings? b + start_of_strings : sect_start;
			sect->name = str_dup_safe (b, string_origin, sect_name_off, end);
			if (!sect->name) {
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
		for (i = 0; i < hdr->n_symbols; i++, cursor += R_CS_EL_SIZE_SYM) {
			RCoreSymCacheElementSymbol *sym = &result->symbols[i];
			sym->paddr = r_read_le32 (cursor);
			sym->size = r_read_le32 (cursor + 0x4);
			sym->unk1 = r_read_le32 (cursor + 0x8);
			size_t name_off = r_read_le32 (cursor + 0xc);
			size_t mangled_name_off = r_read_le32 (cursor + 0x10);
			sym->unk2 = (st32)r_read_le32 (cursor + 0x14);
			string_origin = relative_tostrings? b + start_of_strings : cursor;
			sym->name = str_dup_safe (b, string_origin, name_off, end);
			if (!sym->name) {
				continue;
			}
			sym->mangled_name = str_dup_safe (b, string_origin, mangled_name_off, end);
		}
	}
	if (hdr->n_lined_symbols) {
		result->lined_symbols = R_NEWS0 (RCoreSymCacheElementLinedSymbol, hdr->n_lined_symbols);
		if (!result->lined_symbols) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_lined_symbols;
		for (i = 0; i < hdr->n_lined_symbols; i++, cursor += R_CS_EL_SIZE_LSYM) {
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
			string_origin = relative_tostrings? b + start_of_strings : cursor;
			lsym->sym.name = str_dup_safe (b, string_origin, name_off, end);
			if (!lsym->sym.name) {
				continue;
			}
			lsym->sym.mangled_name = str_dup_safe (b, string_origin, mangled_name_off, end);
			if (!lsym->sym.mangled_name) {
				continue;
			}
			lsym->flc.file = str_dup_safe (b, string_origin, file_name_off, end);
			if (!lsym->flc.file) {
				continue;
			}
			lines_complete &= meta_add_fileline (bf, r_coresym_cache_element_pa2va (result, lsym->sym.paddr), lsym->sym.size, &lsym->flc, &lines_budget);
		}
	}
	if (hdr->n_line_info) {
		result->line_info = R_NEWS0 (RCoreSymCacheElementLineInfo, hdr->n_line_info);
		if (!result->line_info) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_line_info;
		for (i = 0; i < hdr->n_line_info; i++, cursor += R_CS_EL_SIZE_LINFO) {
			RCoreSymCacheElementLineInfo *info = &result->line_info[i];
			info->paddr = r_read_le32 (cursor);
			info->size = r_read_le32 (cursor + 4);
			size_t file_name_off = r_read_le32 (cursor + 8);
			info->flc.line = r_read_le32 (cursor + 0xc);
			info->flc.col = r_read_le32 (cursor + 0x10);
			string_origin = relative_tostrings? b + start_of_strings : cursor;
			info->flc.file = str_dup_safe (b, string_origin, file_name_off, end);
			if (!info->flc.file) {
				continue;
			}
			lines_complete &= meta_add_fileline (bf, r_coresym_cache_element_pa2va (result, info->paddr), info->size, &info->flc, &lines_budget);
		}
	}
	if (!lines_complete) {
		R_LOG_WARN ("CoreSymbolication line info covers more than the element can describe, truncated");
	}

	/*
	 * TODO:
	 * Figure out the meaning of the 2 arrays of hdr->n_symbols
	 * 32-bit integers located at the end of line info.
	 * Those are the last info before the strings at the end.
	 */

	free (b);
	if (file_name) {
		free (result->file_name);
		result->file_name = file_name;
	}
	return result;

beach:
	free (b);
	r_coresym_cache_element_free (result);
	return NULL;
}
