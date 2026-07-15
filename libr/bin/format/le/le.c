/* radare - LGPL - Copyright 2019-2025 - GustavoLCR, mrmacete */

#include "le.h"
#include <r_bin.h>

static const char *__get_module_type(RBinLEObj *bin) {
	switch (bin->header->mflags & M_TYPE_MASK) {
	case M_TYPE_EXE: return "Program module (EXE)";
	case M_TYPE_DLL: return "Library module (DLL)";
	case M_TYPE_PDD: return "Physical Device Driver";
	case M_TYPE_VDD: return "Virtual Device Driver";
	default: return "Unknown";
	}
}

static const char *__get_os_type(RBinLEObj *bin) {
	switch (bin->header->os) {
	case 1: return "OS/2";
	case 2: return "Windows";
	case 3: return "DOS 4.x";
	case 4: return "Windows 386";
	case 5: return "IBM Microkernel Personality Neutral";
	default: return "Unknown";
	}
}

static const char *__get_cpu_type(RBinLEObj *bin) {
	switch (bin->header->cpu) {
	case 1: return "80286";
	case 2: return "80386";
	case 3: return "80486";
	case 0x20: return "N10";
	case 0x21: return "N11";
	case 0x40: return "R3000";
	case 0x41: return "R6000";
	case 0x42: return "R4000";
	default: return "";
	}
}

static const char *__get_arch(RBinLEObj *bin) {
	switch (bin->header->cpu) {
	case 1:
	case 2:
	case 3:
		return "x86";
	case 0x20:
	case 0x21:
		return "i860";
	case 0x40:
	case 0x41:
	case 0x42:
		return "mips";
	default:
		return "";
	}
}

static bool read_le_image_header(RBuffer *buf, ut64 offset, LE_image_header *h) {
	memset (h, 0, sizeof (*h));
	const ut64 prefix_size = r_offsetof (LE_image_header, level);
	if (r_buf_read_at (buf, offset, (ut8 *)h, prefix_size) != (st64)prefix_size) {
		return false;
	}
	const bool be = h->worder != 0;
	if (r_buf_fread_at (buf, offset + prefix_size, (ut8 *)&h->level, be ? "I2S39I" : "i2s39i", 1) < 0) {
		return false;
	}
	(void)r_buf_fread_at (buf, offset + r_offsetof (LE_image_header, heapsize), (ut8 *)&h->heapsize, be ? "2I" : "2i", 1);
	return true;
}

static ut64 get_object_base(RBinLEObj * bin, size_t idx) {
	R_RETURN_VAL_IF_FAIL (bin && bin->header && idx < bin->header->objcnt, 0);
	if (idx < bin->n_bases) {
		return bin->obj_bases[idx];
	}
	return bin->objtbl[idx].reloc_base_addr;
}

static const char *resource_type_name(ut16 type) {
	switch (type) {
	case LE_RT_POINTER: return "POINTER";
	case LE_RT_BITMAP: return "BITMAP";
	case LE_RT_MENU: return "MENU";
	case LE_RT_DIALOG: return "DIALOG";
	case LE_RT_STRING: return "STRING";
	case LE_RT_FONTDIR: return "FONTDIR";
	case LE_RT_FONT: return "FONT";
	case LE_RT_ACCELTABLE: return "ACCELTABLE";
	case LE_RT_RCDATA: return "RCDATA";
	case LE_RT_MESSAGE: return "MESSAGE";
	case LE_RT_DLGINCLUDE: return "DLGINCLUDE";
	case LE_RT_VKEYTBL: return "VKEYTBL";
	case LE_RT_KEYTBL: return "KEYTBL";
	case LE_RT_CHARTBL: return "CHARTBL";
	case LE_RT_DISPLAYINFO: return "DISPLAYINFO";
	case LE_RT_FKASHORT: return "FKASHORT";
	case LE_RT_FKALONG: return "FKALONG";
	case LE_RT_HELPTABLE: return "HELPTABLE";
	case LE_RT_HELPSUBTABLE: return "HELPSUBTABLE";
	case LE_RT_FDDIR: return "FDDIR";
	case LE_RT_FD: return "FD";
	default: return NULL;
	}
}

static bool read_resource_entry(RBinLEObj *bin, ut64 offset, LE_resource_entry *entry) {
	const char *fmt = bin->header->worder? "2SISI": "2sisi";
	return r_buf_fread_at (bin->buf, offset, (ut8 *)entry, fmt, 1) == sizeof (*entry);
}

typedef struct {
	LE_object_page_entry entry;
	ut64 paddr;
	ut64 data_size;
	ut64 vaddr;
	ut64 vsize;
	bool has_data;
} LEObjectPage;

static bool object_page(RBinLEObj *bin, ut32 object_index, ut32 page_index, LEObjectPage *result) {
	LE_image_header *h = bin->header;
	if (object_index >= h->objcnt || !h->pagesize) {
		return false;
	}
	const LE_object_entry *object = &bin->objtbl[object_index];
	if (!object->page_tbl_idx || page_index >= object->page_tbl_entries) {
		return false;
	}
	ut64 table_index = (ut64)object->page_tbl_idx - 1 + page_index;
	if (object_index + 1 < h->objcnt) {
		ut32 next_index = bin->objtbl[object_index + 1].page_tbl_idx;
		if (!next_index || table_index >= (ut64)next_index - 1) {
			return false;
		}
	}
	ut64 entry_size = bin->is_le? sizeof (ut32): sizeof (LE_object_page_entry);
	ut64 entry_delta;
	ut64 entry_offset;
	if (r_mul_overflow (table_index, entry_size, &entry_delta)
		|| r_add_overflow ((ut64)bin->headerOff + h->objmap, entry_delta, &entry_offset)) {
		return false;
	}
	*result = (LEObjectPage){0};
	if (bin->is_le) {
		ut8 raw[sizeof (ut32)];
		if (r_buf_read_at (bin->buf, entry_offset, raw, sizeof (raw)) != sizeof (raw)) {
			return false;
		}
		ut32 page = r_read_be32 (raw);
		result->entry.flags = page & 0xff;
		result->entry.offset = page >> 8;
		result->data_size = result->entry.offset == h->mpages && h->pageshift? h->pageshift: h->pagesize;
	} else {
		const char *fmt = h->worder? "ISS": "iss";
		if (r_buf_fread_at (bin->buf, entry_offset, (ut8 *)&result->entry, fmt, 1) != sizeof (result->entry)) {
			return false;
		}
		result->data_size = result->entry.size;
	}
	ut64 logical_offset;
	if (r_mul_overflow ((ut64)page_index, (ut64)h->pagesize, &logical_offset)
		|| logical_offset >= object->virtual_size
		|| r_add_overflow (get_object_base (bin, object_index), logical_offset, &result->vaddr)) {
		return false;
	}
	result->vsize = R_MIN ((ut64)h->pagesize, (ut64)object->virtual_size - logical_offset);
	ut64 page_offset;
	ut64 base;
	switch (result->entry.flags) {
	case P_LEGAL:
		base = h->datapage;
		if (bin->is_le) {
			if (!result->entry.offset || result->entry.offset > h->mpages
				|| r_mul_overflow ((ut64)result->entry.offset - 1, (ut64)h->pagesize, &page_offset)) {
				return false;
			}
		} else {
			if (h->pageshift > 63 || r_mul_overflow ((ut64)result->entry.offset, (ut64)1 << h->pageshift, &page_offset)) {
				return false;
			}
		}
		break;
	case P_ITERATED:
		base = h->itermap;
		if ((!bin->is_le && h->pageshift > 63) || r_mul_overflow ((ut64)result->entry.offset,
			(ut64)1 << (bin->is_le ? 0 : h->pageshift), &page_offset)) {
			return false;
		}
		break;
	default:
		return true;
	}
	ut64 file_size = r_buf_size (bin->buf);
	if (r_add_overflow (base, page_offset, &result->paddr)
		|| result->paddr > file_size || result->data_size > file_size - result->paddr) {
		return false;
	}
	result->has_data = true;
	return true;
}

static bool resource_paddr(RBinLEObj *bin, const LE_resource_entry *entry, ut64 *paddr) {
	LE_image_header *h = bin->header;
	if (!entry->object || entry->object > h->objcnt || !h->pagesize) {
		return false;
	}
	LE_object_entry *object = &bin->objtbl[entry->object - 1];
	if (entry->offset > object->virtual_size || entry->size > object->virtual_size - entry->offset) {
		return false;
	}
	ut64 logical_offset = entry->offset;
	ut64 remaining = entry->size;
	ut64 consumed = 0;
	bool first = true;
	do {
		ut64 page_index = logical_offset / h->pagesize;
		ut64 in_page = logical_offset % h->pagesize;
		LEObjectPage page;
		if (page_index > UT32_MAX || !object_page (bin, entry->object - 1, page_index, &page)
			|| page.entry.flags != P_LEGAL || !page.has_data || in_page > page.data_size) {
			return false;
		}
		ut64 chunk = R_MIN (remaining, (ut64)h->pagesize - in_page);
		if (chunk > page.data_size - in_page) {
			return false;
		}
		ut64 current = page.paddr + in_page;
		if (first) {
			*paddr = current;
			first = false;
		} else if (current != *paddr + consumed) {
			return false;
		}
		logical_offset += chunk;
		consumed += chunk;
		remaining -= chunk;
	} while (remaining);
	return true;
}

R_IPI bool r_bin_le_load_resources(RBinLEObj *bin, RVecRBinResource *resources) {
	R_RETURN_VAL_IF_FAIL (bin && bin->header && bin->objtbl && resources, false);
	LE_image_header *h = bin->header;
	if (!h->rsrccnt) {
		return true;
	}
	ut64 table_offset;
	ut64 table_size;
	ut64 file_size = r_buf_size (bin->buf);
	if (!h->rsrctab || r_add_overflow ((ut64)bin->headerOff, (ut64)h->rsrctab, &table_offset)
		|| r_mul_overflow ((ut64)h->rsrccnt, (ut64)sizeof (LE_resource_entry), &table_size)
		|| table_offset > file_size || table_size > file_size - table_offset) {
		return false;
	}
	ut32 i;
	for (i = 0; i < h->rsrccnt; i++) {
		LE_resource_entry entry = {0};
		ut64 offset = table_offset + (ut64)i * sizeof (entry);
		ut64 paddr;
		if (!read_resource_entry (bin, offset, &entry) || !resource_paddr (bin, &entry, &paddr)) {
			return false;
		}
		RBinResource *resource = RVecRBinResource_emplace_back (resources);
		if (!resource) {
			return false;
		}
		const char *type = resource_type_name (entry.type_id);
		resource->name = r_str_newf ("%u", entry.name_id);
		resource->type = type? strdup (type): NULL;
		if (!resource->name || (type && !resource->type)) {
			return false;
		}
		resource->vaddr = get_object_base (bin, entry.object - 1) + entry.offset;
		resource->paddr = paddr;
		resource->size = entry.size;
		resource->id = entry.name_id;
		resource->index = i;
		resource->type_id = entry.type_id;
	}
	return true;
}

static char *__read_nonnull_str_at(RBuffer *buf, ut64 *offset) {
	ut8 size = r_buf_read8_at (buf, *offset);
	size &= 0x7F; // Max is 127
	if (!size) {
		return NULL;
	}
	(*offset)++;
	char *str = calloc ((ut64)size + 1, sizeof (char));
	r_buf_read_at (buf, *offset, (ut8 *)str, size);
	*offset += size;
	return str;
}

static RBinSymbol *__get_symbol(RBinLEObj *bin, ut64 *offset) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (!sym) {
		return NULL;
	}
	char *name = __read_nonnull_str_at (bin->buf, offset);
	if (!name) {
		r_bin_symbol_free (sym);
		return NULL;
	}
	sym->name = r_bin_name_new (name);
	free (name);
	ut16 entry_idx = r_buf_read_ble16_at (bin->buf, *offset, bin->header->worder);
	*offset += 2;
	sym->ordinal = entry_idx;
	return sym;
}

static st64 read_entry_bundle_entry(RBinLEObj *bin, ut64 offset, ut8 type, LE_entry_bundle_entry *e) {
	const bool be = bin->header->worder != 0;
	const char *fmt = NULL;
	switch (type & ~ENTRY_PARAMETER_TYPING_PRESENT) {
	case ENTRY16:
		fmt = be ? "cS" : "cs";
		break;
	case CALLGATE:
		fmt = be ? "c2S" : "c2s";
		break;
	case ENTRY32:
		fmt = be ? "cI" : "ci";
		break;
	case FORWARDER:
		fmt = be ? "cSI" : "csi";
		break;
	default:
		return -1;
	}
	return r_buf_fread_at (bin->buf, offset, (ut8 *)e, fmt, 1);
}

static RList *__get_entries(RBinLEObj *bin) {
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->enttab + bin->headerOff;
	RList *l = r_list_newf (free);
	if (!l) {
		return NULL;
	}
	while (true) {
		LE_entry_bundle_header header = {0};
		LE_entry_bundle_entry e = {{0}};
		if (r_buf_fread_at (bin->buf, offset, (ut8 *)&header, h->worder ? "ccS" : "ccs", 1) < 1) {
			break;
		}
		if (!header.count) {
			break;
		}
		ut8 type = header.type & ~ENTRY_PARAMETER_TYPING_PRESENT;
		if (type == UNUSED_ENTRY) {
			offset += sizeof (header.type) + sizeof (header.count);
			while (header.count) {
				r_list_append (l, strdup ("")); // (ut64 *)-1);
				header.count--;
			}
			continue;
		}
		offset += sizeof (LE_entry_bundle_header);
		bool typeinfo = header.type & ENTRY_PARAMETER_TYPING_PRESENT;
		bool has_base = header.objnum > 0 && header.objnum <= h->objcnt;
		ut64 base = has_base ? get_object_base (bin, header.objnum - 1) : 0;
		int i;
		for (i = 0; i < header.count; i++) {
			ut64 entry = UT64_MAX;
			st64 read = read_entry_bundle_entry (bin, offset, type, &e);
			if (read < 1) {
				break;
			}
			offset += (ut64)read;
			switch (type) {
			case ENTRY16:
				if (has_base) {
					entry = base + e.entry_16.offset;
				}
				break;
			case CALLGATE:
				if (has_base) {
					entry = base + e.callgate.offset;
				}
				break;
			case ENTRY32:
				if (has_base) {
					entry = base + e.entry_32.offset;
				}
				break;
			case FORWARDER:
				break;
			}
			if (typeinfo && type != FORWARDER) {
				offset += (ut64)(e.entry_32.flags & ENTRY_PARAM_COUNT_MASK) * 2;
			}
			if (entry != UT64_MAX) {
				r_list_append (l, r_str_newf ("0x%"PFMT64x, entry));
			}
		}
	}
	return l;
}

static void __get_symbols_at(RBinLEObj *bin, RVecRBinSymbol *vec, RList *entl, ut64 offset, ut64 end) {
	while (offset < end) {
		RBinSymbol *sym = __get_symbol (bin, &offset);
		if (!sym) {
			break;
		}
		if (sym->ordinal) {
			const char *n = r_list_get_n (entl, sym->ordinal - 1);
			if (n) {
				sym->vaddr = r_num_get (NULL, n);
				sym->bind = R_BIN_BIND_GLOBAL_STR;
				sym->type = R_BIN_TYPE_FUNC_STR;
				RVecRBinSymbol_push_back (vec, sym);
				free (sym); /* vec now owns inner fields */
				continue;
			}
		}
		r_bin_symbol_free (sym);
	}
}

R_IPI void r_bin_le_load_symbols(RBinLEObj *bin, RVecRBinSymbol *vec) {
	RList *entries = __get_entries (bin);
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->restab + bin->headerOff;
	ut32 end = h->enttab + bin->headerOff;
	__get_symbols_at (bin, vec, entries, offset, end);
	offset = h->nrestab;
	end = h->nrestab + h->cbnrestab;
	__get_symbols_at (bin, vec, entries, offset, end);
	r_list_free (entries);
}

R_IPI void r_bin_le_load_imports(RBinLEObj *bin, RVecRBinImport *vec) {
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->impproc + bin->headerOff + 1; // First entry is a null string
	ut64 end = (ut64)h->fixupsize + h->fpagetab + bin->headerOff;
	while (offset < end) {
		char *name = __read_nonnull_str_at (bin->buf, &offset);
		if (!name) {
			break;
		}
		RBinImport *imp = RVecRBinImport_emplace_back (vec);
		imp->name = r_bin_name_new (name);
		free (name);
		imp->type = R_BIN_TYPE_FUNC_STR;
	}
}

R_IPI RList *r_bin_le_get_entrypoints(RBinLEObj *bin) {
	RList *l = r_list_newf ((RListFree)free);
	if (!l) {
		return NULL;
	}
	RBinAddr *entry = R_NEW0 (RBinAddr);
	if (entry) {
		if ((bin->header->startobj - 1) < bin->header->objcnt) {
			entry->vaddr = get_object_base (bin, bin->header->startobj - 1) + bin->header->eip;
		}
	}
	r_list_append (l, entry);

	return l;
}

R_IPI RList *r_bin_le_get_libs(RBinLEObj *bin) {
	RList *l = r_list_newf ((RListFree)free);
	if (!l) {
		return NULL;
	}
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->impmod + bin->headerOff;
	ut64 end = offset + h->impproc - h->impmod;
	while (offset < end) {
		char *name = __read_nonnull_str_at (bin->buf, &offset);
		if (!name) {
			break;
		}
		r_list_append (l, name);
	}
	return l;
}

static bool create_iter_sections(RVecRBinSection *sections, RBinLEObj *bin, RBinSection *sec, const LEObjectPage *page, ut32 cur_page) {
	LE_image_header *h = bin->header;
	ut64 end;
	if (!page->has_data || page->entry.flags != P_ITERATED || !page->data_size
		|| r_add_overflow (page->paddr, page->data_size, &end)) {
		return false;
	}
	ut64 offset = page->paddr;
	ut64 vaddr = page->vaddr;
	ut64 remaining = page->vsize;
	int iter_cnt = 0;
	while (offset < end) {
		if (end - offset < sizeof (ut16) * 2) {
			return false;
		}
		ut16 iter_n = r_buf_read_ble16_at (bin->buf, offset, h->worder);
		ut16 data_size = r_buf_read_ble16_at (bin->buf, offset + sizeof (ut16), h->worder);
		offset += sizeof (ut16) * 2;
		if (!iter_n || !data_size || data_size > end - offset) {
			return false;
		}
		ut16 i;
		for (i = 0; i < iter_n && remaining; i++) {
			ut64 size = R_MIN ((ut64)data_size, remaining);
			RBinSection *s = RVecRBinSection_emplace_back (sections);
			s->name = r_str_newf ("%s.page.%u.iter.%d", sec->name, cur_page, iter_cnt);
			s->bits = sec->bits;
			s->perm = sec->perm;
			s->size = size;
			s->vsize = size;
			s->paddr = offset;
			s->vaddr = vaddr;
			s->add = true;
			s->is_data = sec->is_data;
			vaddr += size;
			remaining -= size;
			iter_cnt++;
		}
		offset += data_size;
	}
	if (remaining) {
		RBinSection *s = RVecRBinSection_emplace_back (sections);
		s->name = r_str_newf ("%s.page.%u.iter.zerofill", sec->name, cur_page);
		s->bits = sec->bits;
		s->perm = sec->perm;
		s->vsize = remaining;
		s->vaddr = vaddr;
		s->add = true;
		s->is_data = sec->is_data;
	}
	return true;
}

// TODO: Compressed page
R_IPI bool r_bin_le_load_sections(RBinLEObj *bin, RVecRBinSection *sections) {
	R_RETURN_VAL_IF_FAIL (bin && sections, false);
	RVecRBinSection_clear (sections);
	LE_image_header *h = bin->header;
	int i;
	for (i = 0; i < h->objcnt; i++) {
		RBinSection *sec = R_NEW0 (RBinSection);
		const LE_object_entry *entry = &bin->objtbl[i];
		sec->name = r_str_newf ("obj.%d", i + 1);
		sec->vsize = entry->virtual_size;
		sec->vaddr = get_object_base (bin, i);
		sec->add = true;
		if (entry->flags & O_READABLE) {
			sec->perm |= R_PERM_R;
		}
		if (entry->flags & O_WRITABLE) {
			sec->perm |= R_PERM_W;
		}
		if (entry->flags & O_EXECUTABLE) {
			sec->perm |= R_PERM_X;
		}
		if (entry->flags & O_BIG_BIT) {
			sec->bits = R_SYS_BITS_PACK (32);
		} else {
			sec->bits = R_SYS_BITS_PACK (16);
		}
		sec->is_data = (entry->flags & O_RESOURCE) || !(sec->perm & R_PERM_X);
		if (!entry->page_tbl_entries) {
			RBinSection *dst = RVecRBinSection_emplace_back (sections);
			*dst = *sec;
			free (sec);
			continue;
		}
		ut32 j;
		ut64 page_size_sum = 0;
		ut64 page_count = h->pagesize ? R_MIN (entry->page_tbl_entries, (sec->vsize + h->pagesize - 1) / h->pagesize) : 0;
		for (j = 0; entry->page_tbl_idx && j < page_count && page_size_sum < sec->vsize; j++) {
			LEObjectPage page;
			if (!object_page (bin, i, j, &page)) {
				R_LOG_WARN ("Cannot read out of bounds page table entry");
				break;
			}
			RBinSection *s = R_NEW0 (RBinSection);
			s->name = r_str_newf ("%s.page.%u", sec->name, j);
			s->is_data = sec->is_data;
			if (page.entry.flags == P_ITERATED) {
				if (!create_iter_sections (sections, bin, sec, &page, j)) {
					r_bin_section_free (s);
					r_bin_section_free (sec);
					return false;
				}
				r_bin_section_free (s);
				page_size_sum += page.vsize;
				continue;
			}
			if (page.entry.flags == P_COMPRESSED) {
				R_LOG_WARN ("Compressed page not handled: %s", s->name);
			} else if (page.has_data) {
				s->paddr = page.paddr;
			}
			s->vsize = page.vsize;
			s->vaddr = page.vaddr;
			s->perm = sec->perm;
			s->size = R_MIN (page.data_size, s->vsize);
			s->add = true;
			s->bits = sec->bits;
			RBinSection *dst = RVecRBinSection_emplace_back (sections);
			*dst = *s;
			free (s);
			page_size_sum += page.vsize;
		}
		if (page_size_sum < sec->vsize) {
			RBinSection *s = RVecRBinSection_emplace_back (sections);
			s->vsize = sec->vsize - page_size_sum;
			s->vaddr = sec->vaddr + page_size_sum;
			s->perm = sec->perm;
			s->add = true;
			s->bits = sec->bits;
			s->name = r_str_newf ("%s.page.zerofill", sec->name);
			s->is_data = sec->is_data;
		}
		r_bin_section_free (sec);
	}
	return true;
}

static char *__get_modname_by_ord(RBinLEObj *bin, ut32 ordinal) {
	char *modname = NULL;
	ut64 off = (ut64)bin->header->impmod + bin->headerOff;
	while (ordinal > 0) {
		free (modname);
		modname = __read_nonnull_str_at (bin->buf, &off);
		ordinal--;
	}
	return modname;
}

static bool object_page_at(RBinLEObj *bin, ut64 table_index, ut32 *object_index, LEObjectPage *page) {
	while (*object_index < bin->header->objcnt) {
		const LE_object_entry *object = &bin->objtbl[*object_index];
		if (!object->page_tbl_idx) {
			(*object_index)++;
			continue;
		}
		ut64 first = (ut64)object->page_tbl_idx - 1;
		if (table_index < first) {
			return false;
		}
		ut64 relative = table_index - first;
		if (relative < object->page_tbl_entries) {
			return object_page (bin, *object_index, relative, page);
		}
		(*object_index)++;
	}
	return false;
}

static st32 reloc_source_offset(ut16 raw) {
	return raw & 0x8000 ? (st32)raw - 0x10000 : raw;
}

static void reloc_emit(RList *relocs, const RBinReloc *reloc, const LEObjectPage *page, st32 source, st64 addend) {
	ut64 vaddr;
	if (!page || source < 0 || (ut32)source >= page->vsize
		|| r_add_overflow (page->vaddr, (ut32)source, &vaddr)) {
		return;
	}
	RBinReloc *clone = R_NEW0 (RBinReloc);
	*clone = *reloc;
	clone->import = reloc->import ? r_bin_import_clone (reloc->import) : NULL;
	clone->vaddr = vaddr;
	clone->paddr = page->has_data && (ut32)source < page->data_size ? page->paddr + source : 0;
	clone->addend = addend;
	if (!r_list_append (relocs, clone)) {
		r_bin_reloc_free (clone);
	}
}

static bool reloc_page_bounds(RBinLEObj *bin, ut64 page, ut64 fixup_end, ut64 *start, ut64 *end) {
	LE_image_header *h = bin->header;
	ut64 page_offset = (ut64)h->fpagetab + bin->headerOff + page * sizeof (ut32);
	if (page_offset > fixup_end || fixup_end - page_offset < sizeof (ut32) * 2) {
		return false;
	}
	ut32 first = r_buf_read_ble32_at (bin->buf, page_offset, h->worder);
	ut32 last = r_buf_read_ble32_at (bin->buf, page_offset + sizeof (ut32), h->worder);
	if (first == UT32_MAX || last == UT32_MAX) {
		return false;
	}
	ut64 records = (ut64)h->frectab + bin->headerOff;
	*start = records + first;
	*end = records + last;
	return *start <= *end && *end <= fixup_end;
}

static bool reloc_record_end(RBuffer *buf, ut64 offset, ut64 limit, ut64 *end) {
	if (offset > limit || limit - offset < sizeof (LE_fixup_record_header)) {
		return false;
	}
	ut8 source = r_buf_read8_at (buf, offset);
	ut8 target = r_buf_read8_at (buf, offset + 1);
	bool source_list = source & F_SOURCE_LIST;
	ut64 size = sizeof (LE_fixup_record_header) + (source_list ? sizeof (ut8) : sizeof (ut16));
	if (size > limit - offset) {
		return false;
	}
	ut8 count = source_list ? r_buf_read8_at (buf, offset + sizeof (LE_fixup_record_header)) : 0;
	size += target & F_TARGET_ORD16 ? sizeof (ut16) : sizeof (ut8);
	switch (target & F_TARGET_TYPE_MASK) {
	case INTERNAL:
		if ((source & F_SOURCE_TYPE_MASK) != SELECTOR16) {
			size += target & F_TARGET_OFF32 ? sizeof (ut32) : sizeof (ut16);
		}
		break;
	case IMPORTORD:
		if (target & F_TARGET_ORD8) {
			size += sizeof (ut8);
		} else {
			size += target & F_TARGET_OFF32 ? sizeof (ut32) : sizeof (ut16);
		}
		break;
	case IMPORTNAME:
		size += target & F_TARGET_OFF32 ? sizeof (ut32) : sizeof (ut16);
		break;
	case INTERNALENTRY:
		break;
	}
	if (target & F_TARGET_ADDITIVE) {
		size += target & F_TARGET_ADD32 ? sizeof (ut32) : sizeof (ut16);
	}
	size += (ut64)count * sizeof (ut16);
	if (size > limit - offset) {
		return false;
	}
	*end = offset + size;
	return true;
}

R_IPI RList *r_bin_le_get_relocs(RBinLEObj *bin) {
	RList *l = r_list_newf ((RListFree)r_bin_reloc_free);
	if (!l) {
		return NULL;
	}
	RList *entries = __get_entries (bin);
	LE_image_header *h = bin->header;
	const ut64 fixup_start = (ut64)h->fpagetab + bin->headerOff;
	const ut64 fixup_end = R_MIN (fixup_start + h->fixupsize, r_buf_size (bin->buf));
	ut32 object_index = 0;
	ut64 cur_page;
	for (cur_page = 0; cur_page < h->mpages; cur_page++) {
		ut64 offset;
		ut64 end;
		if (!reloc_page_bounds (bin, cur_page, fixup_end, &offset, &end)) {
			break;
		}
		LEObjectPage page;
		const LEObjectPage *page_ref = object_page_at (bin, cur_page, &object_index, &page) ? &page : NULL;
		while (offset < end) {
			ut64 record_end;
			if (!reloc_record_end (bin->buf, offset, end, &record_end)) {
				R_LOG_WARN ("Invalid LE relocation record");
				break;
			}
			RBinReloc *rel = R_NEW0 (RBinReloc);
			ut8 header_source = r_buf_read8_at (bin->buf, offset);
			ut8 header_target = r_buf_read8_at (bin->buf, offset + 1);
			offset += sizeof (LE_fixup_record_header);
			switch (header_source & F_SOURCE_TYPE_MASK) {
			case BYTEFIXUP:
				rel->type = R_BIN_RELOC_8;
				break;
			case SELECTOR16:
			case OFFSET16:
				rel->type = R_BIN_RELOC_16;
				break;
			case OFFSET32:
			case POINTER32:
			case SELFOFFSET32:
				rel->type = R_BIN_RELOC_32;
				break;
			case POINTER48:
				rel->type = 48;
				break;
			}
			ut64 repeat = 0;
			st32 source = 0;
			if (header_source & F_SOURCE_LIST) {
				repeat = r_buf_read8_at (bin->buf, offset);
				offset += sizeof (ut8);
			} else {
				source = reloc_source_offset (r_buf_read_ble16_at (bin->buf, offset, h->worder));
				offset += sizeof (ut16);
			}
			ut32 ordinal;
			if (header_target & F_TARGET_ORD16) {
				ordinal = r_buf_read_ble16_at (bin->buf, offset, h->worder);
				offset += sizeof (ut16);
			} else {
				ordinal = r_buf_read8_at (bin->buf, offset);
				offset += sizeof (ut8);
			}
			rel->ntype = header_source & F_SOURCE_TYPE_MASK; // XXX correct?
			switch (header_target & F_TARGET_TYPE_MASK) {
			case INTERNAL:
				if ((ordinal - 1) < bin->header->objcnt) {
					rel->addend = get_object_base (bin, ordinal - 1);
					if ((header_source & F_SOURCE_TYPE_MASK) != SELECTOR16) {
						if (header_target & F_TARGET_OFF32) {
							rel->addend += r_buf_read_ble32_at (bin->buf, offset, h->worder);
							offset += sizeof (ut32);
						} else {
							rel->addend += r_buf_read_ble16_at (bin->buf, offset, h->worder);
							offset += sizeof (ut16);
						}
					}
				}
				break;
			case IMPORTORD: {
				RBinImport *imp = R_NEW0 (RBinImport);
				char *mod_name = __get_modname_by_ord (bin, ordinal);
				if (!mod_name) {
					r_bin_import_free (imp);
					break;
				}

				if (header_target & F_TARGET_ORD8) {
					ordinal = r_buf_read8_at (bin->buf, offset);
					offset += sizeof (ut8);
				} else if (header_target & F_TARGET_OFF32) {
					ordinal = r_buf_read_ble32_at (bin->buf, offset, h->worder);
					offset += sizeof (ut32);
				} else {
					ordinal = r_buf_read_ble16_at (bin->buf, offset, h->worder);
					offset += sizeof (ut16);
				}
				imp->name = r_bin_name_new_from (r_str_newf ("%s.%u", mod_name, ordinal));
				imp->ordinal = ordinal;
				rel->import = imp;
				free (mod_name);
				break;
			}
			case IMPORTNAME: {
				RBinImport *imp = R_NEW0 (RBinImport);
				ut32 nameoff;
				if (header_target & F_TARGET_OFF32) {
					nameoff = r_buf_read_ble32_at (bin->buf, offset, h->worder);
					offset += sizeof (ut32);
				} else {
					nameoff = r_buf_read_ble16_at (bin->buf, offset, h->worder);
					offset += sizeof (ut16);
				}
				ut64 off = (ut64)h->impproc + nameoff + bin->headerOff;
				char *proc_name = __read_nonnull_str_at (bin->buf, &off);
				char *mod_name = __get_modname_by_ord (bin, ordinal);
				imp->name = r_bin_name_new_from (r_str_newf ("%s.%s", r_str_get (mod_name), r_str_get (proc_name)));
				rel->import = imp;
				free (mod_name);
				free (proc_name);
				break;
			}
			case INTERNALENTRY: {
				const char *n = r_list_get_n (entries, ordinal - 1);
				if (n) {
					rel->addend = r_num_get (NULL, n);
				}
				break;
			}
			}
			if (header_target & F_TARGET_ADDITIVE) {
				ut32 additive = 0;
				if (header_target & F_TARGET_ADD32) {
					additive = r_buf_read_ble32_at (bin->buf, offset, h->worder);
					offset += sizeof (ut32);
				} else {
					additive = r_buf_read_ble16_at (bin->buf, offset, h->worder);
					offset += sizeof (ut16);
				}
				rel->addend += additive;
			}
			ut64 source_list_size = repeat * sizeof (ut16);
			if (offset != record_end - source_list_size) {
				offset = record_end;
				r_bin_reloc_free (rel);
				continue;
			}
			if (repeat) {
				while (repeat--) {
					st32 list_source = reloc_source_offset (r_buf_read_ble16_at (bin->buf, offset, h->worder));
					offset += sizeof (ut16);
					reloc_emit (l, rel, page_ref, list_source, rel->addend);
				}
			} else if ((header_target & F_TARGET_CHAIN) && page_ref && page_ref->has_data) {
				ut32 chain_limit = h->pagesize / sizeof (ut32);
				st32 chain_source = source;
				st64 base_target_address = rel->addend;
				bool first = true;
				while (chain_limit-- && chain_source >= 0
					&& page_ref->data_size >= sizeof (ut32)
					&& (ut32)chain_source <= page_ref->data_size - sizeof (ut32)) {
					ut32 fixupinfo = r_buf_read_ble32_at (bin->buf, page_ref->paddr + chain_source, h->worder);
					if (first) {
						base_target_address -= fixupinfo & 0xFFFFF;
						first = false;
					}
					reloc_emit (l, rel, page_ref, chain_source, base_target_address + (fixupinfo & 0xFFFFF));
					chain_source = (fixupinfo >> 20) & 0xFFF;
					if (chain_source == 0xFFF) {
						break;
					}
				}
			} else {
				reloc_emit (l, rel, page_ref, source, rel->addend);
			}
			r_bin_reloc_free (rel);
		}
	}
	r_list_free (entries);
	return l;
}

static bool __init_header(RBinLEObj *bin, RBuffer *buf) {
	ut8 magic[2];
	r_buf_read_at (buf, 0, magic, sizeof (magic));
	if (!memcmp (&magic, "MZ", 2)) {
		bin->headerOff = r_buf_read_le32_at (buf, 0x3c);
	} else {
		bin->headerOff = 0;
	}
	bin->header = R_NEW0 (LE_image_header);
	if (bin->header) {
		if (!read_le_image_header (buf, bin->headerOff, bin->header)) {
			R_LOG_ERROR ("Cannot read LE header");
			return false;
		}
	} else {
		R_LOG_ERROR ("Failed to allocate memory");
		return false;
	}
	return true;
}

R_IPI void r_bin_le_free(RBinLEObj *bin) {
	if (bin) {
		free (bin->header);
		free (bin->objtbl);
		free (bin->filename);
		free (bin->obj_bases);
		free (bin);
	}
}

static void parse_obj_bases_from_env(RBinLEObj *bin) {
	ut64 * bases = NULL;
	RList * bases_str = NULL;
	char * bases_raw = r_sys_getenv ("RABIN2_LE_BASES");
	if (!bases_raw) {
		goto beach;
	}
	bases_str = r_str_split_list (bases_raw, ":", 0);
	if (!bases_str) {
		goto beach;
	}
	size_t n_bases = r_list_length (bases_str);
	if (!n_bases) {
		goto beach;
	}
	bases = R_NEWS0 (ut64, n_bases);
	if (!bases) {
		goto beach;
	}
	RListIter * it;
	char * base;
	size_t i = 0;
	r_list_foreach (bases_str, it, base) {
		if (i < n_bases) {
			bases[i++] = r_num_get (NULL, base);
		}
	}
	bin->obj_bases = bases;
	bin->n_bases = n_bases;
beach:
	r_list_free (bases_str);
	free (bases_raw);
}

R_IPI RBinLEObj *r_bin_le_new_buf(RBuffer *buf) {
	RBinLEObj *bin = R_NEW0 (RBinLEObj);
	if (!__init_header (bin, buf)) {
		r_bin_le_free (bin);
		return NULL;
	}
	LE_image_header *h = bin->header;
	if (!memcmp (h->magic, "LE", 2)) {
		bin->is_le = true;
	}
	bin->type = __get_module_type (bin);
	bin->cpu = __get_cpu_type (bin);
	bin->os = __get_os_type (bin);
	bin->arch = __get_arch (bin);
	{
		/* dim objcnt */
		ut64 maxcount = 0xfffff / sizeof (LE_object_entry);
		if (h->objcnt > maxcount) {
			h->objcnt = maxcount;
		}
	}
	bin->objtbl = calloc (h->objcnt, sizeof (LE_object_entry));
	if (!bin->objtbl) {
		r_bin_le_free (bin);
		return NULL;
	}
	ut64 offset = (ut64)bin->headerOff + h->restab;
	bin->filename = __read_nonnull_str_at (buf, &offset);
#if 0
	r_buf_read_at (buf, (ut64)h->objtab + bin->headerOff, (ut8 *)bin->objtbl, h->objcnt * sizeof (LE_object_entry));
#else
	char *fmt = r_str_newf ("%di", 6 * h->objcnt);
	r_buf_fread_at (buf, h->objtab + bin->headerOff, (ut8*)bin->objtbl, fmt, 1);
	free (fmt);
#endif
	bin->buf = buf;
	parse_obj_bases_from_env (bin);
	return bin;
}
