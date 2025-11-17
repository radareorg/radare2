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

static ut64 get_object_base(RBinLEObj * bin, size_t idx) {
	R_RETURN_VAL_IF_FAIL (bin && bin->header && idx < bin->header->objcnt, 0);
	if (idx < bin->n_bases) {
		return bin->obj_bases[idx];
	}
	return bin->objtbl[idx].reloc_base_addr;
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
	ut16 entry_idx = r_buf_read_le16_at (bin->buf, *offset);
	*offset += 2;
	sym->ordinal = entry_idx;
	return sym;
}

static RList *__get_entries(RBinLEObj *bin) {
	ut64 offset = (ut64)bin->header->enttab + bin->headerOff;
	RList *l = r_list_newf (free);
	if (!l) {
		return NULL;
	}
	while (true) {
		LE_entry_bundle_header header = {0};
		LE_entry_bundle_entry e = {{0}};
#if 0
		r_buf_read_at (bin->buf, offset, (ut8 *)&header, sizeof (header));
#else
		if (r_buf_fread_at (bin->buf, offset, (ut8*)&header, "ccs", 1) < 1) {
			break;
		}
#endif
		if (!header.count) {
			break;
		}
		if ((header.type & ~ENTRY_PARAMETER_TYPING_PRESENT) == UNUSED_ENTRY) {
			offset += sizeof (header.type) + sizeof (header.count);
			while (header.count) {
				r_list_append (l, strdup ("")); // (ut64 *)-1);
				header.count--;
			}
			continue;
		}
		offset += sizeof (LE_entry_bundle_header);
		bool typeinfo = header.type & ENTRY_PARAMETER_TYPING_PRESENT;
		int i;
		for (i = 0; i < header.count; i++) {
			ut64 entry = -1;
			r_buf_read_at (bin->buf, offset, (ut8 *)&e, sizeof (e));
			switch (header.type & ~ENTRY_PARAMETER_TYPING_PRESENT) {
			case ENTRY16:
				if ((header.objnum - 1) < bin->header->objcnt) {
					entry = (ut64)e.entry_16.offset + get_object_base (bin, header.objnum - 1);
				}
				offset += sizeof (e.entry_16);
				if (typeinfo) {
					offset += (ut64)(e.entry_16.flags & ENTRY_PARAM_COUNT_MASK) * 2;
				}
				break;
			case CALLGATE:
				if ((header.objnum - 1) < bin->header->objcnt) {
					entry = (ut64)e.callgate.offset + get_object_base (bin, header.objnum - 1);
				}
				offset += sizeof (e.callgate);
				if (typeinfo) {
					offset += (ut64)(e.callgate.flags & ENTRY_PARAM_COUNT_MASK) * 2;
				}
				break;
			case ENTRY32:
				if ((header.objnum - 1) < bin->header->objcnt) {
					entry = (ut64)e.entry_32.offset + get_object_base (bin, header.objnum - 1);
				}
				offset += sizeof (e.entry_32);
				if (typeinfo) {
					offset += (ut64)(e.entry_32.flags & ENTRY_PARAM_COUNT_MASK) * 2;
				}
				break;
			case FORWARDER:
				offset += sizeof (e.forwarder);
				break;
			}
			if (entry != UT64_MAX) {
				r_list_append (l, r_str_newf ("0x%"PFMT64x, entry));
			}
		}
	}
	return l;
}

static void __get_symbols_at(RBinLEObj *bin, RList *syml, RList *entl, ut64 offset, ut64 end) {
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
				r_list_append (syml, sym);
			}
		} else {
			r_bin_symbol_free (sym);
		}
	}
}

R_IPI RList *r_bin_le_get_symbols(RBinLEObj *bin) {
	RList *l = r_list_newf ((RListFree)r_bin_symbol_free);
	RList *entries = __get_entries (bin);
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->restab + bin->headerOff;
	ut32 end = h->enttab + bin->headerOff;
	__get_symbols_at (bin, l, entries, offset, end);
	offset = h->nrestab;
	end = h->nrestab + h->cbnrestab;
	__get_symbols_at (bin, l, entries, offset, end);
	r_list_free (entries);
	return l;
}

R_IPI RList *r_bin_le_get_imports(RBinLEObj *bin) {
	RList *l = r_list_newf ((RListFree)r_bin_import_free);
	if (!l) {
		return NULL;
	}
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->impproc + bin->headerOff + 1; // First entry is a null string
	ut64 end = (ut64)h->fixupsize + h->fpagetab + bin->headerOff;
	while (offset < end) {
		RBinImport *imp = R_NEW0 (RBinImport);
		if (!imp) {
			break;
		}
		const char *name = __read_nonnull_str_at (bin->buf, &offset);
		if (!name) {
			r_bin_import_free (imp);
			break;
		}
		imp->name = r_bin_name_new (name);
		if (!imp->name) {
			r_bin_import_free (imp);
			break;
		}
		imp->type = R_BIN_TYPE_FUNC_STR;
		r_list_append (l, imp);
	}
	return l;
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

/*
*	Creates & appends to l iter_n sections with the same paddr for each iter record.
*	page->size is the total size of iter records that describe the page
*	TODO: Don't do this
*/
static void __create_iter_sections(RList *l, RBinLEObj *bin, RBinSection *sec, LE_object_page_entry *page, ut64 vaddr, int cur_page) {
	R_RETURN_IF_FAIL (l && bin && sec && page);
	LE_image_header *h = bin->header;
	if (h->pageshift > ST16_MAX || h->pageshift < 0) {
		// early quit before using an invalid offset
		return;
	}
	ut32 pageshift = R_MIN ((ut64)h->pageshift, 63);
	ut32 offset = (h->itermap + ((ut64)page->offset << (bin->is_le ? 0 : pageshift)));

	// Gets the first iter record
	ut16 iter_n = r_buf_read_ble16_at (bin->buf, offset, h->worder);
	if (iter_n == UT16_MAX) {
		return;
	}
	offset += sizeof (ut16);
	ut16 data_size = r_buf_read_ble16_at (bin->buf, offset, h->worder);
	if (data_size == UT16_MAX) {
		return;
	}
	offset += sizeof (ut16);

	ut64 total_size = r_buf_size (bin->buf);
	ut64 tot_size = 0;
	int iter_cnt = 0;
	ut64 bytes_left = page->size;
	while (iter_n > 0 && bytes_left > 0) {
		int i;
		tot_size = 0;
		for (i = 0; i < iter_n; i++) {
			RBinSection *s = R_NEW0 (RBinSection);
			if (!s) {
				break;
			}
			s->name = r_str_newf ("%s.page.%d.iter.%d", sec->name, cur_page, iter_cnt);
			s->bits = sec->bits;
			s->perm = sec->perm;
			s->size = data_size;
			s->vsize = data_size;
			s->paddr = offset;
			s->vaddr = vaddr;
			s->add = true;
			vaddr += data_size;
			tot_size += data_size;
			if (tot_size > total_size) {
				R_LOG_DEBUG ("section exceeds file size");
		//		break;
			}
			r_list_append (l, s);
			iter_cnt++;
		}
		bytes_left -= sizeof (ut16) * 2 + data_size;
		// Get the next iter record
		offset += data_size;
		iter_n = r_buf_read_ble16_at (bin->buf, offset, h->worder);
		if (iter_n == UT16_MAX) {
			break;
		}
		offset += sizeof (ut16);
		data_size = r_buf_read_ble16_at (bin->buf, offset, h->worder);
		if (data_size == UT16_MAX) {
			break;
		}
		offset += sizeof (ut16);
	}
	if (tot_size < h->pagesize) {
		RBinSection *s = R_NEW0 (RBinSection);
		if (s) {
			s->name = r_str_newf ("%s.page.%d.iter.zerofill", sec->name, cur_page);
			s->bits = sec->bits;
			s->perm = sec->perm;
			s->vsize = h->pagesize - tot_size;
			s->vaddr = vaddr;
			s->add = true;
			r_list_append (l, s);
		}
	}
}

// TODO: Compressed page
R_IPI RList *r_bin_le_get_sections(RBinLEObj *bin) {
	RList *l = r_list_newf ((RListFree)r_bin_section_free);
	if (!l) {
		return NULL;
	}
	LE_image_header *h = bin->header;
	ut32 pages_start_off = h->datapage;
	int i;
	for (i = 0; i < h->objcnt; i++) {
		RBinSection *sec = R_NEW0 (RBinSection);
		if (!sec) {
			return l;
		}
		LE_object_entry *entry = &bin->objtbl[i];
		if  (!entry) {
			free (sec);
			return l;
		}
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
			r_list_append (l, sec);
		}
		int j;
		ut32 page_size_sum = 0;
		ut32 next_idx = i < h->objcnt - 1 ? bin->objtbl[i + 1].page_tbl_idx - 1 : UT32_MAX;
		ut32 objmaptbloff = h->objmap + bin->headerOff;
		ut64 objpageentrysz =  bin->is_le ? sizeof (ut32) : sizeof (LE_object_page_entry);
		for (j = 0; j < entry->page_tbl_entries; j++) {
			LE_object_page_entry page = {0};
			RBinSection *s = R_NEW0 (RBinSection);
			if (!s) {
				r_bin_section_free (sec);
				return l;
			}
			s->name = r_str_newf ("%s.page.%d", sec->name, j);
			s->is_data = sec->is_data;

			int cur_idx = entry->page_tbl_idx + j - 1;
			ut64 page_entry_off = objpageentrysz * cur_idx + objmaptbloff;
#if 0
			int r = r_buf_read_at (bin->buf, page_entry_off, (ut8 *)&page, sizeof (page));
#else
			int r = r_buf_fread_at (bin->buf, page_entry_off, (ut8 *)&page, "iss", 1);
#endif
			if (r < (int)sizeof (page)) {
				R_LOG_WARN ("Cannot read out of bounds page table entry");
				r_bin_section_free (s);
				r_bin_section_free (sec);
				return l;
			}
			if (cur_idx < next_idx) { // If not true rest of pages will be zeroes
				if (bin->is_le) {
					// Why is it big endian???
					ut64 offset = r_buf_read_be32_at (bin->buf, page_entry_off) >> 8;
					s->paddr = (offset - 1) * h->pagesize + pages_start_off;
					if (entry->page_tbl_idx + j == h->mpages) {
						page.size = h->pageshift;
					} else {
						page.size = h->pagesize;
					}
				} else if (page.flags == P_ITERATED) {
					ut64 vaddr = sec->vaddr + page_size_sum;
					__create_iter_sections (l, bin, sec, &page, vaddr, j);
					r_bin_section_free (s);
					page_size_sum += h->pagesize;
					continue;
				} else if (page.flags == P_COMPRESSED) {
					// TODO
					R_LOG_WARN ("Compressed page not handled: %s", s->name);
				} else if (page.flags != P_ZEROED) {
					if (h->pageshift > 63) {
						continue;
					}
					ut32 pageshift = R_MIN (h->pageshift, 63);
					s->paddr = ((ut64)page.offset << pageshift) + pages_start_off;
				}
			}
			s->vsize = R_MIN (h->pagesize, sec->vsize - page_size_sum);
			s->vaddr = sec->vaddr + page_size_sum;
			s->perm = sec->perm;
			s->size = R_MIN (page.size, s->vsize);
			s->add = true;
			s->bits = sec->bits;
			r_list_append (l, s);
			page_size_sum += s->vsize;
		}
		if (entry->page_tbl_entries) {
			if (page_size_sum < sec->vsize) {
				RBinSection *s = R_NEW0 (RBinSection);
				if (!s) {
					r_bin_section_free (sec);
					return l;
				}
				ut64 remainder_size = sec->vsize - page_size_sum;
				s->vsize = remainder_size;
				s->vaddr = sec->vaddr + page_size_sum;
				s->perm = sec->perm;
				s->size = 0;
				s->add = true;
				s->bits = sec->bits;
				s->name = r_str_newf ("%s.page.zerofill", sec->name);
				s->is_data = sec->is_data;
				r_list_append (l, s);
			}
			r_bin_section_free (sec);
		}
	}
	return l;
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

R_IPI RList *r_bin_le_get_relocs(RBinLEObj *bin) {
	RList *l = r_list_newf ((RListFree)free);
	if (!l) {
		return NULL;
	}
	RList *entries = __get_entries (bin);
	RList *sections = r_bin_le_get_sections (bin);
	LE_image_header *h = bin->header;
	ut64 cur_page = 0;
	const ut64 fix_rec_tbl_off = (ut64)h->frectab + bin->headerOff;
	ut32 ofa = r_buf_read_ble32_at (bin->buf, (ut64)h->fpagetab + bin->headerOff + cur_page * sizeof (ut32), h->worder);
	if (ofa == UT32_MAX) {
		return NULL;
	}
	ut64 offset = fix_rec_tbl_off + ofa;
	ut32 ofb = r_buf_read_ble32_at (bin->buf, (ut64)h->fpagetab + bin->headerOff + (cur_page + 1) * sizeof (ut32), h->worder);
	if (ofb == UT32_MAX) {
		return NULL;
	}
	ut64 end = fix_rec_tbl_off + ofb;
	const RBinSection *cur_section = (RBinSection *)r_list_get_n (sections, cur_page);
	ut64 cur_page_offset = cur_section ? cur_section->vaddr : 0;
	while (cur_page < h->mpages) {
		bool rel_appended = false; // whether rel has been appended to l and must not be freed
		RBinReloc *rel = R_NEW0 (RBinReloc);
		if (!rel) {
			break;
		}
		LE_fixup_record_header header;
		int ret = r_buf_read_at (bin->buf, offset, (ut8 *)&header, sizeof (header));
		// XXX this is endiandy unsafe
		if (ret < (int)sizeof (header)) {
			R_LOG_WARN ("oobread in LE header parsing relocs");
			break;
		}
		offset += sizeof (header);
		switch (header.source & F_SOURCE_TYPE_MASK) {
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
		st16 source = 0;
		if (header.source & F_SOURCE_LIST) {
			repeat = r_buf_read8_at (bin->buf, offset);
			offset += sizeof (ut8);
		} else {
			source = r_buf_read_ble16_at (bin->buf, offset, h->worder);
			offset += sizeof (st16);
		}
		ut32 ordinal;
		if (header.target & F_TARGET_ORD16) {
			ordinal = r_buf_read_ble16_at (bin->buf, offset, h->worder);
			if (ordinal == UT16_MAX) {
				break;
			}
			offset += sizeof (ut16);
		} else {
			ordinal = r_buf_read8_at (bin->buf, offset);
			offset += sizeof (ut8);
		}
		rel->ntype = header.source & F_SOURCE_TYPE_MASK; // XXX correct?
		switch (header.target & F_TARGET_TYPE_MASK) {
		case INTERNAL:
			if ((ordinal - 1) < bin->header->objcnt) {
				rel->addend = get_object_base (bin, ordinal - 1);
				if ((header.source & F_SOURCE_TYPE_MASK) != SELECTOR16) {
					if (header.target & F_TARGET_OFF32) {
						rel->addend += r_buf_read_ble32_at (bin->buf, offset, h->worder);
						offset += sizeof (ut32);
					} else {
						rel->addend += r_buf_read_ble16_at (bin->buf, offset, h->worder);
						offset += sizeof (ut16);
					}
				}
			}
			break;
		case IMPORTORD:
		{
			RBinImport *imp = R_NEW0 (RBinImport);
			if (!imp) {
				break;
			}
			char *mod_name = __get_modname_by_ord (bin, ordinal);
			if (!mod_name) {
				r_bin_import_free (imp);
				break;
			}

			if (header.target & F_TARGET_ORD8) {
				ordinal = r_buf_read8_at (bin->buf, offset);
				offset += sizeof (ut8);
			} else if (header.target & F_TARGET_OFF32) {
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
		case IMPORTNAME:
		{
			RBinImport *imp = R_NEW0 (RBinImport);
			if (!imp) {
				break;
			}
			ut32 nameoff;
			if (header.target & F_TARGET_OFF32) {
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
			break;
		}
		case INTERNALENTRY:
			rel->addend = (ut64)(size_t)r_list_get_n (entries, ordinal - 1);
			break;
		}
		if (header.target & F_TARGET_ADDITIVE) {
			ut32 additive = 0;
			if (header.target & F_TARGET_ADD32) {
				additive = r_buf_read_ble32_at (bin->buf, offset, h->worder);
				offset += sizeof (ut32);
			} else {
				additive = r_buf_read_ble16_at (bin->buf, offset, h->worder);
				offset += sizeof (ut16);
			}
			rel->addend += additive;
		}
		if (!repeat && source >= 0) {
			/* Negative source means we already handled the cross-page
			 * fixup in the previous page, so there's no need to dupe it
			 */
			rel->vaddr = cur_page_offset + (st64) source;
			rel->paddr = cur_section ? cur_section->paddr + (st64) source : 0;
			r_list_append (l, rel);
			rel_appended = true;
		}

		if (header.target & F_TARGET_CHAIN) {
			// TODO: add tests for this case
			ut64 source = 0;
			ut32 fixupinfo = r_buf_read_ble32_at (bin->buf, cur_page_offset + source, h->worder);
			ut64 base_target_address = rel->addend - (fixupinfo & 0xFFFFF);
			do {
				fixupinfo = r_buf_read_ble32_at (bin->buf, cur_page_offset + source, h->worder);
				RBinReloc *new = R_NEW0 (RBinReloc);
				*new = *rel;
				new->addend = base_target_address + (fixupinfo & 0xFFFFF);
				r_list_append (l, new);
				source = (fixupinfo >> 20) & 0xFFF;
			} while (source != 0xFFF);
		}

		while (repeat) {
			ut16 off =  r_buf_read_ble16_at (bin->buf, offset, h->worder);
			rel->vaddr = cur_page_offset + off;
			rel->paddr = cur_section ? cur_section->paddr + off : 0;
			RBinReloc *new = R_NEW0 (RBinReloc);
			*new = *rel;
			r_list_append (l, new);
			offset += sizeof (ut16);
			repeat--;
		}
		while (offset >= end) {
			cur_page++;
			if (cur_page >= h->mpages) {
				break;
			}
			ut64 at = h->fpagetab + bin->headerOff;
			ut32 w0 = r_buf_read_ble32_at (bin->buf, at + cur_page * sizeof (ut32), h->worder);
			ut32 w1 = r_buf_read_ble32_at (bin->buf, at + (cur_page + 1) * sizeof (ut32), h->worder);
			if (w0 == UT32_MAX || w1 == UT32_MAX) {
				break;
			}
			offset = fix_rec_tbl_off + w0;
			end = fix_rec_tbl_off + w1;
			if (offset < end) {
				cur_section = (RBinSection *)r_list_get_n (sections, cur_page);
				cur_page_offset = cur_section ? cur_section->vaddr : 0;
			}
		}
		if (!rel_appended) {
			free (rel);
		}
	}
	r_list_free (entries);
	r_list_free (sections);
	return l;
}

static bool __init_header(RBinLEObj *bin, RBuffer *buf) {
	ut8 magic[2];
	r_buf_read_at (buf, 0, magic, sizeof (magic));
	if (!memcmp (&magic, "MZ", 2)) {
		bin->headerOff = r_buf_read_le16_at (buf, 0x3c);
	} else {
		bin->headerOff = 0;
	}
	bin->header = R_NEW0 (LE_image_header);
	if (bin->header) {
#if 0
		r_buf_read_at (buf, bin->headerOff, (ut8 *)bin->header, sizeof (LE_image_header));
#else
		r_buf_fread_at (buf, bin->headerOff, (ut8*)bin->header, "2s41i", 1);
#endif
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
	free (bases_str);
}

R_IPI RBinLEObj *r_bin_le_new_buf(RBuffer *buf) {
	RBinLEObj *bin = R_NEW0 (RBinLEObj);
	if (!__init_header (bin, buf)) {
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
