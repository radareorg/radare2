/* radare - LGPL - Copyright 2019-2025 - GustavoLCR */

#include "ne.h"

static char *__get_target_os(r_bin_ne_obj_t *bin) {
	const int targetOS = (bin->ne_header) ? bin->ne_header->targOS: 0;
	switch (targetOS) {
	case 1:
		return "OS/2";
	case 2:
		return "Windows";
	case 3:
		return "European MS-DOS 4.x";
	case 4:
		return "Windows 386";
	case 5:
		return "BOSS (Borland Operating System Services)";
	default:
		return "Unknown";
	}
}

static int __translate_perms(int flags) {
	int perms = 0;
	if (flags & IS_RX) {
		if (flags & IS_DATA) {
			perms = R_PERM_R;
		} else {
			perms = R_PERM_X;
		}
	}
	if (!perms) {
		perms = R_PERM_RWX;
	}
	return perms;
}

static char *__read_nonnull_str_at(RBuffer *buf, ut64 offset) {
	ut8 sz = r_buf_read8_at (buf, offset);
	if (!sz) {
		return NULL;
	}
	char *str = malloc ((ut64)sz + 1);
	if (!str) {
		return NULL;
	}
	r_buf_read_at (buf, offset + 1, (ut8 *)str, sz);
	str[sz] = '\0';
	return str;
}

static char *__func_name_from_ord(const char *module, ut16 ordinal) {
	if (!module) {
		return NULL;
	}
	char *lower_module = strdup (module);
	r_str_case (lower_module, false);
	char *path = r_str_newf (R_JOIN_4_PATHS ("%s", R2_SDB_FORMAT, "dll", "%s.sdb"), r_sys_prefix (NULL), lower_module);
	free (lower_module);
	char *ord = r_str_newf ("%d", ordinal);
	char *name;
	if (r_file_exists (path)) {
		Sdb *sdb = sdb_new (NULL, path, 0);
		name = sdb_get (sdb, ord, NULL);
		if (!name) {
			name = ord;
		} else {
			free (ord);
		}
		sdb_close (sdb);
		free (sdb);
	} else {
		name = ord;
	}
	free (path);
	return name;
}

RList *r_bin_ne_get_segments(r_bin_ne_obj_t *bin) {
	int i;
	if (!bin || !bin->segment_entries || !bin->ne_header) {
		return NULL;
	}
	RList *segments = r_list_newf (free);
	for (i = 0; i < bin->ne_header->SegCount; i++) {
		RBinSection *bs = R_NEW0 (RBinSection);
		NE_image_segment_entry *se = &bin->segment_entries[i];
		bs->size = se->length;
		bs->vsize = se->minAllocSz ? se->minAllocSz : 64000;
		bs->bits = R_SYS_BITS_PACK (16);
		bs->is_data = se->flags & IS_DATA;
		bs->perm = __translate_perms (se->flags);
		bs->paddr = (ut64)se->offset * bin->alignment;
		bs->name = r_str_newf ("%s.%" PFMT64d, se->flags & IS_MOVEABLE ? "MOVEABLE" : "FIXED", bs->paddr);
		bs->is_segment = true;
		r_list_append (segments, bs);
	}
	bin->segments = segments;
	return segments;
}

static int __find_symbol_by_paddr(const void *paddr, const void *sym) {
	return (int)!(*(ut64 *)paddr == ((RBinSymbol *)sym)->paddr);
}

RList *r_bin_ne_get_symbols(r_bin_ne_obj_t *bin) {
	RBinSymbol *sym;
	if (!bin->ne_header) {
		return NULL;
	}
	ut16 off = bin->ne_header->ResidNamTable + bin->header_offset;
	RList *symbols = r_list_newf (free);
	if (!symbols) {
		return NULL;
	}
	RList *entries = r_bin_ne_get_entrypoints (bin);
	bool resident = true, first = true;
	while (entries) {
		ut8 sz = r_buf_read8_at (bin->buf, off);
		if (!sz) {
			first = true;
			if (resident) {
				resident = false;
				off = bin->ne_header->OffStartNonResTab;
				sz = r_buf_read8_at (bin->buf, off);
				if (!sz) {
					break;
				}
			} else {
				break;
			}
		}
		char *name = malloc ((ut64)sz + 1);
		if (!name) {
			break;
		}
		off++;
		r_buf_read_at (bin->buf, off, (ut8 *)name, sz);
		name[sz] = '\0';
		off += sz;
		sym = R_NEW0 (RBinSymbol);
		sym->name = r_bin_name_new_from (name);
		if (!first) {
			sym->bind = R_BIN_BIND_GLOBAL_STR;
		}
		ut16 entry_off = r_buf_read_le16_at (bin->buf, off);
		off += 2;
		RBinAddr *entry = r_list_get_n (entries, entry_off);
		if (entry) {
			sym->paddr = entry->paddr;
		} else {
			sym->paddr = -1;
		}
		sym->ordinal = entry_off;
		r_list_append (symbols, sym);
		first = false;
	}
	RListIter *it;
	RBinAddr *en;
	int i = 1;
	r_list_foreach (entries, it, en) {
		if (!r_list_find (symbols, &en->paddr, __find_symbol_by_paddr)) {
			sym = R_NEW0 (RBinSymbol);
			sym->name = r_bin_name_new_from (r_str_newf ("entry%d", i - 1));
			sym->paddr = en->paddr;
			sym->bind = R_BIN_BIND_GLOBAL_STR;
			sym->ordinal = i;
			r_list_append (symbols, sym);
		}
		i++;
	}
	bin->symbols = symbols;
	return symbols;
}

static char *__resource_type_str(int type) {
	static const char *names[] = {
		/*  0 */ NULL,
		/*  1 */ "CURSOR",
		/*  2 */ "BITMAP",
		/*  3 */ "ICON",
		/*  4 */ "MENU",
		/*  5 */ "DIALOG",
		/*  6 */ "STRING",
		/*  7 */ "FONTDIR",
		/*  8 */ "FONT",
		/*  9 */ "ACCELERATOR",
		/* 10 */ "RCDATA",
		/* 11 */ "MESSAGETABLE",
		/* 12 */ "GROUP_CURSOR",
		/* 13 */ NULL,
		/* 14 */ "GROUP_ICON",
		/* 15 */ "NAMETABLE",
		/* 16 */ "VERSION",
		/* 17 */ "DLGINCLUDE",
		/* 18 */ NULL,
		/* 19 */ "PLUGPLAY",
		/* 20 */ "VXD",
		/* 21 */ "ANICURSOR",
		/* 22 */ "ANIICON",
		/* 23 */ "HTML",
		/* 24 */ "MANIFEST"
	};
	if ((unsigned)type < (sizeof names / sizeof names[0]) && names[type]) {
		return strdup (names[type]);
	}
	return r_str_newf("UNKNOWN (%d)", type);
}

static void __free_resource_entry(void *entry) {
	r_ne_resource_entry *en = (r_ne_resource_entry *)entry;
	free (en->name);
	free (en);
}

static void __free_resource(void *resource) {
	r_ne_resource *res = (r_ne_resource *)resource;
	free (res->name);
	r_list_free (res->entry);
	free (res);
}

static bool __ne_get_resources(r_bin_ne_obj_t *bin) {
	if (!bin || !bin->ne_header) {
		return false;
	}
	if (!bin->resources) {
		bin->resources = r_list_newf (__free_resource);
		if (!bin->resources) {
			return false;
		}
	}
	ut16 resoff = bin->ne_header->ResTableOffset + bin->header_offset;
	ut16 alignment = r_buf_read_le16_at (bin->buf, resoff);
	ut32 off = resoff + 2;
	while (true) {
		NE_image_typeinfo_entry ti = {0};
		r_ne_resource *res = R_NEW0 (r_ne_resource);
		res->entry = r_list_newf (__free_resource_entry);
		if (!res->entry) {
			break;
		}
		r_buf_fread_at (bin->buf, off, (ut8 *)&ti, "2si", 1);
		if (!ti.rtTypeID) {
			break;
		} else if (ti.rtTypeID & 0x8000) {
			res->name = __resource_type_str (ti.rtTypeID & ~0x8000);
		} else {
			// Offset to resident name table
			res->name = __read_nonnull_str_at (bin->buf, (ut64)resoff + ti.rtTypeID);
		}
		off += sizeof (NE_image_typeinfo_entry);
		const ut32 max_shift = (sizeof (ut32) * 8U) - 1;
		int i;
		for (i = 0; i < ti.rtResourceCount; i++) {
			NE_image_nameinfo_entry ni;
			r_ne_resource_entry *ren = R_NEW0 (r_ne_resource_entry);
			r_buf_fread_at (bin->buf, off, (ut8 *)&ni, "6s", 1);
			ut32 shift = alignment;
			if (shift > max_shift) {
				shift = max_shift;
			}
			ren->offset = (ut32)((ut64)ni.rnOffset << shift);
			ren->size = ni.rnLength;
			if (ni.rnID & 0x8000) {
				ren->name = r_str_newf ("%d", ni.rnID & ~0x8000);
			} else {
				// Offset to resident name table
				ren->name = __read_nonnull_str_at (bin->buf, (ut64)resoff + ni.rnID);
			}
			r_list_append (res->entry, ren);
			off += sizeof (NE_image_nameinfo_entry);
		}
		r_list_append (bin->resources, res);
	}
	return true;
}

RList *r_bin_ne_get_imports(r_bin_ne_obj_t *bin) {
	if (!bin->ne_header) {
		return NULL;
	}
	RList *imports = r_list_newf ((RListFree)r_bin_import_free);
	ut16 off = bin->ne_header->ImportNameTable + bin->header_offset + 1;
	int i;
	for (i = 0; i < bin->ne_header->ModRefs; i++) {
		RBinImport *imp = R_NEW0 (RBinImport);
		ut8 sz = r_buf_read8_at (bin->buf, off);
		if (!sz) {
			r_bin_import_free (imp);
			break;
		}
		off++;
		char *name = malloc ((ut64)sz + 1);
		if (!name) {
			break;
		}
		r_buf_read_at (bin->buf, off, (ut8 *)name, sz);
		name[sz] = '\0';
		imp->name = r_bin_name_new_from (name);
		imp->ordinal = i + 1;
		r_list_append (imports, imp);
		off += sz;
	}
	bin->imports = imports;
	return imports;
}

RList *r_bin_ne_get_entrypoints(r_bin_ne_obj_t *bin) {
	if (!bin->entry_table || !bin->ne_header) {
		return NULL;
	}
	RList *entries = r_list_newf (free);
	RList *segments = r_bin_ne_get_segments (bin);
	if (!segments) {
		r_list_free (entries);
		return NULL;
	}
	if (bin->ne_header->csEntryPoint) {
		RBinAddr *entry = R_NEW0 (RBinAddr);
		if (!entry) {
			r_list_free (entries);
			return NULL;
		}
		entry->bits = 16;
		ut32 entry_cs = bin->ne_header->csEntryPoint;
		RBinSection *s = r_list_get_n (segments, entry_cs - 1);
		entry->paddr = bin->ne_header->ipEntryPoint + (s? s->paddr: 0);

		r_list_append (entries, entry);
	}
	int off = 0;
	size_t tableat = bin->header_offset + bin->ne_header->EntryTableOffset;
	while (off < bin->ne_header->EntryTableLength) {
		if (tableat + off >= r_buf_size (bin->buf)) {
			break;
		}
		ut8 bundle_length = *(ut8 *)(bin->entry_table + off);
		if (!bundle_length) {
			break;
		}
		off++;
		ut8 bundle_type = *(ut8 *)(bin->entry_table + off);
		off++;
		int i;
		for (i = 0; i < bundle_length; i++) {
			if (tableat + off + 4 >= r_buf_size (bin->buf)) {
				break;
			}
			RBinAddr *entry = R_NEW0 (RBinAddr);
			if (!entry) {
				r_list_free (entries);
				return NULL;
			}
			off++;
			if (!bundle_type) { // Skip
				off--;
				free (entry);
				break;
			} else if (bundle_type == 0xff) { // moveable
				off += 2;
				ut8 segnum = *(bin->entry_table + off);
				off++;
				if (off > bin->ne_header->EntryTableLength) {
					free (entry);
					break;
				}
				ut16 segoff = r_read_le16 (bin->entry_table + off);
				if (segnum > 0 && segnum < bin->ne_header->SegCount) {
					entry->paddr = (ut64)bin->segment_entries[segnum - 1].offset * bin->alignment + segoff;
				}
			} else { // Fixed
				if (off + 2 >= bin->ne_header->EntryTableLength) {
					free (entry);
					break;
				}
				ut16 delta = r_read_le16 (bin->entry_table + off);
				if (bundle_type < bin->ne_header->SegCount) {
					entry->paddr = (ut64)bin->segment_entries[bundle_type - 1].offset
						* bin->alignment + delta;
				}
			}
			off += 2;
			r_list_append (entries, entry);
		}
	}
	r_list_free (segments);
	bin->entries = entries;
	return entries;
}

RList *r_bin_ne_get_relocs(r_bin_ne_obj_t *bin) {
	RList *segments = bin->segments;
	if (!segments || !bin->ne_header) {
		return NULL;
	}
	RList *entries = bin->entries;
	if (!entries) {
		return NULL;
	}
	RList *symbols = bin->symbols;
	if (!symbols) {
		return NULL;
	}

	ut16 *modref = calloc (bin->ne_header->ModRefs, sizeof (ut16));
	if (!modref) {
		return NULL;
	}
	r_buf_fread_at (bin->buf, (ut64)bin->ne_header->ModRefTable + bin->header_offset, (ut8 *)modref, "s", bin->ne_header->ModRefs);

	RList *relocs = r_list_newf (free);
	if (!relocs) {
		free (modref);
		return NULL;
	}

	RListIter *it;
	RBinSection *seg;
	int index = -1;
	r_list_foreach (segments, it, seg) {
		index++;
		if (!(bin->segment_entries[index].flags & RELOCINFO)) {
			continue;
		}
		ut32 off = seg->paddr + seg->size;
		ut32 start = off;
		ut16 length = r_buf_read_le16_at (bin->buf, off);
		if (!length) {
			continue;
		}
		off += 2;
		// size_t buf_size = r_buf_size (bin->buf);
		while (off < start + length * sizeof (NE_image_reloc_item)) {
			// && off + sizeof (NE_image_reloc_item) < buf_size)
			NE_image_reloc_item rel = {0};
			if (r_buf_fread_at (bin->buf, off, (ut8 *)&rel, "2c3s", 1) < 1) {
				return NULL;
			}
			RBinReloc *reloc = R_NEW0 (RBinReloc);
			if (!reloc) {
				return NULL;
			}
			reloc->paddr = seg->paddr + rel.offset;
			reloc->ntype = rel.type;
			switch (rel.type) {
			case LOBYTE:
				reloc->type = R_BIN_RELOC_8;
				break;
			case SEL_16:
			case OFF_16:
				reloc->type = R_BIN_RELOC_16;
				break;
			case POI_32:
			case OFF_32:
				reloc->type = R_BIN_RELOC_32;
				break;
			case POI_48:
				reloc->type = R_BIN_RELOC_64;
				break;
			}

			ut32 offset;
			if (rel.flags & (IMPORTED_ORD | IMPORTED_NAME)) {
				RBinImport *imp = R_NEW0 (RBinImport);
				if (!imp) {
					free (reloc);
					break;
				}
				char *name = NULL;
				if (rel.index > bin->ne_header->ModRefs) {
					name = r_str_newf ("UnknownModule%d_%x", rel.index, off); // ????
				} else if (rel.index > 0) {
					offset = modref[rel.index - 1] + bin->header_offset + bin->ne_header->ImportNameTable;
					name = __read_nonnull_str_at (bin->buf, offset);
				}
				if (rel.flags & IMPORTED_ORD) {
					imp->ordinal = rel.func_ord;
					char *fname = __func_name_from_ord (name, rel.func_ord);
					imp->name = r_bin_name_new_from (r_str_newf ("%s.%s", name, fname));
					free (fname);
				} else {
					offset = bin->header_offset + bin->ne_header->ImportNameTable + rel.name_off;
					char *func = __read_nonnull_str_at (bin->buf, offset);
					imp->name = r_bin_name_new_from (r_str_newf ("%s.%s", name, func));
					free (func);
				}
				free (name);
				reloc->import = imp;
			} else if (rel.flags & OSFIXUP) {
				// TODO
			} else {
				if (strstr (seg->name, "FIXED")) {
					RBinSection *s = r_list_get_n (segments, rel.segnum - 1);
					if (s) {
						offset = s->paddr + rel.segoff;
					} else {
						offset = -1;
					}
				} else {
					RBinAddr *entry = r_list_get_n (entries, rel.entry_ordinal - 1);
					if (entry) {
						offset = entry->paddr;
					} else {
						offset = -1;
					}
				}
				reloc->addend = offset;
				RBinSymbol *sym = NULL;
				RListIter *sit;
				r_list_foreach (symbols, sit, sym) {
					if (sym->paddr == reloc->addend) {
						reloc->symbol = sym;
						break;
					}
				}
			}

			if (rel.flags & ADDITIVE) {
				reloc->additive = 1;
				r_list_append (relocs, reloc);
			} else {
				do {
#define NE_BUG 0
#if NE_BUG
					if (reloc->paddr + 4 < r_buf_size (bin->buf)) {
						break;
					}
#endif
					r_list_append (relocs, reloc);
					offset = r_buf_read_le16_at (bin->buf, reloc->paddr);
					RBinReloc *tmp = reloc;
					reloc = R_NEW0 (RBinReloc);
					if (!reloc) {
						break;
					}
					*reloc = *tmp;
					reloc->paddr = seg->paddr + offset;
				} while (offset != 0xFFFF);
				free (reloc);
			}

			off += sizeof (NE_image_reloc_item);
		}
	}
	free (modref);
	return relocs;
}

void __init(RBuffer *buf, r_bin_ne_obj_t *bin) {
	bin->header_offset = r_buf_read_le16_at (buf, 0x3c);
	bin->ne_header = R_NEW0 (NE_image_header);
	bin->buf = buf;
	if (r_buf_fread_at (buf, bin->header_offset, (ut8 *)bin->ne_header, "4c2si4c4si8si3s2c3s2c", 1) < 1) {
		R_FREE (bin->ne_header);
		return;
	}
	if (bin->ne_header->FileAlnSzShftCnt > 15) {
		bin->ne_header->FileAlnSzShftCnt = 15;
	}
	ut64 from = bin->ne_header->ModRefTable + bin->header_offset;
	ut64 left = r_buf_size (bin->buf) - from;
	if (from + bin->ne_header->ModRefs * sizeof (ut16) >= left) {
		bin->ne_header->ModRefs = left / sizeof (ut16);
	}
	bin->alignment = 1 << bin->ne_header->FileAlnSzShftCnt;
	if (!bin->alignment) {
		bin->alignment = 1 << 9;
	}
	bin->os = __get_target_os (bin);

	ut16 offset = bin->ne_header->SegTableOffset + bin->header_offset;
	size_t size = bin->ne_header->SegCount * sizeof (NE_image_segment_entry);
	if (offset >= r_buf_size (bin->buf)) {
		return;
	}
	size_t remaining = r_buf_size (bin->buf) - offset;
	size = R_MIN (remaining, size);
	bin->ne_header->SegCount = size / sizeof (NE_image_segment_entry); // * sizeof (NE_image_segment_entry);
	bin->segment_entries = calloc (1, size);
	if (size >= remaining) {
		bin->ne_header->SegCount = size / sizeof (NE_image_segment_entry);
	}
	if (!bin->segment_entries) {
		return;
	}
	r_buf_fread_at (buf, offset, (ut8 *)bin->segment_entries, "4s", bin->ne_header->SegCount);
	bin->entry_table = calloc (4, bin->ne_header->EntryTableLength);
	if (!bin->entry_table) {
		R_FREE (bin->segment_entries);
		return;
	}
	r_buf_read_at (buf, (ut64)bin->header_offset + bin->ne_header->EntryTableOffset, bin->entry_table, bin->ne_header->EntryTableLength);
	bin->imports = r_bin_ne_get_imports (bin);
	__ne_get_resources (bin);
}

void r_bin_ne_free(r_bin_ne_obj_t *bin) {
	// r_list_free (bin->imports); // double free
	r_list_free (bin->resources);
	free (bin->entry_table);
	free (bin->ne_header);
	free (bin->resident_name_table);
	free (bin->segment_entries);
	free (bin);
}

r_bin_ne_obj_t *r_bin_ne_new_buf(RBuffer *buf, bool verbose) {
	r_bin_ne_obj_t *bin = R_NEW0 (r_bin_ne_obj_t);
	__init (buf, bin);
	return bin;
}
