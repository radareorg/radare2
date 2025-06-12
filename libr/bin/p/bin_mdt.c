/* radare2 - LGPL - Copyright 2025 - Rot127 <unisono@quyllur.org> (ported from rizin2) */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../format/mdt/mdt.h"
#include "../format/elf/elf.h"

typedef struct {
	ut32 load_index;
	ut32 version;
	ut32 paddr;
	ut32 vaddr;
	ut32 psize;
	ut32 code_pa;
	ut32 sign_va;
	ut32 sign_sz;
	ut32 cert_va;
	ut32 cert_sz;
} SblHeader;

static void headers(RBinFile *bf) {
	r_return_if_fail (bf && bf->bo && bf->bo->bin_obj && bf->rbin && bf->rbin->cb_printf);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	char bits[65] = { 0 };
	size_t i;
	RListIter *iter;
	RBinMdtPart *part;

	i = 0;
	r_list_foreach (mdt->parts, iter, part) {
		r_str_bits64 (bits, qcom_p_flags (part->pflags));
		bf->rbin->cb_printf ("==== MDT Segment %"PFMT64u" ====\n", (ut64)i);
		bf->rbin->cb_printf ("     priv_p_flags: 0b%s:", bits);
		if (part->is_layout) {
			bf->rbin->cb_printf (" layout");
		}
		if (part->relocatable) {
			bf->rbin->cb_printf (" reloc");
		}
		switch (part->format) {
		default:
		case R_BIN_MDT_PART_UNIDENTIFIED:
			bf->rbin->cb_printf (" | Unidentified\n");
			break;
		case R_BIN_MDT_PART_ELF:
			bf->rbin->cb_printf (" | ELF\n");
			if (part->obj.elf) {
				bf->rbin->cb_printf (" -- ELF HEADER BEGIN -- \n");
				// Print ELF header info - simplified
				ELFOBJ *eo = part->obj.elf;
				bf->rbin->cb_printf ("0x00000000  MAGIC       %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					eo->ehdr.e_ident[0], eo->ehdr.e_ident[1], eo->ehdr.e_ident[2], eo->ehdr.e_ident[3],
					eo->ehdr.e_ident[4], eo->ehdr.e_ident[5], eo->ehdr.e_ident[6], eo->ehdr.e_ident[7],
					eo->ehdr.e_ident[8], eo->ehdr.e_ident[9], eo->ehdr.e_ident[10], eo->ehdr.e_ident[11],
					eo->ehdr.e_ident[12], eo->ehdr.e_ident[13], eo->ehdr.e_ident[14], eo->ehdr.e_ident[15]);
				bf->rbin->cb_printf ("0x00000010  Type        0x%04x\n", eo->ehdr.e_type);
				bf->rbin->cb_printf ("0x00000012  Machine     0x%04x\n", eo->ehdr.e_machine);
				bf->rbin->cb_printf ("0x00000014  Version     0x%08x\n", eo->ehdr.e_version);
				bf->rbin->cb_printf ("0x00000018  Entrypoint  0x%08"PFMT64x"\n", (ut64)eo->ehdr.e_entry);
				bf->rbin->cb_printf ("0x0000001c  PhOff       0x%08"PFMT64x"\n", (ut64)eo->ehdr.e_phoff);
				bf->rbin->cb_printf ("0x00000020  ShOff       0x%08"PFMT64x"\n", (ut64)eo->ehdr.e_shoff);
				bf->rbin->cb_printf ("0x00000024  Flags       0x%04x\n", eo->ehdr.e_flags);
				bf->rbin->cb_printf ("0x00000028  EhSize      %d\n", eo->ehdr.e_ehsize);
				bf->rbin->cb_printf ("0x0000002a  PhentSize   %d\n", eo->ehdr.e_phentsize);
				bf->rbin->cb_printf ("0x0000002c  PhNum       %d\n", eo->ehdr.e_phnum);
				bf->rbin->cb_printf ("0x0000002e  ShentSize   %d\n", eo->ehdr.e_shentsize);
				bf->rbin->cb_printf ("0x00000030  ShNum       %d\n", eo->ehdr.e_shnum);
				bf->rbin->cb_printf ("0x00000032  ShStrndx    %d\n", eo->ehdr.e_shstrndx);
				bf->rbin->cb_printf (" --- ELF HEADER END --- \n\n");
			} else {
				bf->rbin->cb_printf (" ------- FAILED ------- \n");
			}
			break;
		case R_BIN_MDT_PART_MBN:
			bf->rbin->cb_printf (" | MBN signature segment\n");
			if (part->obj.mbn) {
				SblHeader *mbn = (SblHeader *)part->obj.mbn;
				bf->rbin->cb_printf (" -- MBN AUTH HEADER BEGIN -- \n");
				bf->rbin->cb_printf ("0x00 image_id:   kMbnImageNone (0x%x)\n", 0);
				bf->rbin->cb_printf ("0x04 version:    0x%x\n", mbn->version);
				bf->rbin->cb_printf ("0x08 paddr:      0x%x\n", mbn->paddr);
				bf->rbin->cb_printf ("0x0c vaddr:      0x%x\n", mbn->vaddr);
				bf->rbin->cb_printf ("0x10 psize:      0x%x\n", mbn->psize);
				bf->rbin->cb_printf ("0x14 code_pa:    0x%x\n", mbn->code_pa);
				bf->rbin->cb_printf ("0x18 sign_va:    0x%x\n", mbn->sign_va);
				bf->rbin->cb_printf ("0x1c sign_sz:    0x%x\n", mbn->sign_sz);
				bf->rbin->cb_printf ("0x20 cert_va:    0x%x\n", mbn->cert_va);
				bf->rbin->cb_printf ("0x24 cert_sz:    0x%x\n", mbn->cert_sz);
				bf->rbin->cb_printf (" --- MBN AUTH HEADER END --- \n\n");
			} else {
				bf->rbin->cb_printf (" ------- FAILED ------- \n");
			}
			break;
		}
		i++;
	}
}

static void mdt_map_free(void *ptr) {
	RBinMap *map = (RBinMap *)ptr;
	if (map) {
		free (map->file);
		free (map);
	}
}

static RBinSection *segment_to_section(ut64 paddr, ut64 vaddr, ut64 psize, ut64 vsize, ut32 flags, const char *name) {
	RBinSection *section = R_NEW0 (RBinSection);
	r_return_val_if_fail (section, NULL);

	section->paddr = paddr;
	section->size = psize;
	section->vsize = vsize;
	section->vaddr = vaddr;
	section->perm = flags & 7; // R/W/X flags
	section->is_segment = true;
	section->name = strdup (name);
	return section;
}

static RBinMdtPart *load_segment_part(ELFOBJ *header, int idx) {
	if (!header || !header->phdr || idx < 0 || idx >= header->ehdr.e_phnum) {
		return NULL;
	}

	Elf_(Phdr) *segment = &header->phdr[idx];
	RBinMdtPart *part = NULL;
	RBuffer *vfile_buffer = NULL;
	char *segment_file_path = NULL;
	char *base_name = NULL;

	// Get base name without extension
	if (header->file) {
		base_name = strdup (header->file);
		char *dot = strrchr (base_name, '.');
		if (dot && !strcmp (dot, ".mdt")) {
			*dot = '\0';
		}
	} else {
		base_name = strdup ("firmware");
	}

	segment_file_path = r_str_newf ("%s.b%02d", base_name, idx);
	const char *segment_name = r_file_basename (segment_file_path);

	part = r_bin_mdt_part_new (segment_name, segment->p_flags);
	if (!part) {
		goto error;
	}

	bool zero_segment = segment->p_filesz == 0;
	bool segment_file_exists = r_file_exists (segment_file_path);

	if (zero_segment && segment_file_exists) {
		R_LOG_WARN ("The segment size for '%s' is 0. But the file exists. Skip loading", segment_file_path);
		goto error;
	} else if (!zero_segment && !segment_file_exists) {
		R_LOG_WARN ("The segment size for '%s' is 0x%"PFMT64x". But the file doesn't exist. Skip loading",
			segment_file_path, (ut64)segment->p_filesz);
		goto error;
	}

	// Read segment file
	vfile_buffer = zero_segment ? r_buf_new_empty (segment->p_memsz) : r_buf_new_file (segment_file_path, O_RDONLY, 0);
	if (!vfile_buffer) {
		R_LOG_ERROR ("Failed to read '%s'", segment_file_path);
		goto error;
	}

	// Create map for this part
	RBinMap *map = R_NEW0 (RBinMap);
	if (!map) {
		goto error;
	}
	map->offset = 0;
	map->size = segment->p_filesz;
	map->addr = segment->p_vaddr;
	map->perms = segment->p_flags & 7;
	map->file = strdup (part->name);

	part->paddr = segment->p_paddr;
	part->pflags = segment->p_flags;
	part->map = map;
	part->vfile_buf = vfile_buffer;
	part->vfile_name = strdup (part->name);
	part->sections = r_list_newf ((RListFree)r_bin_section_free);

	// Add segment as section
	RBinSection *bseg = segment_to_section (segment->p_paddr, segment->p_vaddr,
		segment->p_filesz, segment->p_memsz, segment->p_flags, part->name);
	if (bseg) {
		r_list_append (part->sections, bseg);
	}

	// Check content type
	ut8 magic[4];
	if (r_buf_read_at (vfile_buffer, 0, magic, 4) == 4 &&
	    magic[0] == ELFMAG0 && magic[1] == ELFMAG1 &&
	    magic[2] == ELFMAG2 && magic[3] == ELFMAG3) {
		part->format = R_BIN_MDT_PART_ELF;
		// Load nested ELF
		part->obj.elf = Elf_(new_buf) (vfile_buffer, 0, false);
		if (part->obj.elf) {
			// Load symbols from nested ELF
			part->symbols = r_list_newf ((RListFree)r_bin_symbol_free);
			if (Elf_(load_symbols) (part->obj.elf)) {
				// Access symbols through the symbols_by_ord array
				if (part->obj.elf->symbols_by_ord) {
					size_t symbols_size = part->obj.elf->symbols_by_ord_size;
					size_t i;
					for (i = 0; i < symbols_size; i++) {
						RBinSymbol *sym = part->obj.elf->symbols_by_ord[i];
						if (sym) {
							RBinSymbol *clone = r_bin_symbol_clone (sym);
							if (clone) {
								clone->vaddr += part->map->addr;
								r_list_append (part->symbols, clone);
							}
						}
					}
				}
			}

			// Load sections from nested ELF - skip for now
			// (requires RBinFile which we don't have here)
		}
	} else if ((segment->p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_SIGNATURE) {
		part->format = R_BIN_MDT_PART_MBN;
		// Load MBN header
		SblHeader *mbn = R_NEW0 (SblHeader);
		if (mbn && r_buf_fread_at (vfile_buffer, 0, (ut8*)mbn, "10i", 1) == 10) {
			part->obj.mbn = mbn;
		} else {
			free (mbn);
		}
	} else {
		part->format = R_BIN_MDT_PART_UNIDENTIFIED;
	}

	free (segment_file_path);
	free (base_name);
	return part;

error:
	r_bin_mdt_part_free (part);
	r_buf_free (vfile_buffer);
	free (segment_file_path);
	free (base_name);
	return NULL;
}

static bool check(RBinFile *bf, RBuffer *b) {
	return r_bin_mdt_check_buffer (b);
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	r_return_val_if_fail (bf && b, false);

	if (!r_bin_mdt_check_buffer (b)) {
		return false;
	}

	RBinMdtObj *mdt = r_bin_mdt_obj_new ();
	if (!mdt) {
		return false;
	}

	mdt->name = strdup (bf->file ? r_file_basename (bf->file) : "firmware");

	// Load header ELF
	mdt->header = Elf_(new_buf) (b, 0, false);
	if (!mdt->header) {
		R_LOG_ERROR ("Failed to parse .mdt ELF header");
		goto error;
	}

	// Store filename in ELF object for later use
	mdt->header->file = strdup (bf->file);

	// Load segments
	int i;
	for (i = 0; i < mdt->header->ehdr.e_phnum; i++) {
		RBinMdtPart *part = load_segment_part (mdt->header, i);
		if (part) {
			r_list_append (mdt->parts, part);
		}
	}

	bf->bo->bin_obj = mdt;
	return true;

error:
	r_bin_mdt_obj_free (mdt);
	return false;
}

static void destroy(RBinFile *bf) {
	r_return_if_fail (bf && bf->bo && bf->bo->bin_obj);
	r_bin_mdt_obj_free (bf->bo->bin_obj);
}

static RList *maps(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *maps = r_list_newf ((RListFree)mdt_map_free);
	if (!maps) {
		return NULL;
	}

	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach (mdt->parts, iter, part) {
		if (part->map) {
			RBinMap *clone = R_NEW0 (RBinMap);
			if (clone) {
				*clone = *part->map;
				clone->file = strdup (part->map->file);
				r_list_append (maps, clone);
			}
		}
	}

	return maps;
}

static RList *entries(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *entries = r_list_newf ((RListFree)free);
	if (!entries) {
		return NULL;
	}

	RBinAddr *entry = R_NEW0 (RBinAddr);
	if (!entry) {
		r_list_free (entries);
		return NULL;
	}

	// Get entry from header
	entry->vaddr = mdt->header->ehdr.e_entry;
	entry->paddr = mdt->header->ehdr.e_entry;

	// Find which segment contains the entry point
	int i;
	for (i = 0; i < mdt->header->ehdr.e_phnum; i++) {
		Elf_(Phdr) *seg = &mdt->header->phdr[i];
		if (seg->p_type == PT_LOAD &&
		    entry->paddr >= seg->p_paddr &&
		    entry->paddr < seg->p_paddr + seg->p_memsz) {
			entry->paddr = entry->paddr - seg->p_paddr;
			entry->vaddr = seg->p_vaddr + entry->paddr;
			entry->type = R_BIN_ENTRY_TYPE_INIT;
			entry->bits = Elf_(get_bits) (mdt->header);
			break;
		}
	}

	r_list_append (entries, entry);
	return entries;
}

static RList *symbols(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *symbols = r_list_newf ((RListFree)r_bin_symbol_free);
	if (!symbols) {
		return NULL;
	}

	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach (mdt->parts, iter, part) {
		if (!part->symbols) {
			continue;
		}
		RListIter *it;
		RBinSymbol *sym;
		r_list_foreach (part->symbols, it, sym) {
			// Clone symbol
			RBinSymbol *clone = R_NEW0 (RBinSymbol);
			clone->name = r_bin_name_clone (sym->name);
			clone->vaddr = sym->vaddr;
			clone->paddr = sym->paddr;
			clone->size = sym->size;
			clone->ordinal = sym->ordinal;
			clone->bind = sym->bind;
			clone->type = sym->type;
			r_list_append (symbols, clone);
		}
	}

	return symbols;
}

static RList *sections(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *sections = r_list_newf ((RListFree)r_bin_section_free);
	if (!sections) {
		return NULL;
	}

	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach (mdt->parts, iter, part) {
		if (part->sections) {
			RListIter *it;
			RBinSection *sec;
			r_list_foreach (part->sections, it, sec) {
				RBinSection *clone = R_NEW0 (RBinSection);
				if (!clone) {
					continue;
				}
				*clone = *sec;
				clone->name = strdup (sec->name);
				r_list_append (sections, clone);
			}
		}
	}

	return sections;
}

static RList *relocs(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RList *relocs = r_list_newf ((RListFree)free);
	if (!relocs) {
		return NULL;
	}

	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach (mdt->parts, iter, part) {
		if (part->relocs) {
			RListIter *it;
			RBinReloc *rel;
			r_list_foreach (part->relocs, it, rel) {
				RBinReloc *clone = R_NEW0 (RBinReloc);
				if (!clone) {
					continue;
				}
				*clone = *rel;
				r_list_append (relocs, clone);
			}
		} else if (part->format == R_BIN_MDT_PART_ELF && part->obj.elf) {
			// Get relocs from nested ELF
			const RVector *elf_relocs = Elf_(load_relocs) (part->obj.elf);
			if (elf_relocs) {
				RBinElfReloc *erel;
				r_vector_foreach (elf_relocs, erel) {
					RBinReloc *rel = R_NEW0 (RBinReloc);
					if (!rel) {
						continue;
					}
					rel->vaddr = erel->rva + part->map->addr;
					rel->paddr = erel->offset;
					rel->type = erel->type;
					rel->addend = erel->addend;
					// Skip complex symbol resolution for now
					r_list_append (relocs, rel);
				}
			}
		}
	}

	return relocs;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static RBinInfo *info(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;

	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->file = strdup (bf->file);
	ret->type = strdup ("MDT");
	ret->bclass = strdup ("firmware");
	ret->rclass = strdup ("mdt");
	ret->os = strdup ("qcom");
	ret->subsystem = strdup ("unknown");
	ret->machine = Elf_(get_machine_name) (mdt->header);
	ret->arch = Elf_(get_arch) (mdt->header);
	ret->has_va = true;
	ret->bits = Elf_(get_bits) (mdt->header);
	ret->big_endian = Elf_(is_big_endian) (mdt->header);
	ret->dbg_info = 0;
	ret->baddr = 0;

	return ret;
}


RBinPlugin r_bin_plugin_mdt = {
	.meta = {
		.name = "mdt",
		.desc = "Qualcomm MDT firmware format",
		.license = "LGPL-3.-only",
		.author = "Rot127",
	},
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.symbols = &symbols,
	.relocs = &relocs,
	.info = &info,
	.header = &headers,
	.destroy = &destroy,
	.minstrlen = 4,
	.strfilter = 0,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdt,
	.version = R2_VERSION
};
#endif