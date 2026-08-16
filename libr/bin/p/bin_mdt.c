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

static char *headers(RBinFile *bf, int mode) {
	if (!bf || !bf->bo || !bf->bo->bin_obj || !bf->rbin) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
#define p(f,...) r_strbuf_appendf (sb, f, ##__VA_ARGS__)
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	char bits[65] = { 0 };
	size_t i;
	RListIter *iter;
	RBinMdtPart *part;

	i = 0;
	r_list_foreach (mdt->parts, iter, part) {
		r_str_bits64 (bits, qcom_p_flags (part->pflags));
		p ("==== MDT Segment %"PFMT64u" ====\n", (ut64)i);
		p ("     priv_p_flags: 0b%s:", bits);
		if (part->is_layout) {
			p (" layout");
		}
		if (part->relocatable) {
			p (" reloc");
		}
		switch (part->format) {
		default:
		case R_BIN_MDT_PART_UNIDENTIFIED:
			p (" | Unidentified\n");
			break;
		case R_BIN_MDT_PART_ELF:
			p (" | ELF\n");
			if (part->obj.elf) {
				p (" -- ELF HEADER BEGIN -- \n");
				ELFOBJ *eo = part->obj.elf;
				p ("0x00000000  MAGIC       %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					eo->ehdr.e_ident[0], eo->ehdr.e_ident[1], eo->ehdr.e_ident[2], eo->ehdr.e_ident[3],
					eo->ehdr.e_ident[4], eo->ehdr.e_ident[5], eo->ehdr.e_ident[6], eo->ehdr.e_ident[7],
					eo->ehdr.e_ident[8], eo->ehdr.e_ident[9], eo->ehdr.e_ident[10], eo->ehdr.e_ident[11],
					eo->ehdr.e_ident[12], eo->ehdr.e_ident[13], eo->ehdr.e_ident[14], eo->ehdr.e_ident[15]);
				p ("0x00000010  Type        0x%04x\n", eo->ehdr.e_type);
				p ("0x00000012  Machine     0x%04x\n", eo->ehdr.e_machine);
				p ("0x00000014  Version     0x%08x\n", eo->ehdr.e_version);
				p ("0x00000018  Entrypoint  0x%08"PFMT64x"\n", (ut64)eo->ehdr.e_entry);
				p ("0x0000001c  PhOff       0x%08"PFMT64x"\n", (ut64)eo->ehdr.e_phoff);
				p ("0x00000020  ShOff       0x%08"PFMT64x"\n", (ut64)eo->ehdr.e_shoff);
				p ("0x00000024  Flags       0x%04x\n", eo->ehdr.e_flags);
				p ("0x00000028  EhSize      %d\n", eo->ehdr.e_ehsize);
				p ("0x0000002a  PhentSize   %d\n", eo->ehdr.e_phentsize);
				p ("0x0000002c  PhNum       %d\n", eo->ehdr.e_phnum);
				p ("0x0000002e  ShentSize   %d\n", eo->ehdr.e_shentsize);
				p ("0x00000030  ShNum       %d\n", eo->ehdr.e_shnum);
				p ("0x00000032  ShStrndx    %d\n", eo->ehdr.e_shstrndx);
				p (" --- ELF HEADER END --- \n\n");
			} else {
				p (" ------- FAILED ------- \n");
			}
			break;
		case R_BIN_MDT_PART_MBN:
			p (" | MBN signature segment\n");
			if (part->obj.mbn) {
				SblHeader *mbn = (SblHeader *)part->obj.mbn;
				p (" -- MBN AUTH HEADER BEGIN -- \n");
				p ("0x00 image_id:   kMbnImageNone (0x%x)\n", 0);
				p ("0x04 version:    0x%x\n", mbn->version);
				p ("0x08 paddr:      0x%x\n", mbn->paddr);
				p ("0x0c vaddr:      0x%x\n", mbn->vaddr);
				p ("0x10 psize:      0x%x\n", mbn->psize);
				p ("0x14 code_pa:    0x%x\n", mbn->code_pa);
				p ("0x18 sign_va:    0x%x\n", mbn->sign_va);
				p ("0x1c sign_sz:    0x%x\n", mbn->sign_sz);
				p ("0x20 cert_va:    0x%x\n", mbn->cert_va);
				p ("0x24 cert_sz:    0x%x\n", mbn->cert_sz);
				p (" --- MBN AUTH HEADER END --- \n\n");
			} else {
				p (" ------- FAILED ------- \n");
			}
			break;
		}
		i++;
	}
#undef p
	return r_strbuf_drain (sb);
}

static void mdt_map_free(void *ptr) {
	RBinMap *map = (RBinMap *)ptr;
	if (map) {
		free (map->file);
		free (map);
	}
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
	part->vsize = segment->p_memsz;
	part->pflags = segment->p_flags;
	part->map = map;
	part->vfile_buf = vfile_buffer;
	part->vfile_name = strdup (part->name);

	// Check content type
	ut8 magic[4];
	if (r_buf_read_at (vfile_buffer, 0, magic, 4) == 4 &&
	    magic[0] == ELFMAG0 && magic[1] == ELFMAG1 &&
	    magic[2] == ELFMAG2 && magic[3] == ELFMAG3) {
		part->format = R_BIN_MDT_PART_ELF;
		// Load nested ELF
		part->obj.elf = Elf_(new_buf) (vfile_buffer, 0, false);
		// symbols are read from the nested ELF in symbols_vec
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
	r_unref (vfile_buffer);
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

static bool symbols_vec(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, false);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RVecRBinSymbol *ret = &bf->bo->symbols_vec;

	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach (mdt->parts, iter, part) {
		ELFOBJ *eo = part->format == R_BIN_MDT_PART_ELF? part->obj.elf: NULL;
		if (!eo || !Elf_(load_symbols) (eo) || !eo->symbols_by_ord) {
			continue;
		}
		size_t i;
		for (i = 0; i < eo->symbols_by_ord_size; i++) {
			RBinSymbol *sym = eo->symbols_by_ord[i];
			if (!sym) {
				continue;
			}
			RBinSymbol *clone = RVecRBinSymbol_emplace_back (ret);
			clone->name = r_bin_name_clone (sym->name);
			clone->vaddr = sym->vaddr + part->map->addr;
			clone->paddr = sym->paddr;
			clone->size = sym->size;
			clone->ordinal = sym->ordinal;
			clone->bind = sym->bind;
			clone->type = sym->type;
		}
	}

	return true;
}

static bool sections_vec(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, false);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RVecRBinSection_clear (&bf->bo->sections_vec);

	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach (mdt->parts, iter, part) {
		// each segment is exposed as a section
		RBinSection *sec = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		sec->name = strdup (part->name);
		sec->paddr = part->paddr;
		sec->vaddr = part->map->addr;
		sec->size = part->map->size;
		sec->vsize = part->vsize;
		sec->perm = part->pflags & 7; // R/W/X flags
		sec->is_segment = true;
	}

	return true;
}

static RVecRBinReloc *relocs(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->bo && bf->bo->bin_obj, NULL);
	const RBinMdtObj *mdt = bf->bo->bin_obj;
	RVecRBinReloc *relocs = RVecRBinReloc_new ();
	if (!relocs) {
		return NULL;
	}

	RListIter *iter;
	RBinMdtPart *part;
	r_list_foreach (mdt->parts, iter, part) {
		if (part->format != R_BIN_MDT_PART_ELF || !part->obj.elf) {
			continue;
		}
		// Get relocs from nested ELF
		const RVecRBinElfReloc *elf_relocs = Elf_(load_relocs) (part->obj.elf);
		if (!elf_relocs) {
			continue;
		}
		RBinElfReloc *erel;
		R_VEC_FOREACH (elf_relocs, erel) {
			RBinReloc *rel = RVecRBinReloc_emplace_back (relocs);
			rel->vaddr = erel->rva + part->map->addr;
			rel->paddr = erel->offset;
			rel->type = erel->type;
			rel->ntype = erel->type;
			rel->addend = erel->addend;
			// Skip complex symbol resolution for now
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
	.sections_vec = &sections_vec,
	.symbols_vec = &symbols_vec,
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
