/* radare - LGPL - Copyright 2019-2024 - GustavoLCR */

#include <r_bin.h>
#include "../format/le/le.h"

static bool check(RBinFile *bf, RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length < 2) {
		return false;
	}
	ut16 idx = r_buf_read_le16_at (b, 0x3c);
	if ((ut64)idx + 26 < length) {
		ut8 buf[2];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "LX", 2) || !memcmp (buf, "LE", 2)) {
			return true;
		}
		if (!memcmp (buf, "MZ", 2)) {
			r_buf_read_at (b, idx, buf, sizeof (buf));
			if (!memcmp (buf, "LX", 2) || !memcmp (buf, "LE", 2)) {
				return true;
			}
		}
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	RBinLEObj *res = r_bin_le_new_buf (buf);
	if (res) {
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_le_free (bf->bo->bin_obj);
}

static void header(RBinFile *bf) {
	R_RETURN_IF_FAIL (bf && bf->rbin && bf->bo && bf->bo->bin_obj);
	RBin *rbin = bf->rbin;
	RBinLEObj *bin = bf->bo->bin_obj;
	LE_image_header *h = bin->header;
	PrintfCallback p = rbin->cb_printf;
	if (!h || !p) {
		return;
	}
	p ("Signature: %2s\n", h->magic);
	p ("Byte Order: %s\n", h->border ? "Big" : "Little");
	p ("Word Order: %s\n", h->worder ? "Big" : "Little");
	p ("Format Level: %u\n", h->level);
	p ("CPU: %s\n", bin->cpu);
	p ("OS: %s\n", bin->os);
	p ("Version: %u\n", h->ver);
	p ("Flags: 0x%04x\n", h->mflags);
	p ("Pages: %u\n", h->mpages);
	p ("InitialEipObj: %u\n", h->startobj);
	p ("InitialEip: 0x%04x\n", h->eip);
	p ("InitialStackObj: %u\n", h->stackobj);
	p ("InitialEsp: 0x%04x\n", h->esp);
	p ("Page Size: 0x%04x\n", h->pagesize);
	if (bin->is_le) {
		p ("Last Page Size: 0x%04x\n", h->pageshift);
	} else {
		p ("Page Shift: 0x%04x\n", h->pageshift);
	}
	p ("Fixup Size: 0x%04x\n", h->fixupsize);
	p ("Fixup Checksum: 0x%04x\n", h->fixupsum);
	p ("Loader Size: 0x%04x\n", h->ldrsize);
	p ("Loader Checksum: 0x%04x\n", h->ldrsum);
	p ("Obj Table: 0x%04x\n", h->objtab);
	p ("Obj Count: %u\n", h->objcnt);
	p ("Obj Page Map: 0x%04x\n", h->objmap);
	p ("Obj Iter Data Map: 0x%04x\n", h->itermap);
	p ("Resource Table: 0x%04x\n", h->rsrctab);
	p ("Resource Count: %u\n", h->rsrccnt);
	p ("Resident Name Table: 0x%04x\n", h->restab);
	p ("Entry Table: 0x%04x\n", h->enttab);
	p ("Directives Table: 0x%04x\n", h->dirtab);
	p ("Directives Count: %u\n", h->dircnt);
	p ("Fixup Page Table: 0x%04x\n", h->fpagetab);
	p ("Fixup Record Table: 0x%04x\n", h->frectab);
	p ("Import Module Name Table: 0x%04x\n", h->impmod);
	p ("Import Module Name Count: %u\n", h->impmodcnt);
	p ("Import Procedure Name Table: 0x%04x\n", h->impproc);
	p ("Per-Page Checksum Table: 0x%04x\n", h->pagesum);
	p ("Enumerated Data Pages: 0x%04x\n", h->datapage);
	p ("Number of preload pages: %u\n", h->preload);
	p ("Non-resident Names Table: 0x%04x\n", h->nrestab);
	p ("Size Non-resident Names: %u\n", h->cbnrestab);
	p ("Checksum Non-resident Names: 0x%04x\n", h->nressum);
	p ("Autodata Obj: %u\n", h->autodata);
	p ("Debug Info: 0x%04x\n", h->debuginfo);
	p ("Debug Length: 0x%04x\n", h->debuglen);
	p ("Preload pages: %u\n", h->instpreload);
	p ("Demand pages: %u\n", h->instdemand);
	p ("Heap Size: 0x%04x\n", h->heapsize);
	p ("Stack Size: 0x%04x\n", h->stacksize);
}

static RList *sections(RBinFile *bf) {
	return r_bin_le_get_sections (bf->bo->bin_obj);
}

static RList *entries(RBinFile *bf) {
	return r_bin_le_get_entrypoints (bf->bo->bin_obj);
}

static RList *symbols(RBinFile *bf) {
	return r_bin_le_get_symbols (bf->bo->bin_obj);
}

static RList *imports(RBinFile *bf) {
	return r_bin_le_get_imports (bf->bo->bin_obj);
}

static RList *libs(RBinFile *bf) {
	return r_bin_le_get_libs (bf->bo->bin_obj);
}

static RList *relocs(RBinFile *bf) {
	return r_bin_le_get_relocs (bf->bo->bin_obj);
}

static RList* patch_relocs(RBinFile * bf) {
	RList *ret = r_list_newf ((RListFree)free);
	RBin *b = bf->rbin;
	RBinLEObj *bin = bf->bo->bin_obj;
	LE_image_header *h = bin->header;

	RList * all_relocs = relocs (bf);
	if (all_relocs == NULL) {
		goto beach;
	}

	RListIter * it;
	RBinReloc * original;

	r_list_foreach (all_relocs, it, original) {
		if (original->import || original->symbol) {
			continue;
		}

		RBinReloc * r = R_NEW0 (RBinReloc);
		if (!r) {
			break;
		}

		r->import = NULL;
		r->symbol = NULL;
		r->is_ifunc = false;
		r->vaddr = original->vaddr;
		r->paddr = original->paddr;
		r->laddr = original->laddr;
		r->addend = original->addend;
		r->type = original->type;

		r_list_append (ret, r);

		int size = 0, offset = 0;
		ut8 buf[8] = {0};
		switch (r->type) {
			case R_BIN_RELOC_8:
				size = 1;
				buf[0] = r->addend & 0xff;
				break;
			case R_BIN_RELOC_16:
				size = 2;
				r_write_ble16 (buf, r->addend & 0xffff, h->worder);
				break;
			case R_BIN_RELOC_32:
				size = 4;
				r_write_ble32 (buf, r->addend, h->worder);
				break;
			case R_BIN_RELOC_48:
				size = 5;
				r_write_ble64 (buf, r->addend, h->worder);
				if (h->worder) {
					offset = 3;
				}
			default:
				R_LOG_WARN ("Unsupported reloc type %d", r->type);
				break;
		}
		if (size) {
			if (!b->iob.overlay_write_at (b->iob.io, r->vaddr, buf + offset, size)) {
				R_LOG_ERROR ("write error at 0x%"PFMT64x, r->vaddr);
			}
		}
	}

end:
	r_list_free (all_relocs);

	return ret;

beach:
	r_list_free (ret);
	ret = NULL;
	goto end;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *info = R_NEW0 (RBinInfo);
	RBinLEObj *bin = bf->bo->bin_obj;
	LE_image_header *h = bin->header;
	info->bits = 32;
	info->type = strdup (bin->type);
	info->cpu = strdup (bin->cpu);
	info->os = strdup (bin->os);
	info->arch = strdup (bin->arch);
	info->file = strdup (r_str_get (bin->filename));
	info->big_endian = h->worder;
	info->has_va = true;
	info->baddr = 0;
	return info;
}

RBinPlugin r_bin_plugin_le = {
	.meta = {
		.name = "le",
		.desc = "Linear Executables from OS/2, Windows VxD and DOS extenders",
		.author = "GustavoLCR",
		.license = "LGPL-3.0-only",
	},
	.weak_guess = true,
	.check = &check,
	.load = &load,
	.destroy = &destroy,
	.info = &info,
	.header = &header,
	.sections = &sections,
	.entries = &entries,
	.symbols = &symbols,
	.imports = &imports,
	.libs = &libs,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.minstrlen = 4
	// .regstate = &regstate
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_le,
	.version = R2_VERSION
};
#endif
