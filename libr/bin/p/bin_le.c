/* radare - LGPL - Copyright 2019 - GustavoLCR */

#include <r_bin.h>
#include "../format/le/le.h"

static bool check_buffer(RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length <= 0x3d) {
		return false;
	}
	ut16 idx = r_buf_read_le16_at (b, 0x3c);
	if ((ut64)idx + 26 < length) {
		ut8 buf[2];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "LX", 2) || !memcmp (buf, "LE", 2)) {
			return true;
		} else if (!memcmp (buf, "MZ", 2)) {
			r_buf_read_at (b, idx, buf, sizeof (buf));
			if (!memcmp (buf, "LX", 2) || !memcmp (buf, "LE", 2)) {
				return true;
			}
		}
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (bf && bin_obj && buf, false);
	r_bin_le_obj_t *res = r_bin_le_new_buf (buf);
	if (res) {
		*bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_le_free (bf->o->bin_obj);
}

static void header(RBinFile *bf) {
	RBin *rbin = bf->rbin;
	r_bin_le_obj_t *bin = bf->o->bin_obj;
	LE_image_header *h = bin->header;
	rbin->cb_printf("Signature: %2s\n", h->magic);
	rbin->cb_printf("Byte Order: %s\n", h->border ? "Big" : "Little");
	rbin->cb_printf("Word Order: %s\n", h->worder ? "Big" : "Little");
	rbin->cb_printf("Format Level: %u\n", h->level);
	rbin->cb_printf("CPU: %s\n", bin->cpu);
	rbin->cb_printf("OS: %s\n", bin->os);
	rbin->cb_printf("Version: %u\n", h->ver);
	rbin->cb_printf("Flags: 0x%04x\n", h->mflags);
	rbin->cb_printf("Pages: %u\n", h->mpages);
	rbin->cb_printf("InitialEipObj: %u\n", h->startobj);
	rbin->cb_printf("InitialEip: 0x%04x\n", h->eip);
	rbin->cb_printf("InitialStackObj: %u\n", h->stackobj);
	rbin->cb_printf("InitialEsp: 0x%04x\n", h->esp);
	rbin->cb_printf("Page Size: 0x%04x\n", h->pagesize);
	if (bin->is_le) {
		rbin->cb_printf("Last Page Size: 0x%04x\n", h->pageshift);
	} else {
		rbin->cb_printf("Page Shift: 0x%04x\n", h->pageshift);
	}
	rbin->cb_printf("Fixup Size: 0x%04x\n", h->fixupsize);
	rbin->cb_printf("Fixup Checksum: 0x%04x\n", h->fixupsum);
	rbin->cb_printf("Loader Size: 0x%04x\n", h->ldrsize);
	rbin->cb_printf("Loader Checksum: 0x%04x\n", h->ldrsum);
	rbin->cb_printf("Obj Table: 0x%04x\n", h->objtab);
	rbin->cb_printf("Obj Count: %u\n", h->objcnt);
	rbin->cb_printf("Obj Page Map: 0x%04x\n", h->objmap);
	rbin->cb_printf("Obj Iter Data Map: 0x%04x\n", h->itermap);
	rbin->cb_printf("Resource Table: 0x%04x\n", h->rsrctab);
	rbin->cb_printf("Resource Count: %u\n", h->rsrccnt);
	rbin->cb_printf("Resident Name Table: 0x%04x\n", h->restab);
	rbin->cb_printf("Entry Table: 0x%04x\n", h->enttab);
	rbin->cb_printf("Directives Table: 0x%04x\n", h->dirtab);
	rbin->cb_printf("Directives Count: %u\n", h->dircnt);
	rbin->cb_printf("Fixup Page Table: 0x%04x\n", h->fpagetab);
	rbin->cb_printf("Fixup Record Table: 0x%04x\n", h->frectab);
	rbin->cb_printf("Import Module Name Table: 0x%04x\n", h->impmod);
	rbin->cb_printf("Import Module Name Count: %u\n", h->impmodcnt);
	rbin->cb_printf("Import Procedure Name Table: 0x%04x\n", h->impproc);
	rbin->cb_printf("Per-Page Checksum Table: 0x%04x\n", h->pagesum);
	rbin->cb_printf("Enumerated Data Pages: 0x%04x\n", h->datapage);
	rbin->cb_printf("Number of preload pages: %u\n", h->preload);
	rbin->cb_printf("Non-resident Names Table: 0x%04x\n", h->nrestab);
	rbin->cb_printf("Size Non-resident Names: %u\n", h->cbnrestab);
	rbin->cb_printf("Checksum Non-resident Names: 0x%04x\n", h->nressum);
	rbin->cb_printf("Autodata Obj: %u\n", h->autodata);
	rbin->cb_printf("Debug Info: 0x%04x\n", h->debuginfo);
	rbin->cb_printf("Debug Length: 0x%04x\n", h->debuglen);
	rbin->cb_printf("Preload pages: %u\n", h->instpreload);
	rbin->cb_printf("Demand pages: %u\n", h->instdemand);
	rbin->cb_printf("Heap Size: 0x%04x\n", h->heapsize);
	rbin->cb_printf("Stack Size: 0x%04x\n", h->stacksize);
}

static RList *sections(RBinFile *bf) {
	return r_bin_le_get_sections (bf->o->bin_obj);
}

static RList *entries(RBinFile *bf) {
	return r_bin_le_get_entrypoints (bf->o->bin_obj);
}

static RList *symbols(RBinFile *bf) {
	return r_bin_le_get_symbols (bf->o->bin_obj);
}

static RList *imports(RBinFile *bf) {
	return r_bin_le_get_imports (bf->o->bin_obj);
}

static RList *libs(RBinFile *bf) {
	return r_bin_le_get_libs (bf->o->bin_obj);
}

static RList *relocs(RBinFile *bf) {
	return r_bin_le_get_relocs (bf->o->bin_obj);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *info = R_NEW0 (RBinInfo);
	if (info) {
		r_bin_le_obj_t *bin = bf->o->bin_obj;
		LE_image_header *h = bin->header;
		info->bits = 32;
		info->type = strdup (bin->type);
		info->cpu = strdup (bin->cpu);
		info->os = strdup (bin->os);
		info->arch = strdup (bin->arch);
		info->file = strdup (bin->filename);
		info->big_endian = h->worder;
		info->has_va = true;
		info->baddr = 0;
	}
	return info;
}

RBinPlugin r_bin_plugin_le = {
	.name = "le",
	.desc = "LE/LX format r2 plugin",
	.author = "GustavoLCR",
	.license = "LGPL3",
	.check_buffer = &check_buffer,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.info = &info,
	.header = &header,
	.sections = &sections,
	.entries = &entries,
	.symbols = &symbols,
	.imports = &imports,
	.libs = &libs,
	.relocs = &relocs,
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
