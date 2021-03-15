/* radare - LGPL - Copyright 2019 - GustavoLCR */

#include <r_bin.h>
#include "../format/le/le.h"

static bool check_buffer(RBuffer *b) {
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
	r_return_if_fail (bf && bf->rbin && bf->o && bf->o->bin_obj);
	RBin *rbin = bf->rbin;
	r_bin_le_obj_t *bin = bf->o->bin_obj;
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
		info->file = strdup (r_str_get (bin->filename));
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
