/* radare - LGPL3 - Copyright 2016-2023 - c0riolis, x0urc3 */

#include <r_bin.h>
#include "../format/pyc/pyc.h"

static R_TH_LOCAL ut64 code_start_offset = 0;
static R_TH_LOCAL struct pyc_version version;
static R_TH_LOCAL RList *sections_cache = NULL;
RList R_TH_LOCAL *interned_table = NULL; // used from marshall.c

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 4) {
		ut32 buf;
		r_buf_read_at (b, 0, (ut8 *)&buf, sizeof (buf));
		version = get_pyc_version (buf);
		return version.magic != -1;
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	return check (bf, buf);
}

static ut64 get_entrypoint(RBuffer *buf) {
	ut8 b;
	ut64 result;
	int addr;
	for (addr = 0x8; addr <= 0x10; addr += 0x4) {
		r_buf_read_at (buf, addr, &b, sizeof (b));
		if (pyc_is_code (b, version.magic)) {
			code_start_offset = addr;
			r_buf_seek (buf, addr + 1, R_BUF_SET);
			if ((result = get_code_object_addr (buf, version.magic)) == 0) {
				return addr;
			}
			return result;
		}
	}
	return 0;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->type = r_str_newf ("Python %s byte-compiled file", version.version);
	ret->bclass = strdup ("Python byte-compiled file");
	ret->rclass = strdup ("pyc");
	ret->arch = strdup ("pyc");
	ret->machine = r_str_newf ("Python %s VM (rev %s)", version.version,
		version.revision);
	ret->os = strdup ("any");
	ret->bits = 32; // TODO py_version_cmp (version.version, "3.6") >= 0? 32: 16;????
	ret->cpu = strdup (version.version); // pass version info in cpu, Asm plugin will get it
	return ret;
}

static RList *sections(RBinFile *arch) {
	return sections_cache;
}

static RList *entries(RBinFile *arch) {
	RList *entries = r_list_newf ((RListFree)free);
	if (!entries) {
		return NULL;
	}
	RBinAddr *addr = R_NEW0 (RBinAddr);
	if (!addr) {
		r_list_free (entries);
		return NULL;
	}
	ut64 entrypoint = get_entrypoint (arch->buf);
	addr->paddr = entrypoint;
	addr->vaddr = entrypoint;
	r_buf_seek (arch->buf, entrypoint, R_IO_SEEK_SET);
	r_list_append (entries, addr);
	return entries;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static RList *symbols(RBinFile *arch) {
	RList *shared = r_list_newf ((RListFree)r_list_free);
	if (!shared) {
		return NULL;
	}
	RList *cobjs = r_list_newf ((RListFree)free);
	if (!cobjs) {
		r_list_free (shared);
		return NULL;
	}
	interned_table = r_list_newf ((RListFree)free);
	if (!interned_table) {
		r_list_free (shared);
		r_list_free (cobjs);
		return NULL;
	}
	r_list_append (shared, cobjs);
	r_list_append (shared, interned_table);
	arch->bo->bin_obj = shared;
	RList *sections = r_list_newf (NULL); // (RListFree)free);
	if (!sections) {
		r_list_free (shared);
		arch->bo->bin_obj = NULL;
		return NULL;
	}
	RList *symbols = r_list_newf ((RListFree)free);
	if (!symbols) {
		r_list_free (shared);
		arch->bo->bin_obj = NULL;
		r_list_free (sections);
		return NULL;
	}
	RBuffer *buffer = arch->buf;
	r_buf_seek (buffer, code_start_offset, R_BUF_SET);
	pyc_get_sections_symbols (sections, symbols, cobjs, buffer, version.magic);
	sections_cache = sections;
	return symbols;
}

RBinPlugin r_bin_plugin_pyc = {
	.meta = {
		.name = "pyc",
		.author = "c0riolis,x0urc3",
		.desc = "Python byte-compiled",
		.license = "LGPL-3.0-only",
	},
	.info = &info,
	.load = &load,
	.check = &check,
	.entries = &entries,
	.sections = &sections,
	.baddr = &baddr,
	.symbols = &symbols,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pyc,
	.version = R2_VERSION,
};
#endif
