/* radare - LGPL3 - Copyright 2016-2025 - c0riolis, x0urc3 */

#include <r_bin.h>
#include "../format/pyc/pyc.h"

#if 0
typedef struct {
	ut64 code_start_offset;
	struct pyc_version version;
	RList *sections_cache;     // RList<RBinSection*>
	RList *interned_table;     // RList<char*>
	RList *cobjs;              // RList<pyc_code_object*>
} RBinPycObj;
#endif

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 4) {
		ut32 buf;
		r_buf_read_at (b, 0, (ut8 *)&buf, sizeof (buf));
		struct pyc_version v = get_pyc_version (buf);
		return v.magic != -1;
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	if (!check (bf, buf)) {
		return false;
	}
	ut32 m;
	r_buf_read_at (buf, 0, (ut8 *)&m, sizeof (m));
	RBinPycObj *obj = R_NEW0 (RBinPycObj);
	obj->version = get_pyc_version (m);
	bf->bo->bin_obj = obj;
	return true;
}

static ut64 get_entrypoint(RBuffer *buf, ut32 magic, ut64 *out_code_start_offset) {
	ut8 b;
	ut64 result;
	int addr;
	for (addr = 0x8; addr <= 0x10; addr += 0x4) {
		r_buf_read_at (buf, addr, &b, sizeof (b));
		if (pyc_is_code (b, magic)) {
			if (out_code_start_offset) {
				*out_code_start_offset = addr;
			}
			r_buf_seek (buf, addr + 1, R_BUF_SET);
			if ((result = pyc_get_code_object_addr (buf, magic)) == 0) {
				return addr;
			}
			return result;
		}
	}
	return 0;
}

static RBinInfo *info(RBinFile *arch) {
	RBinPycObj *obj = arch && arch->bo ? (RBinPycObj *)arch->bo->bin_obj : NULL;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (arch->file);
	ret->type = r_str_newf ("Python %s byte-compiled file", obj? obj->version.version: "");
	ret->bclass = strdup ("Python byte-compiled file");
	ret->rclass = strdup ("pyc");
	ret->arch = strdup ("pyc");
	ret->machine = r_str_newf ("Python %s VM (rev %s)", obj? obj->version.version: "",
			obj? obj->version.revision: "");
	ret->os = strdup ("any");
	ret->bits = 32; // TODO py_version_cmp (version.version, "3.6") >= 0? 32: 16;????
	ret->cpu = strdup (obj? obj->version.version: ""); // pass version info in cpu, Asm plugin will get it
	return ret;
}

static RList *sections(RBinFile *arch) {
	RBinPycObj *obj = arch && arch->bo ? (RBinPycObj *)arch->bo->bin_obj : NULL;
	return obj? obj->sections_cache: NULL;
}

static RList *entries(RBinFile *arch) {
	RBinPycObj *obj = arch && arch->bo ? (RBinPycObj *)arch->bo->bin_obj : NULL;
	RList *entries = r_list_newf ((RListFree)free);
	if (!entries) {
		return NULL;
	}
	RBinAddr *addr = R_NEW0 (RBinAddr);
	ut64 entrypoint = get_entrypoint (arch->buf, obj? obj->version.magic: 0, obj? &obj->code_start_offset: NULL);
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
	RBinPycObj *obj = arch && arch->bo ? (RBinPycObj *)arch->bo->bin_obj : NULL;
	if (!obj) {
		return NULL;
	}
	if (!obj->cobjs) {
		obj->cobjs = r_list_newf ((RListFree)free);
		if (!obj->cobjs) {
			return NULL;
		}
	}
	if (!obj->interned_table) {
		obj->interned_table = r_list_newf ((RListFree)free);
		if (!obj->interned_table) {
			return NULL;
		}
	}
	RList *sections = r_list_newf (NULL); // keep old behavior; free on destroy if needed
	if (!sections) {
		return NULL;
	}
	RList *symbols = r_list_newf ((RListFree)free);
	if (!symbols) {
		r_list_free (sections);
		return NULL;
	}
	RBuffer *buffer = arch->buf;
	if (!obj->code_start_offset) {
		// ensure code_start_offset is initialized
		(void) get_entrypoint (buffer, obj->version.magic, &obj->code_start_offset);
	}
	r_buf_seek (buffer, obj->code_start_offset, R_BUF_SET);
	pyc_get_sections_symbols (sections, symbols, obj->cobjs, buffer, obj->version.magic, obj->interned_table);
	obj->sections_cache = sections;
	return symbols;
}

static void destroy(RBinFile *bf) {
	if (!bf || !bf->bo) {
		return;
	}
	RBinPycObj *obj = (RBinPycObj *)bf->bo->bin_obj;
	if (!obj) {
		return;
	}
	r_list_free (obj->interned_table);
	r_list_free (obj->cobjs);
	// Causes Double free : r_list_free (obj->sections_cache);
	free (obj);
	bf->bo->bin_obj = NULL;
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
	.destroy = &destroy,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pyc,
	.version = R2_VERSION,
};
#endif
