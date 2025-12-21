/* radare - LGPL3 - Copyright 2016-2025 - c0riolis, x0urc3 */

#include <r_bin.h>
#include "../format/pyc/pyc.h"

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
			if ((result = get_code_object_addr (buf, magic)) == 0) {
				return addr;
			}
			return result;
		}
	}
	return 0;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinPycObj *obj = (RBinPycObj *)R_UNWRAP3 (bf, bo, bin_obj);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = r_str_newf ("Python %s byte-compiled file", obj ? obj->version.version : "");
	ret->bclass = strdup ("Python byte-compiled file");
	ret->rclass = strdup ("pyc");
	ret->arch = strdup ("pyc");
	ret->machine = r_str_newf ("Python %s VM (rev %s)", obj ? obj->version.version : "",
		obj ? obj->version.revision : "");
	ret->os = strdup ("any");
	ret->bits = 32; // TODO py_version_cmp (version.version, "3.6") >= 0? 32: 16;????
	ret->cpu = strdup (obj ? obj->version.version : ""); // pass version info in cpu, Asm plugin will get it
	return ret;
}

static RList *sections(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinPycObj *obj = (RBinPycObj *)R_UNWRAP3 (bf, bo, bin_obj);
	return obj ? obj->sections_cache : NULL;
}

static RList *entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinPycObj *obj = R_UNWRAP3 (bf, bo, bin_obj);
	RList *entries = r_list_newf ((RListFree)free);
	RBinAddr *addr = R_NEW0 (RBinAddr);
	ut64 ep = get_entrypoint (bf->buf, obj ? obj->version.magic : 0, obj ? &obj->code_start_offset : NULL);
	addr->paddr = ep;
	addr->vaddr = ep;
	r_buf_seek (bf->buf, ep, R_IO_SEEK_SET);
	r_list_append (entries, addr);
	return entries;
}

static RList *symbols(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinPycObj *obj = R_UNWRAP3 (bf, bo, bin_obj);
	if (!obj) {
		return NULL;
	}
	if (!obj->cobjs) {
		obj->cobjs = r_list_newf ((RListFree)free);
	}
	if (!obj->interned_table) {
		obj->interned_table = r_list_newf ((RListFree)free);
	}
	RList *sections = r_list_newf (NULL); // keep old behavior; free on destroy if needed
	RList *symbols = r_list_newf ((RListFree)free);
	RBuffer *buffer = bf->buf;
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
	if (obj) {
		bf->bo->bin_obj = NULL;
		r_list_free (obj->interned_table);
		r_list_free (obj->cobjs);
		// sections_cache is handled by RBin core
		free (obj);
	}
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
