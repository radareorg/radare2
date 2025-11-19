/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_core.h>
#include "../i/private.h"
#include "../format/som/som.h"

static bool load(RBinFile *bf, RBuffer *buf, ut64 laddr) {
	ut64 baddr = bf->user_baddr;
	if (baddr == UT64_MAX) {
		baddr = SOM_BADDR;
	}
	bf->bo->bin_obj = r_bin_som_load_buffer (bf, buf, baddr, NULL);
	return bf->bo->bin_obj != NULL;
}

static void destroy(RBinFile *bf) {
	if (bf && bf->bo && bf->bo->bin_obj) {
		r_bin_som_free_buffer (bf->bo->bin_obj);
	}
}

static bool check(RBinFile *bf, RBuffer *buf) {
	return r_bin_som_check_buffer (buf);
}

static ut64 baddr(RBinFile *bf) {
	if (bf && bf->bo && bf->bo->bin_obj) {
		return r_bin_som_get_baddr (bf->bo->bin_obj);
	}
	return 0;
}

static RList *sections(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	return r_bin_som_get_sections (bf->bo->bin_obj);
}

static RList *entries(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	return r_bin_som_get_entries (bf->bo->bin_obj);
}

static RList *symbols(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	return r_bin_som_get_symbols (bf->bo->bin_obj);
}

static RList *imports(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	return r_bin_som_get_imports (bf->bo->bin_obj);
}

static RList *libs(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	return r_bin_som_get_libs (bf->bo->bin_obj);
}

static RList *relocs(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	return r_bin_som_get_relocs (bf->bo->bin_obj);
}

static RBinInfo *info(RBinFile *bf) {
	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	return r_bin_som_get_info (bf->bo->bin_obj);
}

static ut64 size(RBinFile *bf) {
	if (bf && bf->bo && bf->bo->bin_obj) {
		return r_bin_som_get_size (bf->bo->bin_obj);
	}
	return 0;
}

static void header(RBinFile *bf) {
	ut8 buf[64];
	if (r_buf_read_at (bf->buf, 0, buf, sizeof (buf)) == sizeof (buf)) {
		eprintf ("0x00000000  SOM MAGIC   0x%04x\n", r_read_be16 (buf + 2));
		eprintf ("0x00000002  Version     0x%08x\n", r_read_be32 (buf + 4));
		eprintf ("0x00000010  Entry Space 0x%08x\n", r_read_be32 (buf + 16));
		eprintf ("0x00000014  Entry Subsp 0x%08x\n", r_read_be32 (buf + 20));
		eprintf ("0x00000018  Entry Offs  0x%08x\n", r_read_be32 (buf + 24));
		eprintf ("0x00000024  SOM Length  0x%08x\n", r_read_be32 (buf + 36));
	}
}

static RList *fields(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)free);
#define ROW(addr, nam, fmt, cmt) r_list_append (ret, r_bin_field_new (addr, addr, value, 4, nam, cmt, fmt, false))
	ut8 buf[64];
	ut32 value = 0;
	if (r_buf_read_at (bf->buf, 0, buf, sizeof (buf)) == sizeof (buf)) {
		value = r_read_be16 (buf + 2);
		ROW (2, "SOM MAGIC", "x", "Magic number");
		value = r_read_be32 (buf + 4);
		ROW (4, "Version ID", "x", "Version identifier");
		value = r_read_be32 (buf + 16);
		ROW (16, "Entry Space", "x", "Entry point space");
		value = r_read_be32 (buf + 20);
		ROW (20, "Entry Subspace", "x", "Entry point subspace");
		value = r_read_be32 (buf + 24);
		ROW (24, "Entry Offset", "x", "Entry point offset");
		value = r_read_be32 (buf + 36);
		ROW (36, "SOM Length", "x", "Total file length");
	}
	return ret;
}

RBinPlugin r_bin_plugin_som = {
	.meta = {
		.name = "som",
		.author = "pancake",
		.desc = "HP PA-RISC SOM (System Object Model) format",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.minstrlen = 4,
	.imports = &imports,
	.info = &info,
	.fields = &fields,
	.header = &header,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_som,
	.version = R2_VERSION
};
#endif
