/* radare - LGPL3 - 2023-2025 - murphy */

#include <r_bin.h>
#include <r_lib.h>
#include "wad/wad.h"

typedef struct {
	Sdb *kv;
	WADHeader hdr;
	RBuffer *buf;
} WadObj;

static bool wad_header_load(WadObj *wo) {
	if (r_buf_size (wo->buf) < sizeof (WADHeader)) {
		return false;
	}
	if (r_buf_fread_at (wo->buf, 0, (ut8 *)&wo->hdr, "iii", 1) != sizeof (WADHeader)) {
		return false;
	}
	sdb_num_set (wo->kv, "header.num_lumps", wo->hdr.numlumps, 0);
	sdb_num_set (wo->kv, "header.diroffset", wo->hdr.diroffset, 0);
	return true;
}

static Sdb *get_sdb(RBinFile *bf) {
	WadObj *wo = (WadObj *)R_UNWRAP3 (bf, bo, bin_obj);
	return wo ? wo->kv : NULL;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 sig[4];
	if (r_buf_read_at (b, 0, sig, sizeof (sig)) != 4) {
		return false;
	}
	return !memcmp (sig, "IWAD", 4) || !memcmp (sig, "PWAD", 4);
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	WadObj *wo = R_NEW0 (WadObj);
	wo->buf = r_ref (buf);
	wo->kv = sdb_new0 ();
	if (wo->kv && wad_header_load (wo)) {
		sdb_ns_set (bf->sdb, "info", wo->kv);
	}
	bf->bo->bin_obj = wo;
	return true;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("WAD");
	ret->machine = strdup ("DOOM Engine");
	ret->os = strdup ("DOOM Engine");
	ret->arch = strdup ("any");
	ret->bits = 32;
	ret->has_va = false;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static void addsym(RList *ret, char *name, ut64 addr, ut32 size) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	ptr->name = r_bin_name_new_from (name);
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	r_list_append (ret, ptr);
}

static RList *symbols(RBinFile *bf) {
	RList *ret = r_list_new ();
	WadObj *wo = bf->bo->bin_obj;
	ut64 bsize = r_buf_size (bf->buf);
	ut32 numlumps = wo->hdr.numlumps;
	ut32 diroff = wo->hdr.diroffset;
	if (diroff >= bsize || numlumps > (bsize - diroff) / sizeof (WAD_DIR_Entry)) {
		return ret;
	}
	size_t i;
	for (i = 0; i < numlumps; i++) {
		ut64 off = diroff + (i * sizeof (WAD_DIR_Entry));
		ut32 filepos = r_buf_read_le32_at (bf->buf, off);
		ut32 sz = r_buf_read_le32_at (bf->buf, off + 4);
		char name[9] = {0};
		r_buf_read_at (bf->buf, off + 8, (ut8 *)name, 8);
		addsym (ret, r_str_ndup (name, 8), filepos, sz);
	}
	return ret;
}

static char *wad_header_fields(RBinFile *bf, int mode) {
	RStrBuf *sb = r_strbuf_new ("");
#define p(f,...) r_strbuf_appendf (sb, f, ##__VA_ARGS__)
	p ("pf.wad_header @ 0x%08"PFMT64x"\n", (ut64)0);
	p ("0x00000000  Magic           0x%x\n", r_buf_read_le32_at (bf->buf, 0));
	p ("0x00000004  Numlumps        %d\n", r_buf_read_le32_at (bf->buf, 0x04));
	p ("0x00000008  TableOffset     0x%x\n", r_buf_read_le32_at (bf->buf, 0x08));
#undef p
	return r_strbuf_drain (sb);
}

static RList *wad_fields(RBinFile *bf) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	ut64 addr = 0;
#define ROW(nam,siz,val,fmt) \
	r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, NULL, fmt, false)); \
	addr += siz;
	ut32 magic = r_buf_read_le32 (bf->buf);
	ut32 numlumps = r_buf_read_le32 (bf->buf);
	ut32 table_offset = r_buf_read_le32 (bf->buf);
	ROW ("wad_magic", 4, magic, "[4]c");
	ROW ("numlumps", 4, numlumps, "i");
	ROW ("table_offset", 4, table_offset, "x");
	return ret;
}

static void destroy(RBinFile *bf) {
	WadObj *obj = bf->bo->bin_obj;
	sdb_free (obj->kv);
	r_unref (obj->buf);
	free (obj);
}

RBinPlugin r_bin_plugin_wad = {
	.meta = {
		.name = "wad",
		.desc = "DOOM WAD Maps",
		.license = "LGPL-3.0-only",
		.author = "murphy",
	},
	.get_sdb = &get_sdb,
	.symbols = &symbols,
	.check = &check,
	.load = &load,
	.baddr = &baddr,
	.info = &info,
	.header = &wad_header_fields,
	.fields = &wad_fields,
	.destroy = &destroy
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_wad,
	.version = R2_VERSION
};
#endif
