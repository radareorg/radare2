/* radare - LGPL3 - 2023-2025 - murphy */

#include <r_bin.h>
#include <r_lib.h>
#include "wad/wad.h"

typedef struct {
	Sdb *kv; // we can just use bf->sdb
	WADHeader hdr;
	RBuffer *buf;
} WadObj;

static int wad_header_load(WadObj *wo, Sdb *kv) {
	if (r_buf_size (wo->buf) < sizeof (WADHeader)) {
		return false;
	}
	WADHeader *hdr = &wo->hdr;
	if (r_buf_fread_at (wo->buf, 0, (ut8 *) hdr, "iii", 1) != sizeof (WADHeader)) {
		return false;
	}
	sdb_num_set (kv, "header.num_lumps", (ut64)(hdr->numlumps), 0);
	sdb_num_set (kv, "header.diroffset", (ut64)(hdr->diroffset), 0);
	return true;
}

static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->bo;
	if (!o) {
		return NULL;
	}
	WadObj *wo = o->bin_obj;
	return wo? wo->kv: NULL;
}

static bool check(RBinFile *bf, RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, false);
	ut8 sig[4];
	if (r_buf_read_at (b, 0, sig, sizeof (sig)) != 4) {
		return false;
	}
	if (memcmp (sig, "IWAD", 4) && memcmp (sig, "PWAD", 4)) {
		return false;
	}
	return true;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	WadObj *wo = R_NEW0 (WadObj);
	R_RETURN_VAL_IF_FAIL (wo, false);
#if 0
	// we can just use bf->sdb in here
	wad_header_load (wo, bf->sdb);
#else
	wo->kv = sdb_new0 ();
	if (wo->kv) {
		wad_header_load (wo, wo->kv);
		sdb_ns_set (bf->sdb, "info", wo->kv);
	}
#endif
	wo->buf = r_buf_ref (buf);
	bf->bo->bin_obj = wo;
	return true;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
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
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static RList *symbols(RBinFile *bf) {
	RList *ret = r_list_new ();
	WAD_DIR_Entry dir;
	size_t i = 0;
	WadObj *wo = bf->bo->bin_obj;
	while (i < wo->hdr.numlumps) {
		memset (&dir, 0, sizeof (dir));
		r_buf_read_at (bf->buf, wo->hdr.diroffset + (i * 16), (ut8*)&dir, sizeof (dir));
		addsym (ret, r_str_ndup (dir.name, 8), dir.filepos, dir.size);
		i++;
	}
	return ret;
}

// Prints header info using iH
static void wad_header_fields(RBinFile *bf) {
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	cb_printf ("pf.wad_header @ 0x%08"PFMT64x"\n", (ut64)0);
	cb_printf ("0x00000000  Magic           0x%x\n", r_buf_read_le32_at (bf->buf, 0));
	cb_printf ("0x00000004  Numlumps        %d\n", r_buf_read_le32_at (bf->buf, 0x04));
	cb_printf ("0x00000008  TableOffset     0x%x\n", r_buf_read_le32_at (bf->buf, 0x08));
}

static RList *wad_fields(RBinFile *bf) {
	RList *ret = r_list_newf (free);
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
	r_buf_free (obj->buf);
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
