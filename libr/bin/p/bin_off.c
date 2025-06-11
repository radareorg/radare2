/* radare2 - MIT - 2021-2023 - pancake */
// https://en.wikipedia.org/wiki/OS/360_Object_File_Format

#include <r_bin.h>
#include <r_lib.h>

typedef struct {
	RBuffer *buf;
} OffObj;

static bool check(RBinFile *bf, RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, false);
	ut8 sig[4];
	if (r_buf_read_at (b, 0, sig, sizeof (sig)) != 4) {
		return false;
	}
	if (memcmp (sig, "\xc9\xc5\xe6\xd7 ", 4)) {
		return false;
	}
	return true;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	bf->bo->bin_obj = R_NEW0 (OffObj);
	return true;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("OFF");
	ret->machine = strdup ("s360");
	ret->os = strdup ("Z/OS");
	ret->arch = strdup ("s390");
	ret->cpu = strdup ("zarch");
	ret->bits = 64;
	ret->big_endian = true;
	ret->has_va = false;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

// Prints header info using iH
static void off_header_fields(RBinFile *bf) {
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	cb_printf ("pf.off_header @ 0x%08"PFMT64x"\n", (ut64)0);
	cb_printf ("0x00000000  Magic           0x%x\n", r_buf_read_le32_at (bf->buf, 0));
}

static RList *off_fields(RBinFile *bf) {
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
	ROW ("off_magic", 4, magic, "[4]c");
	ROW ("numlumps", 4, numlumps, "i");
	ROW ("table_offset", 4, table_offset, "x");
	return ret;
}

static void destroy(RBinFile *bf) {
	OffObj *obj = bf->bo->bin_obj;
	r_buf_free (obj->buf);
	free (obj);
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = ptr->vaddr = 0x1928;
	r_list_append (ret, ptr);
	return ret;
}

RBinPlugin r_bin_plugin_off = {
	.meta = {
		.name = "off",
		.desc = "OS/360 Object Files",
		.license = "MIT",
		.author = "pancake",
	},
	.entries = entries,
	.check = &check,
	.load = &load,
	.baddr = &baddr,
	.info = &info,
	.header = &off_header_fields,
	.fields = &off_fields,
	.destroy = &destroy
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_off,
	.version = R2_VERSION
};
#endif
