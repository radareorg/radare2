/* radare - LGPL3 - 2019 - thestr4ng3r */

#include <r_bin.h>
#include <r_lib.h>

static bool check_buffer(RBuffer *b) {
	// no magic
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return true;
}

static ut64 baddr(RBinFile *bf) {
	ut16 base = r_buf_read_le16_at (bf->buf, 0);
	return base != UT16_MAX ? base : 0;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("PRG");
	ret->machine = strdup ("Commodore 64");
	ret->os = strdup ("c64");
	ret->arch = strdup ("6502");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)r_bin_section_free);
	if (!ret) {
		return NULL;
	}
	ut64 sz = r_buf_size (bf->buf);
	if (sz < 2) {
		return ret;
	}
	RBinSection *section = R_NEW0 (RBinSection);
	if (!section) {
		return ret;
	}
	section->name = strdup ("prg");
	section->paddr = 2;
	section->size = sz - 2;
	section->vaddr = baddr (bf);
	section->vsize = sz - 2;
	section->perm = R_PERM_RWX;
	section->add = true;
	r_list_append (ret, section);
	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RBinAddr *binaddr = R_NEW0 (RBinAddr);
	if (!binaddr) {
		return ret;
	}
	binaddr->paddr = 2;
	binaddr->vaddr = baddr (bf);
	r_list_append (ret, binaddr);
	return ret;
}

RBinPlugin r_bin_plugin_prg = {
	.name = "prg",
	.desc = "C64 PRG",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.baddr = baddr,
	.check_buffer = check_buffer,
	.entries = entries,
	.sections = sections,
	.info = info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_prg,
	.version = R2_VERSION
};
#endif
