/* radare - LGPL - 2018-2025 - a0rtega */

#include <r_bin.h>
#include "nin/n3ds.h"

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 magic[4];
	r_buf_read_at (b, 0, magic, sizeof (magic));
	return (!memcmp (magic, "FIRM", 4));
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	struct n3ds_firm_hdr *loaded_header = R_NEW0 (struct n3ds_firm_hdr);
	if (r_buf_read_at (b, 0, (ut8*)loaded_header, sizeof (*loaded_header)) == sizeof (*loaded_header)) {
		bf->bo->bin_obj = loaded_header;
		return true;
	}
	return false;
}

static bool sections_vec(RBinFile *bf) {
	struct n3ds_firm_hdr *loaded_header = (void*)bf->bo->bin_obj;
	RVecRBinSection_clear (&bf->bo->sections_vec);

	/* FIRM has always 4 sections, normally the 4th section is not used */
	int i;
	for (i = 0; i < 4; i++) {
		/* Check if section is used */
		if (loaded_header->sections[i].size) {
			RBinSection *section = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
			if (!section) {
				return false;
			}
			/* Firmware Type ('0'=ARM9/'1'=ARM11) */
			if (loaded_header->sections[i].type == 0x0) {
				section->name = strdup ("arm9");
			} else if (loaded_header->sections[i].type == 0x1) {
				section->name = strdup ("arm11");
			} else {
				RVecRBinSection_clear (&bf->bo->sections_vec);
				return false;
			}
			section->size = loaded_header->sections[i].size;
			section->vsize = loaded_header->sections[i].size;
			section->paddr = loaded_header->sections[i].offset;
			section->vaddr = loaded_header->sections[i].address;
			section->perm = r_str_rwx ("rwx");
			section->add = true;
		}
	}

	return true;
}

static RList *entries(RBinFile *bf) {
	struct n3ds_firm_hdr *loaded_header = (void*)bf->bo->bin_obj;
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RBinAddr *ptr9 = R_NEW0 (RBinAddr);
	ptr9->vaddr = loaded_header->arm9_ep;
	r_list_append (ret, ptr9);

	RBinAddr *ptr11 = R_NEW0 (RBinAddr);
	ptr11->vaddr = loaded_header->arm11_ep;
	r_list_append (ret, ptr11);
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->type = strdup ("FIRM");
	ret->machine = strdup ("Nintendo 3DS");
	ret->os = strdup ("n3ds");
	ret->arch = strdup ("arm");
	ret->has_va = true;
	ret->bits = 32;

	return ret;
}

RBinPlugin r_bin_plugin_nin3ds = {
	.meta = {
		.name = "nin3ds",
		.author = "a0rtega",
		.desc = "Nintendo 3DS Firmware",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.check = &check,
	.entries = &entries,
	.sections_vec = &sections_vec,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nin3ds,
	.version = R2_VERSION
};
#endif
