/* radare - LGPL - 2018-2019 - a0rtega */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>

#include "nin/n3ds.h"

static struct n3ds_firm_hdr loaded_header;

static bool check_buffer(RBuffer *b) {
	ut8 magic[4];
	r_buf_read_at (b, 0, magic, sizeof (magic));
	return (!memcmp (magic, "FIRM", 4));
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb) {
	if (r_buf_read_at (b, 0, (ut8*)&loaded_header, sizeof (loaded_header)) == sizeof (loaded_header)) {
		*bin_obj = &loaded_header;
		return true;
	}
	return false;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *sections[4] = {
		NULL, NULL, NULL, NULL
	};
	int i, corrupt = false;

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	/* FIRM has always 4 sections, normally the 4th section is not used */
	for (i = 0; i < 4; i++) {
		/* Check if section is used */
		if (loaded_header.sections[i].size) {
			sections[i] = R_NEW0 (RBinSection);
			/* Firmware Type ('0'=ARM9/'1'=ARM11) */
			if (loaded_header.sections[i].type == 0x0) {
				sections[i]->name = strdup ("arm9");
			} else if (loaded_header.sections[i].type == 0x1) {
				sections[i]->name = strdup ("arm11");
			} else {
				corrupt = true;
				break;
			}
			sections[i]->size = loaded_header.sections[i].size;
			sections[i]->vsize = loaded_header.sections[i].size;
			sections[i]->paddr = loaded_header.sections[i].offset;
			sections[i]->vaddr = loaded_header.sections[i].address;
			sections[i]->perm = r_str_rwx ("rwx");
			sections[i]->add = true;
		}
	}

	/* Append sections or free them if file is corrupt to avoid memory leaks */
	for (i = 0; i < 4; i++) {
		if (sections[i]) {
			if (corrupt) {
				free (sections[i]);
			} else {
				r_list_append (ret, sections[i]);
			}
		}
	}
	if (corrupt) {
		r_list_free (ret);
		return NULL;
	}

	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_new ();
	RBinAddr *ptr9 = NULL, *ptr11 = NULL;

	if (bf && bf->buf) {
		if (!ret) {
			return NULL;
		}
		ret->free = free;
		if (!(ptr9 = R_NEW0 (RBinAddr))) {
			r_list_free (ret);
			return NULL;
		}
		if (!(ptr11 = R_NEW0 (RBinAddr))) {
			r_list_free (ret);
			free (ptr9);
			return NULL;
		}

		/* ARM9 entry point */
		ptr9->vaddr = loaded_header.arm9_ep;
		r_list_append (ret, ptr9);

		/* ARM11 entry point */
		ptr11->vaddr = loaded_header.arm11_ep;
		r_list_append (ret, ptr11);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}

	if (!bf || !bf->buf) {
		free (ret);
		return NULL;
	}

	ret->type = strdup ("FIRM");
	ret->machine = strdup ("Nintendo 3DS");
	ret->os = strdup ("n3ds");
	ret->arch = strdup ("arm");
	ret->has_va = true;
	ret->bits = 32;

	return ret;
}

RBinPlugin r_bin_plugin_nin3ds = {
	.name = "nin3ds",
	.desc = "Nintendo 3DS FIRM format r_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nin3ds,
	.version = R2_VERSION
};
#endif
