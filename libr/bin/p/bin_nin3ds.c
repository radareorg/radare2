/* radare - LGPL - 2016 - a0rtega */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>

#include "nin/n3ds.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static struct n3ds_firm_hdr loaded_header;

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < sizeof(struct n3ds_firm_hdr)) return false;
	return (!memcmp(buf, "FIRM", 4));
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	return memcpy (&loaded_header, buf, sizeof(struct n3ds_firm_hdr));
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) return false;
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return true;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *sections[4] = {NULL, NULL, NULL, NULL};
	int i, corrupt = false;

	if (!(ret = r_list_new ())) return NULL;

	/* FIRM has always 4 sections, normally the 4th section is not used */
	for (i=0; i<4; i++) {
		/* Check if section is used */
		if (loaded_header.sections[i].size) {
			sections[i] = R_NEW0(RBinSection);
			/* Firmware Type ('0'=ARM9/'1'=ARM11) */
			if (loaded_header.sections[i].type == 0x0)
				strncpy(sections[i]->name, "arm9", 4);
			else if (loaded_header.sections[i].type == 0x1)
				strncpy(sections[i]->name, "arm11", 5);
			else {
				corrupt = true;
				break;
			}
			sections[i]->size = loaded_header.sections[i].size;
			sections[i]->vsize = loaded_header.sections[i].size;
			sections[i]->paddr = loaded_header.sections[i].offset;
			sections[i]->vaddr = loaded_header.sections[i].address;
			sections[i]->srwx = r_str_rwx ("mrwx");
			sections[i]->add = true;
		}
	}

	/* Append sections or free them if file is corrupt to avoid memory leaks */
	for (i=0; i<4; i++) {
		if (sections[i]) {
			if (corrupt) free(sections[i]);
			else r_list_append(ret, sections[i]);
		}
	}
	if (corrupt) {
		r_list_free(ret);
		return NULL;
	}

	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret = r_list_new ();
	RBinAddr *ptr9 = NULL, *ptr11 = NULL;

	if (arch && arch->buf) {
		if (!ret) return NULL;
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

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) return NULL;

	if (!arch || !arch->buf) {
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

struct r_bin_plugin_t r_bin_plugin_nin3ds = {
	.name = "nin3ds",
	.desc = "Nintendo 3DS FIRM format r_bin plugin",
	.license = "LGPL3",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nin3ds,
	.version = R2_VERSION
};
#endif

