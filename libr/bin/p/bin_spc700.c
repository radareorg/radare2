/* radare - LGPL - 2015-2016 - maijin */

#include <r_bin.h>
#include <r_lib.h>
#include "../format/spc700/spc_specs.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 27) {
		return false;
	}
	return !memcmp (buf, SPC_MAGIC, 27);
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	spc_hdr spchdr;
	memset (&spchdr, 0, SPC_HDR_SIZE);
	int reat = r_buf_read_at (arch->buf, 0, (ut8*)&spchdr, SPC_HDR_SIZE);
	if (reat != SPC_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->type = strdup ("Sound File Data");
	ret->machine = strdup ("SPC700");
	ret->os = strdup ("spc700");
	ret->arch = strdup ("spc700");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	spc_hdr spchdr;
	memset (&spchdr, 0, SPC_HDR_SIZE);
	int reat = r_buf_read_at (arch->buf, 0, (ut8*)&spchdr, SPC_HDR_SIZE);
	if (reat != SPC_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinSection))) {
		r_list_free (ret);
		return NULL;
	}
	strcpy (ptr->name, "RAM");
	ptr->paddr = RAM_START_ADDRESS;
	ptr->size = RAM_SIZE;
	ptr->vaddr = 0x0;
	ptr->vsize = RAM_SIZE;
	ptr->srwx = R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = RAM_START_ADDRESS;
	ptr->vaddr = 0;
	r_list_append (ret, ptr);
	return ret;
}

RBinPlugin r_bin_plugin_spc700 = {
	.name = "spc700",
	.desc = "SNES-SPC700 Sound File Data",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_spc700,
	.version = R2_VERSION
};
#endif
