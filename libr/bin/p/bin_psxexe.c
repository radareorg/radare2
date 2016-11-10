/* radare - LGPL - Copyright 2015-2016 - Dax89, pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "psxexe/psxexe.h"

static int check_bytes(const ut8 *buf, ut64 length);

static void* load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || (length < PSXEXE_ID_LEN)) {
		return false;
	}
	return !memcmp (buf, PSXEXE_ID, PSXEXE_ID_LEN);
}

static int check(RBinFile *arch) {
	if (!arch || !arch->buf) {
		return false;
	}
	return check_bytes (r_buf_buffer (arch->buf), r_buf_size (arch->buf));
}

static RBinInfo* info(RBinFile* arch) {
	RBinInfo* ret = NULL;
	psxexe_header psxheader;

	if (r_buf_read_at (arch->buf, 0, (ut8*)&psxheader, sizeof(psxexe_header)) < sizeof(psxexe_header)) {
		eprintf ("Truncated Header\n");
		return NULL;
	}

	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;

	ret->file = strdup (arch->file);
	ret->type = strdup ("Sony PlayStation 1 Executable");
	ret->machine = strdup ("Sony PlayStation 1");
	ret->os = strdup ("psx");
	ret->arch = strdup ("mips");
	ret->bits = 32;
	ret->has_va = true;
	return ret;
}

static RList* sections(RBinFile* arch) {
	RList* ret = NULL;
	RBinSection* sect = NULL;
	psxexe_header psxheader;
	ut64 sz = 0;

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	if(!(sect = R_NEW0 (RBinSection))) {
		r_list_free (ret);
		return NULL;
	}

	if (r_buf_fread_at (arch->buf, 0, (ut8*)&psxheader, "8c17i", 1) < sizeof (psxexe_header)) {
		eprintf ("Truncated Header\n");
		free (sect);
		r_list_free (ret);
		return NULL;
	}

	sz = r_buf_size (arch->buf);

	strcpy (sect->name, "TEXT");
	sect->paddr = PSXEXE_TEXTSECTION_OFFSET;
	sect->size = sz - PSXEXE_TEXTSECTION_OFFSET;
	sect->vaddr = psxheader.t_addr;
	sect->vsize = psxheader.t_size;
	sect->srwx = R_BIN_SCN_MAP | R_BIN_SCN_EXECUTABLE;
	sect->add = true;
	sect->has_strings = true;

	r_list_append (ret, sect);
	return ret;
}

static RList* entries(RBinFile* arch) {
	RList* ret = NULL;
	RBinAddr* addr = NULL;
	psxexe_header psxheader;

	if (!(ret = r_list_new ()))
		return NULL;

	if(!(addr = R_NEW0 (RBinAddr))) {
		r_list_free (ret);
		return NULL;
	}

	if (r_buf_fread_at (arch->buf, 0, (ut8*)&psxheader, "8c17i", 1) < sizeof (psxexe_header)) {
		eprintf ("Truncated Header\n");
		r_list_free (ret);
		return NULL;
	}

	addr->paddr = (psxheader.pc0 - psxheader.t_addr) + PSXEXE_TEXTSECTION_OFFSET;
	addr->vaddr = psxheader.pc0;

	r_list_append (ret, addr);
	return ret;
}

RBinPlugin r_bin_plugin_psxexe = {
	.name = "psxexe",
	.desc = "Sony PlayStation 1 Executable",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.info = &info,
	.sections = &sections,
	.entries = &entries,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_psxexe,
	.version = R2_VERSION
};
#endif
