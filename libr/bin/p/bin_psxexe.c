/* radare - LGPL - Copyright 2015-2018 - Dax89, pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"
#include "psxexe/psxexe.h"

static bool check_buffer(RBuffer *b) {
	ut8 magic[PSXEXE_ID_LEN];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) == PSXEXE_ID_LEN) {
		return !memcmp (magic, PSXEXE_ID, PSXEXE_ID_LEN);
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (b);
}

static RBinInfo* info(RBinFile* bf) {
	RBinInfo* ret = NULL;
	psxexe_header psxheader;

	if (r_buf_read_at (bf->buf, 0, (ut8*)&psxheader, sizeof(psxexe_header)) < sizeof(psxexe_header)) {
		eprintf ("Truncated Header\n");
		return NULL;
	}

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}

	ret->file = strdup (bf->file);
	ret->type = strdup ("Sony PlayStation 1 Executable");
	ret->machine = strdup ("Sony PlayStation 1");
	ret->os = strdup ("psx");
	ret->arch = strdup ("mips");
	ret->bits = 32;
	ret->has_va = true;
	return ret;
}

static RList* sections(RBinFile* bf) {
	RList* ret = NULL;
	RBinSection* sect = NULL;
	psxexe_header psxheader;
	ut64 sz = 0;

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	if (!(sect = R_NEW0 (RBinSection))) {
		r_list_free (ret);
		return NULL;
	}

	if (r_buf_fread_at (bf->buf, 0, (ut8*)&psxheader, "8c17i", 1) < sizeof (psxexe_header)) {
		eprintf ("Truncated Header\n");
		free (sect);
		r_list_free (ret);
		return NULL;
	}

	sz = r_buf_size (bf->buf);

	sect->name = strdup ("TEXT");
	sect->paddr = PSXEXE_TEXTSECTION_OFFSET;
	sect->size = sz - PSXEXE_TEXTSECTION_OFFSET;
	sect->vaddr = psxheader.t_addr;
	sect->vsize = psxheader.t_size;
	sect->perm = R_PERM_RX;
	sect->add = true;
	sect->has_strings = true;

	r_list_append (ret, sect);
	return ret;
}

static RList* entries(RBinFile* bf) {
	RList* ret = NULL;
	RBinAddr* addr = NULL;
	psxexe_header psxheader;

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	if (!(addr = R_NEW0 (RBinAddr))) {
		r_list_free (ret);
		return NULL;
	}

	if (r_buf_fread_at (bf->buf, 0, (ut8*)&psxheader, "8c17i", 1) < sizeof (psxexe_header)) {
		eprintf ("PSXEXE Header truncated\n");
		r_list_free (ret);
		free (addr);
		return NULL;
	}

	addr->paddr = (psxheader.pc0 - psxheader.t_addr) + PSXEXE_TEXTSECTION_OFFSET;
	addr->vaddr = psxheader.pc0;

	r_list_append (ret, addr);
	return ret;
}

static RList* strings(RBinFile* bf) {
	// hardcode minstrlen = 20
	return r_bin_file_get_strings (bf, 20, 0, 2);
}

RBinPlugin r_bin_plugin_psxexe = {
	.name = "psxexe",
	.desc = "Sony PlayStation 1 Executable",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.info = &info,
	.sections = &sections,
	.entries = &entries,
	.strings = &strings,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_psxexe,
	.version = R2_VERSION
};
#endif
