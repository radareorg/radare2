/* radare - LGPL - Copyright 2016-2025 - Oscar Salvador */

#include <r_util.h>
#include "bflt.h"

#define READ(x, i) r_read_be32 ((x) + (i)); (i) += 4;

R_IPI RBinAddr *r_bflt_get_entry(struct r_bin_bflt_obj *bin) {
	if (!bin || !bin->hdr) {
		return NULL;
	}
	RBinAddr *addr = R_NEW0 (RBinAddr);
	if (addr) {
		addr->paddr = bin->hdr->entry;
	}
	return addr;
}

static int bflt_init_hdr(struct r_bin_bflt_obj *bin) {
	ut8 bhdr[BFLT_HDR_SIZE] = {0};

	int len = r_buf_read_at (bin->b, 0, bhdr, BFLT_HDR_SIZE);
	if (len < BFLT_HDR_SIZE) {
		R_LOG_WARN ("read bFLT hdr failed: expected %d bytes, got %d", BFLT_HDR_SIZE, len);
		goto fail;
	}

	if (strncmp ((const char *)bhdr, "bFLT", 4)) {
		R_LOG_WARN ("wrong magic number in bFLT file");
		goto fail;
	}

	struct bflt_hdr *p_hdr = R_NEW0 (struct bflt_hdr);
	int i = 4;
	p_hdr->rev = READ (bhdr, i);
	p_hdr->entry = READ (bhdr, i);
	p_hdr->data_start = READ (bhdr, i);
	p_hdr->data_end = READ (bhdr, i);
	p_hdr->bss_end = READ (bhdr, i);
	p_hdr->stack_size = READ (bhdr, i);
	p_hdr->reloc_start = READ (bhdr, i);
	p_hdr->reloc_count = READ (bhdr, i);
	p_hdr->flags = READ (bhdr, i);
	p_hdr->build_date = READ (bhdr, i);
	/* cpu_type may be stored in filler[5] by some toolchains, read it separately */
	bin->cpu_type = r_read_be32 (bhdr + 60);	/* offset 60 = filler[5] */
	if (bin->cpu_type == 0 || bin->cpu_type > 0x100) {
		bin->cpu_type = BFLT_CPU_ARM;	/* default to ARM if invalid */
	}

	if (p_hdr->rev != FLAT_VERSION) {
		R_LOG_WARN ("only v4 is supported!");
		R_FREE (p_hdr);
		goto fail;
	}
	bin->hdr = p_hdr;
	return true;
fail:
	return false;
}

static bool r_bin_bflt_init(RBinBfltObj *obj, RBuffer *buf) {
	obj->b = r_buf_ref (buf);
	obj->size = r_buf_size (buf);
	obj->endian = false;
	obj->reloc_table = NULL;
	obj->got_table = NULL;
	obj->n_got = 0;
	obj->hdr = NULL;

	if (!bflt_init_hdr (obj)) {
		return false;
	}
	return true;
}

R_IPI void r_bin_bflt_free(RBinBfltObj *o) {
	if (o) {
		if (o->relocs_list) {
			o->relocs_list->free = NULL;
			r_list_free (o->relocs_list);
		}
		R_FREE (o->hdr);
		r_buf_free (o->b);
		free (o);
	}
}

R_IPI RBinBfltObj *r_bin_bflt_new_buf(RBuffer *buf) {
	R_RETURN_VAL_IF_FAIL (buf, NULL);
	RBinBfltObj *o = R_NEW0 (RBinBfltObj);
	if (r_bin_bflt_init (o, buf)) {
		return o;
	}
	r_bin_bflt_free (o);
	return NULL;
}
