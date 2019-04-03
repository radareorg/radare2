/* radare - LGPL - Copyright 2016 - Oscar Salvador */

#include <r_util.h>
#include <r_types.h>

#include "bflt.h"

#define READ(x, i) r_read_be32 ((x) + (i)); (i) += 4;

RBinAddr *r_bflt_get_entry(struct r_bin_bflt_obj *bin) {
        RBinAddr *addr = R_NEW0 (RBinAddr);
        if (addr && bin && bin->hdr) {
        	addr->paddr = bin->hdr->entry;
        }
        return addr;
}

static int bflt_init_hdr (struct r_bin_bflt_obj *bin) {
	struct bflt_hdr *p_hdr;
	ut8 bhdr[BFLT_HDR_SIZE] = {0};
	int len, i = 0;
	
	len = r_buf_read_at (bin->b, 0, bhdr, BFLT_HDR_SIZE);
	if (len < 1) {
		eprintf ("Warning: read bFLT hdr failed\n");
		goto fail;
	}
	
	if (strncmp ((const char *)bhdr, "bFLT", 4)) {
		eprintf ("Warning: wrong magic number in bFLT file\n");
		goto fail;
	}
	p_hdr = R_NEW0 (struct bflt_hdr);
	if (!p_hdr) {
		eprintf ("Warning: couldn't allocate memory\n");
		goto fail;
	}
	
	i += 4;
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

	if (p_hdr->rev != FLAT_VERSION) {
		eprintf ("Warning: only v4 is supported!\n");
		R_FREE (p_hdr);
		goto fail;
	}
	bin->hdr = p_hdr;
	return true;
fail:
	return false;
}

static int r_bin_bflt_init(struct r_bin_bflt_obj *obj, RBuffer *buf) {
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

struct r_bin_bflt_obj *r_bin_bflt_new_buf(RBuffer *buf) {
	struct r_bin_bflt_obj *bin = R_NEW0 (struct r_bin_bflt_obj);
	if (bin && r_bin_bflt_init (bin, buf)) {
		return bin;
	}
	r_bin_bflt_free (bin);
	return NULL;
}

void r_bin_bflt_free(struct r_bin_bflt_obj *obj) {
	if (obj) {
		R_FREE (obj->hdr);
		r_buf_free (obj->b);
		R_FREE (obj);
	}
}
