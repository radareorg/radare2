/* radare - LGPL - Copyright 2010-2013 - nibble */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "fatmach0.h"

static int r_bin_fatmach0_init(struct r_bin_fatmach0_obj_t* bin) {
	int len = r_buf_fread_at (bin->b, 0, (ut8*)&bin->hdr, "2I", 1);
	if (len == -1) {
		perror ("read (fat_header)");
		return R_FALSE;
	}
	bin->nfat_arch = bin->hdr.nfat_arch;
	if (bin->hdr.magic != FAT_MAGIC || bin->nfat_arch == 0 || bin->nfat_arch<1)
		return R_FALSE;
	if (!(bin->archs = malloc (bin->nfat_arch * sizeof (struct fat_arch)))) {
		perror ("malloc (fat_arch)");
		return R_FALSE;
	}
	len = r_buf_fread_at (bin->b, R_BUF_CUR, (ut8*)bin->archs, "5I", bin->nfat_arch);
	if (len == -1) {
		perror ("read (fat_arch)");
		return R_FALSE;
	}
	return R_TRUE;
}

struct r_bin_fatmach0_arch_t *r_bin_fatmach0_extract(struct r_bin_fatmach0_obj_t* bin, int idx, int *narch) {
	struct r_bin_fatmach0_arch_t *ret;
	ut8 *buf = NULL;

	if (!bin || (idx < 0) || (idx > bin->hdr.nfat_arch))
		return NULL;
	if (narch) *narch = bin->hdr.nfat_arch;
	if (!(ret = R_NEW0 (struct r_bin_fatmach0_arch_t))) {
		perror ("malloc (ret)");
		return NULL;
	}
	if (bin->archs[idx].size == 0 || bin->archs[idx].size > bin->size) {
		eprintf ("Corrupted file\n");
		free (ret);
		return NULL;
	}
	if (!(buf = malloc (1+bin->archs[idx].size))) {
		perror ("malloc (buf)");
		free (ret);
		return NULL;
	}
	if (r_buf_read_at (bin->b, bin->archs[idx].offset, buf, bin->archs[idx].size) == -1) {
		perror ("read (buf)");
		free (buf);
		free (ret);
		return NULL;
	}
	if (!(ret->b = r_buf_new ())) {
		free (buf);
		free (ret);
		return NULL;
	}
	if (!r_buf_set_bytes (ret->b, buf, bin->archs[idx].size)) {
		free (buf);
		r_buf_free (ret->b);
		free (ret);
		return NULL;
	}
	free (buf);
	ret->offset = bin->archs[idx].offset;
	ret->size = bin->archs[idx].size;
	return ret;
}

void* r_bin_fatmach0_free(struct r_bin_fatmach0_obj_t* bin) {
	if (!bin) return NULL;
	free (bin->archs);
	r_buf_free (bin->b);
	free (bin);
	return NULL;
}

struct r_bin_fatmach0_obj_t* r_bin_fatmach0_new(const char* file) {
	ut8 *buf;
	struct r_bin_fatmach0_obj_t *bin = R_NEW0 (struct r_bin_fatmach0_obj_t);
	if (!bin) return NULL;
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &bin->size))) 
		return r_bin_fatmach0_free (bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return r_bin_fatmach0_free (bin);
	}
	free (buf);
	if (!r_bin_fatmach0_init (bin))
		return r_bin_fatmach0_free (bin);
	return bin;
}

struct r_bin_fatmach0_obj_t* r_bin_fatmach0_from_bytes_new(const ut8* buf, ut64 size) {
	struct r_bin_fatmach0_obj_t *bin = R_NEW0 (struct r_bin_fatmach0_obj_t);
	if (!bin) return NULL;
	if (!buf) return r_bin_fatmach0_free (bin);
	bin->b = r_buf_new ();
	bin->size = size;
	if (!r_buf_set_bytes (bin->b, buf, size))
		return r_bin_fatmach0_free (bin);
	if (!r_bin_fatmach0_init (bin))
		return r_bin_fatmach0_free (bin);
	return bin;
}
