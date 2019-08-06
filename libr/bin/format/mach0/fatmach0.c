/* radare - LGPL - Copyright 2010-2013 - nibble */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "fatmach0.h"

static int r_bin_fatmach0_init(struct r_bin_fatmach0_obj_t* bin) {
	ut32 size;
	ut32 i;
	ut8 hdrbytes[sizeof (struct fat_header)] = {0};
	int len = r_buf_read_at (bin->b, 0, &hdrbytes[0], sizeof (struct fat_header));
	if (len != sizeof (struct fat_header)) {
		perror ("read (fat_header)");
		return false;
	}
	bin->hdr.magic = r_read_be32 (&hdrbytes[0]);
	bin->hdr.nfat_arch = r_read_be32 (&hdrbytes[4]);
	bin->nfat_arch = bin->hdr.nfat_arch;
	if (sizeof (struct fat_header) + bin->nfat_arch *
		sizeof (struct fat_arch) > bin->size) {
		return false;
	}
	if (bin->hdr.magic != FAT_MAGIC || !bin->nfat_arch || bin->nfat_arch < 1) {
		eprintf ("Endian FAT_MAGIC failed (?)\n");
		return false;
	}
	size = bin->nfat_arch * sizeof (struct fat_arch);
	if (size < bin->nfat_arch) {
		return false;
	}
	if (!(bin->archs = malloc (size))) {
		perror ("malloc (fat_arch)");
		return false;
	}
	for (i = 0; i < bin->nfat_arch; i++) {
		ut8 archbytes[sizeof (struct fat_arch)] = {0};
		len = r_buf_read_at (bin->b, 8 + i * sizeof (struct fat_arch), &archbytes[0], sizeof (struct fat_arch));
		if (len != sizeof (struct fat_arch)) {
			perror ("read (fat_arch)");
			R_FREE (bin->archs);
			return false;
		}
		bin->archs[i].cputype = r_read_be32 (&archbytes[0]);
		bin->archs[i].cpusubtype = r_read_be32 (&archbytes[4]);
		bin->archs[i].offset = r_read_be32 (&archbytes[8]);
		bin->archs[i].size = r_read_be32 (&archbytes[12]);
		bin->archs[i].align = r_read_be32 (&archbytes[16]);
	}
	return true;
}

struct r_bin_fatmach0_arch_t *r_bin_fatmach0_extract(struct r_bin_fatmach0_obj_t* bin, int idx, int *narch) {
	if (!bin || (idx < 0) || (idx > bin->nfat_arch)) {
		return NULL;
	}
	if (bin->archs[idx].offset > bin->size ||
		bin->archs[idx].offset + bin->archs[idx].size > bin->size) {
		return NULL;
	}
	if (narch) {
		*narch = bin->nfat_arch;
	}
	struct r_bin_fatmach0_arch_t *ret = R_NEW0 (struct r_bin_fatmach0_arch_t);
	if (ret) {
		ret->size = bin->archs[idx].size;
		if (!ret->size || ret->size > bin->size) {
			eprintf ("Skipping corrupted sub-bin %d arch %d\n", idx, bin->archs[idx].size);
			free (ret);
			return NULL;
		}
		ret->offset = bin->archs[idx].offset;
		ret->b = r_buf_new_slice (bin->b, ret->offset, ret->size);
	}
	return ret;
}

void* r_bin_fatmach0_free(struct r_bin_fatmach0_obj_t* bin) {
	if (!bin) {
		return NULL;
	}
	free (bin->archs);
	r_buf_free (bin->b);
	R_FREE (bin);
	return NULL;
}

struct r_bin_fatmach0_obj_t* r_bin_fatmach0_new(const char* file) {
	ut8 *buf;
	struct r_bin_fatmach0_obj_t *bin = R_NEW0 (struct r_bin_fatmach0_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &bin->size))) {
		return r_bin_fatmach0_free (bin);
	}
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return r_bin_fatmach0_free (bin);
	}
	free (buf);
	if (!r_bin_fatmach0_init (bin)) {
		return r_bin_fatmach0_free (bin);
	}
	return bin;
}

struct r_bin_fatmach0_obj_t* r_bin_fatmach0_from_buffer_new(RBuffer *b) {
	r_return_val_if_fail (b, NULL);
	struct r_bin_fatmach0_obj_t *bo = R_NEW0 (struct r_bin_fatmach0_obj_t);
	if (bo) {
		bo->b = r_buf_ref (b);
		bo->size = r_buf_size (bo->b); // XXX implicit in bo->b
		if (!r_bin_fatmach0_init (bo)) {
			return r_bin_fatmach0_free (bo);
		}
	}
	return bo;
}

struct r_bin_fatmach0_obj_t* r_bin_fatmach0_from_bytes_new(const ut8* buf, ut64 size) {
	struct r_bin_fatmach0_obj_t *bin = R_NEW0 (struct r_bin_fatmach0_obj_t);
	if (!bin) {
		return NULL;
	}
	if (!buf) {
		return r_bin_fatmach0_free (bin);
	}
	bin->b = r_buf_new ();
	bin->size = size;
	if (!r_buf_set_bytes (bin->b, buf, size)) {
		return r_bin_fatmach0_free (bin);
	}
	if (!r_bin_fatmach0_init (bin)) {
		return r_bin_fatmach0_free (bin);
	}
	return bin;
}
