/* radare - LGPL - Copyright 2010 nibble at develsec.org */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "fatmach0.h"

static int r_bin_fatmach0_init(struct r_bin_fatmach0_obj_t* bin) {
	int len;

	len = r_buf_fread_at(bin->b, 0, (ut8*)&bin->hdr, "2I", 1);
	if (len == -1) {
		perror ("read (fat_header)");
		return R_FALSE;
	}
	bin->nfat_arch = bin->hdr.nfat_arch;
	if (bin->hdr.magic != FAT_MAGIC || bin->nfat_arch == 0)
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

struct r_bin_fatmach0_arch_t *r_bin_fatmach0_extract(struct r_bin_fatmach0_obj_t* bin) {
	ut8 *buf = NULL;
	struct r_bin_fatmach0_arch_t *ret;
	int i;

	if (bin->hdr.nfat_arch < 0)
		return R_FALSE;
	ret = malloc ((bin->hdr.nfat_arch+1) * sizeof(struct r_bin_fatmach0_arch_t));
	for (i = 0; i < bin->hdr.nfat_arch; i++) {
		if (bin->archs[i].size == 0 || bin->archs[i].size > bin->size) {
			eprintf ("Corrupted file\n");
			return NULL;
		}
		if (!(buf = malloc (bin->archs[i].size))) {
			perror ("malloc (buf)");
			return NULL;
		}
		if (r_buf_read_at (bin->b, bin->archs[i].offset, buf, bin->archs[i].size) == -1) {
			perror ("read (buf)");
			free (buf);
			return NULL;
		}
		if (!(ret[i].b = r_buf_new ())) {
			free (buf);
			return NULL;
		}
		if (!r_buf_set_bytes (ret[i].b, buf, bin->archs[i].size)) {
			free (buf);
			r_buf_free (ret[i].b);
			return NULL;
		}
		free (buf);
		ret[i].size = bin->archs[i].size;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	return ret;
}

void* r_bin_fatmach0_free(struct r_bin_fatmach0_obj_t* bin) {
	if (!bin)
		return NULL;
	if (bin->archs)
		free (bin->archs);
	if (bin->b)
		r_buf_free (bin->b);
	free(bin);
	return NULL;
}

struct r_bin_fatmach0_obj_t* r_bin_fatmach0_new(const char* file) {
	struct r_bin_fatmach0_obj_t *bin;
	ut8 *buf;

	if (!(bin = malloc(sizeof(struct r_bin_fatmach0_obj_t))))
		return NULL;
	memset (bin, 0, sizeof (struct r_bin_fatmach0_obj_t));
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size))) 
		return r_bin_fatmach0_free(bin);
	bin->b = r_buf_new();
	if (!r_buf_set_bytes(bin->b, buf, bin->size))
		return r_bin_fatmach0_free(bin);
	free (buf);
	if (!r_bin_fatmach0_init(bin))
		return r_bin_fatmach0_free(bin);
	return bin;
}
