/* radare - LGPL - Copyright 2010 nibble at develsec.org */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "dyldcache.h"

static int r_bin_dyldcache_init(struct r_bin_dyldcache_obj_t* bin) {
	int len = r_buf_fread_at (bin->b, 0, (ut8*)&bin->hdr, "16c4il", 1);
	if (len == -1) {
		perror ("read (cache_header)");
		return R_FALSE;
	}
	bin->nlibs = bin->hdr.numlibs;
	return R_TRUE;
}

struct r_bin_dyldcache_lib_t *r_bin_dyldcache_extract(struct r_bin_dyldcache_obj_t* bin) {
	struct r_bin_dyldcache_lib_t *ret = NULL;
	ut64 curoffset, liboff, libla, libpath;
	ut64 tcuroffset, tliboff, tlibla, nextliboff;
	ut8 *buf;
	char *libname;
	int i, j, k, libsz;

	if (bin->nlibs < 0 || bin->hdr.baseaddroff >= bin->b->length)
		return NULL;
	if (!(ret = malloc ((bin->nlibs+1) * sizeof(struct r_bin_dyldcache_lib_t))))
		return NULL;
	for (i = 0, j = 0, curoffset = bin->hdr.startaddr; i < bin->nlibs; i++, curoffset+=32) {
		if (curoffset+24 >= bin->b->length)
			return NULL;
		libla = *(ut64*)(bin->b->buf+curoffset);
		liboff = libla - *(ut64*)&bin->b->buf[bin->hdr.baseaddroff];
		if (liboff < 0 || liboff > bin->size)
			continue;
		libpath = *(ut64*)(bin->b->buf+curoffset + 24);
		for (k = 0, nextliboff = bin->size, tcuroffset = bin->hdr.startaddr; k < bin->nlibs; k++, tcuroffset+=32) {
			if (tcuroffset >= bin->b->length)
				return NULL;
			tlibla = *(ut64*)(bin->b->buf+tcuroffset);
			tliboff = tlibla - *(ut64*)&bin->b->buf[bin->hdr.baseaddroff];
			if (tliboff > liboff && tliboff <= nextliboff)
				nextliboff = tliboff;
		}
		libsz = nextliboff - liboff;
		if (!(buf = malloc (libsz))) {
			perror ("malloc (buf)");
			return NULL;
		}
		if (r_buf_read_at (bin->b, liboff, buf, libsz) == -1) {
			perror ("read (buf)");
			free (buf);
			return NULL;
		}
		if (!(ret[j].b = r_buf_new ())) {
			free (buf);
			return NULL;
		}
		if (!r_buf_set_bytes (ret[j].b, buf, libsz)) {
			free (buf);
			r_buf_free (ret[j].b);
			return NULL;
		}
		free (buf);
		libname = (char*)(bin->b->buf+libpath);
		strncpy (ret[i].path, libname, sizeof (ret[j].path));
		ret[j].size = libsz;
		ret[j].last = 0;
		j++;
		//printf("0x%08llx -> %i -> %s\n", liboff, libsz, libname);
	}
	ret[i].last = 1;
	return ret;
}

void* r_bin_dyldcache_free(struct r_bin_dyldcache_obj_t* bin) {
	if (!bin)
		return NULL;
	if (bin->b)
		r_buf_free (bin->b);
	free(bin);
	return NULL;
}

struct r_bin_dyldcache_obj_t* r_bin_dyldcache_new(const char* file) {
	struct r_bin_dyldcache_obj_t *bin;
	ut8 *buf;
	if (!(bin = malloc(sizeof(struct r_bin_dyldcache_obj_t))))
		return NULL;
	memset (bin, 0, sizeof (struct r_bin_dyldcache_obj_t));
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size))) 
		return r_bin_dyldcache_free(bin);
	bin->b = r_buf_new();
	if (!r_buf_set_bytes(bin->b, buf, bin->size))
		return r_bin_dyldcache_free(bin);
	free (buf);
	if (!r_bin_dyldcache_init(bin))
		return r_bin_dyldcache_free(bin);
	return bin;
}
