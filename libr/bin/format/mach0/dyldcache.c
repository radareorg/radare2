/* radare - LGPL - Copyright 2010-2016 - nibble, pancake  */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "dyldcache.h"

static int r_bin_dyldcache_init(struct r_bin_dyldcache_obj_t* bin) {
	int len = r_buf_fread_at (bin->b, 0, (ut8*)&bin->hdr, "16c4i7l", 1);
	if (len == -1) {
		perror ("read (cache_header)");
		return false;
	}
	bin->nlibs = bin->hdr.numlibs;
	return true;
}

static int r_bin_dyldcache_apply_patch (struct r_buf_t* buf, ut32 data, ut64 offset) {
	return r_buf_write_at (buf, offset, (ut8*)&data, sizeof (data));
}

#define NZ_OFFSET(x) if(x > 0) r_bin_dyldcache_apply_patch (dbuf, x - linkedit_offset, (ut64)((size_t)&x - (size_t)data))

/* TODO: Needs more testing and ERROR HANDLING */
struct r_bin_dyldcache_lib_t *r_bin_dyldcache_extract(struct r_bin_dyldcache_obj_t* bin, int idx, int *nlib) {
	ut64 liboff, linkedit_offset;
	ut64 dyld_vmbase;
	ut32 addend = 0;
	struct r_bin_dyldcache_lib_t *ret = NULL;
	struct dyld_cache_image_info* image_infos = NULL;
	struct mach_header *mh;
	ut8 *data, *cmdptr;
	int cmd, libsz = 0;
	RBuffer* dbuf;
	char *libname;

	if (!bin)
	    	return NULL;
	if (bin->size < 1) {
		eprintf ("Empty file? (%s)\n", bin->file? bin->file: "(null)");
		return NULL;
	}
	if (bin->nlibs < 0 || idx < 0 || idx > bin->nlibs)
		return NULL;
	*nlib = bin->nlibs;
	ret = R_NEW0 (struct r_bin_dyldcache_lib_t);
	if (!ret) {
		perror ("malloc (ret)");
		return NULL;
	}
	if (bin->hdr.startaddr > bin->size) {
	    	eprintf ("corrupted dyldcache");
		free (ret);
		return NULL;
	}
	if (bin->hdr.startaddr > bin->size || bin->hdr.baseaddroff > bin->size) {
		eprintf ("corrupted dyldcache");
		free (ret);
		return NULL;
	}
	image_infos = (struct dyld_cache_image_info*) (bin->b->buf + bin->hdr.startaddr);
	dyld_vmbase = *(ut64 *)(bin->b->buf + bin->hdr.baseaddroff);
	liboff = image_infos[idx].address - dyld_vmbase;
	if (liboff > bin->size) {
		eprintf ("Corrupted file\n");
		free (ret);
		return NULL;
	}
	ret->offset = liboff;
	if (image_infos[idx].pathFileOffset > bin->size) {
	    eprintf ("corrupted file\n");
		free (ret);
		return NULL;
	}
	libname = (char *)(bin->b->buf + image_infos[idx].pathFileOffset);
	/* Locate lib hdr in cache */
	data = bin->b->buf + liboff;
	mh = (struct mach_header *)data;
	/* Check it is mach-o */
	if (mh->magic != MH_MAGIC && mh->magic != MH_MAGIC_64) {
	    	if (mh->magic == 0xbebafeca) //FAT binary
		    	eprintf ("FAT Binary\n");
		eprintf ("Not mach-o\n");
		free (ret);
		return NULL;
	}
	/* Write mach-o hdr */
	if (!(dbuf = r_buf_new ())) {
		eprintf ("new (dbuf)\n");
		free (ret);
		return NULL;
	}
	addend = mh->magic == MH_MAGIC? sizeof (struct mach_header) : sizeof (struct mach_header_64);
	r_buf_set_bytes (dbuf, data, addend);
	cmdptr = data + addend;
	/* Write load commands */
	for (cmd = 0; cmd < mh->ncmds; cmd++) {
		struct load_command *lc = (struct load_command *)cmdptr;
		r_buf_append_bytes (dbuf, (ut8*)lc, lc->cmdsize);
		cmdptr += lc->cmdsize;
	}
	cmdptr = data + addend;
	/* Write segments */
	for (cmd = linkedit_offset = 0; cmd < mh->ncmds; cmd++) {
		struct load_command *lc = (struct load_command *)cmdptr;
		cmdptr += lc->cmdsize;
		switch (lc->cmd) {
		case LC_SEGMENT:
			{
			/* Write segment and patch offset */
			struct segment_command *seg = (struct segment_command *)lc;
			int t = seg->filesize;
			if (seg->fileoff + seg->filesize > bin->size || seg->fileoff > bin->size) {
				eprintf ("malformed dyldcache\n");
				free (ret);
				r_buf_free (dbuf);
				return NULL;
			}
			r_buf_append_bytes (dbuf, bin->b->buf+seg->fileoff, t);
			r_bin_dyldcache_apply_patch (dbuf, dbuf->length, (ut64)((size_t)&seg->fileoff - (size_t)data));
			/* Patch section offsets */
			int sect_offset = seg->fileoff - libsz;
			libsz = dbuf->length;
			if (!strcmp(seg->segname, "__LINKEDIT"))
				linkedit_offset = sect_offset;
			if (seg->nsects > 0) {
				struct section *sects = (struct section *)((ut8 *)seg + sizeof(struct segment_command));
				int nsect;
				for (nsect = 0; nsect < seg->nsects; nsect++) {
					if (sects[nsect].offset > libsz) {
						r_bin_dyldcache_apply_patch (dbuf, sects[nsect].offset - sect_offset,
							(ut64)((size_t)&sects[nsect].offset - (size_t)data));
					}
				}
			}
			}
			break;
		case LC_SYMTAB:
			{
			struct symtab_command *st = (struct symtab_command *)lc;
			NZ_OFFSET (st->symoff);
			NZ_OFFSET (st->stroff);
			}
			break;
		case LC_DYSYMTAB:
			{
			struct dysymtab_command *st = (struct dysymtab_command *)lc;
			NZ_OFFSET (st->tocoff);
			NZ_OFFSET (st->modtaboff);
			NZ_OFFSET (st->extrefsymoff);
			NZ_OFFSET (st->indirectsymoff);
			NZ_OFFSET (st->extreloff);
			NZ_OFFSET (st->locreloff);
			}
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			{
			struct dyld_info_command *st = (struct dyld_info_command *)lc;
			NZ_OFFSET (st->rebase_off);
			NZ_OFFSET (st->bind_off);
			NZ_OFFSET (st->weak_bind_off);
			NZ_OFFSET (st->lazy_bind_off);
			NZ_OFFSET (st->export_off);
			}
			break;
		}
	}
	/* Fill r_bin_dyldcache_lib_t ret */
	ret->b = dbuf;
	strncpy (ret->path, libname, sizeof (ret->path) - 1);
	ret->size = libsz;
	return ret;
}

void* r_bin_dyldcache_free(struct r_bin_dyldcache_obj_t* bin) {
	if (!bin) {
		return NULL;
	}
	r_buf_free (bin->b);
	free (bin);
	return NULL;
}

void r_bin_dydlcache_get_libname(struct r_bin_dyldcache_lib_t *lib, char **libname) {
	char *cur = lib->path;
	char *res = lib->path;
	int path_length = strlen (lib->path);
	while (cur < cur + path_length - 1) {
		cur = strchr (cur, '/');
		if (!cur) {
			break;
		}
		cur++;
		res = cur;
	}
	*libname = res;
}

struct r_bin_dyldcache_obj_t* r_bin_dyldcache_new(const char* file) {
	struct r_bin_dyldcache_obj_t *bin;
	ut8 *buf;
	if (!(bin = R_NEW0 (struct r_bin_dyldcache_obj_t)))
		return NULL;
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &bin->size))) {
		return r_bin_dyldcache_free (bin);
	}
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return r_bin_dyldcache_free (bin);
	}
	free (buf);
	if (!r_bin_dyldcache_init (bin))
		return r_bin_dyldcache_free (bin);
	return bin;
}

struct r_bin_dyldcache_obj_t* r_bin_dyldcache_from_bytes_new(const ut8* buf, ut64 size) {
	struct r_bin_dyldcache_obj_t *bin;
	if (!(bin = malloc (sizeof (struct r_bin_dyldcache_obj_t))))
		return NULL;
	memset (bin, 0, sizeof (struct r_bin_dyldcache_obj_t));
	if (!buf)
		return r_bin_dyldcache_free (bin);
	bin->b = r_buf_new();
	if (!r_buf_set_bytes (bin->b, buf, size))
		return r_bin_dyldcache_free (bin);
	if (!r_bin_dyldcache_init (bin))
		return r_bin_dyldcache_free (bin);
	bin->size = size;
	return bin;
}
