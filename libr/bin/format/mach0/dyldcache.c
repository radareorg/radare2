/* radare - LGPL - Copyright 2010-2018 - nibble, pancake  */

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

static int r_bin_dyldcache_apply_patch(RBuffer* buf, ut32 data, ut64 offset) {
	return r_buf_write_at (buf, offset, (ut8 *)&data, sizeof (data));
}

#define NZ_OFFSET(x, y, z) if((x) > 0) r_bin_dyldcache_apply_patch (dbuf, (x) - linkedit_offset, addend + r_offsetof (y, z))

// make it public in util/buf.c ?
static ut64 r_buf_read64le(RBuffer *buf, ut64 off) {
	ut8 data[8] = {0};
	r_buf_read_at (buf, off, data, 8);
	return r_read_le64 (data);
}

static char *r_buf_read_string(RBuffer *buf, ut64 addr, int len) {
	ut8 *data = malloc (len);
	if (data) {
		r_buf_read_at (buf, addr, data, len);
		data[len - 1] = 0;
		return (char *)data;
	}
	return NULL;
}

/* TODO: Needs more testing and ERROR HANDLING */
struct r_bin_dyldcache_lib_t *r_bin_dyldcache_extract(struct r_bin_dyldcache_obj_t* bin, int idx, int *nlib) {
	ut64 liboff, linkedit_offset;
	ut64 dyld_vmbase;
	ut32 addend = 0;
	struct r_bin_dyldcache_lib_t *ret = NULL;
	struct dyld_cache_image_info* image_infos = NULL;
	struct mach_header mh;
	ut64 cmdptr;
	int cmd, libsz = 0;
	RBuffer* dbuf = NULL;
	char *libname;

	if (!bin) {
		return NULL;
	}
	if (bin->size < 1) {
		eprintf ("Empty file? (%s)\n", r_str_getf (bin->file));
		return NULL;
	}
	if (bin->nlibs < 0 || idx < 0 || idx >= bin->nlibs) {
		return NULL;
	}
	*nlib = bin->nlibs;
	ret = R_NEW0 (struct r_bin_dyldcache_lib_t);
	if (!ret) {
		return NULL;
	}
	if (bin->hdr.startaddr > bin->size) {
	    	eprintf ("corrupted dyldcache");
		goto ret_err;
	}

	if (bin->hdr.startaddr > bin->size || bin->hdr.baseaddroff > bin->size) {
		eprintf ("corrupted dyldcache");
		goto ret_err;
	}
	int sz = bin->nlibs * sizeof (struct dyld_cache_image_info);
	image_infos = malloc (sz);
	if (!image_infos) {
		goto ret_err;
	}
	r_buf_read_at (bin->b, bin->hdr.startaddr, (ut8*)image_infos, sz);
	dyld_vmbase = r_buf_read64le (bin->b, bin->hdr.baseaddroff);
	liboff = image_infos[idx].address - dyld_vmbase;
	if (liboff > bin->size) {
		eprintf ("Corrupted file\n");
		goto ret_err;
	}
	ret->offset = liboff;
	int pfo = image_infos[idx].pathFileOffset;
	if (pfo < 0 || pfo > bin->size) {
		eprintf ("corrupted file: pathFileOffset > bin->size (%d)\n", pfo);
		goto ret_err;
	}
	libname = r_buf_read_string (bin->b, pfo, 64);
	/* Locate lib hdr in cache */
	int r = r_buf_read_at (bin->b, liboff, (ut8 *)&mh, sizeof (mh));
	if (r != sizeof (mh)) {
		goto ret_err;
	}
	/* Check it is mach-o */
	if (mh.magic != MH_MAGIC && mh.magic != MH_MAGIC_64) {
		if (mh.magic == 0xbebafeca) { //FAT binary
			eprintf ("FAT Binary\n");
		}
		eprintf ("Not mach-o\n");
		goto ret_err;
	}
	addend = mh.magic == MH_MAGIC? sizeof (struct mach_header) : sizeof (struct mach_header_64);
	/* Write mach-o hdr */
	if (!(dbuf = r_buf_new ())) {
		eprintf ("new (dbuf)\n");
		goto ret_err;
	}
	if (!r_buf_append_buf_slice (dbuf, bin->b, liboff, addend)) {
		goto dbuf_err;
	}
	cmdptr = liboff + addend;
	/* Write load commands */
	for (cmd = 0; cmd < mh.ncmds; cmd++) {
		struct load_command lc;
		int r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&lc, sizeof (lc));
		if (r != sizeof (lc)) {
			goto dbuf_err;
		}
		r_buf_append_bytes (dbuf, (ut8 *)&lc, lc.cmdsize);
		cmdptr += lc.cmdsize;
	}
	cmdptr = liboff + addend;
	/* Write segments */
	for (cmd = linkedit_offset = 0; cmd < mh.ncmds; cmd++) {
		struct load_command lc;
		int r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&lc, sizeof (lc));
		if (r != sizeof (lc)) {
			goto dbuf_err;
		}
		switch (lc.cmd) {
		case LC_SEGMENT:
			{
			/* Write segment and patch offset */
			struct segment_command seg;
			r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&seg, sizeof (seg));
			if (r != sizeof (seg)) {
				goto dbuf_err;
			}
			int t = seg.filesize;
			if (seg.fileoff + seg.filesize > bin->size || seg.fileoff > bin->size) {
				eprintf ("malformed dyldcache\n");
				goto dbuf_err;
			}
			r_buf_append_buf_slice (dbuf, bin->b, seg.fileoff, t);
			r_bin_dyldcache_apply_patch (dbuf, r_buf_size (dbuf),
				addend + r_offsetof (struct segment_command, fileoff));
			/* Patch section offsets */
			int sect_offset = seg.fileoff - libsz;
			libsz = r_buf_size (dbuf);
			if (!strcmp (seg.segname, "__LINKEDIT")) {
				linkedit_offset = sect_offset;
			}
			if (seg.nsects > 0) {
				int nsect;
				for (nsect = 0; nsect < seg.nsects; nsect++) {
					struct section sect;
					r = r_buf_read_at (bin->b, cmdptr + nsect * sizeof (struct segment_command), (ut8 *)&sect, sizeof (sect));
					if (r != sizeof (sect)) {
						break;
					}
					if (sect.offset > libsz) {
						r_bin_dyldcache_apply_patch (dbuf, sect.offset - sect_offset,
							addend + r_offsetof (struct section, offset));
					}
				}
			}
			}
			break;
		case LC_SYMTAB:
			{
			struct symtab_command st;
			r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&st, sizeof (st));
			if (r != sizeof (st)) {
				goto dbuf_err;
			}
			NZ_OFFSET (st.symoff, struct symtab_command, symoff);
			NZ_OFFSET (st.stroff, struct symtab_command, stroff);
			}
			break;
		case LC_DYSYMTAB:
			{
			struct dysymtab_command st;
			r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&st, sizeof (st));
			if (r != sizeof (st)) {
				goto dbuf_err;
			}
			NZ_OFFSET (st.tocoff, struct dysymtab_command, tocoff);
			NZ_OFFSET (st.modtaboff, struct dysymtab_command, modtaboff);
			NZ_OFFSET (st.extrefsymoff, struct dysymtab_command, extrefsymoff);
			NZ_OFFSET (st.indirectsymoff, struct dysymtab_command, indirectsymoff);
			NZ_OFFSET (st.extreloff, struct dysymtab_command, extreloff);
			NZ_OFFSET (st.locreloff, struct dysymtab_command, locreloff);
			}
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			{
			struct dyld_info_command st;
			r = r_buf_read_at (bin->b, cmdptr, (ut8 *)&st, sizeof (st));
			if (r != sizeof (st)) {
				goto dbuf_err;
			}
			NZ_OFFSET (st.rebase_off, struct dyld_info_command, rebase_off);
			NZ_OFFSET (st.bind_off, struct dyld_info_command, bind_off);
			NZ_OFFSET (st.weak_bind_off, struct dyld_info_command, weak_bind_off);
			NZ_OFFSET (st.lazy_bind_off, struct dyld_info_command, lazy_bind_off);
			NZ_OFFSET (st.export_off, struct dyld_info_command, export_off);
			}
			break;
		}
		cmdptr += lc.cmdsize;
	}
	/* Fill r_bin_dyldcache_lib_t ret */
	ret->b = dbuf;
	strncpy (ret->path, libname, sizeof (ret->path) - 1);
	ret->size = libsz;
	return ret;

dbuf_err:
	r_buf_free (dbuf);
ret_err:
	free (ret);
	return NULL;
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
	if (!(bin = R_NEW0 (struct r_bin_dyldcache_obj_t))) {
		return NULL;
	}
	bin->file = file;
	size_t binsz;
	ut8 *buf = (ut8 *)r_file_slurp (file, &binsz);
	bin->size = binsz;
	if (!buf) {
		return r_bin_dyldcache_free (bin);
	}
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return r_bin_dyldcache_free (bin);
	}
	free (buf);
	if (!r_bin_dyldcache_init (bin)) {
		return r_bin_dyldcache_free (bin);
	}
	return bin;
}

struct r_bin_dyldcache_obj_t* r_bin_dyldcache_from_bytes_new(const ut8* buf, ut64 size) {
	struct r_bin_dyldcache_obj_t *bin = R_NEW0 (struct r_bin_dyldcache_obj_t);
	if (!bin) {
		return NULL;
	}
	if (!buf) {
		return r_bin_dyldcache_free (bin);
	}
	bin->b = r_buf_new ();
	if (!bin->b || !r_buf_set_bytes (bin->b, buf, size)) {
		return r_bin_dyldcache_free (bin);
	}
	if (!r_bin_dyldcache_init (bin)) {
		return r_bin_dyldcache_free (bin);
	}
	bin->size = size;
	return bin;
}
