/* radare - LGPL - Copyright 2009-2016 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/fatmach0.h"
#include "mach0/mach0.h"

static RBinXtrData * extract(RBin *bin, int idx);
static RList * extractall(RBin *bin);
static RBinXtrData * oneshot(RBin *bin, const ut8 *buf, ut64 size, int idx);
static RList * oneshotall(RBin *bin, const ut8 *buf, ut64 size );
static int free_xtr (void *xtr_obj) ;

static int check(RBin *bin) {
	ut8 *h, buf[4];
	int off, ret = false;
	RMmap *m = r_file_mmap (bin->file, false, 0);
	if (!m || !m->buf) {
		r_file_mmap_free (m);
		return false;
	}
	h = m->buf;
	if (m->len >= 0x300 && !memcmp (h, "\xca\xfe\xba\xbe", 4)) {
		// XXX assuming BE
		off = r_read_at_be32 (h, 4 * sizeof (int));
		if (off > 0 && off < m->len) {
			memcpy (buf, h + off, 4);
			if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xce", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
				!memcmp (buf, "\xcf\xfa\xed\xfe", 4))
				ret = true;
		}
	}
	r_file_mmap_free (m);
	return ret;
}

static int check_bytes(const ut8* bytes, ut64 sz) {
	const ut8 *h;
	ut8 buf[4];
	int off, ret = false;

	if (!bytes || sz < 0x300) {
		return false;
	}
	// XXX assuming BE
	off = r_read_at_be32 (bytes, 4 * sizeof (int));

	h = bytes;
	if (sz >= 0x300 && !memcmp (h, "\xca\xfe\xba\xbe", 4)) {
		// XXX assuming BE
		off = r_read_at_be32 (h, 4 * sizeof (int));
		if (off > 0 && off < sz) {
			memcpy (buf, h + off, 4);
			if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xce", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
				!memcmp (buf, "\xcf\xfa\xed\xfe", 4)) {
				ret = true;
			}
		}
	}
	return ret;
}

// TODO: destroy must be void?
static int destroy(RBin *bin) {
	return free_xtr (bin->cur->xtr_obj);
}

static int free_xtr (void *xtr_obj) {
	r_bin_fatmach0_free ((struct r_bin_fatmach0_obj_t*)xtr_obj);
	return true;
}

static bool load(RBin *bin) {
	return ((bin->cur->xtr_obj = r_bin_fatmach0_new (bin->file)) != NULL);
}

static int size(RBin *bin) {
	// TODO
	return 0;
}

static inline void fill_metadata_info_from_hdr(RBinXtrMetadata *meta, struct MACH0_(mach_header) *hdr) {
	meta->arch = MACH0_(get_cputype_from_hdr) (hdr);
	meta->bits = MACH0_(get_bits_from_hdr) (hdr);
	meta->machine = MACH0_(get_cpusubtype_from_hdr) (hdr);
	meta->type = MACH0_(get_filetype_from_hdr) (hdr);
	meta->libname = NULL;
}

static RBinXtrData * extract(RBin* bin, int idx) {
	int narch;
	RBinXtrData * res = NULL;
	struct r_bin_fatmach0_obj_t *fb = bin->cur->xtr_obj;
	struct r_bin_fatmach0_arch_t *arch;
	struct MACH0_(mach_header) *hdr = NULL;

	arch = r_bin_fatmach0_extract (fb, idx, &narch);
	if (!arch) {
		return res;
	}
	RBinXtrMetadata *metadata = R_NEW0 (RBinXtrMetadata);
	if (!metadata) {
		r_buf_free (arch->b);
		free (arch);
		return NULL;
	}
	hdr = MACH0_(get_hdr_from_bytes) (arch->b);
	if (!hdr) {
		free (arch);
		free (hdr);
		return NULL;
	}
	fill_metadata_info_from_hdr (metadata, hdr);
	res = r_bin_xtrdata_new (arch->b, arch->offset, arch->size,
		narch, metadata, bin->sdb);
	r_buf_free (arch->b);
	free (arch);
	free (hdr);
	return res;
}

static RBinXtrData * oneshot(RBin *bin, const ut8 *buf, ut64 size, int idx) {
	struct r_bin_fatmach0_obj_t *fb;
	struct r_bin_fatmach0_arch_t *arch;
	RBinXtrData *res = NULL;
	int narch;
	struct MACH0_(mach_header) *hdr;

	if (!bin || !bin->cur) {
		return NULL;
	}

	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = r_bin_fatmach0_from_bytes_new (buf, size);
	}

	fb = bin->cur->xtr_obj;
	arch = r_bin_fatmach0_extract (fb, idx, &narch);
	if (!arch) {
		return res;
	}

	RBinXtrMetadata *metadata = R_NEW0 (RBinXtrMetadata);
	if (!metadata) {
		free (arch);
		return NULL;
	}
	hdr = MACH0_(get_hdr_from_bytes) (arch->b);
	if (!hdr) {
		free (arch);
		free (metadata);
		return NULL;
	}
	fill_metadata_info_from_hdr (metadata, hdr);
	res = r_bin_xtrdata_new (arch->b, arch->offset, arch->size, narch, metadata, bin->sdb);
	r_buf_free (arch->b);
	free (arch);
	free (hdr);
	return res;
}

static RList * extractall(RBin *bin) {
	RList *res = NULL;
	int narch, i = 0;
	RBinXtrData *data = NULL;

	data = extract (bin, i);
	if (!data) return res;

	// XXX - how do we validate a valid narch?
	narch = data->file_count;
	res = r_list_newf (r_bin_xtrdata_free);
	r_list_append (res, data);
	for (i = 1; data && i < narch; i++) {
		data = NULL;
		data = extract (bin, i);
		r_list_append (res, data);
	}
	return res;
}

static RList * oneshotall(RBin *bin, const ut8 *buf, ut64 size) {
	RList *res = NULL;
	int narch, i = 0;
	RBinXtrData *data = oneshot (bin, buf, size, i);

	if (!data) return res;
	// XXX - how do we validate a valid narch?
	narch = data->file_count;
	res = r_list_newf (r_bin_xtrdata_free);
	r_list_append (res, data);
	for (i = 1; data && i < narch; i++) {
		data = NULL;
		data = oneshot (bin, buf, size, i);
		r_list_append (res, data);
	}

	return res;
}

RBinXtrPlugin r_bin_xtr_plugin_fatmach0 = {
	.name = "fatmach0",
	.desc = "fat mach0 bin extractor plugin",
	.license = "LGPL3",
	.check = &check,
	.load = &load,
	.size = &size,
	.extract = &extract,
	.extractall = &extractall,
	.destroy = &destroy,
	.extract_from_bytes = &oneshot,
	.extractall_from_bytes = &oneshotall,
	.free_xtr = &free_xtr,
	.check_bytes = &check_bytes,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_fatmach0,
	.version = R2_VERSION
};
#endif
