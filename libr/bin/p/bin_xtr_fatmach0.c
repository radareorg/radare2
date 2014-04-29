/* radare - LGPL - Copyright 2009-2013 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/fatmach0.h"

static RBinXtrData * extract(RBin *bin, int idx);
static RList * extractall(RBin *bin);
static RBinXtrData * oneshot(const ut8 *buf, ut64 size, int idx);
static RList * oneshotall(const ut8 *buf, ut64 size );
static int free_xtr (void *xtr_obj) ;

static int check(RBin *bin) {
	ut8 *h, buf[4];
	int off, ret = R_FALSE;
	RMmap *m = r_file_mmap (bin->file, R_FALSE, 0);
	if (!m || !m->buf) {
		r_file_mmap_free (m);
		return R_FALSE;
	}
	h = m->buf;
	if (m->len>=0x300 && !memcmp (h, "\xca\xfe\xba\xbe", 4)) {
		memcpy (&off, h+4*sizeof (int), sizeof (int));
		r_mem_copyendian ((ut8*)&off, (ut8*)&off, sizeof(int), !LIL_ENDIAN);
		if (off > 0 && off < m->len) {
			memcpy (buf, h+off, 4);
			if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xce", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
				!memcmp (buf, "\xcf\xfa\xed\xfe", 4))
				ret = R_TRUE;
		}
	}
	r_file_mmap_free (m);
	return ret;
}

static int check_bytes(const ut8* bytes, ut64 sz) {
	const ut8 *h;
	ut8 buf[4];
	int off, ret = R_FALSE;

	if (!bytes || sz < 0x300) {
		return R_FALSE;
	}
	memcpy (&off, bytes+4*sizeof (int), sizeof (int));
	r_mem_copyendian ((ut8*)&off, (ut8*)&off, sizeof(int), !LIL_ENDIAN);

	h = bytes;
	if (sz>=0x300 && !memcmp (h, "\xca\xfe\xba\xbe", 4)) {
		memcpy (&off, h+4*sizeof (int), sizeof (int));
		r_mem_copyendian ((ut8*)&off, (ut8*)&off, sizeof(int), !LIL_ENDIAN);
		if (off > 0 && off < sz) {
			memcpy (buf, h+off, 4);
			if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xce", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
				!memcmp (buf, "\xcf\xfa\xed\xfe", 4))
				ret = R_TRUE;
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
	return R_TRUE;
}

static int load(RBin *bin) {
	return (bin->cur->xtr_obj = r_bin_fatmach0_new (bin->file))?
		R_TRUE: R_FALSE;
}

static int size(RBin *bin) {
	// TODO
	return 0;
}

static RBinXtrData * extract(RBin* bin, int idx) {
	int narch;
	RBinXtrData * res = NULL;
	struct r_bin_fatmach0_obj_t *fb = bin->cur->xtr_obj;
	struct r_bin_fatmach0_arch_t *arch;

	arch = r_bin_fatmach0_extract (fb, idx, &narch);
	if (!arch) return res;

	res = r_bin_xtrdata_new (NULL, NULL, arch->b, arch->offset,
							arch->size, narch);
	r_buf_free (arch->b);
	free (arch);
	return res;
}

static RBinXtrData * oneshot(const ut8 *buf, ut64 size, int idx) {
	int narch;
	RBinXtrData * res = NULL;
	void *xtr_obj = r_bin_fatmach0_from_bytes_new (buf, size);

	struct r_bin_fatmach0_obj_t *fb = xtr_obj;
	struct r_bin_fatmach0_arch_t *arch;

	arch = r_bin_fatmach0_extract (fb, idx, &narch);
	if (!arch) {
		free_xtr (xtr_obj);
		return res;
	}

	res = r_bin_xtrdata_new (xtr_obj, free_xtr, arch->b, arch->offset,
							arch->size, narch);
	r_buf_free (arch->b);
	free (arch);
	return res;
}


static RList * extractall(RBin *bin) {
	RList *res = NULL;
	int narch, i=0;
	RBinXtrData *data = NULL;

	data = extract (bin, i);
	if (!data) return res;

	// XXX - how do we validate a valid narch?
	narch = data->file_count;
	res = r_list_newf (r_bin_xtrdata_free);
	r_list_append (res, data);
	for (i=1; data && i < narch; i++) {
		data = NULL;
		data = extract (bin, i);
		r_list_append (res, data);
	}

	return res;
}

static RList * oneshotall(const ut8 *buf, ut64 size) {
	RList *res = NULL;
	int narch, i=0;
	RBinXtrData *data = NULL;

	data = oneshot (buf, size, i);
	if (!data) return res;

	// XXX - how do we validate a valid narch?
	narch = data->file_count;
	res = r_list_newf (r_bin_xtrdata_free);
	r_list_append (res, data);
	for (i=1; data && i < narch; i++) {
		data = NULL;
		data = oneshot (buf, size, i);
		r_list_append (res, data);
	}

	return res;
}
struct r_bin_xtr_plugin_t r_bin_xtr_plugin_fatmach0 = {
	.name = "fatmach0",
	.desc = "fat mach0 bin extractor plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
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
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_fatmach0
};
#endif
