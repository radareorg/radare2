/* radare - LGPL - Copyright 2009-2012 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/dyldcache.h"

static RBinXtrData * extract(RBin *bin, int idx);
static RList * extractall(RBin *bin);
static RBinXtrData * oneshot(const ut8 *buf, ut64 size, int idx);
static RList * oneshotall(const ut8 *buf, ut64 size );
static int free_xtr (void *xtr_obj) ;

static int check(RBin *bin) {
	int size, ret = R_FALSE;
	ut8 *filebuf = (ut8*)r_file_slurp_range (bin->file, 0, 4, &size);
	if (filebuf){
		if (size == 4) {
			if (!memcmp (filebuf, "\x64\x79\x6c\x64", 4))
				ret = R_TRUE;
			free (filebuf);
		} else free (filebuf);
	}
	return ret;
}

static int check_bytes(const ut8* bytes, ut64 sz) {
	int ret = R_FALSE;

	if (!bytes || sz < 4) return R_FALSE;
	if (!memcmp (bytes, "\x64\x79\x6c\x64", 4))
		ret = R_TRUE;

	return ret;
}

// TODO: destroy must be void?
static int destroy(RBin *bin) {
	return free_xtr (bin->cur->xtr_obj);
}

static int free_xtr (void *xtr_obj) {
	r_bin_dyldcache_free ((struct r_bin_dyldcache_obj_t*)xtr_obj);
	return R_TRUE;
}

static int load(RBin *bin) {
	return ((bin->cur->xtr_obj = r_bin_dyldcache_new (bin->file)))? R_TRUE: R_FALSE;
}

static RList * extractall(RBin *bin) {
	RList *result = NULL;
	int nlib, i=0;
	RBinXtrData *data = NULL;

	data = extract (bin, i);
	if (!data) return result;

	// XXX - how do we validate a valid nlib?
	nlib = data->file_count;

	result = r_list_newf (r_bin_xtrdata_free);
	r_list_append (result, data);
	for (i=1; data && i < nlib; i++) {
		data = NULL;
		data = extract (bin, i);
		r_list_append (result, data);
	}

	return result;
}
static RBinXtrData * extract(RBin *bin, int idx) {
	int nlib = 0;
	RBinXtrData * res = NULL;
	struct r_bin_dyldcache_lib_t *lib;

	lib = r_bin_dyldcache_extract (
		(struct r_bin_dyldcache_obj_t*)bin->cur->xtr_obj, idx, &nlib);
	if (!lib) return res;
	res = r_bin_xtrdata_new (NULL, NULL, lib->b, lib->offset, lib->size, nlib);

	r_buf_free (lib->b);
	free (lib);
	return res;
}

static RBinXtrData * oneshot(const ut8* buf, ut64 size, int idx) {
	RBinXtrData * res = NULL;
	void *xtr_obj = r_bin_dyldcache_from_bytes_new (buf, size);
	struct r_bin_dyldcache_lib_t *lib;
	int nlib = 0;
	lib = r_bin_dyldcache_extract (
		(struct r_bin_dyldcache_obj_t*)xtr_obj, idx, &nlib);

	if (!lib) {
		free_xtr (xtr_obj);
		return res;
	}
	res = r_bin_xtrdata_new (xtr_obj, free_xtr, lib->b, lib->offset, lib->size, nlib);

	r_buf_free (lib->b);
	free (lib);
	return res;
}

static RList * oneshotall(const ut8* buf, ut64 size) {
	RList *res = NULL;
	int nlib, i=1;
	RBinXtrData *data = NULL;

	data = oneshot (buf, size, i);
	if (!data) return res;

	// XXX - how do we validate a valid nlib?
	nlib = data->file_count;
	res = r_list_newf (r_bin_xtrdata_free);
	r_list_append (res, data);
	for (i=1; data && i < nlib; i++) {
		data = NULL;
		data = oneshot (buf, size, i);
		r_list_append (res, data);
	}

	return res;
}

struct r_bin_xtr_plugin_t r_bin_xtr_plugin_dyldcache = {
	.name = "dyldcache",
	.desc = "dyld cache bin extractor plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.check = &check,
	.load = &load,
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
	.data = &r_bin_xtr_plugin_dyldcache
};
#endif
