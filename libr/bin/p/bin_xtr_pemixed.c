/* radare - LGPL - Copyright 2018 - JohnPeng47 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pe/pemixed.h"

static RList * oneshotall(RBin *bin, const ut8 *buf, ut64 size);
static bool check_bytes(const ut8 *bytes, ut64 sz);
static RBinXtrData * oneshot(RBin *bin, const ut8 *buf, ut64 size, int subbin_type);
static int destroy(RBin *bin);
static int free_xtr (void *xtr_obj);

//copied from bin_pe
//another check is used later to check for .NET only code
static bool check_bytes(const ut8 *bytes, ut64 sz) {
	// XXX pemixed is always loaded because it uses
	// XXX the same signature for fat and non-fat
	// XXX so we need to make that action implicit
	return false;
#if 0
	if (!bytes) {
		return false;
	}
	if (sz <= 0x3d) { //less than size of MS-DOS header which is 64bytes
		return false;
	}
	ut32 idx = (bytes[0x3c] | (bytes[0x3d]<<8));
	if (sz > idx + 0x18 + 2) {
		/* Here PE signature for usual PE files
		 * and PL signature for Phar Lap TNT DOS extender 32bit executables
		 */
		if (!memcmp (bytes, "MZ", 2)) {
			if (!memcmp (bytes+idx, "PE", 2) &&
				!memcmp (bytes+idx+0x18, "\x0b\x01", 2)) {
				return true;
			}
			// TODO: Add one more indicator, to prevent false positives
			if (!memcmp (bytes+idx, "PL", 2)) {
				return true;
			}
		}
	}
	return false;
#endif
}

static RList * oneshotall(RBin *bin, const ut8 *buf, ut64 size) {
	//extract dos componenent first
	RBinXtrData *data = oneshot (bin, buf, size, SUB_BIN_DOS);

	if (!data) {
		return NULL;
	}
	// XXX - how do we validate a valid narch?
	RList * res = r_list_newf (r_bin_xtrdata_free);
	r_list_append (res, data);

	if ((data = oneshot (bin, buf, size, SUB_BIN_NATIVE))){
		r_list_append (res, data);
	}

	if ((data = oneshot (bin, buf, size, SUB_BIN_NET))){
		r_list_append (res, data);
	}

	return res;
}

//implement this later
static void fill_metadata_info_from_hdr(RBinXtrMetadata *meta, void *foo) {// struct Pe_32_r_bin_pemixed_obj_t* pe_bin){
	meta->arch = NULL;
	meta->bits = 0;
	meta->machine = NULL;
	meta->type = NULL;
	meta->libname = NULL;
	meta->xtr_type = "net";
	//strcpy (meta->xtr_type, "net");
}

static RBinXtrData * oneshot(RBin *bin, const ut8 *buf, ut64 size, int sub_bin_type) {
	struct r_bin_pemixed_obj_t* fb;
	struct PE_(r_bin_pe_obj_t)* pe;

	if (!bin || !bin->cur) {
		return NULL;
	}

	if (!bin->cur->xtr_obj){
		bin->cur->xtr_obj = r_bin_pemixed_from_bytes_new(buf, size);
	}

	fb = bin->cur->xtr_obj;

	//this function is prolly not nessescary
	pe = r_bin_pemixed_extract (fb, sub_bin_type);

	if (!pe){
		return NULL;
	}

	RBinXtrMetadata *metadata = R_NEW0 (RBinXtrMetadata);
	if (!metadata) {
		return NULL;
	}

	fill_metadata_info_from_hdr (metadata, pe);
	return r_bin_xtrdata_new (pe->b, 0, pe->size, 3, metadata);
}

static int destroy(RBin *bin) {
	return free_xtr (bin->cur->xtr_obj);
}

static int free_xtr (void *xtr_obj) {
	r_bin_pemixed_free ((struct r_bin_pemixed_obj_t*) xtr_obj);
	return true;
}

RBinXtrPlugin r_bin_xtr_plugin_xtr_pemixed = {
	.name = "xtr.pemixed",
	.desc = "Extract sub-binaries in PE files",
	.load = NULL, 		//not yet implemented
	.extract = NULL, 	//not yet implemented
	.extractall = NULL, //not yet implemented
	.destroy = &destroy,
	.extract_from_bytes = &oneshot,
	.extractall_from_bytes = &oneshotall,
	.free_xtr = &free_xtr,
	.check_bytes = &check_bytes,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_pemixed,
	.version = R2_VERSION
};
#endif
