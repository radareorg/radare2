/* radare - LGPL - Copyright 2009-2019 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/fatmach0.h"
#include "mach0/mach0.h"

static RBinXtrData * extract(RBin *bin, int idx);

static bool checkHeader(RBuffer *b) {
	ut8 buf[4];
	const ut64 sz = r_buf_size (b);
	r_buf_read_at (b, 0, buf, 4);
	if (sz >= 0x300 && !memcmp (buf, "\xca\xfe\xba\xbe", 4)) {
		ut64 addr = 4 * sizeof (32);
		ut64 off = r_buf_read_be32_at (b, addr);
		if (off > 0 && off + 4 < sz) {
			ut64 h = 0;
			r_buf_read_at (b, h + off, buf, 4);
			if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xce", 4) ||
				!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
				!memcmp (buf, "\xcf\xfa\xed\xfe", 4)) {
				return true;
			}
		}
	}
	return false;
}

static bool check_buffer (RBuffer *buf) {
	r_return_val_if_fail (buf, false);
	return checkHeader (buf);
}

static void free_xtr (void *xtr_obj) {
	r_bin_fatmach0_free ((struct r_bin_fatmach0_obj_t*)xtr_obj);
}

static void destroy(RBin *bin) {
	free_xtr (bin->cur->xtr_obj);
}

static bool load(RBin *bin) {
	return ((bin->cur->xtr_obj = r_bin_fatmach0_new (bin->file)) != NULL);
}

static int size(RBin *bin) {
	// TODO
	return 0;
}

static inline void fill_metadata_info_from_hdr(RBinXtrMetadata *meta, struct MACH0_(mach_header) *hdr) {
	meta->arch = strdup (MACH0_(get_cputype_from_hdr) (hdr));
	meta->bits = MACH0_(get_bits_from_hdr) (hdr);
	meta->machine = MACH0_(get_cpusubtype_from_hdr) (hdr);
	meta->type = MACH0_(get_filetype_from_hdr) (hdr);
	meta->libname = NULL;
	meta->xtr_type = "fat";
}

// XXX deprecate
static RBinXtrData *extract(RBin* bin, int idx) {
	int narch;
	struct r_bin_fatmach0_obj_t *fb = bin->cur->xtr_obj;
	struct r_bin_fatmach0_arch_t *arch = r_bin_fatmach0_extract (fb, idx, &narch);
	if (!arch) {
		return NULL;
	}
	RBinXtrMetadata *metadata = R_NEW0 (RBinXtrMetadata);
	if (!metadata) {
		r_buf_free (arch->b);
		free (arch);
		return NULL;
	}
	struct MACH0_(mach_header) *hdr = MACH0_(get_hdr) (arch->b);
	if (!hdr) {
		free (metadata);
		free (arch);
		free (hdr);
		return NULL;
	}
	fill_metadata_info_from_hdr (metadata, hdr);
	RBinXtrData * res = r_bin_xtrdata_new (arch->b, arch->offset, arch->size, narch, metadata);
	r_buf_free (arch->b);
	free (arch);
	free (hdr);
	return res;
}

static RBinXtrData *oneshot_buffer(RBin *bin, RBuffer *b, int idx) {
	r_return_val_if_fail (bin && bin->cur, NULL);

	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = r_bin_fatmach0_from_buffer_new (b);
	}
	int narch;
	struct r_bin_fatmach0_obj_t *fb = bin->cur->xtr_obj;
	struct r_bin_fatmach0_arch_t *arch = r_bin_fatmach0_extract (fb, idx, &narch);
	if (arch) {
		RBinXtrMetadata *metadata = R_NEW0 (RBinXtrMetadata);
		if (metadata) {
			struct MACH0_(mach_header) *hdr = MACH0_(get_hdr) (arch->b);
			if (hdr) {
				fill_metadata_info_from_hdr (metadata, hdr);
				RBinXtrData *res = r_bin_xtrdata_new (arch->b, arch->offset, arch->size, narch, metadata);
				r_buf_free (arch->b);
				free (arch);
				free (hdr);
				return res;
			}
			free (metadata);
		}
		free (arch);
	}
	return NULL;
}

static RList * oneshotall_buffer(RBin *bin, RBuffer *b) {
	RBinXtrData *data = oneshot_buffer (bin, b, 0);
	if (data) {
		// XXX - how do we validate a valid narch?
		int  narch = data->file_count;
		RList *res = r_list_newf (r_bin_xtrdata_free);
		if (!res) {
			r_bin_xtrdata_free (data);
			return NULL;
		}
		r_list_append (res, data);
		int i = 0;
		for (i = 1; data && i < narch; i++) {
			data = oneshot_buffer (bin, b, i);
			r_list_append (res, data);
		}
		return res;
	}
	return NULL;
}

RBinXtrPlugin r_bin_xtr_plugin_xtr_fatmach0 = {
	.name = "xtr.fatmach0",
	.desc = "fat mach0 bin extractor plugin",
	.license = "LGPL3",
	.load = &load,
	.size = &size,
	.extract = &extract,
	.destroy = &destroy,
	.extract_from_buffer = &oneshot_buffer,
	.extractall_from_buffer = &oneshotall_buffer,
	.free_xtr = &free_xtr,
	.check_buffer = check_buffer,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_fatmach0,
	.version = R2_VERSION
};
#endif
