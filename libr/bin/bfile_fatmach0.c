/* radare - LGPL - Copyright 2026 - pancake */

/* Native fat Mach-O slice dispatch for r_bin.
 *
 * This replaces the former bin_xtr_fatmach0 plugin: fat Mach-O is a
 * container of mach-o slices, not a binary format of its own. The old
 * xtr plugin indirection (iterated from r_bin_open_buf) is gone; this
 * file exposes r_bin_file_fatmach0_load() which produces the same
 * RBinFile + xtr_data shape r_bin_file_find_by_arch_bits expects.
 *
 * A matching r_fs plugin (fs_fatmacho) exposes the same data to users
 * via `m /mnt fatmacho` without going through r_bin at all. */

#include <r_bin.h>
#include "i/private.h"
#include "format/mach0/fatmach0.h"
#include "format/mach0/mach0.h"

static bool is_fatmach0(RBuffer *b) {
	ut8 buf[4] = {0};
	const ut64 sz = r_buf_size (b);
	if (sz < 0x300) {
		return false;
	}
	if (r_buf_read_at (b, 0, buf, 4) != 4) {
		return false;
	}
	if (memcmp (buf, "\xca\xfe\xba\xbe", 4)) {
		return false;
	}
	// check that the first arch points at a real mach-o to disambiguate
	// from java .class (same magic).
	ut64 off = r_buf_read_be32_at (b, 4 * sizeof (32));
	if (off == 0 || off + 4 >= sz) {
		return false;
	}
	if (r_buf_read_at (b, off, buf, 4) != 4) {
		return false;
	}
	return !memcmp (buf, "\xce\xfa\xed\xfe", 4)
		|| !memcmp (buf, "\xfe\xed\xfa\xce", 4)
		|| !memcmp (buf, "\xfe\xed\xfa\xcf", 4)
		|| !memcmp (buf, "\xcf\xfa\xed\xfe", 4);
}

static void fill_metadata(RBinXtrMetadata *meta, struct MACH0_(mach_header) *hdr) {
	meta->arch = strdup (MACH0_(get_cputype_from_hdr) (hdr));
	meta->bits = MACH0_(get_bits_from_hdr) (hdr);
	meta->machine = MACH0_(get_cpusubtype_from_hdr) (hdr);
	meta->type = MACH0_(get_filetype_from_hdr) (hdr);
	meta->libname = NULL;
	meta->xtr_type = "fat";
}

static RBinXtrData *slice_to_xtrdata(struct r_bin_fatmach0_obj_t *fb, int idx, int narch) {
	struct r_bin_fatmach0_arch_t *arch = r_bin_fatmach0_extract (fb, idx, NULL);
	if (!arch) {
		return NULL;
	}
	RBinXtrData *res = NULL;
	struct MACH0_(mach_header) *hdr = MACH0_(get_hdr) (arch->b);
	if (hdr) {
		RBinXtrMetadata *meta = R_NEW0 (RBinXtrMetadata);
		if (meta) {
			fill_metadata (meta, hdr);
			res = r_bin_xtrdata_new (arch->b, arch->offset, arch->size, narch, meta);
		}
		free (hdr);
	}
	r_unref (arch->b);
	free (arch);
	return res;
}

R_IPI bool r_bin_file_fatmach0_check(RBuffer *buf) {
	return buf && is_fatmach0 (buf);
}

R_IPI RBinFile *r_bin_file_fatmach0_load(RBin *bin, const char *filename, RBuffer *buf,
		ut64 baseaddr, ut64 loadaddr, int fd, int rawstr) {
	R_RETURN_VAL_IF_FAIL (bin && buf, NULL);

	struct r_bin_fatmach0_obj_t *fb = r_bin_fatmach0_from_buffer_new (buf);
	if (!fb) {
		return NULL;
	}
	const int narch = fb->nfat_arch;
	RList *xtr_data = r_list_newf (r_bin_xtrdata_free);
	if (!xtr_data) {
		r_bin_fatmach0_free (fb);
		return NULL;
	}
	int i;
	for (i = 0; i < narch; i++) {
		RBinXtrData *d = slice_to_xtrdata (fb, i, narch);
		if (d) {
			r_list_append (xtr_data, d);
		}
	}
	r_bin_fatmach0_free (fb);
	if (r_list_empty (xtr_data)) {
		r_list_free (xtr_data);
		return NULL;
	}

	RBinFile *bf = r_bin_file_find_by_name (bin, filename);
	if (!bf) {
		RBinFileOptions *opt = R_NEW0 (RBinFileOptions);
		opt->rawstr = rawstr;
		opt->fd = fd;
		opt->pluginname = "fatmach0"; // informational: previously "xtr.fatmach0"
		bf = r_bin_file_new (bin, filename, r_buf_size (buf), opt, bin->sdb, false);
		if (!bf) {
			r_list_free (xtr_data);
			return NULL;
		}
		r_list_append (bin->binfiles, bf);
		if (!bin->cur) {
			bin->cur = bf;
		}
	}
	r_list_free (bf->xtr_data);
	bf->xtr_data = xtr_data;

	RListIter *iter;
	RBinXtrData *x;
	r_list_foreach (bf->xtr_data, iter, x) {
		if (x) {
			x->baddr = baseaddr ? baseaddr : UT64_MAX;
			x->laddr = loadaddr ? loadaddr : UT64_MAX;
		}
	}
	bf->loadaddr = loadaddr;
	return bf;
}
