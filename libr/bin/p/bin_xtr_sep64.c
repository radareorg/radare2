/* radare - LGPL - Copyright 2009-2019 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#define R_BIN_MACH064 1
#include "../format/mach0/mach0.h"
#include "../format/mach0/mach0_defines.h"

/* at offset 0x10f8 (pointer to it stored right after "legion2") */
typedef struct _RSepHdr64 {
	ut8 kernel_uuid[16];
	ut64 unknown0;
	ut64 kernel_base_paddr;
	ut64 kernel_max_paddr;
	ut64 app_images_base_paddr;
	ut64 app_images_max_paddr;
	ut64 paddr_max; /* size of SEP firmware image */
	ut64 unknown1;
	ut64 unknown2;
	ut64 unknown3;
	ut64 init_base_paddr;
	ut64 unknown4;
	ut64 unknown5;
	ut64 unknown6;
	ut64 unknown7;
	ut64 unknown8;
	ut64 unknown9;
	char init_name[16];
	ut8 init_uuid[16];
	ut64 unknown10;
	ut64 unknown11;
	ut64 n_apps;
} RSepHdr64;

/* right after the above, from offset 0x11c0 */
typedef struct _RSepApp64 {
	ut64 phys_text;
	ut64 size_text;
	ut64 phys_data;
	ut64 size_data;
	ut64 virt;
	ut64 entry;
	ut64 unknown4;
	ut64 unknown5;
	ut64 unknown6;
	ut32 minus_one;
	ut32 unknown7;
	char app_name[16];
	ut8 app_uuid[16];
	ut64 unknown8;
} RSepApp64;

typedef struct _RSepMachoInfo {
	struct MACH0_(mach_header) * hdr;
	ut64 total_size;
	ut64 text_size;
	ut64 data_offset;
	ut64 data_size;
	ut64 text_offset_in_whole;
	ut64 data_offset_in_whole;
} RSepMachoInfo;

typedef struct _RSepSlice64 {
	RBuffer * buf;
	RBinXtrMetadata * meta;
	ut64 nominal_offset;
	ut64 total_size;
} RSepSlice64;

typedef struct _RSepXtr64Ctx {
	RSepHdr64 * hdr;
	RSepApp64 * apps;
} RSepXtr64Ctx;

static RSepXtr64Ctx * sep64_xtr_ctx_new(RBuffer * buf);
static void sep64_xtr_ctx_free(void * p);
static RSepSlice64 * sep64_xtr_ctx_get_slice(RSepXtr64Ctx * ctx, RBuffer * whole, int idx);

static RSepMachoInfo * mach0_info_new(RBuffer * buf, ut64 at, ut64 max_size);
static void mach0_info_free(RSepMachoInfo * info);

static ut32 read_arm64_ins(RBuffer *b, int idx);
static char * get_proper_name (const char * app_name);
static RBuffer * extract_slice(RBuffer * whole, RSepMachoInfo * info);
static inline void fill_metadata_info_from_hdr(RBinXtrMetadata *meta, struct MACH0_(mach_header) *hdr);

#define BTW(val, min, max) ((val) > min && (val) < max)

static bool check_buffer(RBuffer *b) {
	r_return_val_if_fail (b, false);

	const ut64 sz = r_buf_size (b);
	if (sz < 0x11c0) {
		return false;
	}

	ut32 msr_vbar_el1 = read_arm64_ins (b, 2);
	if (msr_vbar_el1 != 0xd518c002) {
		return false;
	}
	ut32 adr = read_arm64_ins (b, 1);
	if (adr != 0x10003fe2) {
		return false;
	}

	/* check exception vector */
	if (read_arm64_ins (b, 512) != 0x14000000) {
		return false;
	}
	if (read_arm64_ins (b, 1023) != 0x14000000) {
		return false;
	}

	/* legion2 */
	if (read_arm64_ins (b, 1028) !=  0x326e6f69) {
		return false;
	}

	/* data header start */
	ut64 hdr_offset = read_arm64_ins (b, 1029);
	if (hdr_offset >= sz) {
		return false;
	}

	/* check size */
	if (r_buf_read_le64_at (b, hdr_offset + 56) != sz) {
		return false;
	}

	return true;
}

static bool load(RBin *bin) {
	return ((bin->cur->xtr_obj = sep64_xtr_ctx_new (bin->cur->buf)) != NULL);
}

static void destroy(RBin *bin) {
	sep64_xtr_ctx_free (bin->cur->xtr_obj);
}

static int size(RBin *bin) {
	// TODO
	return 0;
}

static RBinXtrData *oneshot_buffer(RBin *bin, RBuffer *b, int idx) {
	r_return_val_if_fail (bin && bin->cur, NULL);

	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = sep64_xtr_ctx_new (b);
	}
	RSepXtr64Ctx * ctx = bin->cur->xtr_obj;

	RSepSlice64 * slice = sep64_xtr_ctx_get_slice (ctx, b, idx);
	RBinXtrData * res = r_bin_xtrdata_new (slice->buf, slice->nominal_offset, slice->total_size, 3 + ctx->hdr->n_apps, slice->meta);

	r_buf_free (slice->buf);
	free (slice);
	return res;
}

static RList * oneshotall_buffer(RBin *bin, RBuffer *b) {
	RBinXtrData *data = oneshot_buffer (bin, b, 0);
	if (data) {
		int narch = data->file_count;
		RList *res = r_list_newf (r_bin_xtrdata_free);
		if (!res) {
			r_bin_xtrdata_free (data);
			return NULL;
		}
		r_list_append (res, data);
		int i;
		for (i = 1; data && i < narch; i++) {
			data = oneshot_buffer (bin, b, i);
			r_list_append (res, data);
		}
		return res;
	}
	return NULL;
}

static RSepXtr64Ctx * sep64_xtr_ctx_new(RBuffer * buf) {
	RSepHdr64 * hdr = NULL;
	RSepApp64 * apps = NULL;
	RSepXtr64Ctx * ctx = NULL;

	ut64 hdr_offset = r_buf_read_le64_at (buf, 0x1014);
	if (hdr_offset == UT64_MAX) {
		goto beach;
	}

	hdr = R_NEW0 (RSepHdr64);
	if (!hdr) {
		goto beach;
	}
	if (r_buf_fread_at (buf, hdr_offset, (ut8 *) hdr, "16c16l16c16c3l", 1) != sizeof (RSepHdr64)) {
		goto beach;
	}

	if (!hdr->n_apps) {
		goto beach;
	}

	ut64 apps_at = hdr_offset + sizeof (RSepHdr64);
	apps = R_NEWS0 (RSepApp64, hdr->n_apps);
	if (!apps) {
		goto beach;
	}
	if (r_buf_fread_at (buf, apps_at, (ut8*) apps, "9l2i16c16cl", hdr->n_apps) != (sizeof (RSepApp64) * hdr->n_apps)) {
		goto beach;
	}

	ctx = R_NEW0 (RSepXtr64Ctx);
	if (!ctx) {
		goto beach;
	}

	ctx->hdr = hdr;
	ctx->apps = apps;

	return ctx;
beach:
	free (hdr);
	free (apps);
	free (ctx);

	return NULL;
}

static void sep64_xtr_ctx_free(void * p) {
	if (!p) {
		return;
	}

	RSepXtr64Ctx * ctx = p;

	R_FREE (ctx->hdr);
	R_FREE (ctx->apps);

	free (ctx);
}

static RSepSlice64 * sep64_xtr_ctx_get_slice(RSepXtr64Ctx * ctx, RBuffer * whole, int idx) {
	if (idx >= ctx->hdr->n_apps + 3) {
		return NULL;
	}

	ut64 whole_size = r_buf_size (whole);
	RBuffer * slice_buf = NULL;
	char * name = NULL;
	RSepSlice64 * slice = NULL;
	RSepMachoInfo * info = NULL;
	RBinXtrMetadata * meta = NULL;
	ut64 nominal_offset = 0;
	ut64 total_size = 0;

	if (idx == 0) {
		name = strdup ("boot");
		slice_buf = r_buf_new_slice (whole, 0, ctx->hdr->kernel_base_paddr);
		total_size = ctx->hdr->kernel_base_paddr;
	} else if (idx == 1) {
		name = strdup ("kernel");
		info = mach0_info_new (whole, ctx->hdr->kernel_base_paddr, whole_size - ctx->hdr->kernel_base_paddr);
		if (!info) {
			goto beach;
		}
		slice_buf = r_buf_new_slice (whole, ctx->hdr->kernel_base_paddr, info->total_size);
		nominal_offset = ctx->hdr->kernel_base_paddr;
		total_size = info->total_size;
	} else if (idx == 2) {
		name = get_proper_name (ctx->hdr->init_name);
		info = mach0_info_new (whole, ctx->hdr->init_base_paddr, whole_size - ctx->hdr->init_base_paddr);
		if (!info) {
			goto beach;
		}
		slice_buf = extract_slice (whole, info);
		nominal_offset = ctx->hdr->init_base_paddr;
		total_size = info->total_size;
	} else {
		int app_idx = idx - 3;
		name = get_proper_name (ctx->apps[app_idx].app_name);
		info = mach0_info_new (whole, ctx->apps[app_idx].phys_text, whole_size - ctx->apps[app_idx].phys_text);
		if (!info) {
			goto beach;
		}
		info->data_offset_in_whole = ctx->apps[app_idx].phys_data;
		slice_buf = extract_slice (whole, info);
		nominal_offset = ctx->apps[app_idx].phys_text;
		total_size = info->total_size;
	}

	if (!name || !slice_buf) {
		goto beach;
	}

	meta = R_NEW0 (RBinXtrMetadata);
	if (!meta) {
		goto beach;
	}

	if (info) {
		fill_metadata_info_from_hdr (meta, info->hdr);
	} else {
		meta->arch = strdup ("arm");
		meta->bits = 64;
		meta->machine = strdup ("arm64e");
		meta->type = strdup ("Executable file");
	}

	meta->xtr_type = "SEP";
	meta->libname = name;

	slice = R_NEW0 (RSepSlice64);
	if (!slice) {
		goto beach;
	}

	slice->buf = slice_buf;
	slice->nominal_offset = nominal_offset;
	slice->total_size = total_size;
	slice->meta = meta;

	mach0_info_free (info);

	return slice;
beach:
	r_buf_free (slice_buf);
	free (name);
	free (slice);
	free (meta);
	mach0_info_free (info);
	return NULL;
}

static RSepMachoInfo * mach0_info_new(RBuffer * buf, ut64 at, ut64 max_size) {
	r_return_val_if_fail (max_size >= 1024, NULL);

	RSepMachoInfo * result = NULL;
	struct MACH0_(mach_header) *hdr = NULL;
	ut8 * commands = NULL;
	ut64 total_size = 0, text_size = 0, data_offset = 0, data_size = 0;

	ut32 hdr_size = sizeof (struct MACH0_(mach_header));
	hdr = malloc (hdr_size);
	if (!hdr) {
		goto beach;
	}
	if (r_buf_read_at (buf, at, (ut8 *) hdr, hdr_size) != hdr_size) {
		goto beach;
	}
	if (hdr->magic != MH_MAGIC_64 || !BTW (hdr->sizeofcmds, 0, max_size)) {
		goto beach;
	}

	commands = malloc (hdr->sizeofcmds);
	if (!commands) {
		goto beach;
	}
	if (r_buf_read_at (buf, at + hdr_size, commands, hdr->sizeofcmds) != hdr->sizeofcmds) {
		goto beach;
	}

	ut32 i;
	ut8 * cursor = commands;
	for (i = 0; i < hdr->ncmds; i++) {
		const struct load_command * cmd = (struct load_command *) cursor;
		if (cmd->cmd == LC_SEGMENT_64) {
			const struct MACH0_(segment_command) * seg = (struct MACH0_(segment_command) *) cursor;
			ut64 end = seg->fileoff + seg->filesize;
			if (total_size < end) {
				total_size = end;
			}
			if (!strcmp (seg->segname, "__TEXT")) {
				text_size = seg->filesize;
			} else if (!strcmp (seg->segname, "__DATA")) {
				data_offset = seg->fileoff;
				data_size = seg->filesize;
			}
		}
		cursor = cursor + cmd->cmdsize;
	}

	if (total_size == 0 || text_size == 0 || data_offset == 0 || data_size == 0) {
		goto beach;
	}

	result = R_NEW0 (RSepMachoInfo);
	if (!result) {
		goto beach;
	}

	result->hdr = hdr;
	result->total_size = total_size;
	result->text_size = text_size;
	result->data_offset = data_offset;
	result->data_size = data_size;
	result->text_offset_in_whole = at;

	free (commands);

	return result;
beach:

	free (result);
	free (hdr);
	free (commands);

	return NULL;
}

static void mach0_info_free(RSepMachoInfo * info) {
	if (!info) {
		return;
	}

	free (info->hdr);
	free (info);
}

static RBuffer * extract_slice(RBuffer * whole, RSepMachoInfo * info) {
	ut8 * content = NULL;

	content = (ut8 *) malloc (info->total_size);
	if (!content) {
		goto beach;
	}
	if (r_buf_read_at (whole, info->text_offset_in_whole, content, info->text_size) != info->text_size) {
		goto beach;
	}
	ut64 data_offset = info->data_offset_in_whole ? info->data_offset_in_whole : info->text_offset_in_whole + info->data_offset;
	if (r_buf_read_at (whole, data_offset, content + info->data_offset, info->data_size) != info->data_size) {
		goto beach;
	}

	return r_buf_new_with_pointers (content, info->total_size, true);
beach:
	free (content);

	return NULL;
}

static inline void fill_metadata_info_from_hdr(RBinXtrMetadata *meta, struct MACH0_(mach_header) *hdr) {
	meta->arch = strdup (MACH0_(get_cputype_from_hdr) (hdr));
	meta->bits = MACH0_(get_bits_from_hdr) (hdr);
	meta->machine = MACH0_(get_cpusubtype_from_hdr) (hdr);
	meta->type = MACH0_(get_filetype_from_hdr) (hdr);
}

static char * get_proper_name (const char * app_name) {
	char * proper_name = calloc (13, 1);
	if (!proper_name) {
		return NULL;
	}
	int i;

	for (i = 12; i != -1; i--) {
		if (app_name[i] == ' ') {
			proper_name[i] = 0;
		} else {
			proper_name[i] = app_name[i];
		}
	}

	return proper_name;
}

static ut32 read_arm64_ins(RBuffer *b, int idx) {
	return r_buf_read_le32_at (b, idx * 4);
}

RBinXtrPlugin r_bin_xtr_plugin_xtr_sep64 = {
	.name = "xtr.sep64",
	.desc = "64-bit SEP bin extractor plugin",
	.license = "LGPL3",
	.check_buffer = check_buffer,
	.load = &load,
	.destroy = &destroy,
	.size = &size,
	.extract_from_buffer = &oneshot_buffer,
	.extractall_from_buffer = &oneshotall_buffer,
	.free_xtr = &sep64_xtr_ctx_free,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_xtr_sep64,
	.version = R2_VERSION
};
#endif
