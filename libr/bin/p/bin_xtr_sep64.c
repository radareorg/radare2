/* radare - LGPLv3 - Copyright 2009-2024 - pancake */

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
	struct MACH0_(mach_header) hdr;
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

static RSepXtr64Ctx * sep64_xtr_ctx_new(RBuffer *buf);
static void sep64_xtr_ctx_free(void *p);
static RSepSlice64 * sep64_xtr_ctx_get_slice(RSepXtr64Ctx * ctx, RBuffer *whole, int idx);

static RSepMachoInfo * mach0_info_new(RBuffer *buf, ut64 at, ut64 max_size);
static RBinXtrMetadata * metadata_new(char *name, RSepMachoInfo *info);

static ut32 read_arm64_ins(RBuffer *b, int idx);
static char * get_proper_name(const char *app_name);
static RBuffer * extract_slice(RBuffer * whole, RSepMachoInfo *info);
static inline void fill_metadata_info_from_hdr(RBinXtrMetadata *meta, struct MACH0_(mach_header) *hdr);

static bool check(RBinFile *bf, RBuffer *b) {
	R_RETURN_VAL_IF_FAIL (b, false);

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
	return ((bin->cur->xtr_obj = sep64_xtr_ctx_new (bin->cur->buf)));
}

static void destroy(RBin *bin) {
	sep64_xtr_ctx_free (bin->cur->xtr_obj);
}

static int size(RBin *bin) {
	// TODO
	return 0;
}

static RBinXtrData *oneshot_buffer(RBin *bin, RBuffer *b, int idx) {
	R_RETURN_VAL_IF_FAIL (bin && bin->cur && b, NULL);

	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = sep64_xtr_ctx_new (b);
	}
	RSepXtr64Ctx *ctx = bin->cur->xtr_obj;
	if (!ctx) {
		return NULL;
	}
	RSepSlice64 *slice = sep64_xtr_ctx_get_slice (ctx, b, idx);
	if (!slice) {
		R_LOG_DEBUG ("Cannot get slice %d, binary reports %"PFMT64u" entries", idx, ctx->hdr->n_apps);
		ctx->hdr->n_apps = idx > 0? idx - 1: 0;
		return NULL;
	}
	RBinXtrData * res = r_bin_xtrdata_new (slice->buf, slice->nominal_offset,
			slice->total_size, 3 + ctx->hdr->n_apps, slice->meta);

	r_unref (slice->buf);
	free (slice);
	return res;
}

static RList *oneshotall_buffer(RBin *bin, RBuffer *b) {
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
			if (data) {
				r_list_append (res, data);
			}
		}
		return res;
	}
	return NULL;
}

static RSepXtr64Ctx *sep64_xtr_ctx_new(RBuffer *buf) {
	R_RETURN_VAL_IF_FAIL (buf, NULL);

	const ut64 buf_size = r_buf_size (buf);
	ut64 hdr_offset = r_buf_read_le64_at (buf, 0x1014);
	if (hdr_offset == UT64_MAX || hdr_offset > buf_size || sizeof (RSepHdr64) > buf_size - hdr_offset) {
		return NULL;
	}

	RSepHdr64 *hdr = R_NEW0 (RSepHdr64);
	if (r_buf_fread_at (buf, hdr_offset, (ut8 *) hdr, "16c16l16c16c3l", 1) != sizeof (RSepHdr64)) {
		free (hdr);
		return NULL;
	}
	ut64 apps_at = hdr_offset + sizeof (RSepHdr64);
	ut64 max_apps = (buf_size - apps_at) / sizeof (RSepApp64);
	if (!hdr->n_apps || hdr->n_apps > max_apps) {
		free (hdr);
		return NULL;
	}
	RSepApp64 *apps = R_NEWS0 (RSepApp64, hdr->n_apps);
	if (!apps) {
		free (hdr);
		return NULL;
	}
	if (r_buf_fread_at (buf, apps_at, (ut8*) apps, "9l2i16c16cl", hdr->n_apps) != (sizeof (RSepApp64) * hdr->n_apps)) {
		free (apps);
		free (hdr);
		return NULL;
	}

	RSepXtr64Ctx *ctx = R_NEW0 (RSepXtr64Ctx);
	ctx->hdr = hdr;
	ctx->apps = apps;
	return ctx;
}

static void sep64_xtr_ctx_free(void *p) {
	if (p) {
		RSepXtr64Ctx *ctx = p;
		R_FREE (ctx->hdr);
		R_FREE (ctx->apps);
		free (ctx);
	}
}

static RSepSlice64 *sep64_xtr_ctx_get_slice(RSepXtr64Ctx * ctx, RBuffer *whole, int idx) {
	R_RETURN_VAL_IF_FAIL (ctx && ctx->hdr && whole, NULL);

	if (idx < 0 || idx >= ctx->hdr->n_apps + 3) {
		return NULL;
	}

	ut64 whole_size = r_buf_size (whole);
	RBuffer * slice_buf = NULL;
	RSepMachoInfo * info = NULL;
	ut64 nominal_offset = 0;
	ut64 total_size = 0;
	ut64 at = 0;
	ut64 data_offset_in_whole = 0;
	bool extract = false;
	char *name = NULL;

	if (idx == 0) {
		name = strdup ("boot");
		total_size = ctx->hdr->kernel_base_paddr;
		if (!name || total_size > whole_size) {
			free (name);
			return NULL;
		}
		slice_buf = r_buf_new_slice (whole, 0, total_size);
	} else {
		nominal_offset = idx == 1? ctx->hdr->kernel_base_paddr: idx == 2? ctx->hdr->init_base_paddr: ctx->apps[idx - 3].phys_text;
		at = nominal_offset;
		if (at >= whole_size) {
			return NULL;
		}
		if (idx == 1) {
			name = strdup ("kernel");
		} else if (idx == 2) {
			name = get_proper_name (ctx->hdr->init_name);
			extract = true;
		} else {
			name = get_proper_name (ctx->apps[idx - 3].app_name);
			data_offset_in_whole = ctx->apps[idx - 3].phys_data;
			extract = true;
		}
		if (!name) {
			return NULL;
		}
		info = mach0_info_new (whole, at, whole_size - at);
		if (!info) {
			free (name);
			return NULL;
		}
		info->data_offset_in_whole = data_offset_in_whole;
		total_size = info->total_size;
		slice_buf = extract? extract_slice (whole, info): r_buf_new_slice (whole, at, total_size);
	}

	if (!slice_buf) {
		free (info);
		free (name);
		return NULL;
	}

	RBinXtrMetadata *meta = metadata_new (name, info);
	free (info);
	if (!meta) {
		r_unref (slice_buf);
		return NULL;
	}
	RSepSlice64 *slice = R_NEW0 (RSepSlice64);
	slice->buf = slice_buf;
	slice->nominal_offset = nominal_offset;
	slice->total_size = total_size;
	slice->meta = meta;
	return slice;
}

static RSepMachoInfo * mach0_info_new(RBuffer *buf, ut64 at, ut64 max_size) {
	R_RETURN_VAL_IF_FAIL (buf && max_size >= sizeof (struct MACH0_(mach_header)), NULL);

	struct MACH0_(mach_header) hdr;
	ut64 total_size = 0, text_size = 0, data_offset = 0, data_size = 0;
	bool has_text = false, has_data = false;
	ut32 hdr_size = sizeof (hdr);
	if (r_buf_read_at (buf, at, (ut8 *) &hdr, hdr_size) != hdr_size) {
		return NULL;
	}
	if (hdr.magic != MH_MAGIC_64 || !hdr.ncmds || hdr.sizeofcmds < sizeof (struct load_command) || hdr.sizeofcmds > max_size - hdr_size) {
		return NULL;
	}

	ut8 *commands = malloc (hdr.sizeofcmds);
	if (!commands) {
		return NULL;
	}
	if (r_buf_read_at (buf, at + hdr_size, commands, hdr.sizeofcmds) != hdr.sizeofcmds) {
		free (commands);
		return NULL;
	}

	ut32 i;
	ut8 * cursor = commands;
	ut8 * commands_end = commands + hdr.sizeofcmds;
	for (i = 0; i < hdr.ncmds; i++) {
		if (cursor > commands_end || sizeof (struct load_command) > (size_t)(commands_end - cursor)) {
			free (commands);
			return NULL;
		}
		const struct load_command * cmd = (struct load_command *) cursor;
		if (cmd->cmdsize < sizeof (struct load_command) || cmd->cmdsize > (ut32)(commands_end - cursor)) {
			free (commands);
			return NULL;
		}
		if (cmd->cmd == LC_SEGMENT_64) {
			if (cmd->cmdsize < sizeof (struct MACH0_(segment_command))) {
				free (commands);
				return NULL;
			}
			const struct MACH0_(segment_command) * seg = (struct MACH0_(segment_command) *) cursor;
			if (seg->fileoff > max_size || seg->filesize > max_size - seg->fileoff) {
				free (commands);
				return NULL;
			}
			ut64 seg_end = seg->fileoff + seg->filesize;
			if (total_size < seg_end) {
				total_size = seg_end;
			}
			if (!strcmp (seg->segname, "__TEXT")) {
				text_size = seg->filesize;
				has_text = true;
			} else if (!strcmp (seg->segname, "__DATA")) {
				data_offset = seg->fileoff;
				data_size = seg->filesize;
				has_data = true;
			}
		}
		cursor += cmd->cmdsize;
	}
	free (commands);

	if (total_size == 0 || !text_size || !data_size || !has_text || !has_data || text_size > total_size || data_offset > total_size || data_size > total_size - data_offset) {
		return NULL;
	}

	RSepMachoInfo *result = R_NEW0 (RSepMachoInfo);
	result->hdr = hdr;
	result->total_size = total_size;
	result->text_size = text_size;
	result->data_offset = data_offset;
	result->data_size = data_size;
	result->text_offset_in_whole = at;
	return result;
}

static RBuffer * extract_slice(RBuffer * whole, RSepMachoInfo *info) {
	R_RETURN_VAL_IF_FAIL (whole && info, NULL);

	ut64 whole_size = r_buf_size (whole);
	if (!info->data_offset_in_whole && info->data_offset > UT64_MAX - info->text_offset_in_whole) {
		return NULL;
	}
	ut64 data_offset = info->data_offset_in_whole? info->data_offset_in_whole: info->text_offset_in_whole + info->data_offset;
	if (info->text_size > info->total_size
		|| info->data_offset > info->total_size
		|| info->data_size > info->total_size - info->data_offset
		|| info->text_offset_in_whole > whole_size
		|| info->text_size > whole_size - info->text_offset_in_whole
		|| data_offset > whole_size
		|| info->data_size > whole_size - data_offset) {
		return NULL;
	}

	ut8 *content = calloc (1, info->total_size);
	if (!content) {
		return NULL;
	}
	if (r_buf_read_at (whole, info->text_offset_in_whole, content, info->text_size) != info->text_size
		|| r_buf_read_at (whole, data_offset, content + info->data_offset, info->data_size) != info->data_size) {
		free (content);
		return NULL;
	}

	return r_buf_new_with_pointers (content, info->total_size, true);
}

static inline void fill_metadata_info_from_hdr(RBinXtrMetadata *meta, struct MACH0_(mach_header) *hdr) {
	meta->arch = strdup (MACH0_(get_cputype_from_hdr) (hdr));
	meta->bits = MACH0_(get_bits_from_hdr) (hdr);
	meta->machine = MACH0_(get_cpusubtype_from_hdr) (hdr);
	meta->type = MACH0_(get_filetype_from_hdr) (hdr);
}

static RBinXtrMetadata * metadata_new(char *name, RSepMachoInfo *info) {
	if (!name) {
		return NULL;
	}
	RBinXtrMetadata *meta = R_NEW0 (RBinXtrMetadata);
	if (info) {
		fill_metadata_info_from_hdr (meta, &info->hdr);
	} else {
		meta->arch = strdup ("arm");
		meta->bits = 64;
		meta->machine = strdup ("arm64e");
		meta->type = strdup ("Executable file");
	}
	meta->xtr_type = "SEP";
	meta->libname = name;
	return meta;
}

static char * get_proper_name(const char *app_name) {
	char * proper_name = calloc (17, 1);
	if (!proper_name) {
		return NULL;
	}
	memcpy (proper_name, app_name, 16);
	int i;

	for (i = 15; i >= 0; i--) {
		if (!proper_name[i] || proper_name[i] == ' ') {
			proper_name[i] = 0;
		} else {
			break;
		}
	}

	return proper_name;
}

static ut32 read_arm64_ins(RBuffer *b, int idx) {
	return r_buf_read_le32_at (b, idx * 4);
}

RBinXtrPlugin r_bin_xtr_plugin_xtr_sep64 = {
	.meta = {
		.name = "xtr.sep64",
		.author = "pancake",
		.desc = "Secure Enclave 64-bit Executable",
		.license = "LGPL-3.0-only",
	},
	.check = check,
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
