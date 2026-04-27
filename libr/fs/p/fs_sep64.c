/* radare - LGPL - Copyright 2026 - pancake */

#include <r_fs.h>
#include <r_lib.h>

// SEP firmware layout: a 0x1000-byte ARM64 boot stub points at a header at
// the offset stored at 0x1014 (right after the "legion2" tag). The header
// lists a kernel image, an init image and N app images. App images keep
// __TEXT and __DATA at unrelated container offsets, so reads have to stitch
// the two regions together to look like a flat mach-o.
#define HDR_PTR_OFFSET 0x1014
#define MIN_SIZE       0x11c0
#define HDR_SIZE       200
#define APP_SIZE       120
#define NAPPS_MAX      256
#define MH_MAGIC_64    0xfeedfacfu
#define LC_SEGMENT_64  0x19u

typedef struct {
	char *name;
	ut64 size;          // total slice size
	ut64 phys_text;     // container offset of the text region (or boot start)
	ut64 text_size;     // bytes [0, text_size) come from phys_text
	ut64 data_offset;   // bytes [data_offset, data_offset+data_size) come from phys_data
	ut64 data_size;     // 0 for boot (no data region)
	ut64 phys_data;
} Slice;

typedef struct {
	ut32 nslices;
	Slice *slices;
	RBuffer *buf;       // owned: iob-backed at mount time, caller-owned in bins()
	bool owns_buf;
} Ctx;

static void ctx_free(Ctx *ctx) {
	if (!ctx) {
		return;
	}
	ut32 i;
	for (i = 0; i < ctx->nslices; i++) {
		free (ctx->slices[i].name);
	}
	free (ctx->slices);
	if (ctx->owns_buf) {
		r_unref (ctx->buf);
	}
	free (ctx);
}

// Locate __TEXT/__DATA in the mach-o at `at`. Returns true on success.
static bool parse_macho(RBuffer *b, ut64 at, ut64 max_size,
		ut64 *total, ut64 *text_sz, ut64 *data_off, ut64 *data_sz) {
	ut8 hdr[32];
	if (max_size < sizeof (hdr) || r_buf_read_at (b, at, hdr, sizeof (hdr)) != sizeof (hdr)) {
		return false;
	}
	if (r_read_le32 (hdr) != MH_MAGIC_64) {
		return false;
	}
	ut32 ncmds = r_read_le32 (hdr + 16);
	ut32 sizeofcmds = r_read_le32 (hdr + 20);
	if (!ncmds || sizeofcmds < 8 || sizeofcmds > max_size - 32) {
		return false;
	}
	ut8 *cmds = malloc (sizeofcmds);
	if (!cmds || r_buf_read_at (b, at + 32, cmds, sizeofcmds) != (int)sizeofcmds) {
		free (cmds);
		return false;
	}
	bool has_text = false, has_data = false;
	*total = *text_sz = *data_off = *data_sz = 0;
	ut32 cur = 0;
	while (ncmds-- && sizeofcmds - cur >= 8) {
		ut32 cmd = r_read_le32 (cmds + cur);
		ut32 cmdsize = r_read_le32 (cmds + cur + 4);
		if (cmdsize < 8 || cmdsize > sizeofcmds - cur) {
			break;
		}
		if (cmd == LC_SEGMENT_64 && cmdsize >= 72) {
			const char *segname = (const char *)(cmds + cur + 8);
			ut64 fileoff = r_read_le64 (cmds + cur + 40);
			ut64 filesize = r_read_le64 (cmds + cur + 48);
			if (fileoff > max_size || filesize > max_size - fileoff) {
				break;
			}
			ut64 end = fileoff + filesize;
			if (*total < end) {
				*total = end;
			}
			if (!strncmp (segname, "__TEXT", 16)) {
				*text_sz = filesize;
				has_text = true;
			} else if (!strncmp (segname, "__DATA", 16)) {
				*data_off = fileoff;
				*data_sz = filesize;
				has_data = true;
			}
		}
		cur += cmdsize;
	}
	free (cmds);
	return has_text && has_data && *total > 0
		&& *text_sz <= *total && *data_off <= *total
		&& *data_sz <= *total - *data_off;
}

// Populate a non-boot mach-o slice. data is contiguous with text when
// phys_data == 0 (kernel/init); apps pass an explicit phys_data.
static bool fill_macho_slice(RBuffer *b, ut64 sz, Slice *s, ut64 phys_text, ut64 phys_data, char *name) {
	ut64 total, text_sz, data_off, data_sz;
	if (phys_text >= sz || !parse_macho (b, phys_text, sz - phys_text,
			&total, &text_sz, &data_off, &data_sz)) {
		free (name);
		return false;
	}
	if (!phys_data) {
		phys_data = phys_text + data_off;
	}
	if (phys_data > sz || data_sz > sz - phys_data) {
		free (name);
		return false;
	}
	s->name = name;
	s->size = total;
	s->phys_text = phys_text;
	s->text_size = text_sz;
	s->data_offset = data_off;
	s->data_size = data_sz;
	s->phys_data = phys_data;
	return true;
}

static char *trim_name(const char *src, const char *fallback) {
	char *out = calloc (17, 1);
	memcpy (out, src, 16);
	r_str_trim_tail (out);
	if (!*out) {
		free (out);
		return strdup (fallback);
	}
	return out;
}

static Ctx *ctx_parse(RBuffer *b, bool log) {
	ut64 sz = r_buf_size (b);
	if (sz < MIN_SIZE) {
		return NULL;
	}
	// ARM64 boot stub fingerprints + "legion2" magic
	ut32 ins1 = r_buf_read_le32_at (b, 4);
	ut32 ins2 = r_buf_read_le32_at (b, 8);
	ut32 ins512 = r_buf_read_le32_at (b, 512 * 4);
	ut32 ins1023 = r_buf_read_le32_at (b, 1023 * 4);
	ut32 legion = r_buf_read_le32_at (b, 1028 * 4);
	if (ins1 != 0x10003fe2 || ins2 != 0xd518c002
			|| ins512 != 0x14000000 || ins1023 != 0x14000000
			|| legion != 0x326e6f69) {
		return NULL;
	}
	ut64 hdr_off = r_buf_read_le64_at (b, HDR_PTR_OFFSET);
	if (hdr_off == UT64_MAX || hdr_off > sz - HDR_SIZE
			|| r_buf_read_le64_at (b, hdr_off + 56) != sz) {
		return NULL;
	}
	ut8 hdr[HDR_SIZE];
	if (r_buf_read_at (b, hdr_off, hdr, sizeof (hdr)) != sizeof (hdr)) {
		return NULL;
	}
	ut64 kernel_base = r_read_le64 (hdr + 24);
	ut64 init_base = r_read_le64 (hdr + 104);
	ut64 n_apps = r_read_le64 (hdr + 192);
	ut64 apps_at = hdr_off + HDR_SIZE;
	ut64 max_apps = (sz - apps_at) / APP_SIZE;
	if (kernel_base >= sz || init_base >= sz
			|| n_apps > max_apps || n_apps > NAPPS_MAX) {
		return NULL;
	}
	Ctx *ctx = R_NEW0 (Ctx);
	ctx->buf = b;
	ctx->nslices = (ut32)(3 + n_apps);
	ctx->slices = R_NEWS0 (Slice, ctx->nslices);

	// boot: bytes [0, kernel_base). No data region. phys_data is set so the
	// "contiguous" predicate (phys_data == phys_text + data_offset) holds for
	// boot too — that way bins() can use a zero-copy slice for it.
	ctx->slices[0].name = strdup ("boot");
	ctx->slices[0].size = kernel_base;
	ctx->slices[0].text_size = kernel_base;
	ctx->slices[0].data_offset = kernel_base;
	ctx->slices[0].phys_data = kernel_base;

	if (!fill_macho_slice (b, sz, &ctx->slices[1], kernel_base, 0, strdup ("kernel"))) {
		if (log) R_LOG_WARN ("fs_sep64: kernel mach-o parse failed at 0x%"PFMT64x, kernel_base);
		ctx->nslices = 1; // free what we built so far via ctx_free
		ctx_free (ctx);
		return NULL;
	}
	if (!fill_macho_slice (b, sz, &ctx->slices[2], init_base, 0, trim_name ((const char *)hdr + 144, "init"))) {
		if (log) R_LOG_WARN ("fs_sep64: init mach-o parse failed at 0x%"PFMT64x, init_base);
		ctx->nslices = 2;
		ctx_free (ctx);
		return NULL;
	}
	ut64 i;
	for (i = 0; i < n_apps; i++) {
		ut8 app[APP_SIZE];
		if (r_buf_read_at (b, apps_at + i * APP_SIZE, app, sizeof (app)) != sizeof (app)) {
			ctx->nslices = (ut32)(3 + i);
			ctx_free (ctx);
			return NULL;
		}
		ut64 phys_text = r_read_le64 (app + 0);
		ut64 phys_data = r_read_le64 (app + 16);
		char *fb = r_str_newf ("app%u", (unsigned)i);
		if (!fill_macho_slice (b, sz, &ctx->slices[3 + i], phys_text, phys_data,
				trim_name ((const char *)app + 80, fb))) {
			free (fb);
			if (log) R_LOG_WARN ("fs_sep64: app[%u] mach-o parse failed", (unsigned)i);
			ctx->nslices = (ut32)(3 + i);
			ctx_free (ctx);
			return NULL;
		}
		free (fb);
	}
	return ctx;
}

// Read [addr, addr+len) from a slice into dst, stitching __TEXT and __DATA
// from their separate container offsets and zero-filling any gap between.
static bool slice_read(RBuffer *b, Slice *s, ut64 addr, ut8 *dst, ut64 len) {
	if (addr >= s->size) {
		return false;
	}
	if (len > s->size - addr) {
		len = s->size - addr;
	}
	while (len > 0) {
		ut64 chunk;
		if (addr < s->text_size) {
			chunk = R_MIN (len, s->text_size - addr);
			if (r_buf_read_at (b, s->phys_text + addr, dst, chunk) != (int)chunk) {
				return false;
			}
		} else if (addr < s->data_offset) {
			chunk = R_MIN (len, s->data_offset - addr);
			memset (dst, 0, chunk);
		} else if (addr < s->data_offset + s->data_size) {
			chunk = R_MIN (len, s->data_offset + s->data_size - addr);
			if (r_buf_read_at (b, s->phys_data + addr - s->data_offset, dst, chunk) != (int)chunk) {
				return false;
			}
		} else {
			chunk = len;
			memset (dst, 0, chunk);
		}
		addr += chunk;
		dst += chunk;
		len -= chunk;
	}
	return true;
}

static Slice *find_slice(Ctx *ctx, const char *path) {
	while (*path == '/') {
		path++;
	}
	if (!*path) {
		return NULL;
	}
	ut32 i;
	for (i = 0; i < ctx->nslices; i++) {
		if (!strcmp (ctx->slices[i].name, path)) {
			return &ctx->slices[i];
		}
	}
	return NULL;
}

static bool fs_sep64_mount(RFSRoot *root) {
	if (!root->iob.io || !root->iob.io->desc) {
		return false;
	}
	int fd = root->iob.io->desc->fd;
	RBuffer *b = r_buf_new_with_io (&root->iob, fd);
	if (!b) {
		return false;
	}
	Ctx *ctx = ctx_parse (b, true);
	if (!ctx) {
		r_unref (b);
		return false;
	}
	ctx->owns_buf = true;
	root->ptr = ctx;
	root->fd = fd;
	return true;
}

static void fs_sep64_umount(RFSRoot *root) {
	ctx_free (root->ptr);
	root->ptr = NULL;
}

static RFSFile *fs_sep64_open(RFSRoot *root, const char *path, bool create) {
	if (create || !root->ptr) {
		return NULL;
	}
	Slice *s = find_slice (root->ptr, path);
	if (!s) {
		return NULL;
	}
	RFSFile *f = r_fs_file_new (root, path);
	if (f) {
		f->type = R_FS_FILE_TYPE_REGULAR;
		f->size = s->size;
		f->off = s->phys_text;
		f->p = root->p;
		f->ptr = s;
	}
	return f;
}

static int fs_sep64_read(RFSFile *file, ut64 addr, int len) {
	Ctx *ctx = file->root->ptr;
	Slice *s = file->ptr;
	if (!s || !ctx || len < 0) {
		return -1;
	}
	if (addr >= s->size) {
		return 0;
	}
	if (addr + len > s->size) {
		len = s->size - addr;
	}
	free (file->data);
	file->data = malloc (len);
	if (!file->data || !slice_read (ctx->buf, s, addr, file->data, len)) {
		R_FREE (file->data);
		return -1;
	}
	return len;
}

static RFSFile *fs_sep64_slurp(RFSRoot *root, const char *path) {
	RFSFile *f = fs_sep64_open (root, path, false);
	if (!f) {
		return NULL;
	}
	if (fs_sep64_read (f, 0, ((Slice *)f->ptr)->size) < 0) {
		r_fs_file_free (f);
		return NULL;
	}
	return f;
}

static RList *fs_sep64_dir(RFSRoot *root, const char *path, R_UNUSED int view) {
	Ctx *ctx = root->ptr;
	if (!ctx) {
		return NULL;
	}
	while (*path == '/') {
		path++;
	}
	if (*path) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	ut32 i;
	for (i = 0; i < ctx->nslices; i++) {
		RFSFile *fsf = r_fs_file_new (NULL, ctx->slices[i].name);
		if (fsf) {
			fsf->type = R_FS_FILE_TYPE_REGULAR;
			fsf->size = ctx->slices[i].size;
			fsf->off = ctx->slices[i].phys_text;
			r_list_append (list, fsf);
		}
	}
	return list;
}

static RList *fs_sep64_bins(RBuffer *b) {
	Ctx *ctx = ctx_parse (b, false);
	if (!ctx) {
		return NULL;
	}
	RList *out = r_list_newf ((RListFree)r_fs_file_free);
	ut32 i;
	for (i = 0; i < ctx->nslices; i++) {
		Slice *s = &ctx->slices[i];
		// Zero-copy slice when __DATA sits right after __TEXT in the
		// container (boot, kernel, init). Apps with discontiguous __DATA
		// have to be materialized so r_bin sees a flat mach-o image.
		bool contiguous = s->phys_data == s->phys_text + s->data_offset;
		RBuffer *sbuf;
		if (contiguous) {
			sbuf = r_buf_new_slice (b, s->phys_text, s->size);
		} else {
			ut8 *bytes = malloc (s->size);
			if (!bytes || !slice_read (b, s, 0, bytes, s->size)) {
				free (bytes);
				continue;
			}
			sbuf = r_buf_new_with_pointers (bytes, s->size, true);
		}
		if (!sbuf) {
			continue;
		}
		RFSFile *f = r_fs_file_new (NULL, s->name);
		if (!f) {
			r_unref (sbuf);
			continue;
		}
		f->type = R_FS_FILE_TYPE_REGULAR;
		f->off = s->phys_text;
		f->size = s->size;
		f->buf = sbuf;
		f->arch = strdup ("arm");
		f->bits = 64;
		f->machine = strdup ("arm64e");
		r_list_append (out, f);
	}
	ctx_free (ctx);
	return out;
}

RFSPlugin r_fs_plugin_sep64 = {
	.meta = {
		.name = "sep64",
		.author = "pancake",
		.desc = "Apple Secure Enclave 64-bit firmware container",
		.license = "LGPL-3.0-only",
	},
	.mount = fs_sep64_mount,
	.umount = fs_sep64_umount,
	.open = fs_sep64_open,
	.slurp = fs_sep64_slurp,
	.read = fs_sep64_read,
	.dir = fs_sep64_dir,
	.bins = fs_sep64_bins,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_sep64,
	.version = R2_VERSION
};
#endif
