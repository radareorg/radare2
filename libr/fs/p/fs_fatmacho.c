/* radare - LGPL - Copyright 2026 - pancake */

#include <r_fs.h>
#include <r_lib.h>

#define FATMACHO_MAGIC_BE 0xcafebabe
#define FATMACHO_MAGIC_LE 0xbebafeca

/* cputype constants: match Apple's loader.h. We intentionally duplicate the
 * small set we care about here rather than pulling mach0_specs.h across the
 * r_fs/r_bin boundary. */
#define CPU_ARCH_ABI64   0x01000000
#define CPU_TYPE_VAX     1
#define CPU_TYPE_MC680x0 6
#define CPU_TYPE_X86     7
#define CPU_TYPE_X86_64  (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_MIPS    8
#define CPU_TYPE_MC98000 10
#define CPU_TYPE_HPPA    11
#define CPU_TYPE_ARM     12
#define CPU_TYPE_ARM64   (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_MC88000 13
#define CPU_TYPE_SPARC   14
#define CPU_TYPE_I860    15
#define CPU_TYPE_POWERPC 18
#define CPU_TYPE_POWERPC64 (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)

typedef struct {
	ut32 cputype;
	ut32 cpusubtype;
	ut64 offset;
	ut64 size;
	char *name;
} FatmachoSlice;

typedef struct {
	ut32 nfat;
	FatmachoSlice *slices;
	ut64 container_size;
} FatmachoCtx;

static const char *cpu_name(ut32 cputype) {
	switch (cputype) {
	case CPU_TYPE_X86:       return "x86_32";
	case CPU_TYPE_X86_64:    return "x86_64";
	case CPU_TYPE_ARM:       return "arm_32";
	case CPU_TYPE_ARM64:     return "arm_64";
	case CPU_TYPE_POWERPC:   return "ppc_32";
	case CPU_TYPE_POWERPC64: return "ppc_64";
	case CPU_TYPE_MC680x0:   return "m68k";
	case CPU_TYPE_MC88000:   return "m88k";
	case CPU_TYPE_MC98000:   return "m98k";
	case CPU_TYPE_SPARC:     return "sparc";
	case CPU_TYPE_MIPS:      return "mips";
	case CPU_TYPE_HPPA:      return "hppa";
	case CPU_TYPE_I860:      return "i860";
	case CPU_TYPE_VAX:       return "vax";
	}
	return "unknown";
}

static bool read_fat_header(RIOBind *iob, ut32 *magic, ut32 *nfat, ut64 container_size) {
	ut8 buf[8] = {0};
	if (!iob->read_at (iob->io, 0, buf, 8)) {
		return false;
	}
	*magic = r_read_be32 (buf);
	*nfat = r_read_be32 (buf + 4);
	if (*magic != FATMACHO_MAGIC_BE) {
		return false;
	}
	if (*nfat == 0 || *nfat > 32) {
		// 32 is a generous upper bound; Apple tools never produce more than ~5.
		return false;
	}
	if (container_size < 8 + (ut64)(*nfat) * 20) {
		return false;
	}
	return true;
}

static FatmachoCtx *fatmacho_parse(RIOBind *iob) {
	RIOMap *map = iob->map_get_at (iob->io, 0);
	if (!map) {
		return NULL;
	}
	ut64 sz = r_itv_size (map->itv);
	ut32 magic = 0, nfat = 0;
	if (!read_fat_header (iob, &magic, &nfat, sz)) {
		return NULL;
	}
	FatmachoCtx *ctx = R_NEW0 (FatmachoCtx);
	if (!ctx) {
		return NULL;
	}
	ctx->container_size = sz;
	ctx->nfat = nfat;
	ctx->slices = R_NEWS0 (FatmachoSlice, nfat);
	if (!ctx->slices) {
		free (ctx);
		return NULL;
	}
	ut32 i;
	for (i = 0; i < nfat; i++) {
		ut8 ab[20] = {0};
		if (!iob->read_at (iob->io, 8 + (ut64)i * 20, ab, 20)) {
			R_LOG_WARN ("fs_fatmacho: short read at arch[%u]", i);
			goto fail;
		}
		FatmachoSlice *s = &ctx->slices[i];
		s->cputype    = r_read_be32 (ab);
		s->cpusubtype = r_read_be32 (ab + 4);
		s->offset     = r_read_be32 (ab + 8);
		s->size       = r_read_be32 (ab + 12);
		// align at ab+16 is unused here
		if (s->offset > sz || s->size > sz || s->offset + s->size > sz) {
			R_LOG_WARN ("fs_fatmacho: corrupt arch[%u] off=0x%"PFMT64x" sz=0x%"PFMT64x" cont=0x%"PFMT64x,
				i, s->offset, s->size, sz);
			goto fail;
		}
		// ensure unique names by appending index if two slices share cputype
		const char *base = cpu_name (s->cputype);
		s->name = r_str_newf ("%s.%u", base, i);
	}
	return ctx;
fail:
	for (i = 0; i < nfat; i++) {
		free (ctx->slices[i].name);
	}
	free (ctx->slices);
	free (ctx);
	return NULL;
}

static void fatmacho_free(FatmachoCtx *ctx) {
	if (!ctx) {
		return;
	}
	ut32 i;
	for (i = 0; i < ctx->nfat; i++) {
		free (ctx->slices[i].name);
	}
	free (ctx->slices);
	free (ctx);
}

static FatmachoSlice *find_slice_by_path(FatmachoCtx *ctx, const char *path) {
	// accept "/arm_64.0", "arm_64.0", "/0" (index), "0"
	while (*path == '/') {
		path++;
	}
	if (!*path) {
		return NULL;
	}
	ut32 i;
	// exact name
	for (i = 0; i < ctx->nfat; i++) {
		if (!strcmp (ctx->slices[i].name, path)) {
			return &ctx->slices[i];
		}
	}
	// numeric index
	char *endp = NULL;
	long idx = strtol (path, &endp, 10);
	if (endp && *endp == 0 && idx >= 0 && (ut32)idx < ctx->nfat) {
		return &ctx->slices[idx];
	}
	// prefix match on arch name ("arm_64" matches "arm_64.0" if unique)
	FatmachoSlice *hit = NULL;
	for (i = 0; i < ctx->nfat; i++) {
		const char *n = ctx->slices[i].name;
		size_t plen = strlen (path);
		if (!strncmp (n, path, plen) && (n[plen] == 0 || n[plen] == '.')) {
			if (hit) {
				return NULL; // ambiguous
			}
			hit = &ctx->slices[i];
		}
	}
	return hit;
}

static bool fs_fatmacho_mount(RFSRoot *root) {
	FatmachoCtx *ctx = fatmacho_parse (&root->iob);
	if (!ctx) {
		return false;
	}
	root->ptr = ctx;
	return true;
}

static void fs_fatmacho_umount(RFSRoot *root) {
	fatmacho_free (root->ptr);
	root->ptr = NULL;
}

static RFSFile *fs_fatmacho_open(RFSRoot *root, const char *path, bool create) {
	if (create) {
		return NULL;
	}
	FatmachoCtx *ctx = root->ptr;
	if (!ctx) {
		return NULL;
	}
	FatmachoSlice *s = find_slice_by_path (ctx, path);
	if (!s) {
		return NULL;
	}
	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}
	file->type = R_FS_FILE_TYPE_REGULAR;
	file->size = s->size;
	file->off = s->offset;
	file->p = root->p;
	file->ptr = s;
	return file;
}

static RFSFile *fs_fatmacho_slurp(RFSRoot *root, const char *path) {
	RFSFile *file = fs_fatmacho_open (root, path, false);
	if (!file) {
		return NULL;
	}
	FatmachoSlice *s = file->ptr;
	file->data = malloc (s->size);
	if (!file->data) {
		r_fs_file_free (file);
		return NULL;
	}
	if (!root->iob.read_at (root->iob.io, s->offset, file->data, s->size)) {
		R_LOG_WARN ("fs_fatmacho: short slice read %"PFMT64u, s->size);
		R_FREE (file->data);
		r_fs_file_free (file);
		return NULL;
	}
	return file;
}

static int fs_fatmacho_read(RFSFile *file, ut64 addr, int len) {
	FatmachoSlice *s = file->ptr;
	if (!s) {
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
	if (!file->data) {
		return -1;
	}
	if (!file->root->iob.read_at (file->root->iob.io, s->offset + addr, file->data, len)) {
		R_FREE (file->data);
		return -1;
	}
	return len;
}

static void fs_fatmacho_close(RFSFile *file) {
	// file->data freed by r_fs_file_free; nothing else owned here.
}

static RList *fs_fatmacho_dir(RFSRoot *root, const char *path, R_UNUSED int view) {
	FatmachoCtx *ctx = root->ptr;
	if (!ctx) {
		return NULL;
	}
	while (*path == '/') {
		path++;
	}
	if (*path) {
		// flat namespace: subdirectories don't exist
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	if (!list) {
		return NULL;
	}
	ut32 i;
	for (i = 0; i < ctx->nfat; i++) {
		FatmachoSlice *s = &ctx->slices[i];
		RFSFile *fsf = r_fs_file_new (NULL, s->name);
		if (!fsf) {
			continue;
		}
		fsf->type = R_FS_FILE_TYPE_REGULAR;
		fsf->size = s->size;
		fsf->off = s->offset;
		r_list_append (list, fsf);
	}
	return list;
}

RFSPlugin r_fs_plugin_fatmacho = {
	.meta = {
		.name = "fatmacho",
		.author = "pancake",
		.desc = "Fat Mach-O slice enumeration",
		.license = "LGPL-3.0-only",
	},
	.mount = fs_fatmacho_mount,
	.umount = fs_fatmacho_umount,
	.open = fs_fatmacho_open,
	.slurp = fs_fatmacho_slurp,
	.read = fs_fatmacho_read,
	.close = fs_fatmacho_close,
	.dir = fs_fatmacho_dir,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_fatmacho,
	.version = R2_VERSION
};
#endif
