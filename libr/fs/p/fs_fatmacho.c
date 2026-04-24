/* radare - LGPL - Copyright 2026 - pancake */

#include <r_fs.h>
#include <r_lib.h>

#define FATMACHO_MAGIC_BE 0xcafebabe
#define FATMACHO_HEADER_SIZE 8
#define FATMACHO_ARCH_SIZE 20
#define FATMACHO_NFAT_MAX 32

// cputype constants match Apple's loader.h without pulling mach0 specs into r_fs.
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
	int fd; // -1 if unknown; reads go through fd_read_at to bypass IO maps
} FatmachoCtx;

typedef bool (*FatmachoReadAt)(void *user, ut64 addr, ut8 *buf, int len);

static void fatmacho_free(FatmachoCtx *ctx);

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

static const char *arch_name(ut32 cputype) {
	switch (cputype) {
	case CPU_TYPE_X86:
	case CPU_TYPE_X86_64:    return "x86";
	case CPU_TYPE_ARM:
	case CPU_TYPE_ARM64:     return "arm";
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64: return "ppc";
	case CPU_TYPE_MC680x0:
	case CPU_TYPE_MC88000:
	case CPU_TYPE_MC98000:   return "m68k";
	case CPU_TYPE_SPARC:     return "sparc";
	case CPU_TYPE_MIPS:      return "mips";
	case CPU_TYPE_HPPA:      return "hppa";
	case CPU_TYPE_I860:      return "i860";
	case CPU_TYPE_VAX:       return "vax";
	}
	return NULL;
}

static int arch_bits(ut32 cputype) {
	return (cputype & CPU_ARCH_ABI64) ? 64 : 32;
}

// Compact subtype string mapping, self-contained to keep fs_fatmacho decoupled from r_bin.
static const char *cpu_subtype_name(ut32 cputype, ut32 cpusubtype) {
	ut32 sub = cpusubtype & 0xff;
	switch (cputype) {
	case CPU_TYPE_X86_64:
		return "x86 64 all";
	case CPU_TYPE_X86:
		switch (sub) {
		case 3:  return "386";
		case 4:  return "486";
		case 5:  return "586";
		case 10: return "Pentium Pro";
		case 11: return "Pentium 3 M3";
		default: return "i386";
		}
	case CPU_TYPE_ARM64:
		switch (sub) {
		case 0: return "all";
		case 1: return "arm64v8";
		case 2: return "arm64e";
		default: return "arm64";
		}
	case CPU_TYPE_ARM:
		switch (sub) {
		case 0:  return "all";
		case 5:  return "v4t";
		case 7:  return "v5";
		case 6:  return "v6";
		case 8:  return "xscale";
		case 9:  return "v7";
		case 10: return "v7f";
		case 11: return "v7s";
		case 12: return "v7k";
		case 15: return "v7m";
		case 16: return "v7em";
		default: return "arm";
		}
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		switch (sub) {
		case 0:  return "all";
		case 1:  return "601";
		case 2:  return "602";
		case 3:  return "603";
		case 4:  return "603e";
		case 5:  return "603ev";
		case 6:  return "604";
		case 7:  return "604e";
		case 8:  return "620";
		case 9:  return "750";
		case 10: return "7400";
		case 11: return "7450";
		case 100: return "970";
		default: return "ppc";
		}
	}
	return "unknown";
}

typedef struct {
	RIOBind *iob;
	int fd;
} FatmachoIobFd;

static bool fatmacho_read_iob_fd(void *user, ut64 addr, ut8 *buf, int len) {
	FatmachoIobFd *u = user;
	return u->iob->fd_read_at (u->iob->io, u->fd, addr, buf, len) == len;
}

static bool fatmacho_read_buf(void *user, ut64 addr, ut8 *buf, int len) {
	return r_buf_read_at ((RBuffer *)user, addr, buf, len) == len;
}

static FatmachoCtx *fatmacho_parse_read(void *user, FatmachoReadAt read_at, ut64 sz, bool verbose) {
	ut8 hdr[FATMACHO_HEADER_SIZE] = {0};
	if (sz < FATMACHO_HEADER_SIZE || !read_at (user, 0, hdr, sizeof (hdr))) {
		return NULL;
	}
	if (r_read_be32 (hdr) != FATMACHO_MAGIC_BE) {
		return NULL;
	}
	ut32 nfat = r_read_be32 (hdr + 4);
	if (nfat == 0 || nfat > FATMACHO_NFAT_MAX) {
		return NULL;
	}
	if (sz < FATMACHO_HEADER_SIZE + (ut64)nfat * FATMACHO_ARCH_SIZE) {
		return NULL;
	}
	FatmachoCtx *ctx = R_NEW0 (FatmachoCtx);
	ctx->fd = -1;
	ctx->container_size = sz;
	ctx->nfat = nfat;
	ctx->slices = R_NEWS0 (FatmachoSlice, nfat);
	if (!ctx->slices) {
		free (ctx);
		return NULL;
	}
	ut32 i;
	for (i = 0; i < nfat; i++) {
		ut8 ab[FATMACHO_ARCH_SIZE] = {0};
		if (!read_at (user, FATMACHO_HEADER_SIZE + (ut64)i * FATMACHO_ARCH_SIZE, ab, sizeof (ab))) {
			if (verbose) {
				R_LOG_WARN ("fs_fatmacho: short read at arch[%u]", i);
			}
			goto fail;
		}
		FatmachoSlice *s = &ctx->slices[i];
		s->cputype    = r_read_be32 (ab);
		s->cpusubtype = r_read_be32 (ab + 4);
		s->offset     = r_read_be32 (ab + 8);
		s->size       = r_read_be32 (ab + 12);
		if (s->offset > sz || s->size > sz || s->offset + s->size > sz) {
			if (verbose) {
				R_LOG_WARN ("fs_fatmacho: corrupt arch[%u] off=0x%"PFMT64x" sz=0x%"PFMT64x" cont=0x%"PFMT64x,
					i, s->offset, s->size, sz);
			}
			goto fail;
		}
		s->name = r_str_newf ("%s.%u", cpu_name (s->cputype), i);
	}
	return ctx;
fail:
	fatmacho_free (ctx);
	return NULL;
}

static FatmachoCtx *fatmacho_parse(RIOBind *iob) {
	// Reads go through fd_read_at so they survive IO remaps (after slice
	// selection the container file is no longer mapped at vaddr 0, but the
	// fd itself stays reachable). We need the fd of the container file: on
	// auto-mount from r_bin_open_buf this is the current io->desc, since
	// the descriptor was just opened and no other files are in play yet.
	if (!iob->io || !iob->io->desc) {
		return NULL;
	}
	int fd = iob->io->desc->fd;
	ut64 sz = iob->fd_size (iob->io, fd);
	if (!sz) {
		return NULL;
	}
	FatmachoIobFd u = { iob, fd };
	FatmachoCtx *ctx = fatmacho_parse_read (&u, fatmacho_read_iob_fd, sz, true);
	if (ctx) {
		ctx->fd = fd;
	}
	return ctx;
}

static void fatmacho_free(FatmachoCtx *ctx) {
	if (!ctx) {
		return;
	}
	ut32 i;
	if (ctx->slices) {
		for (i = 0; i < ctx->nfat; i++) {
			free (ctx->slices[i].name);
		}
	}
	free (ctx->slices);
	free (ctx);
}

static FatmachoCtx *fatmacho_parse_buf(RBuffer *b) {
	return fatmacho_parse_read (b, fatmacho_read_buf, r_buf_size (b), false);
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
	root->fd = ctx->fd;
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

// Reads via the cached fd so we bypass IO maps — the container file stays
// reachable through the fd even after slice selection remaps IO.
static bool fatmacho_slice_read(RFSRoot *root, ut64 offset, ut8 *data, ut64 size) {
	FatmachoCtx *ctx = root->ptr;
	if (ctx && ctx->fd >= 0) {
		return root->iob.fd_read_at (root->iob.io, ctx->fd, offset, data, size) == (int)size;
	}
	return root->iob.read_at (root->iob.io, offset, data, size);
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
	if (!fatmacho_slice_read (root, s->offset, file->data, s->size)) {
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
	if (!fatmacho_slice_read (file->root, s->offset + addr, file->data, len)) {
		R_FREE (file->data);
		return -1;
	}
	return len;
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

// Disambiguate fat Mach-O from Java .class (same magic): first arch offset
// must point at a real mach-o header.
static bool looks_like_fatmacho(RBuffer *b) {
	ut64 sz = r_buf_size (b);
	ut8 first[20];
	if (r_buf_read_at (b, 8, first, 20) != 20) {
		return false;
	}
	ut64 off0 = r_read_be32 (first + 8);
	ut8 m[4];
	if (off0 + 4 > sz || r_buf_read_at (b, off0, m, 4) != 4) {
		return false;
	}
	return !memcmp (m, "\xce\xfa\xed\xfe", 4)
		|| !memcmp (m, "\xfe\xed\xfa\xce", 4)
		|| !memcmp (m, "\xfe\xed\xfa\xcf", 4)
		|| !memcmp (m, "\xcf\xfa\xed\xfe", 4);
}

static RList *fs_fatmacho_bins(RBuffer *b) {
	if (!looks_like_fatmacho (b)) {
		return NULL;
	}
	FatmachoCtx *ctx = fatmacho_parse_buf (b);
	if (!ctx) {
		return NULL;
	}
	RList *out = r_list_newf ((RListFree)r_fs_file_free);
	ut32 i;
	for (i = 0; i < ctx->nfat; i++) {
		FatmachoSlice *s = &ctx->slices[i];
		const char *arch = arch_name (s->cputype);
		RFSFile *f = r_fs_file_new (NULL, s->name);
		if (!f) {
			continue;
		}
		f->type = R_FS_FILE_TYPE_REGULAR;
		f->off = s->offset;
		f->size = s->size;
		f->buf = r_buf_new_slice (b, s->offset, s->size);
		f->arch = arch? strdup (arch): NULL;
		f->bits = arch_bits (s->cputype);
		f->machine = strdup (cpu_subtype_name (s->cputype, s->cpusubtype));
		r_list_append (out, f);
	}
	fatmacho_free (ctx);
	return out;
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
	.dir = fs_fatmacho_dir,
	.bins = fs_fatmacho_bins,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_fatmacho,
	.version = R2_VERSION
};
#endif
