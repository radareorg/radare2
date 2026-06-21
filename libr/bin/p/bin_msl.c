/* radare - LGPL - Copyright 2026 - memslicer */

// RBin plugin for Memory Slice (.msl) process memory dumps.
//
// Presents an .msl as a CORE-like object: architecture/bits/OS from the file
// header, the program counter of the Current thread as entry0, and one memory
// map per contiguous run of Captured pages (vaddr -> file offset of PageData).
// Failed/Unmapped pages are left unmapped so radare2 fills them with io.0xff,
// exactly like the ELF coredump loader.
//
// Open a slice with `r2 dump.msl` (default file IO). For a raw virtual-address
// view without bin metadata, the companion io plugin handles `msl://dump.msl`.
//
// MVP scope: uncompressed, unencrypted slices.

#include <r_bin.h>

#define MSL_FILE_MAGIC "MEMSLICE"
#define MSL_BLOCK_MAGIC "MSLC"
#define MSL_HDR_FLAG_ENCRYPTED 0x4
#define MSL_BLOCK_FLAG_COMPRESSED 0x1
#define MSL_BT_MEMORY_REGION 0x0001
#define MSL_BT_THREAD_CONTEXT 0x0011
#define MSL_BT_END_OF_CAPTURE 0x0FFF
#define MSL_BLOCK_HEADER_SIZE 80
#define MSL_REG_FLAG_PC 0x1
#define MSL_THREAD_FLAG_CURRENT 0x1
#define MSL_MAX_PAGES (1ULL << 28)

typedef struct {
	RList *maps;       // RBinMap*
	ut64 entry;        // PC of the Current thread
	bool has_entry;
	ut16 os_type;
	ut16 arch_type;
	int bits;
	int compressed_skipped; // compressed regions that can't be file-mapped
} RBinMslObj;

static inline ut64 msl_pad8(ut64 n) {
	return (n + 7) & ~(ut64)7;
}

static const char *msl_arch_str(ut16 arch, int *bits) {
	switch (arch) {
	case 0: *bits = 32; return "x86";   // x86
	case 1: *bits = 64; return "x86";   // x86_64
	case 2: *bits = 64; return "arm";   // ARM64
	case 3: *bits = 32; return "arm";   // ARM32
	case 4: *bits = 32; return "mips";  // MIPS32
	case 5: *bits = 64; return "mips";  // MIPS64
	case 6: *bits = 32; return "riscv"; // RV32
	case 7: *bits = 64; return "riscv"; // RV64
	case 8: *bits = 32; return "ppc";   // PPC32
	case 9: *bits = 64; return "ppc";   // PPC64
	default: *bits = 64; return "x86";
	}
}

static const char *msl_os_str(ut16 os) {
	switch (os) {
	case 0: return "windows";
	case 1: return "linux";
	case 2: return "macos";
	case 3: return "android";
	case 4: return "ios";
	default: return "unknown";
	}
}

static int msl_page_state(ut8 *psm, ut64 page) {
	ut8 byte = psm[page >> 2];
	int bitpos = 6 - (int)((page & 3) * 2);
	return (byte >> bitpos) & 3;
}

// Append one RBinMap per contiguous run of Captured pages in a region.
static void msl_region_maps(RBinMslObj *o, RBuffer *b, ut64 payload_off, ut16 bflags) {
	ut8 p[32];
	if (r_buf_read_at (b, payload_off, p, sizeof (p)) != sizeof (p)) {
		return;
	}
	if (bflags & MSL_BLOCK_FLAG_COMPRESSED) {
		// Compressed PageData cannot be expressed as a vaddr->file-offset
		// map. Open the slice with the `msl://` URI instead (the io plugin
		// decompresses lz4 in memory).
		o->compressed_skipped++;
		return;
	}
	ut64 base = r_read_le64 (p);
	ut64 size = r_read_le64 (p + 8);
	ut8 prot = p[16];
	ut8 psl = p[18];
	if (psl < 10 || psl > 40 || size == 0) {
		return;
	}
	ut64 page_size = 1ULL << psl;
	if (size & (page_size - 1)) {
		return;
	}
	ut64 npages = size >> psl;
	if (npages > MSL_MAX_PAGES) {
		return;
	}
	ut64 psm_bytes = msl_pad8 ((npages + 3) / 4);
	ut8 *psm = malloc (psm_bytes? (size_t)psm_bytes: 1);
	if (!psm) {
		return;
	}
	if (psm_bytes && r_buf_read_at (b, payload_off + 32, psm, psm_bytes) != (st64)psm_bytes) {
		free (psm);
		return;
	}
	ut64 data_off = payload_off + 32 + psm_bytes;
	int perm = ((prot & 1)? R_PERM_R: 0) | ((prot & 2)? R_PERM_W: 0) | ((prot & 4)? R_PERM_X: 0);

	ut64 cap_count = 0;    // captured pages seen so far (file offset cursor)
	ut64 run_start = 0;    // page index where current run began
	ut64 run_foff = 0;     // file offset of current run start
	bool in_run = false;
	ut64 i;
	for (i = 0; i < npages; i++) {
		bool captured = msl_page_state (psm, i) == 0;
		if (captured && !in_run) {
			in_run = true;
			run_start = i;
			run_foff = data_off + cap_count * page_size;
		} else if (!captured && in_run) {
			RBinMap *m = R_NEW0 (RBinMap);
			if (m) {
				m->addr = base + run_start * page_size;
				m->offset = run_foff;
				m->size = (int)((i - run_start) * page_size);
				m->perms = perm;
				m->file = strdup ("msl");
				r_list_append (o->maps, m);
			}
			in_run = false;
		}
		if (captured) {
			cap_count++;
		}
	}
	if (in_run) {
		RBinMap *m = R_NEW0 (RBinMap);
		if (m) {
			m->addr = base + run_start * page_size;
			m->offset = run_foff;
			m->size = (int)((npages - run_start) * page_size);
			m->perms = perm;
			m->file = strdup ("msl");
			r_list_append (o->maps, m);
		}
	}
	free (psm);
}

// Extract the program counter from a Thread Context block payload.
static bool msl_thread_pc(RBuffer *b, ut64 payload_off, ut64 payload_len, ut64 *pc, bool *is_current) {
	ut8 hdr[32];
	if (payload_len < sizeof (hdr) || r_buf_read_at (b, payload_off, hdr, sizeof (hdr)) != sizeof (hdr)) {
		return false;
	}
	ut16 tflags = r_read_le16 (hdr + 16);
	ut32 regcount = r_read_le32 (hdr + 20);
	ut16 namelen = r_read_le16 (hdr + 24);
	ut64 off = payload_off + 32 + msl_pad8 (namelen);
	ut64 end = payload_off + payload_len;
	ut32 r;
	for (r = 0; r < regcount; r++) {
		ut8 e[8];
		if (off + 8 > end || r_buf_read_at (b, off, e, sizeof (e)) != sizeof (e)) {
			return false;
		}
		ut8 rnamelen = e[0];
		ut8 width = e[1];
		ut16 rflags = r_read_le16 (e + 2);
		ut64 name_pad = msl_pad8 (rnamelen);
		ut64 val_off = off + 8 + name_pad;
		if (rflags & MSL_REG_FLAG_PC) {
			ut8 v[8] = {0};
			int n = (width > 8)? 8: width;
			if (r_buf_read_at (b, val_off, v, n) != n) {
				return false;
			}
			*pc = r_read_le64 (v);
			*is_current = (tflags & MSL_THREAD_FLAG_CURRENT) != 0;
			return true;
		}
		off = val_off + msl_pad8 (width);
	}
	return false;
}

static bool msl_parse(RBinMslObj *o, RBuffer *b) {
	ut8 h[16];
	if (r_buf_read_at (b, 0, h, sizeof (h)) != sizeof (h)) {
		return false;
	}
	if (memcmp (h, MSL_FILE_MAGIC, 8)) {
		return false;
	}
	ut32 flags = r_read_le32 (h + 12);
	if (flags & MSL_HDR_FLAG_ENCRYPTED) {
		R_LOG_ERROR ("msl: encrypted slices are not supported yet");
		return false;
	}
	ut8 header_size = h[9];
	ut8 osarch[4];
	if (r_buf_read_at (b, 0x30, osarch, sizeof (osarch)) == sizeof (osarch)) {
		o->os_type = r_read_le16 (osarch);
		o->arch_type = r_read_le16 (osarch + 2);
	}
	o->maps = r_list_newf (free);
	bool have_current_pc = false;
	ut64 fsize = r_buf_size (b);
	ut64 off = header_size;
	while (off + MSL_BLOCK_HEADER_SIZE <= fsize) {
		ut8 bh[MSL_BLOCK_HEADER_SIZE];
		if (r_buf_read_at (b, off, bh, sizeof (bh)) != sizeof (bh)) {
			break;
		}
		if (memcmp (bh, MSL_BLOCK_MAGIC, 4)) {
			break;
		}
		ut16 btype = r_read_le16 (bh + 4);
		ut16 bflags = r_read_le16 (bh + 6);
		ut32 blen = r_read_le32 (bh + 8);
		if (blen < MSL_BLOCK_HEADER_SIZE) {
			break;
		}
		ut64 payload_off = off + MSL_BLOCK_HEADER_SIZE;
		ut64 payload_len = blen - MSL_BLOCK_HEADER_SIZE;
		if (btype == MSL_BT_MEMORY_REGION) {
			msl_region_maps (o, b, payload_off, bflags);
		} else if (btype == MSL_BT_THREAD_CONTEXT && !have_current_pc) {
			ut64 pc = 0;
			bool is_current = false;
			if (msl_thread_pc (b, payload_off, payload_len, &pc, &is_current)) {
				// Prefer the Current thread; otherwise keep the first PC seen.
				if (is_current || !o->has_entry) {
					o->entry = pc;
					o->has_entry = true;
				}
				if (is_current) {
					have_current_pc = true;
				}
			}
		} else if (btype == MSL_BT_END_OF_CAPTURE) {
			break;
		}
		off += blen;
	}
	return true;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 magic[8];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) != sizeof (magic)) {
		return false;
	}
	return !memcmp (magic, MSL_FILE_MAGIC, 8);
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	RBinMslObj *o = R_NEW0 (RBinMslObj);
	if (!o) {
		return false;
	}
	if (!msl_parse (o, buf)) {
		r_list_free (o->maps);
		free (o);
		return false;
	}
	if (o->compressed_skipped > 0) {
		R_LOG_WARN ("msl: %d compressed region(s) are not mapped by the bin "
			"plugin; open the slice as 'msl://%s' to read them (the io "
			"plugin decompresses lz4).", o->compressed_skipped, bf->file);
	}
	bf->bo->bin_obj = o;
	return true;
}

static void destroy(RBinFile *bf) {
	if (bf && bf->bo && bf->bo->bin_obj) {
		RBinMslObj *o = bf->bo->bin_obj;
		r_list_free (o->maps);
		free (o);
		bf->bo->bin_obj = NULL;
	}
}

static RList *maps(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinMslObj *o = bf->bo->bin_obj;
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RListIter *it;
	RBinMap *m;
	r_list_foreach (o->maps, it, m) {
		RBinMap *c = R_NEW0 (RBinMap);
		if (c) {
			*c = *m;
			c->file = m->file? strdup (m->file): NULL;
			r_list_append (ret, c);
		}
	}
	return ret;
}

// Sections with add=true are what radare2 turns into IO maps (the RBinMap
// list is only used to rename them for CORE files). One section per captured
// run; failed/unmapped pages stay unmapped and read back as io.0xff.
static bool sections_vec(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	RBinMslObj *o = bf->bo->bin_obj;
	RVecRBinSection_clear (&bf->bo->sections_vec);
	RListIter *it;
	RBinMap *m;
	int i = 0;
	r_list_foreach (o->maps, it, m) {
		RBinSection *s = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		if (!s) {
			continue;
		}
		memset (s, 0, sizeof (*s));
		s->name = r_str_newf ("region.%d", i++);
		s->paddr = m->offset;
		s->vaddr = m->addr;
		s->size = (ut64)(ut32)m->size;
		s->vsize = s->size;
		s->perm = m->perms;
		s->add = true;
	}
	return true;
}

static RList *entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinMslObj *o = bf->bo->bin_obj;
	RList *ret = r_list_newf (free);
	if (!ret || !o->has_entry) {
		return ret;
	}
	RBinAddr *a = R_NEW0 (RBinAddr);
	if (a) {
		a->vaddr = o->entry;
		a->paddr = o->entry;
		a->bits = o->bits;
		r_list_append (ret, a);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinMslObj *o = bf->bo->bin_obj;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	int bits = 64;
	const char *arch = msl_arch_str (o->arch_type, &bits);
	o->bits = bits;
	ret->file = strdup (bf->file);
	ret->type = strdup ("CORE");
	ret->rclass = strdup ("msl");
	ret->bclass = strdup ("Memory Slice");
	ret->arch = strdup (arch);
	ret->machine = strdup ("Memory Slice dump");
	ret->os = strdup (msl_os_str (o->os_type));
	ret->bits = bits;
	ret->big_endian = false;
	ret->has_va = true;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

RBinPlugin r_bin_plugin_msl = {
	.meta = {
		.name = "msl",
		.desc = "Memory Slice (.msl) process memory dump",
		.author = "memslicer",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &maps,
	.sections_vec = &sections_vec,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_msl,
	.version = R2_VERSION
};
#endif
