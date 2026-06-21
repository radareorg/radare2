/* radare - LGPL - Copyright 2026 - memslicer */

// IO plugin for Memory Slice (.msl) process memory dumps.
//
// The plugin exposes the captured process *virtual* address space: an IO
// offset is interpreted as a virtual address. Each Memory Region block
// (type 0x0001) is indexed at open time; reads translate the requested
// address to the matching page in the region's PageData, honoring the
// three-state page map (Captured / Failed / Unmapped). Failed, unmapped
// and unbacked addresses read back as the IO fill byte.
//
// MVP scope: uncompressed, unencrypted slices. Compressed regions are
// indexed but read back as fill bytes (decode is future work); encrypted
// files are rejected.

#include <r_io.h>

#define MSL_FILE_MAGIC "MEMSLICE"
#define MSL_BLOCK_MAGIC "MSLC"
#define MSL_HDR_FLAG_ENCRYPTED 0x4
#define MSL_BLOCK_FLAG_COMPRESSED 0x1
#define MSL_COMPALGO_ZSTD 1
#define MSL_COMPALGO_LZ4 2
#define MSL_BT_MEMORY_REGION 0x0001
#define MSL_BT_END_OF_CAPTURE 0x0FFF
#define MSL_BLOCK_HEADER_SIZE 80
// Guard against absurd page counts from a corrupt region (256M pages).
#define MSL_MAX_PAGES (1ULL << 28)

typedef struct {
	ut64 vaddr;      // region base virtual address
	ut64 vsize;      // region size in bytes
	ut32 psl;        // page size log2
	ut64 npages;
	ut64 data_off;   // offset of PageData within the source (file or mem)
	ut32 *cumcap;    // cumcap[i] = captured pages in [0, i); length npages + 1
	ut8 *mem;        // decompressed payload (NULL = read PageData from file)
} RMslRegion;

typedef struct {
	RBuffer *b;
	RMslRegion *regions;
	int nregions;
	ut64 cur;        // current virtual address
	ut64 maxaddr;    // highest vaddr + vsize seen
	int pid;         // PID from the file header (for debug mode)
	int unsupported_comp; // regions skipped due to an undecodable codec (zstd)
} RIOMsl;

static inline ut64 msl_pad8(ut64 n) {
	return (n + 7) & ~(ut64)7;
}

// Decompress one LZ4 block. memslicer emits `lz4.block` (size-prefixed); the
// caller passes the raw block (after the 4-byte size prefix) and the exact
// uncompressed length, so decoding stops once `dlen` bytes are produced and
// any trailing 8-byte alignment padding is ignored. Returns bytes written or
// -1 on malformed input.
static int msl_lz4_block(const ut8 *src, int slen, ut8 *dst, int dlen) {
	int sp = 0, dp = 0;
	while (dp < dlen) {
		if (sp >= slen) {
			return -1;
		}
		ut8 token = src[sp++];
		int litlen = token >> 4;
		if (litlen == 15) {
			ut8 e;
			do {
				if (sp >= slen) {
					return -1;
				}
				e = src[sp++];
				litlen += e;
			} while (e == 255);
		}
		if (litlen > dlen - dp || litlen > slen - sp) {
			return -1;
		}
		memcpy (dst + dp, src + sp, litlen);
		dp += litlen;
		sp += litlen;
		if (dp >= dlen) {
			break; // final literal run
		}
		if (sp + 2 > slen) {
			return -1;
		}
		int offset = src[sp] | (src[sp + 1] << 8);
		sp += 2;
		if (offset == 0 || offset > dp) {
			return -1;
		}
		int matchlen = token & 0xf;
		if (matchlen == 15) {
			ut8 e;
			do {
				if (sp >= slen) {
					return -1;
				}
				e = src[sp++];
				matchlen += e;
			} while (e == 255);
		}
		matchlen += 4;
		if (matchlen > dlen - dp) {
			matchlen = dlen - dp;
		}
		int mpos = dp - offset;
		int k;
		for (k = 0; k < matchlen; k++) {
			dst[dp + k] = dst[mpos + k];
		}
		dp += matchlen;
	}
	return dp;
}

static int msl_page_state(ut8 *psm, ut64 page) {
	ut8 byte = psm[page >> 2];
	int bitpos = 6 - (int)((page & 3) * 2);
	return (byte >> bitpos) & 3;
}

// Decompress a compressed region payload into a freshly malloc'd buffer.
// On-disk layout (spec 4.2.1): UncompressedSize(8B) + CompressedData, padded.
// memslicer's lz4 codec is `lz4.block` (a 4-byte size prefix then the block).
// Returns the buffer (caller frees) and sets *out_len, or NULL on failure /
// unsupported codec (zstd has no decoder in radare2).
static ut8 *msl_decompress_payload(RIOMsl *mo, ut64 payload_off, ut32 blen,
		int algo, ut64 *out_len) {
	if (algo != MSL_COMPALGO_LZ4) {
		mo->unsupported_comp++;   // zstd / unknown: cannot decode here
		return NULL;
	}
	if (blen < MSL_BLOCK_HEADER_SIZE + 8 + 4) {
		return NULL;
	}
	ut8 szbuf[8];
	if (r_buf_read_at (mo->b, payload_off, szbuf, 8) != 8) {
		return NULL;
	}
	ut64 ulen = r_read_le64 (szbuf);
	if (ulen == 0 || ulen > (1ULL << 32)) {
		return NULL;
	}
	ut64 comp_len = (ut64)blen - MSL_BLOCK_HEADER_SIZE - 8;
	ut8 *cbuf = malloc ((size_t)comp_len);
	if (!cbuf) {
		return NULL;
	}
	if (r_buf_read_at (mo->b, payload_off + 8, cbuf, comp_len) != (st64)comp_len) {
		free (cbuf);
		return NULL;
	}
	ut8 *mem = malloc ((size_t)ulen);
	if (!mem) {
		free (cbuf);
		return NULL;
	}
	// Skip the 4-byte lz4.block size prefix; decode the raw block.
	int n = msl_lz4_block (cbuf + 4, (int)(comp_len - 4), mem, (int)ulen);
	free (cbuf);
	if (n != (int)ulen) {
		R_LOG_WARN ("msl: lz4 decode failed for a compressed region");
		free (mem);
		return NULL;
	}
	*out_len = ulen;
	return mem;
}

static bool msl_add_region(RIOMsl *mo, ut64 payload_off, ut16 bflags, ut32 blen) {
	ut8 *mem = NULL;       // decompressed payload (compressed regions)
	ut64 mem_len = 0;
	if (bflags & MSL_BLOCK_FLAG_COMPRESSED) {
		mem = msl_decompress_payload (mo, payload_off, blen,
			(bflags >> 1) & 3, &mem_len);
		if (!mem) {
			return false;
		}
	}

	// Read the fixed 32-byte region header from the decompressed buffer or
	// straight from the file.
	ut8 p[32];
	if (mem) {
		if (mem_len < 32) {
			free (mem);
			return false;
		}
		memcpy (p, mem, 32);
	} else if (r_buf_read_at (mo->b, payload_off, p, sizeof (p)) != sizeof (p)) {
		return false;
	}
	ut64 base = r_read_le64 (p);
	ut64 size = r_read_le64 (p + 8);
	ut8 psl = p[18];
	if (psl < 10 || psl > 40) {
		R_LOG_WARN ("msl: skipping region @ 0x%"PFMT64x" with invalid PageSizeLog2 %d", base, psl);
		free (mem);
		return false;
	}
	ut64 page_size = 1ULL << psl;
	if (size == 0 || (size & (page_size - 1))) {
		R_LOG_WARN ("msl: skipping region @ 0x%"PFMT64x" with misaligned size", base);
		free (mem);
		return false;
	}
	ut64 npages = size >> psl;
	if (npages > MSL_MAX_PAGES) {
		R_LOG_WARN ("msl: skipping oversized region @ 0x%"PFMT64x" (%"PFMT64u" pages)", base, npages);
		free (mem);
		return false;
	}
	ut64 psm_bytes = msl_pad8 ((npages + 3) / 4);

	// Locate the PageStateMap (in mem or file) and the PageData offset.
	ut64 data_off;
	ut8 *psm_tmp = NULL;
	const ut8 *psm;
	if (mem) {
		if (32 + psm_bytes > mem_len) {
			free (mem);
			return false;
		}
		psm = mem + 32;
		data_off = 32 + psm_bytes;            // offset within mem
	} else {
		data_off = payload_off + 32 + psm_bytes;  // file offset
		psm_tmp = malloc (psm_bytes? (size_t)psm_bytes: 1);
		if (!psm_tmp) {
			return false;
		}
		if (psm_bytes && r_buf_read_at (mo->b, payload_off + 32, psm_tmp, psm_bytes) != (st64)psm_bytes) {
			free (psm_tmp);
			return false;
		}
		psm = psm_tmp;
	}

	ut32 *cumcap = malloc (sizeof (ut32) * (size_t)(npages + 1));
	if (!cumcap) {
		free (mem);
		free (psm_tmp);
		return false;
	}
	ut32 running = 0;
	ut64 i;
	for (i = 0; i < npages; i++) {
		cumcap[i] = running;
		if (msl_page_state ((ut8 *)psm, i) == 0) {
			running++;
		}
	}
	cumcap[npages] = running;
	free (psm_tmp);

	RMslRegion *nr = realloc (mo->regions, sizeof (RMslRegion) * (mo->nregions + 1));
	if (!nr) {
		free (cumcap);
		free (mem);
		return false;
	}
	mo->regions = nr;
	RMslRegion *rg = &mo->regions[mo->nregions++];
	rg->vaddr = base;
	rg->vsize = size;
	rg->psl = psl;
	rg->npages = npages;
	rg->data_off = data_off;
	rg->cumcap = cumcap;
	rg->mem = mem;
	if (base + size > mo->maxaddr) {
		mo->maxaddr = base + size;
	}
	return true;
}

static int msl_region_cmp(const void *a, const void *b) {
	const RMslRegion *ra = a;
	const RMslRegion *rb = b;
	if (ra->vaddr < rb->vaddr) {
		return -1;
	}
	if (ra->vaddr > rb->vaddr) {
		return 1;
	}
	return 0;
}

static RMslRegion *msl_region_at(RIOMsl *mo, ut64 addr) {
	int lo = 0, hi = mo->nregions - 1;
	while (lo <= hi) {
		int mid = (lo + hi) / 2;
		RMslRegion *rg = &mo->regions[mid];
		if (addr < rg->vaddr) {
			hi = mid - 1;
		} else if (addr >= rg->vaddr + rg->vsize) {
			lo = mid + 1;
		} else {
			return rg;
		}
	}
	return NULL;
}

// Smallest region base strictly greater than addr, or UT64_MAX.
static ut64 msl_next_region(RIOMsl *mo, ut64 addr) {
	ut64 best = UT64_MAX;
	int i;
	for (i = 0; i < mo->nregions; i++) {
		ut64 base = mo->regions[i].vaddr;
		if (base > addr && base < best) {
			best = base;
		}
	}
	return best;
}

static bool msl_parse(RIOMsl *mo) {
	ut8 h[16];
	if (r_buf_read_at (mo->b, 0, h, sizeof (h)) != sizeof (h)) {
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
	ut8 pidbuf[4];
	if (r_buf_read_at (mo->b, 0x34, pidbuf, sizeof (pidbuf)) == sizeof (pidbuf)) {
		mo->pid = (int)r_read_le32 (pidbuf);
	}
	if (mo->pid <= 0) {
		mo->pid = 1;
	}
	ut64 fsize = r_buf_size (mo->b);
	ut64 off = header_size;
	while (off + MSL_BLOCK_HEADER_SIZE <= fsize) {
		ut8 bh[MSL_BLOCK_HEADER_SIZE];
		if (r_buf_read_at (mo->b, off, bh, sizeof (bh)) != sizeof (bh)) {
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
		if (btype == MSL_BT_MEMORY_REGION) {
			msl_add_region (mo, off + MSL_BLOCK_HEADER_SIZE, bflags, blen);
		}
		if (btype == MSL_BT_END_OF_CAPTURE) {
			break;
		}
		off += blen;
	}
	if (mo->nregions > 1) {
		qsort (mo->regions, mo->nregions, sizeof (RMslRegion), msl_region_cmp);
	}
	if (mo->unsupported_comp > 0) {
		R_LOG_WARN ("msl: %d region(s) use zstd compression, which radare2 "
			"cannot decode; those addresses read as the fill byte. "
			"Recapture with '-c lz4' or '-c none', or use memslicer-emu.",
			mo->unsupported_comp);
	}
	return true;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data || count < 0) {
		return -1;
	}
	RIOMsl *mo = fd->data;
	memset (buf, io->Oxff, count);
	ut64 addr = mo->cur;
	int i = 0;
	while (i < count) {
		ut64 cur = addr + i;
		RMslRegion *rg = msl_region_at (mo, cur);
		if (!rg) {
			ut64 next = msl_next_region (mo, cur);
			if (next == UT64_MAX || next >= addr + count) {
				break;
			}
			i = (int)(next - addr);
			continue;
		}
		ut64 roff = cur - rg->vaddr;
		ut64 page = roff >> rg->psl;
		ut64 page_size = 1ULL << rg->psl;
		ut64 in_page = roff & (page_size - 1);
		ut64 want = page_size - in_page;
		ut64 region_left = rg->vsize - roff;
		want = R_MIN (want, region_left);
		want = R_MIN (want, (ut64)(count - i));
		// Page state is recomputed from cumcap deltas to avoid keeping the
		// raw map resident: a page is captured iff its cumulative count
		// increases at the next index.
		bool captured = page < rg->npages
			&& rg->cumcap[page + 1] > rg->cumcap[page];
		if (captured) {
			ut64 src_off = rg->data_off + (ut64)rg->cumcap[page] * page_size + in_page;
			if (rg->mem) {
				memcpy (buf + i, rg->mem + src_off, want);
			} else {
				r_buf_read_at (mo->b, src_off, buf + i, want);
			}
		}
		i += (int)want;
	}
	mo->cur += count;
	return count;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (!fd || !fd->data) {
		return offset;
	}
	RIOMsl *mo = fd->data;
	switch (whence) {
	case R_IO_SEEK_SET:
		mo->cur = offset;
		break;
	case R_IO_SEEK_CUR:
		mo->cur += offset;
		break;
	case R_IO_SEEK_END:
		mo->cur = mo->maxaddr;
		break;
	}
	return mo->cur;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "msl://");
}

static int __getpid(RIODesc *desc) {
	RIOMsl *mo = (desc && desc->data)? desc->data: NULL;
	return mo? mo->pid: -1;
}

static int __gettid(RIODesc *desc) {
	return __getpid (desc);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, false)) {
		return NULL;
	}
	const char *path = pathname + strlen ("msl://");
	RBuffer *b = r_buf_new_mmap (path, R_PERM_R);
	if (!b) {
		R_LOG_ERROR ("msl: cannot open %s", path);
		return NULL;
	}
	RIOMsl *mo = R_NEW0 (RIOMsl);
	if (!mo) {
		r_unref (b);
		return NULL;
	}
	mo->b = b;
	if (!msl_parse (mo)) {
		R_LOG_ERROR ("msl: %s is not a valid Memory Slice file", path);
		r_unref (b);
		free (mo->regions);
		free (mo);
		return NULL;
	}
	R_LOG_INFO ("msl: indexed %d memory region(s), VA up to 0x%"PFMT64x, mo->nregions, mo->maxaddr);
	return r_io_desc_new (io, &r_io_plugin_msl, pathname, R_PERM_R, mode, mo);
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	RIOMsl *mo = fd->data;
	int i;
	for (i = 0; i < mo->nregions; i++) {
		free (mo->regions[i].cumcap);
		free (mo->regions[i].mem);
	}
	free (mo->regions);
	r_unref (mo->b);
	free (mo);
	fd->data = NULL;
	return true;
}

RIOPlugin r_io_plugin_msl = {
	.meta = {
		.name = "msl",
		.desc = "Memory Slice (.msl) process memory dump",
		.author = "memslicer",
		.license = "LGPL-3.0-only",
	},
	.uris = "msl://",
	.isdbg = true,
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek,
	.getpid = __getpid,
	.gettid = __gettid,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_msl,
	.version = R2_VERSION
};
#endif
