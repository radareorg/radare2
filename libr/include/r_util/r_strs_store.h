#ifndef R_STRS_STORE_H
#define R_STRS_STORE_H

#include <r_util/r_strs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- RStrsStore: immutable indexed string pool ----
 *
 * Stores N strings in a single shared buffer with O(1) random access.
 * Two entry layouts were evaluated at the assembly level:
 *
 *   AoS {ut32 off, ut32 len}  — 8 B/entry, power-of-two stride.
 *     access: entries[n] is  base + n*8  (single LEA with scale=8).
 *     off and len share one cache line on random access.
 *
 *   SoA (separate offsets[] + lengths[]) — 6 B/entry effective.
 *     access: two independent arrays → two cache lines per random lookup.
 *     Better only for "scan all lengths without offsets" which is rare.
 *
 *   Packed {ut32 off, ut16 len} — 6 B but pads to 8 B anyway due to
 *     alignment of the trailing ut32 in the next element. Same size as
 *     AoS but with an artificial 64 KB cap and a n*6 non-power-of-two
 *     stride that requires imul instead of shift.
 *
 * Conclusion: AoS {ut32, ut32} at 8 bytes is optimal — no padding waste,
 * native addressing, one cache line per access, no artificial size cap.
 *
 * The store is built in two phases:
 *   1. Build: call _new() then _add()/_addstrs() to append strings.
 *   2. Seal: call _seal() to compact allocations. After this, _add is UB.
 * Or construct from an existing buffer via _from_entries / _from_utf16le.
 *
 * Relation to RStrpool: RStrpool is a mutable pool with dedup (bloom) and
 * NUL-terminated entries. RStrsStore is the immutable, length-prefixed
 * counterpart. Entries may overlap in the base buffer (shared suffixes).
 * RStrpool callers (corelog, addrline) that need mutation stay on RStrpool.
 */

typedef struct {
	ut32 off;
	ut32 len;
} RStrsEntry;

typedef struct {
	char *base;          /* shared UTF-8 buffer (owned unless borrowed_base) */
	ut32 base_len;       /* bytes used in base */
	ut32 base_cap;       /* allocated capacity (= base_len after seal) */
	RStrsEntry *entries; /* array of (off, len) pairs */
	ut32 count;          /* number of strings */
	ut32 cap;            /* allocated entry slots (= count after seal) */
	bool borrowed_base;  /* base not owned — do not free, do not grow */
} RStrsStore;

/* Convert a standalone entry + base pointer into an RStrs slice */
static inline RStrs r_strs_entry_to_strs(const char *base, RStrsEntry e) {
	return r_strs_from_len (base + e.off, e.len);
}

/* Inline accessors */
static inline ut32 r_strs_store_count(const RStrsStore *ss) {
	return ss? ss->count: 0;
}

static inline RStrs r_strs_store_get(const RStrsStore *ss, ut32 idx) {
	if (R_LIKELY (ss && idx < ss->count)) {
		const RStrsEntry *e = ss->entries + idx;
		if (R_LIKELY (e->off + e->len <= ss->base_len)) {
			return r_strs_from_len (ss->base + e->off, e->len);
		}
	}
	RStrs r = {0};
	return r;
}

/* Builder API (out of line) */
R_API RStrsStore *r_strs_store_new(ut32 capacity);
R_API int r_strs_store_add(RStrsStore *ss, const char *s, int len);
R_API void r_strs_store_seal(RStrsStore *ss);
R_API void r_strs_store_free(RStrsStore *ss);

static inline int r_strs_store_addstrs(RStrsStore *ss, RStrs s) {
	return r_strs_store_add (ss, s.a, (int)r_strs_len (s));
}

/* Bulk construction (out of line) — returns a sealed store */
R_API RStrsStore *r_strs_store_from_entries(const char *buf, ut32 buf_len, const RStrsEntry *entries, ut32 count);
R_API RStrsStore *r_strs_store_from_utf16le(const ut8 *src, ut32 src_len, const RStrsEntry *src_entries, ut32 count);

/* Borrowing split: slices `s` on any char in `seps` into (off, len) entries.
 * The base buffer is NOT copied and must outlive the store. Only the entries
 * array and the store header are allocated. If `trim`, leading/trailing
 * whitespace is stripped from each token (empty tokens are preserved). */
R_API RStrsStore *r_strs_store_split(const char *s, int len, const char *seps, bool trim);

#ifdef __cplusplus
}
#endif

#endif
