// mach-o glue for the shared swift5 metadata walker in format/swift/swift.c:
// virtual address reads go through the mach0 segment mapping and indirect
// symbolic references are resolved against the mach-o relocs/binds

#include "../swift/swift.h"

typedef struct {
	RBinFile *bf;
	const RSkipList *relocs;
} SwiftMachoCtx;

static int swift_mo_read_at(void *user, ut64 va, ut8 *buf, int len) {
	SwiftMachoCtx *ctx = user;
	ut32 offset, left;
	const mach0_ut pa = va2pa (ctx->bf, va, &offset, &left);
	if (!pa) {
		return 0;
	}
	if (left > 0 && len > left) {
		len = left;
	}
	return r_buf_read_at (ctx->bf->buf, pa, buf, len);
}

static char *swift_mo_slot(void *user, ut64 va, ut64 *target) {
	SwiftMachoCtx *ctx = user;
	if (ctx->relocs) {
		struct reloc_t rr = { .addr = va };
		RSkipListNode *node = r_skiplist_find ((RSkipList *)ctx->relocs, &rr);
		if (node) {
			struct reloc_t *rel = node->data;
			if (rel->name[0]) {
				return strdup (rel->name);
			}
			if (rel->addend > 0) {
				*target = rel->addend;
				return NULL;
			}
		}
	}
	ut8 b[sizeof (mach0_ut)] = {0};
	if (swift_mo_read_at (user, va, b, sizeof (b)) == sizeof (b)) {
		ut64 v = r_read_ble (b, false, 8 * sizeof (mach0_ut));
		if (v >> 48) {
			// strip chained-fixup/PAC bits, keeping the 36bit target offset
			v &= 0xFFFFFFFFFULL;
		}
		v &= ~1ULL;
		if (v) {
			*target = v;
		}
	}
	return NULL;
}

static void parse_swift_classes(RBinFile *bf, RList *ret, MetaSections *ms, const RSkipList *relocs, int limit) {
	RVecRBinSymbol *symbols = NULL;
	if (!class_names_only (bf) && MACH0_(load_symbols) (bf->bo->bin_obj)) {
		symbols = &bf->bo->symbols_vec;
	}
	SwiftMachoCtx ctx = { .bf = bf, .relocs = relocs };
	RBinSwiftLoader ld = {
		.bf = bf,
		.user = &ctx,
		.read_at = swift_mo_read_at,
		.slot = swift_mo_slot,
		.symbols = symbols,
	};
	r_bin_swift_load_classes (&ld, ret, ms->types.vaddr, ms->types.size,
		ms->protos.have? ms->protos.vaddr: 0, ms->protos.size, limit);
}
