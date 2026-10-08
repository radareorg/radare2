/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"

// the .debug_loclists contribution whose header starts at `at`
static bool dwarf_loclists_contribution_at(const ut8 *sec, size_t len, bool be, size_t at, DwarfLoclistsContribution *c) {
	if (at > len || len - at < 12) {
		return false;
	}
	const bool dwarf64 = r_read_ble32 (sec + at, be) == DWARF_INIT_LEN_64;
	c->base = at + (dwarf64? 20: 12);
	if (c->base > len) {
		return false;
	}
	c->address_size = sec[c->base - 6];
	c->offset_size = dwarf64? 8: 4;
	c->count = r_read_ble32 (sec + c->base - 4, be);
	if ((c->address_size != 2 && c->address_size != 4 && c->address_size != 8)
		|| !dwarf_index_contribution_end (sec, len, be, c->base - 4, dwarf64, true, c->address_size, &c->end)
		|| c->end < c->base || (ut64)c->count * c->offset_size > c->end - c->base) {
		return false;
	}
	c->lists = c->base + (size_t)c->count * c->offset_size;
	return true;
}

// the contribution whose offset table starts at base (DW_AT_loclists_base)
R_IPI bool dwarf_loclists_contribution_base(const ut8 *sec, size_t len, bool be, ut64 base, DwarfLoclistsContribution *c) {
	if (base > len) {
		return false;
	}
	return (base >= 20 && dwarf_loclists_contribution_at (sec, len, be, (size_t)base - 20, c) && c->base == base)
		|| (base >= 12 && dwarf_loclists_contribution_at (sec, len, be, (size_t)base - 12, c) && c->base == base);
}

typedef struct {
	RBinFile *bf;
	const ut8 *addr; // .debug_addr, NULL when the unit has no usable table
	ut64 addr_base;
	ut64 base; // the unit's low_pc, what offset pairs count from
	size_t addr_end;
	ut8 addr_size;
	bool be;
	bool raw; // the dump: keep addrx indices and unrelocated addresses
} LoclistCtx;

static bool loclist_uleb(const ut8 **buf, const ut8 *limit, ut64 *value) {
	if (*buf >= limit) {
		return false;
	}
	*buf = dwarf_read_uleb_index (*buf, limit, value);
	return *buf != NULL;
}

static bool loclist_addr(const LoclistCtx *ctx, const ut8 **buf, const ut8 *limit, ut64 *value) {
	if (limit - *buf < ctx->addr_size) {
		return false;
	}
	const ut64 address = dwarf_read_address (ctx->bf->rbin, ctx->addr_size, buf, limit);
	*value = address;
	return ctx->raw || dwarf_relocate_address (ctx->bf, address, value);
}

static bool loclist_addrx(const LoclistCtx *ctx, const ut8 **buf, const ut8 *limit, ut64 *value) {
	size_t entry;
	if (!loclist_uleb (buf, limit, value)) {
		return false;
	}
	if (!ctx->addr) {
		return ctx->raw;
	}
	ut64 address;
	if (!dwarf_index_entry_offset (ctx->addr_base, *value, ctx->addr_size, ctx->addr_end, &entry)
		|| !dwarf_read_index (ctx->addr + entry, ctx->addr + ctx->addr_end, ctx->be, ctx->addr_size, &address)) {
		return false;
	}
	*value = address;
	return ctx->raw || dwarf_relocate_address (ctx->bf, address, value);
}

// a base entry only moves *base; the default location has no range
static bool loclist_entry(const LoclistCtx *ctx, const ut8 **buf, const ut8 *limit, ut8 *lle, ut64 *base, ut64 *start, ut64 *end, RBinDwarfBlock *expr) {
	if (*buf >= limit) {
		return false;
	}
	*lle = *(*buf)++;
	*start = *end = 0;
	ut64 length = 0;
	bool ok = true;
	switch (*lle) {
	case DW_LLE_end_of_list:
		return true;
	case DW_LLE_base_addressx:
		return loclist_addrx (ctx, buf, limit, base);
	case DW_LLE_base_address:
		return loclist_addr (ctx, buf, limit, base);
	case DW_LLE_startx_endx:
		ok = loclist_addrx (ctx, buf, limit, start) && loclist_addrx (ctx, buf, limit, end);
		break;
	case DW_LLE_startx_length:
		ok = loclist_addrx (ctx, buf, limit, start) && loclist_uleb (buf, limit, &length)
			&& !r_add_overflow (*start, length, end);
		break;
	case DW_LLE_offset_pair:
		ok = loclist_uleb (buf, limit, start) && loclist_uleb (buf, limit, end)
			&& !r_add_overflow (*base, *start, start) && !r_add_overflow (*base, *end, end);
		break;
	case DW_LLE_default_location:
		break;
	case DW_LLE_start_end:
		ok = loclist_addr (ctx, buf, limit, start) && loclist_addr (ctx, buf, limit, end);
		break;
	case DW_LLE_start_length:
		ok = loclist_addr (ctx, buf, limit, start) && loclist_uleb (buf, limit, &length)
			&& !r_add_overflow (*start, length, end);
		break;
	default:
		return false;
	}
	if (!ok || *end < *start || !loclist_uleb (buf, limit, &length) || length > limit - *buf) {
		return false;
	}
	expr->length = length;
	expr->data = *buf;
	*buf += length;
	return true;
}

static inline bool loclist_is_base(ut8 lle) {
	return lle == DW_LLE_base_addressx || lle == DW_LLE_base_address;
}

// one list up to its DW_LLE_end_of_list; false when any entry is malformed
static bool loclist_foreach(const LoclistCtx *ctx, const ut8 *buf, const ut8 *limit, RBinDwarfLocEntryCb cb, void *user) {
	ut64 base = ctx->base;
	bool has_default = false;
	ut8 lle;
	ut64 start, end;
	RBinDwarfBlock expr;
	while (loclist_entry (ctx, &buf, limit, &lle, &base, &start, &end, &expr)) {
		if (lle == DW_LLE_end_of_list) {
			return true;
		}
		if (loclist_is_base (lle)) {
			continue;
		}
		const bool is_default = lle == DW_LLE_default_location;
		if (is_default && has_default) {
			return false;
		}
		has_default |= is_default;
		if (!cb (user, start, end, &expr, is_default)) {
			return true;
		}
	}
	return false;
}

static ut64 comp_unit_low_pc(const RBinDwarfCompUnit *unit) {
	RBinDwarfDie *root = RVecDwarfDie_at (unit->dies, 0);
	if (root && root->attr_values) {
		RBinDwarfAttrValue *value;
		R_VEC_FOREACH (root->attr_values, value) {
			if (value->attr_name == DW_AT_low_pc && value->kind == DW_AT_KIND_ADDRESS) {
				return value->address;
			}
		}
	}
	return 0;
}

struct r_bin_dwarf_loclists_t {
	RBinFile *bf;
	const ut8 *sec;
	size_t len;
	const ut8 *addr;
	size_t addr_len;
	const RBinDwarfCompUnit *unit; // whose bases ctx and contribution hold
	LoclistCtx ctx;
	DwarfLoclistsContribution contribution;
	bool unit_ok;
	bool has_contribution;
	bool be;
};

R_API RBinDwarfLocLists *r_bin_dwarf_loclists_new(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_LOCLISTS);
	const ut8 *sec = section? dwarf_get_section_bytes (bf, section): NULL;
	if (!sec) {
		return NULL;
	}
	RBinDwarfLocLists *ll = R_NEW0 (RBinDwarfLocLists);
	ll->bf = bf;
	ll->sec = sec;
	ll->len = section->bytes.len;
	ll->be = r_bin_is_big_endian (bf->rbin);
	RBinSection *addr_section = dwarf_get_section (bf, DWARF_SN_ADDR);
	ll->addr = addr_section? dwarf_get_section_bytes (bf, addr_section): NULL;
	ll->addr_len = ll->addr? addr_section->bytes.len: 0;
	return ll;
}

R_API void r_bin_dwarf_loclists_free(RBinDwarfLocLists *ll) {
	free (ll);
}

// the bases of the unit a list belongs to, kept for its next list
static bool loclists_unit(RBinDwarfLocLists *ll, const RBinDwarfCompUnit *unit) {
	if (ll->unit == unit) {
		return ll->unit_ok;
	}
	ll->unit = unit;
	ll->unit_ok = false;
	ut64 str_base, addr_base, loclists_base;
	bool has_str_base, has_addr_base, has_loclists_base;
	if (unit->hdr.version < 5 || !unit->dies
		|| !dwarf_comp_unit_index_bases (unit, false, true, true, &str_base, &has_str_base,
			&addr_base, &has_addr_base, &loclists_base, &has_loclists_base)) {
		return false;
	}
	LoclistCtx ctx = { .bf = ll->bf, .be = ll->be, .addr_size = unit->hdr.address_size, .base = comp_unit_low_pc (unit) };
	if (ll->addr && has_addr_base && dwarf_address_base (ll->addr, ll->addr_len, ll->be,
			addr_base, ctx.addr_size, &ctx.addr_end)) {
		ctx.addr = ll->addr;
		ctx.addr_base = addr_base;
	}
	ll->ctx = ctx;
	DwarfLoclistsContribution c;
	// a unit without a base resumes the walk at the last contribution
	if (has_loclists_base && dwarf_loclists_contribution_base (ll->sec, ll->len, ll->be, loclists_base, &c)) {
		ll->contribution = c;
		ll->has_contribution = true;
	}
	ll->unit_ok = true;
	return true;
}

// the contribution holding the list at offset, walking headers past the last
static bool loclists_contribution_of(RBinDwarfLocLists *ll, ut64 offset, DwarfLoclistsContribution *c) {
	if (ll->has_contribution && offset >= ll->contribution.lists && offset < ll->contribution.end) {
		*c = ll->contribution;
		return c->address_size == ll->ctx.addr_size;
	}
	size_t at = ll->has_contribution && offset >= ll->contribution.end? ll->contribution.end: 0;
	while (dwarf_loclists_contribution_at (ll->sec, ll->len, ll->be, at, c)) {
		if (offset < c->end) {
			if (offset < c->lists || c->address_size != ll->ctx.addr_size) {
				return false;
			}
			ll->contribution = *c;
			ll->has_contribution = true;
			return true;
		}
		at = c->end;
	}
	return false;
}

R_API bool r_bin_dwarf_loclists_foreach(RBinDwarfLocLists *ll, const RBinDwarfCompUnit *unit, ut64 offset, RBinDwarfLocEntryCb cb, void *user) {
	R_RETURN_VAL_IF_FAIL (unit && cb, false);
	DwarfLoclistsContribution c;
	if (!ll || !loclists_unit (ll, unit) || !loclists_contribution_of (ll, offset, &c)) {
		return false;
	}
	return loclist_foreach (&ll->ctx, ll->sec + offset, ll->sec + c.end, cb, user);
}

static const char *dwarf_lle_names[] = {
	"end_of_list", "base_addressx", "startx_endx", "startx_length",
	"offset_pair", "default_location", "base_address", "start_end", "start_length"
};

static const char *loclist_entry_name(ut8 lle) {
	return lle < R_ARRAY_SIZE (dwarf_lle_names)? dwarf_lle_names[lle]: "unknown";
}

// every .debug_loclists contribution as ranges; addrx indices stay unresolved
R_API R_OWNED char *r_bin_dwarf_print_loclists_stream(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_LOCLISTS);
	const ut8 *sec = section? dwarf_get_section_bytes (bf, section): NULL;
	if (!sec) {
		return NULL;
	}
	RBin *bin = bf->rbin;
	const size_t len = section->bytes.len;
	const bool be = r_bin_is_big_endian (bin);
	RStrBuf *sb = r_strbuf_new (NULL);
	r_strbuf_append (sb, "\nContents of the .debug_loclists section:\n");
	size_t at = 0;
	DwarfLoclistsContribution c;
	while (at < len && !dwarf_is_breaked (bin)) {
		if (!dwarf_loclists_contribution_at (sec, len, be, at, &c)) {
			r_strbuf_appendf (sb, "0x%" PFMT64x " <Malformed header>\n", (ut64)at);
			break;
		}
		r_strbuf_appendf (sb, "0x%" PFMT64x " version 5 address size %d offsets %u\n", (ut64)at, c.address_size, c.count);
		LoclistCtx ctx = { .bf = bf, .be = be, .addr_size = c.address_size, .raw = true };
		const ut8 *buf = sec + c.lists;
		const ut8 *const limit = sec + c.end;
		ut8 lle;
		ut64 base = 0, start, end;
		RBinDwarfBlock expr;
		while (buf < limit) {
			const ut64 entry = buf - sec;
			if (!loclist_entry (&ctx, &buf, limit, &lle, &base, &start, &end, &expr)) {
				r_strbuf_appendf (sb, "0x%" PFMT64x " <Malformed entry>\n", entry);
				break;
			}
			if (lle == DW_LLE_end_of_list) {
				r_strbuf_appendf (sb, "0x%" PFMT64x " <End of list>\n", entry);
				base = 0;
			} else if (loclist_is_base (lle)) {
				r_strbuf_appendf (sb, "0x%" PFMT64x " %s 0x%" PFMT64x "\n", entry, loclist_entry_name (lle), base);
			} else {
				r_strbuf_appendf (sb, "0x%" PFMT64x " %s 0x%" PFMT64x " 0x%" PFMT64x " %" PFMT64u "\n", entry, loclist_entry_name (lle), start, end, expr.length);
			}
		}
		at = c.end;
	}
	r_strbuf_append (sb, "\n");
	return r_strbuf_drain (sb);
}

/* Itanium C++ ABI LSDA (language specific data area) parser. This is the
 * layout of the gcc_except_tab sections referenced by eh_frame or by the
 * mach0 compact unwind info, with every field using the DW_EH_PE pointer
 * encodings from the DWARF exception headers. */
