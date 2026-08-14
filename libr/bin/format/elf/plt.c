/* radare - LGPL - Copyright 2026 - pancake */

// PLT entry geometry lives here: new per-arch stub math belongs in this
// file instead of growing elf.c further.

#include "elf.h"

#define ARM64_PLT_OFFSET 0x20
#define ARM64_PLT_ENTRY_SIZE 0x10
#define ARM64_PAC_PLT_ENTRY_SIZE 0x18
#define ARM64_BTI_C 0xd503245f

// 0 for an unmapped, short or all-ones read: none of those is an opcode here
static ut32 read32_at(ELFOBJ *eo, ut64 vaddr) {
	const ut64 off = Elf_(v2p) (eo, vaddr);
	if (off == UT64_MAX) {
		return 0;
	}
	const ut32 w = r_buf_read_ble32_at (eo->b, off, eo->endian);
	return (w == UT32_MAX)? 0: w;
}

// every entry opens with adrp x16 or the bti c that guards it
static bool arm64_plt_entry_starts_at(ELFOBJ *eo, ut64 vaddr) {
	const ut32 op = read32_at (eo, vaddr);
	return op == ARM64_BTI_C || (op & 0x9f00001f) == 0x90000010;
}

// bfd pads pac entries and lld pads bti entries out to 24 bytes, and the
// stride is a file property, so measure it once from the first two entries
static ut64 arm64_measure_stride(ELFOBJ *eo, ut64 plt_addr) {
	static const ut64 strides[2] = { ARM64_PLT_ENTRY_SIZE, ARM64_PAC_PLT_ENTRY_SIZE };
	// the pac dynamic tag pins 24 bytes on every linker
	if (eo->dyn_info.dt_aarch64_pac_plt) {
		return ARM64_PAC_PLT_ENTRY_SIZE;
	}
	RBinElfSection *plt = Elf_(plt_section_by_name) (eo, ".plt");
	// a lazy got slot points at the plt header even with the sections gone
	const ut64 base = plt? plt->rva: plt_addr;
	const ut64 nrel = Elf_(plt_num_relocs) (eo);
	if (!base || !nrel) {
		return ARM64_PLT_ENTRY_SIZE;
	}
	const ut64 first = base + ARM64_PLT_OFFSET;
	size_t i;
	if (nrel > 1 && arm64_plt_entry_starts_at (eo, first)) {
		// reading past the last entry would decide the stride on foreign bytes
		const ut64 last = (plt && plt->size > 4)? plt->rva + plt->size - 4: UT64_MAX;
		for (i = 0; i < R_ARRAY_SIZE (strides); i++) {
			const ut64 next = first + strides[i];
			if (next <= last && arm64_plt_entry_starts_at (eo, next)) {
				return strides[i];
			}
		}
	}
	// a lone entry can only be sized by the section payload
	if (plt && plt->size > ARM64_PLT_OFFSET) {
		const ut64 payload = plt->size - ARM64_PLT_OFFSET;
		for (i = 0; i < R_ARRAY_SIZE (strides); i++) {
			if (payload == nrel * strides[i]) {
				return strides[i];
			}
		}
	}
	return ARM64_PLT_ENTRY_SIZE;
}

// entry vaddr for the pos-th plt reloc; the header owns the first 32 bytes
ut64 Elf_(plt_arm64_entry)(ELFOBJ *eo, ut64 plt_addr, ut64 pos) {
	if (!eo->arm64_plt_esize) {
		eo->arm64_plt_esize = arm64_measure_stride (eo, plt_addr);
	}
	return plt_addr + pos * eo->arm64_plt_esize + ARM64_PLT_OFFSET;
}

#define PPC32_MTCTR_R11 0x7d6903a6
#define PPC32_BCTR 0x4e800420
#define PPC32_THUNK_SCAN_WORDS 16
// padding and the tls prefix let a slot own several thunk candidates
#define PPC32_THUNKS_PER_SLOT 8
#define PPC32_TLS_OPT_SIZE 32

// a plt_pic32 call thunk loads its slot relative to r30, whose runtime value
// is unknown here, so only the displacement identifies the slot
static bool ppc32_thunk_disp(ELFOBJ *eo, ut64 vaddr, st64 *disp) {
	const ut64 off = Elf_(v2p) (eo, vaddr);
	if (off == UT64_MAX) {
		return false;
	}
	ut8 buf[16];
	if (r_buf_read_at (eo->b, off, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	const ut32 w0 = r_read_ble32 (buf, eo->endian);
	const ut32 w1 = r_read_ble32 (buf + 4, eo->endian);
	const ut32 w2 = r_read_ble32 (buf + 8, eo->endian);
	const ut32 w3 = r_read_ble32 (buf + 12, eo->endian);
	// lwz r11, disp(r30); mtctr r11; bctr
	if ((w0 & 0xffff0000) == 0x817e0000 && w1 == PPC32_MTCTR_R11 && w2 == PPC32_BCTR) {
		*disp = (st64)(st16)w0;
		return true;
	}
	// addis r11, r30, disp@ha; lwz r11, disp@l(r11); mtctr r11; bctr
	if ((w0 & 0xffff0000) == 0x3d7e0000 && (w1 & 0xffff0000) == 0x816b0000
			&& w2 == PPC32_MTCTR_R11 && w3 == PPC32_BCTR) {
		*disp = ((st64)(st16)w0 * 0x10000) + (st16)w1;
		return true;
	}
	return false;
}

// bfd prepends this 8 word fast path to the __tls_get_addr thunk
static bool ppc32_tls_opt_prefix(ELFOBJ *eo, ut64 vaddr) {
	static const ut32 prefix[8] = {
		0x81630000, 0x81830004, 0x7c601b78, 0x2c0b0000,
		0x7c6c1214, 0x4d820020, 0x7c030378, 0x60000000,
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (prefix); i++) {
		if (read32_at (eo, vaddr + (i * 4)) != prefix[i]) {
			return false;
		}
	}
	return true;
}

// bfd --plt-align pads each thunk, so scan for the next instead of striding
static ut64 ppc32_prev_thunk(ELFOBJ *eo, ut64 below, st64 *disp) {
	ut64 vaddr = below;
	int i;
	for (i = 0; i < PPC32_THUNK_SCAN_WORDS && vaddr >= 4; i++) {
		vaddr -= 4;
		if (ppc32_thunk_disp (eo, vaddr, disp)) {
			const ut64 tls = vaddr - PPC32_TLS_OPT_SIZE;
			return (vaddr >= PPC32_TLS_OPT_SIZE && ppc32_tls_opt_prefix (eo, tls))? tls: vaddr;
		}
	}
	return UT64_MAX;
}

typedef struct {
	ut64 vaddr;
	st64 disp;
} PPC32Thunk;

// the lowest displacement is slot 0; scanned downwards, so the last thunk
// claiming a slot is its true start
static bool ppc32_index_thunks(ut64 *slots, ut64 nrel, const PPC32Thunk *thunks, ut64 count) {
	st64 lowest = ST64_MAX;
	ut64 i;
	for (i = 0; i < count; i++) {
		lowest = R_MIN (lowest, thunks[i].disp);
	}
	for (i = 0; i < count; i++) {
		const ut64 delta = (ut64)(thunks[i].disp - lowest);
		// a displacement off the slot grid means two got2 bases
		if ((delta & 3) || delta >= nrel * 4) {
			return false;
		}
		slots[delta / 4] = thunks[i].vaddr;
	}
	// an unclaimed slot means the lowest displacement is not the first one
	for (i = 0; i < nrel; i++) {
		if (!slots[i]) {
			return false;
		}
	}
	return true;
}

// r30 is unknown, so decode the thunks below the resolver: the map survives
// only when every slot resolves, otherwise the caller keeps its old math
static bool ppc32_build_thunk_map(ELFOBJ *eo) {
	const ut64 got = eo->dyn_info.dt_pltgot;
	const ut64 nrel = Elf_(plt_num_relocs) (eo);
	if (got == R_BIN_ELF_ADDR_MAX || !nrel) {
		return false;
	}
	const ut64 glink = read32_at (eo, got);
	if (!glink) {
		return false;
	}
	const ut64 maxthunks = (nrel + 1) * PPC32_THUNKS_PER_SLOT;
	PPC32Thunk *thunks = calloc (maxthunks, sizeof (PPC32Thunk));
	ut64 *slots = calloc (nrel, sizeof (ut64));
	if (!thunks || !slots) {
		free (thunks);
		free (slots);
		return false;
	}
	ut64 count = 0;
	ut64 at = glink;
	while (count < maxthunks) {
		st64 disp;
		const ut64 vaddr = ppc32_prev_thunk (eo, at, &disp);
		if (vaddr == UT64_MAX) {
			break;
		}
		thunks[count].vaddr = vaddr;
		thunks[count].disp = disp;
		at = vaddr;
		count++;
	}
	const bool ok = count >= nrel && ppc32_index_thunks (slots, nrel, thunks, count);
	free (thunks);
	if (!ok) {
		free (slots);
		return false;
	}
	eo->ppc32_thunks = slots;
	eo->ppc32_nthunks = nrel;
	return true;
}

// call thunk for the given plt slot, UT64_MAX when the map could not be built
ut64 Elf_(plt_ppc32_thunk)(ELFOBJ *eo, ut64 slot_vaddr) {
	if (!eo->ppc32_thunks_done) {
		eo->ppc32_thunks_done = true;
		ppc32_build_thunk_map (eo);
	}
	if (!eo->ppc32_thunks) {
		return UT64_MAX;
	}
	const ut64 delta = slot_vaddr - eo->dyn_info.dt_pltgot;
	const ut64 idx = delta / 4;
	if ((delta & 3) || idx >= eo->ppc32_nthunks) {
		return UT64_MAX;
	}
	return eo->ppc32_thunks[idx];
}
