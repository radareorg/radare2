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
