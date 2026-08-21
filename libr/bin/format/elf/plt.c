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

#define MIPS_PLT_OFFSET 0x20
#define PLT_HDR_SIZE 0x20
#define X86_PLT_ENTRY_SIZE 0x10
#define SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6
#define X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6
#define R_ELF_PART_RELRO 1
#define COMPUTE_PLTGOT_POSITION(rel, pltgot_addr, n_initial_unused_entries) \
	((rel->rva - pltgot_addr - n_initial_unused_entries * R_BIN_ELF_WORDSIZE) / R_BIN_ELF_WORDSIZE)

static ut64 get_got_entry(ELFOBJ *eo, RBinElfReloc *rel) {
	if (!rel || !rel->rva || rel->rva == UT64_MAX) {
		return UT64_MAX;
	}
	ut64 p_sym_got_addr = Elf_(v2p) (eo, rel->rva);
	ut64 addr;
#if R_BIN_ELF64
	addr = r_buf_read_ble64_at (eo->b, p_sym_got_addr, eo->endian);
#else
	addr = r_buf_read_ble32_at (eo->b, p_sym_got_addr, eo->endian);
#endif
	return (!addr || addr == R_BIN_ELF_WORD_MAX) ? UT64_MAX : addr;
}

// classic layout shared by several arches: a lazy got slot points back at the
// plt, whose header is followed by fixed-stride entries
static ut64 indexed_plt_entry(ELFOBJ *eo, RBinElfReloc *rel, int skipped_slots, ut64 esize) {
	const ut64 got_addr = eo->dyn_info.dt_pltgot;
	if (got_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}
	const ut64 plt_addr = get_got_entry (eo, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}
	return plt_addr + PLT_HDR_SIZE + COMPUTE_PLTGOT_POSITION (rel, got_addr, skipped_slots) * esize;
}

static ut64 get_import_addr_qdsp6(ELFOBJ *eo, RBinElfReloc *rel) {
	return (rel->type == R_QDSP6_JUMP_SLOT)? indexed_plt_entry (eo, rel, 3, 16): UT64_MAX;
}

static ut64 get_import_addr_arm(ELFOBJ *eo, RBinElfReloc *rel) {
	ut64 got_addr = eo->dyn_info.dt_pltgot;
	if (got_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry (eo, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	const ut64 pos = COMPUTE_PLTGOT_POSITION (rel, got_addr, 0x3);

	switch (rel->type) {
	case R_ARM_JUMP_SLOT:
		plt_addr += pos * 12 + 20;
		if (plt_addr & 1) {
			plt_addr--;
		}
		return plt_addr;
	case R_ARM_GLOB_DAT:
	case R_ARM_ABS32:
		return rel->rva;
	default:
		R_LOG_WARN ("Unsupported relocation type for imports %d", rel->type);
		return UT64_MAX;
	}
	return UT64_MAX;
}

static ut64 get_import_addr_arm64(ELFOBJ *eo, RBinElfReloc *rel) {
	ut64 got_addr = eo->dyn_info.dt_pltgot;
	if (got_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry (eo, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	const ut64 pos = COMPUTE_PLTGOT_POSITION (rel, got_addr, 0x3);

	switch (rel->type) {
	case R_AARCH64_RELATIVE:
		// Direct binding: adjust by program base for relative relocations.
		return eo->baddr + rel->addend;
	case R_AARCH64_IRELATIVE:
		if (rel->addend > plt_addr) { // start
			return Elf_(plt_arm64_entry) (eo, plt_addr, pos) + rel->addend;
		}
		// same as fallback to JUMP_SLOT
		return Elf_(plt_arm64_entry) (eo, plt_addr, pos);
	case R_AARCH64_JUMP_SLOT:
		return Elf_(plt_arm64_entry) (eo, plt_addr, pos);
	case R_AARCH64_GLOB_DAT:
		return rel->rva;
	default:
		R_LOG_WARN ("Unsupported relocation type for imports %d", rel->type);
		return UT64_MAX;
	}
	return UT64_MAX;
}

static ut64 get_import_addr_mips(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 jmprel_addr = bin->dyn_info.dt_jmprel;
	ut64 got_addr = bin->dyn_info.dt_mips_pltgot;
	if (jmprel_addr != R_BIN_ELF_ADDR_MAX && got_addr != R_BIN_ELF_ADDR_MAX) {
		ut64 pos = COMPUTE_PLTGOT_POSITION (rel, got_addr, 0x2);
		ut8 buf[128]; /// XXX why arbitrary 128
		ut64 plt_addr = jmprel_addr + bin->dyn_info.dt_pltrelsz;
		ut64 p_plt_addr = Elf_(v2p) (bin, plt_addr);
		int res = r_buf_read_at (bin->b, p_plt_addr, buf, sizeof (buf));
		if (res == sizeof (buf)) {
			const ut8 *base = r_mem_mem_aligned (buf, sizeof (buf), (const ut8 *)"\x3c\x0f\x00", 3, 4);
			plt_addr += base? (int)(size_t) (base - buf):  MIPS_PLT_OFFSET + 8; // HARDCODED HACK
			plt_addr += pos * 16;
			return plt_addr;
		}
	}
	return UT64_MAX;
}

// riscv, loongarch and vax share the same 16-byte entries after a 32-byte header
static ut64 get_import_addr_riscv(ELFOBJ *bin, RBinElfReloc *rel) {
	return indexed_plt_entry (bin, rel, 2, 16);
}

static ut64 get_import_addr_sparc(ELFOBJ *eo, RBinElfReloc *rel) {
	if (rel->type != R_SPARC_JMP_SLOT) {
		R_LOG_DEBUG ("Unknown sparc reloc type %d", rel->type);
		return UT64_MAX;
	}

	ut64 tmp = get_got_entry (eo, rel);
	return (tmp == UT64_MAX) ? UT64_MAX : tmp + SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr_s390x(ELFOBJ *eo, RBinElfReloc *rel) {
	ut64 a = get_got_entry (eo, rel);
	if (a == UT64_MAX) {
		// GLOBALS, OBJECTS, NOTYPE, ..
		return UT64_MAX;
	}
	return a - 14;
}

// EF_PPC64_ABI: 1 = ELFv1, 2 = ELFv2, 3 = undefined; unflagged objects predate the field, so guess from the endian
int Elf_(plt_ppc64_abi)(ELFOBJ *eo) {
	if (eo->ehdr.e_machine != EM_PPC64) {
		return 0;
	}
	switch (eo->ehdr.e_flags & EF_PPC64_ABI) {
	case 1: return 1;
	case 2: return 2;
	case 3: return 0;
	}
	return eo->endian? 1: 2;
}
#if R_BIN_ELF64
// PLT slot vaddr -> lazy glink stub vaddr; the N-th DT_JMPREL entry owns the N-th
// stub after DT_PPC64_GLINK + 32 (binutils ppc64_elf_get_synthetic_symtab)
static HtUU *ppc64_build_glink_map(ELFOBJ *eo, int abi) {
	const RBinElfDynamicInfo *di = &eo->dyn_info;
	if (di->dt_ppc64_glink == R_BIN_ELF_ADDR_MAX) {
		return NULL;
	}
	if (di->dt_jmprel == R_BIN_ELF_ADDR_MAX || !di->dt_pltrelsz) {
		return NULL;
	}
	const ut64 num_plts = Elf_(plt_num_relocs) (eo);
	const size_t relsize = num_plts? di->dt_pltrelsz / num_plts: 0;
	if (!relsize) {
		return NULL;
	}
	HtUU *map = ht_uu_new0 ();
	if (!map) {
		return NULL;
	}
	ut64 stub_vma = di->dt_ppc64_glink + 32;
	// num_plts was validated with relsize above
	ut64 n;
	for (n = 0; n < num_plts; n++) {
		ut64 rela_off = Elf_(v2p) (eo, di->dt_jmprel + n * relsize);
		if (rela_off == UT64_MAX) {
			break;
		}
		ut64 slot_vaddr = r_buf_read_ble64_at (eo->b, rela_off, eo->endian);
		if (slot_vaddr == UT64_MAX) {
			break;
		}
		ht_uu_insert (map, slot_vaddr, stub_vma);
		// an ELFv2 stub is a single branch; ELFv1 stubs grow to 12 bytes past slot 0x8000
		stub_vma += (abi == 2)? 4: (n >= 0x8000)? 12: 8;
	}
	return map;
}
#endif

// PLT stub vaddr for the given GOT slot in a ppc64 binary, building the stub cache on demand
ut64 Elf_(ppc64_get_plt_stub_for_slot)(ELFOBJ *eo, ut64 slot_vaddr) {
#if R_BIN_ELF64
	const int abi = Elf_(plt_ppc64_abi) (eo);
	if (!abi) {
		return UT64_MAX;
	}
	if (!eo->ppc64_plt_stubs) {
		eo->ppc64_plt_stubs = ppc64_build_glink_map (eo, abi);
	}
	if (eo->ppc64_plt_stubs) {
		bool found = false;
		ut64 stub = ht_uu_find (eo->ppc64_plt_stubs, slot_vaddr, &found);
		if (found) {
			return stub;
		}
	}
#endif
	return UT64_MAX;
}

#if R_BIN_ELF64
// an ELFv1 call dispatches through a 7-word plt_call stub in .text:
//   std r2, 40(r1); ld rX, d(r2); mtctr rX; ld r2, d+8(r2);
//   cmpldi r2, 0; bnectr+; b <glink stub>
// the trailing branch into a known glink stub names the plt slot it serves
#define PPC64_STD_R2_40R1 0xf8410028
// shortest form: std, ld, mtctr, ld r2, bctr
#define PPC64_TEXT_STUB_MIN 20
// longest form: std, addis, ld, mtctr, ld env, ld r2, cmpldi, bnectr, b
#define PPC64_TEXT_STUB_MAX 36
// bytes of executable ranges worth scanning for stubs before giving up
#define PPC64_TEXT_SCAN_MAX 0x2000000

// reloc index + 1 of the slot a plt_call stub serves, 0 when it is not one;
// after the std comes an optional addis r11, r2, ha, then ld rX, d(base);
// mtctr rX; ld r2, d+8(base), ending either in bctr (eager: the slot is
// toc + disp) or in cmpldi r2, 0; bnectr+; b <glink> (lazy: the branch
// target names the slot)
static ut64 ppc64v1_text_stub_reloc(ELFOBJ *eo, const ut8 *w, ut64 vaddr,
		HtUU *rel_by_glink, HtUU *rel_by_slot, ut64 toc, ut32 *size) {
	int i = 1;
	st64 ha = 0;
	ut32 base = 2;
	ut32 op = r_read_ble32 (w + 4 * i, eo->endian);
	if ((op & 0xffff0000) == 0x3d620000) { // addis r11, r2, disp@ha
		ha = (st64)(st16)op * 0x10000;
		base = 11;
		i++;
		op = r_read_ble32 (w + 4 * i, eo->endian);
	}
	if ((op & 0xfc1f0003) != (0xe8000000 | (base << 16))) { // ld rX, d(base)
		return 0;
	}
	const ut32 reg = (op >> 21) & 0x1f;
	const st32 lo = (st16)(op & 0xfffc);
	op = r_read_ble32 (w + 4 * ++i, eo->endian);
	if (reg == 2 || reg == base
			|| (op & 0xfc1fffff) != 0x7c0903a6 || ((op >> 21) & 0x1f) != reg) { // mtctr rX
		return 0;
	}
	// --plt-static-chain also loads the descriptor env word, ld rX, d+16(base),
	// before the toc restore or after it, depending on whether it clobbers base
	op = r_read_ble32 (w + 4 * ++i, eo->endian);
	bool env = false;
	if ((op & 0xfc1f0003) == (0xe8000000 | (base << 16)) && ((op >> 21) & 0x1f) != base
			&& ((op >> 21) & 0x1f) != 2 && (st32)(st16)(op & 0xfffc) == lo + 16) {
		env = true;
		op = r_read_ble32 (w + 4 * ++i, eo->endian);
	}
	// the code address and the toc it runs with come from one descriptor
	if ((op & 0xffff0003) != (0xe8400000 | (base << 16)) // ld r2, d+8(base)
			|| (st32)(st16)(op & 0xfffc) != lo + 8) {
		return 0;
	}
	op = r_read_ble32 (w + 4 * ++i, eo->endian);
	if (!env && (op & 0xfc1f0003) == (0xe8000000 | (base << 16)) && ((op >> 21) & 0x1f) != 2
			&& (st32)(st16)(op & 0xfffc) == lo + 16) {
		op = r_read_ble32 (w + 4 * ++i, eo->endian);
	}
	if (op == 0x4e800420) { // bctr: an eager stub, only the toc names the slot
		*size = 4 * (i + 1);
		return toc? ht_uu_find (rel_by_slot, toc + ha + lo, NULL): 0;
	}
	if (op != 0x28220000) { // cmpldi r2, 0
		return 0;
	}
	op = r_read_ble32 (w + 4 * ++i, eo->endian);
	if ((op & 0xff9fffff) != 0x4c820420) { // bnectr+
		return 0;
	}
	op = r_read_ble32 (w + 4 * ++i, eo->endian);
	if ((op & 0xfc000003) != 0x48000000) { // b <glink>
		return 0;
	}
	*size = 4 * (i + 1);
	const st32 boff = ((st32)((op & 0x03fffffc) << 6)) >> 6;
	return ht_uu_find (rel_by_glink, vaddr + 4 * i + boff, NULL);
}

// name the .text call stubs plt.<target> so calls read bl sym.plt.strlen and
// the anal name join can recover forwarded arguments through them
// the stub target is a local symbol or an import, whichever owns the reloc
static const char *ppc64v1_stub_target(ELFOBJ *eo, RBinElfReloc *rel, const char **bind) {
	if ((size_t)rel->sym < eo->symbols_by_ord_size && eo->symbols_by_ord[rel->sym]) {
		RBinSymbol *t = eo->symbols_by_ord[rel->sym];
		*bind = t->bind;
		return r_bin_name_tostring2 (t->name, 'o');
	}
	if ((size_t)rel->sym < eo->imports_by_ord_size && eo->imports_by_ord[rel->sym]) {
		RBinImport *t = eo->imports_by_ord[rel->sym];
		*bind = t->bind;
		return r_bin_name_tostring2 (t->name, 'o');
	}
	return NULL;
}

typedef struct {
	HtUU *rel_by_glink;
	HtUU *rel_by_slot;
	ut64 toc;
	ut64 budget;
} PPC64StubScan;

// scan one executable file range for plt_call stubs, clamped to the file and
// to the remaining scan budget so corrupt headers cannot make this expensive
static void ppc64v1_scan_stubs(ELFOBJ *eo, PPC64StubScan *sc, ut64 paddr, ut64 vaddr, ut64 size) {
	const ut64 fsz = r_buf_size (eo->b);
	if (paddr >= fsz || !sc->budget) {
		return;
	}
	size = R_MIN (size, fsz - paddr);
	size = R_MIN (size, sc->budget);
	if (size < PPC64_TEXT_STUB_MIN) {
		return;
	}
	sc->budget -= size;
	// zero padding lets the matcher read a full stub window at the range end
	ut8 *buf = calloc (size + PPC64_TEXT_STUB_MAX, 1);
	if (!buf || r_buf_read_at (eo->b, paddr, buf, size) != (st64)size) {
		free (buf);
		return;
	}
	ut64 i;
	for (i = 0; i + PPC64_TEXT_STUB_MIN <= size; i += 4) {
		if (r_read_ble32 (buf + i, eo->endian) != PPC64_STD_R2_40R1) {
			continue;
		}
		ut32 stub_size = 0;
		const ut64 relnum = ppc64v1_text_stub_reloc (eo, buf + i, vaddr + i,
			sc->rel_by_glink, sc->rel_by_slot, sc->toc, &stub_size);
		RBinElfReloc *rel;
		if (!relnum || !(rel = RVecRBinElfReloc_at (&eo->g_relocs, relnum - 1))) {
			continue;
		}
		const char *tbind = NULL;
		const char *tname = ppc64v1_stub_target (eo, rel, &tbind);
		if (R_STR_ISEMPTY (tname)) {
			continue;
		}
		RBinSymbol sym = {0};
		sym.name = r_bin_name_new_from (r_str_newf ("plt.%s", tname));
		sym.forwarder = "NONE";
		sym.bind = tbind? tbind: R_BIN_BIND_LOCAL_STR;
		sym.type = R_BIN_TYPE_FUNC_STR;
		sym.attr.size = stub_size;
		sym.ordinal = rel->sym;
		sym.vaddr = vaddr + i;
		sym.paddr = paddr + i;
		RVecRBinSymbol_push_back (&eo->plt_symbols_cache, &sym);
	}
	free (buf);
}

void Elf_(plt_ppc64v1_load_text_stubs)(RBinFile *bf, ELFOBJ *eo) {
	if (Elf_(plt_ppc64_abi) (eo) != 1) {
		return;
	}
	Elf_(load_symbols_vec) (bf, eo);
	// each glink stub or plt slot identifies its reloc, and that its target
	RBinElfSection *got = Elf_(plt_section_by_name) (eo, ".got");
	PPC64StubScan sc = {
		.rel_by_glink = ht_uu_new0 (),
		.rel_by_slot = ht_uu_new0 (),
		.toc = got? got->rva + 0x8000: 0,
		.budget = PPC64_TEXT_SCAN_MAX,
	};
	if (!sc.rel_by_glink || !sc.rel_by_slot) {
		goto beach;
	}
	RBinElfReloc *rel;
	ut64 nrel = 0;
	bool any = false;
	R_VEC_FOREACH (&eo->g_relocs, rel) {
		nrel++;
		if (rel->type == R_PPC64_JMP_SLOT && rel->sym > 0) {
			const ut64 glink = Elf_(ppc64_get_plt_stub_for_slot) (eo, rel->rva);
			any |= ht_uu_insert (sc.rel_by_slot, rel->rva, nrel);
			if (glink != UT64_MAX) {
				ht_uu_insert (sc.rel_by_glink, glink, nrel);
			}
		}
	}
	if (!any) {
		goto beach;
	}
	// bfd emits stubs into every code section (.init holds __gmon_start__),
	// and without section headers the executable segments are all we have
	bool scanned = false;
	RBinElfSection *s;
	R_VEC_FOREACH (&eo->g_sections, s) {
		if (s->type == SHT_PROGBITS && (s->flags & SHF_EXECINSTR)) {
			ppc64v1_scan_stubs (eo, &sc, s->offset, s->rva, s->size);
			scanned = true;
		}
	}
	if (!scanned && eo->phdr) {
		size_t i;
		// phnum is the resolved count, e_phnum is 0xffff under PN_XNUM
		for (i = 0; i < eo->phnum; i++) {
			const Elf_(Phdr) *p = &eo->phdr[i];
			if (p->p_type == PT_LOAD && (p->p_flags & PF_X)) {
				ppc64v1_scan_stubs (eo, &sc, p->p_offset, p->p_vaddr, p->p_filesz);
			}
		}
	}
beach:
	ht_uu_free (sc.rel_by_glink);
	ht_uu_free (sc.rel_by_slot);
}
#endif

static ut64 get_import_addr_ppc(ELFOBJ *eo, RBinElfReloc *rel) {
#if R_BIN_ELF64
	if (Elf_(plt_ppc64_abi) (eo)) {
		ut64 stub = Elf_(ppc64_get_plt_stub_for_slot) (eo, rel->rva);
		if (stub != UT64_MAX) {
			return stub;
		}
		return rel->rva; // no DT_PPC64_GLINK or no map entry
	}
#endif
	ut64 plt_addr = eo->dyn_info.dt_pltgot;
	if (plt_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	// -fPIC secure-plt objects reach the slot through r30-relative call
	// thunks; when the whole map decodes it overrides the legacy math
	const ut64 thunk = Elf_(plt_ppc32_thunk) (eo, rel->rva);
	if (thunk != UT64_MAX) {
		return thunk;
	}
	if (rel->rva < plt_addr) {
		ut64 delta = plt_addr - rel->rva;
		ut64 orva = rel->rva + (2 * delta);
		R_LOG_DEBUG ("Massaged pointer below plt from 0x%"PFMT64x" to 0x%"PFMT64x, rel->rva, orva);
		return orva;
	}

	ut64 p_plt_addr = Elf_(v2p) (eo, plt_addr);
	if (p_plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 base = r_buf_read_ble32_at (eo->b, p_plt_addr, eo->endian);
	if (base == UT32_MAX) {
		return UT64_MAX;
	}

	ut64 nrel = Elf_(plt_num_relocs) (eo);
	ut64 pos = COMPUTE_PLTGOT_POSITION (rel, plt_addr, 0x0);

	if (eo->endian) {
		base -= nrel * 16;
		base += pos * 16;
		return base;
	}

	base -= (nrel * 12) + 20;
	base += (pos * 8);
	return base;
}

static ut64 get_import_addr_x86_manual(ELFOBJ *eo, RBinElfReloc *rel) {
	ut64 got_addr = eo->dyn_info.dt_pltgot;
	if (got_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 got_offset = Elf_(v2p) (eo, got_addr);
	if (got_offset == UT64_MAX) {
		return UT64_MAX;
	}

	//XXX HACK ALERT!!!! full relro?? try to fix it
	//will there always be .plt.got, what would happen if is .got.plt?
	RBinElfSection *s = Elf_(plt_section_by_name) (eo, ".plt.got");
	if (Elf_(has_relro) (eo) < R_ELF_PART_RELRO || !s) {
		return UT64_MAX;
	}

	ut8 buf[sizeof (Elf_(Addr))] = {0};
	// Elf_(Addr) buf;

	ut64 plt_addr = s->offset;
	ut64 plt_sym_addr;

	while (plt_addr + 2 + 4 < s->offset + s->size && plt_addr + 2 + 4 < eo->size) {
		/*we try to locate the plt entry that correspond with the relocation
		  since got does not point back to .plt. In this case it has the following
		  form
		  ff253a152000   JMP QWORD [RIP + 0x20153A]
		  6690		     NOP
		  ----
		  ff25ec9f0408   JMP DWORD [reloc.puts_236]
		  plt_addr + 2 to remove jmp opcode and get the imm reading 4
		  and if RIP (plt_addr + 6) + imm == rel->offset
		  return plt_addr, that will be our sym addr
		  perhaps this hack doesn't work on 32 bits
		  */
		int res = r_buf_read_at (eo->b, plt_addr + 2, buf, sizeof (ut32));
		if (res < 0) {
			return UT64_MAX;
		}

#if R_BIN_ELF64
		plt_sym_addr = r_read_ble64 (buf, eo->endian);
#else
		plt_sym_addr = r_read_ble32 (buf, eo->endian);
#endif

		//relative address
		if ((plt_addr + 6 + plt_sym_addr) == rel->rva) {
			return plt_addr;
		}
		if (plt_sym_addr == rel->rva) {
			return plt_addr;
		}
		plt_addr += 8;
	}

	return UT64_MAX;
}

static ut64 get_import_addr_x86(ELFOBJ *eo, RBinElfReloc *rel) {
	ut64 tmp = get_got_entry (eo, rel);
	if (tmp == UT64_MAX) {
		return get_import_addr_x86_manual (eo, rel);
	}
	RBinElfSection *pltsec = Elf_(plt_section_by_name) (eo, ".plt.sec");
	if (pltsec) {
		ut64 got_addr = eo->dyn_info.dt_pltgot;
		ut64 pos = COMPUTE_PLTGOT_POSITION (rel, got_addr, 3);
		return pltsec->rva + pos * X86_PLT_ENTRY_SIZE;
	}
	return tmp + X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

ut64 Elf_(plt_get_import_addr)(ELFOBJ *eo, int sym) {
	if ((!eo->shdr || !eo->strtab) && !eo->phdr) {
		return UT64_MAX;
	}

	if (!eo->rel_cache) {
		return UT64_MAX;
	}

	int index = ht_uu_find (eo->rel_cache, sym + 1, NULL);
	if (index < 1) {
		return UT64_MAX;
	}
	// lookup the right rel/rela entry
	RBinElfReloc *rel = RVecRBinElfReloc_at (&eo->g_relocs, index - 1);
	if (!rel) {
		return UT64_MAX;
	}

	switch (eo->ehdr.e_machine) {
	case EM_S390:
		return get_import_addr_s390x (eo, rel);
	case EM_ARM:
		return get_import_addr_arm (eo, rel);
	case EM_AARCH64:
		return get_import_addr_arm64 (eo, rel);
	case EM_MIPS: // MIPS32 BIG ENDIAN relocs
		return get_import_addr_mips (eo, rel);
	case EM_QDSP6: // also known as HEXAGON
		return get_import_addr_qdsp6 (eo, rel);
	case EM_VAX:
		// as beautiful as riscv <3
		return get_import_addr_riscv (eo, rel);
	case EM_RISCV:
		return get_import_addr_riscv (eo, rel);
	case EM_SPARC:
	case EM_SPARCV9:
	case EM_SPARC32PLUS:
		return get_import_addr_sparc (eo, rel);
	case EM_PPC:
	case EM_PPC64:
		return get_import_addr_ppc (eo, rel);
	case EM_386:
	case EM_X86_64:
	case EM_IAMCU:
		return get_import_addr_x86 (eo, rel);
	case EM_LOONGARCH:
		return get_import_addr_riscv (eo, rel);
	case EM_SBPF:
		// sBPF relocations are handled in patch_reloc, return the offset for imports
		return rel->offset;
	case EM_BPF:
		return rel->offset;
	case EM_V800:
	case EM_V850:
		return rel->offset;
	case EM_NDS32:
		return rel->offset;
	default:
		R_LOG_WARN ("Unsupported relocs type %" PFMT64u " for arch %d",
				(ut64) rel->type, eo->ehdr.e_machine);
		return UT64_MAX;
	}
}
