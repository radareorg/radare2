/* radare - LGPL - Copyright 2008-2025 - nibble, pancake, alvaro_fe */

// R2R db/formats/elf/versioninfo
// R2R db/formats/elf/reloc
#define R_LOG_ORIGIN "elf"
#include <r_types.h>
#include <r_util.h>
#include "elf.h"

/// XXX this should be a runtime option
#define PERMIT_UNNAMED_SYMBOLS 0

#define MIPS_PLT_OFFSET 0x20
#define RISCV_PLT_OFFSET 0x20
#define LOONGARCH_PLT_OFFSET 0x20
#define S390_PLT_OFFSET 0x20

#define RISCV_PLT_ENTRY_SIZE 0x10
#define LOONGARCH_PLT_ENTRY_SIZE 0x10
#define X86_PLT_ENTRY_SIZE 0x10

#define SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6
#define X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6

#define ELF_PAGE_MASK 0xFFFFFFFFFFFFF000LL
#define ELF_PAGE_SIZE 4096

#define R_ELF_NO_RELRO 0
#define R_ELF_PART_RELRO 1
#define R_ELF_FULL_RELRO 2

#define MAX_REL_RELA_SZ (sizeof (Elf_(Rel)) > sizeof (Elf_(Rela))? sizeof (Elf_(Rel)): sizeof (Elf_(Rela)))

#define READ8(x, i) r_read_ble8((x) + (i)); (i) += 1
#define READ16(x, i) r_read_ble16((x) + (i), eo->endian); (i) += 2
#define READ32(x, i) r_read_ble32((x) + (i), eo->endian); (i) += 4
#define READ64(x, i) r_read_ble64((x) + (i), eo->endian); (i) += 8

#define BREAD8(x, i) r_buf_read_ble8_at (x, i); (i) += 1
#define BREAD16(x, i) r_buf_read_ble16_at (x, i, eo->endian); (i) += 2
#define BREAD32(x, i) r_buf_read_ble32_at (x, i, eo->endian); (i) += 4
#define BREAD64(x, i) r_buf_read_ble64_at (x, i, eo->endian); (i) += 8
#define NUMENTRIES_ROUNDUP(sectionsize, entrysize) (((sectionsize) + (entrysize) - 1) / (entrysize))
#define COMPUTE_PLTGOT_POSITION(rel, pltgot_addr, n_initial_unused_entries) \
	((rel->rva - pltgot_addr - n_initial_unused_entries * R_BIN_ELF_WORDSIZE) / R_BIN_ELF_WORDSIZE)

#define round_up(a) ((((a) + (4) - (1)) / (4)) * (4))

#define EF_MIPS_ABI_O32                0x00001000  /* O32 ABI.  */
#define EF_MIPS_ABI_O64                0x00002000  /* O32 extended for 64 bit.  */
#define EF_MIPS_ABI            0x0000f000

/* ARCH_ASE */
#define EF_MIPS_MICROMIPS      0x02000000 /* microMIPS */
#define EF_MIPS_ARCH_ASE_M16   0x04000000 /* Has Mips-16 ISA extensions */
#define EF_MIPS_ARCH_ASE_MDMX  0x08000000 /* Has MDMX multimedia extensions */
#define EF_MIPS_ARCH_ASE       0x0f000000 /* Mask for EF_MIPS_ARCH_ASE_xxx flags */

static bool reloc_fill_local_address(ELFOBJ *eo);
static inline bool is_elfclass64(Elf_(Ehdr) * h) {
	return h->e_ident[EI_CLASS] == ELFCLASS64;
}

static bool is_intel(const ELFOBJ *eo) {
	switch (eo->ehdr.e_machine) {
	case EM_386:
	case EM_X86_64:
	case EM_IAMCU:
		return true;
	}
	return false;
}

static bool is_mips_o32(Elf_(Ehdr) *h) {
	if (h->e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}
	if ((h->e_flags & EF_MIPS_ABI2) != 0) {
		return false;
	}
	if ((h->e_flags & EF_MIPS_ABI) != 0 && (h->e_flags & EF_MIPS_ABI) != EF_MIPS_ABI_O32) {
		return false;
	}
	return true;
}

static bool is_mips_micro(Elf_(Ehdr) *h) {
	if (h->e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}
	if ((h->e_flags & EF_MIPS_MICROMIPS) != 0) {
		return true;
	}
	return false;
}

static bool is_mips_n32(Elf_(Ehdr) *h) {
	if (h->e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}
	if ((h->e_flags & EF_MIPS_ABI2) == 0 || (h->e_flags & EF_MIPS_ABI) != 0) {
		return false;
	}
	return true;
}

enum {
	X86,
	X86_64,
	ARM,
	AARCH64,
	RCE,
	ARCH_LEN
};

typedef struct reginfo {
	ut32 regsize;
	ut32 regdelta;
} reginfo_t;

static const reginfo_t reginf[ARCH_LEN] = {
	{ 160, 0x5c },
	{ 216, 0x84 },
	{ 72, 0x5c },
	{ 272, 0x84 },
	{ 272, 0x84 }
};

static bool is_bin_etrel(ELFOBJ *eo) {
	return eo->ehdr.e_type == ET_REL;
}

static bool __is_valid_ident(ut8 *e_ident) {
	return !strncmp ((char*)e_ident, ELFMAG, SELFMAG) ||
		!strncmp ((char*)e_ident, CGCMAG, SCGCMAG);
}

static bool init_ehdr(ELFOBJ *eo) {
	ut8 ehdr[sizeof (Elf_(Ehdr))] = {0};
	int i;

	ut8 *e_ident = (ut8*)&eo->ehdr.e_ident;
	if (r_buf_read_at (eo->b, 0, e_ident, EI_NIDENT) != EI_NIDENT) {
		R_LOG_DEBUG ("read (magic)");
		return false;
	}

	if (!__is_valid_ident (e_ident)) {
		return false;
	}

	eo->endian = (e_ident[EI_DATA] == ELFDATA2MSB)? 1: 0;

	int len = r_buf_read_at (eo->b, 0, ehdr, sizeof (ehdr));
	if (len < 32) { // tinyelf != sizeof (Elf_(Ehdr))) {
		R_LOG_DEBUG ("read (ehdr)");
		return false;
	}

	sdb_num_set (eo->kv, "elf_header.offset", 0, 0);
	sdb_num_set (eo->kv, "elf_header.size", sizeof (Elf_(Ehdr)), 0);

	i = 16;
	eo->ehdr.e_type = READ16 (ehdr, i);
	eo->ehdr.e_machine = READ16 (ehdr, i);
	eo->ehdr.e_version = READ32 (ehdr, i);
#if R_BIN_ELF64
	eo->ehdr.e_entry = READ64 (ehdr, i);
	eo->ehdr.e_phoff = READ64 (ehdr, i);
	eo->ehdr.e_shoff = READ64 (ehdr, i);
#else
	eo->ehdr.e_entry = READ32 (ehdr, i);
	eo->ehdr.e_phoff = READ32 (ehdr, i);
	eo->ehdr.e_shoff = READ32 (ehdr, i);
#endif
	eo->ehdr.e_flags = READ32 (ehdr, i);
	eo->ehdr.e_ehsize = READ16 (ehdr, i);
	eo->ehdr.e_phentsize = READ16 (ehdr, i);
	eo->ehdr.e_phnum = READ16 (ehdr, i);
	eo->ehdr.e_shentsize = READ16 (ehdr, i);
	eo->ehdr.e_shnum = READ16 (ehdr, i);
	eo->ehdr.e_shstrndx = READ16 (ehdr, i);
	return true;
	// [Outdated] Usage example:
	// > td `k bin/cur/info/elf_type.cparse`; td `k bin/cur/info/elf_machine.cparse`
	// > pf `k bin/cur/info/elf_header.format` @ `k bin/cur/info/elf_header.offset`
}

ut64 Elf_(get_phnum)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, 0);

	if (eo->ehdr.e_phnum == UT16_MAX) {
		// sh_info member of the initial entry in section header table.
		if (eo->ehdr.e_shnum > 0) {
			Elf_(Shdr) shdr = {0};
			int r = r_buf_read_at (eo->b, eo->ehdr.e_shoff, (ut8 *)&shdr, sizeof (shdr));
			if (r != sizeof (shdr)) {
				return 0;
			}
#if R_BIN_ELF64
			ut64 num = r_read_ble64 (&shdr.sh_info, eo->endian);
#else
			ut64 num = (ut64)r_read_ble32 (&shdr.sh_info, eo->endian);
#endif
			if ((int) num < 1) {
				return UT16_MAX;
			}
			return num;
		}
	}
	return eo->ehdr.e_phnum & UT16_MAX;
}

static bool read_phdr(ELFOBJ *eo) {
	const ut64 phnum = Elf_(get_phnum) (eo);

	/*
	 * Here is the where all the fun starts.
	 * Linux kernel during 2005-2022 calculates phdr offset wrongly
	 * adding it to the load address (va of the LOAD0).
	 * See `fs/binfmt_elf.c` file, search for this line:
	 *    NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	 *
	 * We solve this by first looking up one of the PT_LOAD segments.
	 * If we can't find it, we need to fix the phdr offset.
	 */
	const size_t _128K = 1024 * 128;
	// Enable this hack only for the X86 64bit ELFs
	const bool linux_kern_hack = r_buf_size (eo->b) > _128K &&
		(eo->ehdr.e_machine == EM_X86_64 || eo->ehdr.e_machine == EM_386 || eo->ehdr.e_machine == EM_IAMCU);
	if (linux_kern_hack) {
		bool load_header_found = false;

		int i;
#if 0
		if (phnum > UT16_MAX) {
			return false;
		}
#endif
		for (i = 0; i < phnum; i++) {
			ut8 phdr[sizeof (Elf_(Phdr))] = {0};
			const size_t rsize = eo->ehdr.e_phoff + i * sizeof (phdr);
			int len = r_buf_read_at (eo->b, rsize, phdr, sizeof (phdr));
			if (len != sizeof (phdr)) {
				R_LOG_DEBUG ("read (phdr)");
				return false;
			}

			int j = 0;
			Elf_(Word) p_type = READ32 (phdr, j);
			if (p_type == PT_LOAD) {
				load_header_found = true;
				break;
			}
		}
		if (!load_header_found) {
			const ut64 load_addr = Elf_(get_baddr) (eo);
			eo->ehdr.e_phoff = Elf_(v2p) (eo, load_addr + eo->ehdr.e_phoff);
		}
	}

#if R_BIN_ELF64
	const bool is_elf64 = true;
#else
	const bool is_elf64 = false;
#endif
	int i;
#if 0
	if (phnum > UT16_MAX) {
		return false;
	}
#endif
	for (i = 0; i < phnum; i++) {
		ut8 phdr[sizeof (Elf_(Phdr))] = {0};
		const size_t rsize = eo->ehdr.e_phoff + i * sizeof (Elf_(Phdr));
		int len = r_buf_read_at (eo->b, rsize, phdr, sizeof (phdr));
		if (len != sizeof (phdr)) {
			R_LOG_DEBUG ("read (phdr)");
			return false;
		}

		int j = 0;
		eo->phdr[i].p_type = READ32 (phdr, j);
		if (is_elf64) {
			eo->phdr[i].p_flags = READ32 (phdr, j);
		}
		eo->phdr[i].p_offset = R_BIN_ELF_READWORD (phdr, j);
		eo->phdr[i].p_vaddr = R_BIN_ELF_READWORD (phdr, j);
		eo->phdr[i].p_paddr = R_BIN_ELF_READWORD (phdr, j);
		eo->phdr[i].p_filesz = R_BIN_ELF_READWORD (phdr, j);
		eo->phdr[i].p_memsz = R_BIN_ELF_READWORD (phdr, j);
		if (!is_elf64) {
			eo->phdr[i].p_flags = READ32 (phdr, j);
		//	eo->phdr[i].p_flags |= 1; tiny.elf needs this somehow :? LOAD0 is always +x for linux?
		}
		eo->phdr[i].p_align = R_BIN_ELF_READWORD (phdr, j);
	}

	return true;
}

static int init_phdr(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo && !eo->phdr, false);

	if (!eo->ehdr.e_phnum) {
		return false;
	}

	ut32 phdr_size;
	if (!UT32_MUL (&phdr_size, (ut32)eo->ehdr.e_phnum, sizeof (Elf_(Phdr)))) {
		return false;
	}
	if (!phdr_size || phdr_size > (ut32) eo->size) {
		return false;
	}
	if (eo->ehdr.e_phoff > eo->size || eo->ehdr.e_phoff + phdr_size > eo->size) {
		return false;
	}
	ut64 phnum = Elf_(get_phnum) (eo);
#if 0
	if (phnum > SIZE_MAX / sizeof (Elf_(Phdr))) {
		return false;
	}
#endif
	if (!(eo->phdr = R_NEWS0 (Elf_(Phdr), phnum))) {
		r_sys_perror ("malloc (phdr)");
		return false;
	}

	if (!read_phdr (eo)) {
		R_FREE (eo->phdr);
		return false;
	}

	sdb_num_set (eo->kv, "elf_phdr.offset", eo->ehdr.e_phoff, 0);
	sdb_num_set (eo->kv, "elf_phdr.size", sizeof (Elf_(Phdr)), 0);
	sdb_set (eo->kv, "elf_p_type.cparse", "enum elf_p_type {PT_NULL=0,PT_LOAD=1,PT_DYNAMIC=2,"
		"PT_INTERP=3,PT_NOTE=4,PT_SHLIB=5,PT_PHDR=6,PT_LOOS=0x60000000,"
		"PT_HIOS=0x6fffffff,PT_LOPROC=0x70000000,PT_HIPROC=0x7fffffff};",
		0);
	sdb_set (eo->kv, "elf_p_flags.cparse", "enum elf_p_flags {PF_None=0,PF_Exec=1,"
			"PF_Write=2,PF_Write_Exec=3,PF_Read=4,PF_Read_Exec=5,PF_Read_Write=6,"
			"PF_Read_Write_Exec=7};", 0);
#if R_BIN_ELF64
	sdb_set (eo->kv, "elf_phdr.format", "[4]E[4]Eqqqqqq (elf_p_type)type (elf_p_flags)flags"
			" offset vaddr paddr filesz memsz align", 0);
#else
	sdb_set (eo->kv, "elf_phdr.format", "[4]Exxxxx[4]Ex (elf_p_type)type offset vaddr paddr"
			" filesz memsz (elf_p_flags)flags align", 0);
#endif
	return true;
	// Usage example:
	// > td `k bin/cur/info/elf_p_type.cparse`; td `k bin/cur/info/elf_p_flags.cparse`
	// > pf `k bin/cur/info/elf_phdr.format` @ `k bin/cur/info/elf_phdr.offset`
}

static int init_shdr(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo && !eo->shdr, false);

	ut32 shdr_size;
	if (!UT32_MUL (&shdr_size, eo->ehdr.e_shnum, sizeof (Elf_(Shdr)))) {
		return false;
	}
	if (shdr_size < 1 || shdr_size > eo->size) {
		return false;
	}
	if (eo->ehdr.e_shoff > eo->size || eo->ehdr.e_shoff + shdr_size > eo->size) {
		return false;
	}
	if (!(eo->shdr = R_NEWS0 (Elf_(Shdr), eo->ehdr.e_shnum))) {
		r_sys_perror ("malloc (shdr)");
		return false;
	}
	sdb_num_set (eo->kv, "elf_shdr.offset", eo->ehdr.e_shoff, 0);
	sdb_num_set (eo->kv, "elf_shdr.size", sizeof (Elf_(Shdr)), 0);
	sdb_set (eo->kv, "elf_s_type.cparse", "enum elf_s_type {SHT_NULL=0,SHT_PROGBITS=1,"
			"SHT_SYMTAB=2,SHT_STRTAB=3,SHT_RELA=4,SHT_HASH=5,SHT_DYNAMIC=6,SHT_NOTE=7,"
			"SHT_NOBITS=8,SHT_REL=9,SHT_SHLIB=10,SHT_DYNSYM=11,SHT_LOOS=0x60000000,"
			"SHT_HIOS=0x6fffffff,SHT_LOPROC=0x70000000,SHT_HIPROC=0x7fffffff};", 0);

	ut8 shdr[sizeof (Elf_(Shdr))] = {0};
	size_t i;
	for (i = 0; i < eo->ehdr.e_shnum; i++) {
		size_t j = 0;
		size_t len = r_buf_read_at (eo->b, eo->ehdr.e_shoff + i * sizeof (Elf_(Shdr)), shdr, sizeof (Elf_(Shdr)));
		if (len != sizeof (Elf_(Shdr))) {
			R_LOG_DEBUG ("read (shdr) at 0x%" PFMT64x, (ut64) eo->ehdr.e_shoff);
			R_FREE (eo->shdr);
			return false;
		}
		eo->shdr[i].sh_name = READ32 (shdr, j);
		eo->shdr[i].sh_type = READ32 (shdr, j);
		eo->shdr[i].sh_flags = R_BIN_ELF_READWORD (shdr, j);
		eo->shdr[i].sh_addr = R_BIN_ELF_READWORD (shdr, j);
		eo->shdr[i].sh_offset = R_BIN_ELF_READWORD (shdr, j);
		eo->shdr[i].sh_size = R_BIN_ELF_READWORD (shdr, j);
		eo->shdr[i].sh_link = READ32 (shdr, j);
		eo->shdr[i].sh_info = READ32 (shdr, j);
		eo->shdr[i].sh_addralign = R_BIN_ELF_READWORD (shdr, j);
		eo->shdr[i].sh_entsize = R_BIN_ELF_READWORD (shdr, j);
	}

#if R_BIN_ELF64
	sdb_set (eo->kv, "elf_s_flags_64.cparse", "enum elf_s_flags_64 {SF64_None=0,SF64_Exec=1,"
			"SF64_Alloc=2,SF64_Alloc_Exec=3,SF64_Write=4,SF64_Write_Exec=5,"
			"SF64_Write_Alloc=6,SF64_Write_Alloc_Exec=7};", 0);
	sdb_set (eo->kv, "elf_shdr.format", "x[4]E[8]Eqqqxxqq name (elf_s_type)type"
			" (elf_s_flags_64)flags addr offset size link info addralign entsize", 0);
#else
	sdb_set (eo->kv, "elf_s_flags_32.cparse", "enum elf_s_flags_32 {SF32_None=0,SF32_Exec=1,"
			"SF32_Alloc=2,SF32_Alloc_Exec=3,SF32_Write=4,SF32_Write_Exec=5,"
			"SF32_Write_Alloc=6,SF32_Write_Alloc_Exec=7};", 0);
	sdb_set (eo->kv, "elf_shdr.format", "x[4]E[4]Exxxxxxx name (elf_s_type)type"
			" (elf_s_flags_32)flags addr offset size link info addralign entsize", 0);
#endif
	return true;
	// Usage example:
	// > td `k bin/cur/info/elf_s_type.cparse`; td `k bin/cur/info/elf_s_flags_64.cparse`
	// > pf `k bin/cur/info/elf_shdr.format` @ `k bin/cur/info/elf_shdr.offset`
}

static bool is_shidx_valid(ELFOBJ *eo, Elf_(Half) value) {
	return value < eo->ehdr.e_shnum && !R_BETWEEN (SHN_LORESERVE, value, SHN_HIRESERVE);
}

static bool init_strtab(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (!eo->strtab, false);

	if (!eo->shdr) {
		return false;
	}

	Elf_(Half) shstrndx = eo->ehdr.e_shstrndx;
	if (shstrndx != SHN_UNDEF && !is_shidx_valid (eo, shstrndx)) {
		R_LOG_DEBUG ("invalid section header index");
		return false;
	}

	// sh_size must not be zero, to avoid bugs with malloc()
	if (!eo->shdr[shstrndx].sh_size) {
		R_LOG_DEBUG ("empty section header size cant be zero");
		return false;
	}
	eo->shstrtab_section = eo->strtab_section = &eo->shdr[shstrndx];
	eo->shstrtab_size = eo->shstrtab_section->sh_size;
	if (eo->shstrtab_size > eo->size) {
		R_LOG_DEBUG ("sh string tab section is larger than the whole file");
		return false;
	}
	if (eo->shstrtab_section->sh_offset > eo->size) {
		R_LOG_DEBUG ("sh string tab section is larger than the whole file");
		return false;
	}
	if (eo->shstrtab_section->sh_offset + eo->shstrtab_section->sh_size > eo->size) {
		return false;
	}

	if (!(eo->shstrtab = calloc (1, eo->shstrtab_size + 1))) {
		r_sys_perror ("malloc");
		eo->shstrtab = NULL;
		return false;
	}
	int res = r_buf_read_at (eo->b, eo->shstrtab_section->sh_offset, (ut8*)eo->shstrtab,
		eo->shstrtab_section->sh_size);
	if (res != eo->shstrtab_section->sh_size) {
		R_LOG_DEBUG ("read (shstrtab) at 0x%" PFMT64x, (ut64) eo->shstrtab_section->sh_offset);
		R_FREE (eo->shstrtab);
		return false;
	}
	eo->shstrtab[eo->shstrtab_section->sh_size] = '\0';

	sdb_num_set (eo->kv, "elf_shstrtab.offset", eo->shstrtab_section->sh_offset, 0);
	sdb_num_set (eo->kv, "elf_shstrtab.size", eo->shstrtab_section->sh_size, 0);

	return true;
}

static Elf_(Phdr) *get_dynamic_segment(ELFOBJ *eo) {
	int i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		if (eo->phdr[i].p_type != PT_DYNAMIC) {
			continue;
		}

		if (eo->phdr[i].p_filesz > eo->size ||
			eo->phdr[i].p_offset > eo->size ||
			eo->phdr[i].p_offset + sizeof (Elf_(Dyn)) > eo->size) {
			return NULL;
		}

		return &eo->phdr[i];
	}

	return NULL;
}

static void set_default_value_dynamic_info(ELFOBJ *eo) {
	eo->dyn_info.dt_pltrelsz = 0;
	eo->dyn_info.dt_hash = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_strtab = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_symtab = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_rela = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_relr = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_relasz = 0;
	eo->dyn_info.dt_relaent = 0;
	eo->dyn_info.dt_relrsz = 0;
	eo->dyn_info.dt_relrent = 0;
	eo->dyn_info.dt_strsz = 0;
	eo->dyn_info.dt_syment = 0;
	eo->dyn_info.dt_rel = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_relsz = 0;
	eo->dyn_info.dt_relent = 0;
	eo->dyn_info.dt_pltrel = R_BIN_ELF_XWORD_MAX;
	eo->dyn_info.dt_jmprel = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_pltgot = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_mips_pltgot = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_crel = R_BIN_ELF_ADDR_MAX;
	eo->dyn_info.dt_bind_now = false;
	eo->dyn_info.dt_flags = R_BIN_ELF_XWORD_MAX;
	eo->dyn_info.dt_flags_1 = R_BIN_ELF_XWORD_MAX;
	eo->dyn_info.dt_rpath = R_BIN_ELF_XWORD_MAX;
	eo->dyn_info.dt_runpath = R_BIN_ELF_XWORD_MAX;
	r_vector_init (&eo->dyn_info.dt_needed, sizeof (Elf_(Off)), NULL, NULL);
}

static inline size_t get_maximum_number_of_dynamic_entries(ut64 dyn_size) {
	return dyn_size / sizeof (Elf_(Dyn));
}

static bool fill_dynamic_entry(ELFOBJ *eo, ut64 entry_offset, Elf_(Dyn) *d) {
	ut8 sdyn[sizeof (Elf_(Dyn))] = {0};
	int len = r_buf_read_at (eo->b, entry_offset, sdyn, sizeof (sdyn));
	if (len != sizeof (sdyn)) {
		return false;
	}
	int j = 0; // required because its used in a macro
	d->d_tag = R_BIN_ELF_READWORD (sdyn, j);
	d->d_un.d_ptr = R_BIN_ELF_READWORD (sdyn, j);
	return true;
}

static void fill_dynamic_entries(ELFOBJ *eo, ut64 loaded_offset, ut64 dyn_size) {
	Elf_(Dyn) d = {0};
	size_t i;
	size_t number_of_entries = get_maximum_number_of_dynamic_entries(dyn_size);

	for (i = 0; i < number_of_entries; i++) {
		ut64 entry_offset = loaded_offset + i * sizeof (Elf_(Dyn));
		if (!fill_dynamic_entry (eo, entry_offset, &d)) {
			break;
		}

		switch (d.d_tag) {
		case DT_NULL:
			break;
		case DT_PLTRELSZ:
			eo->dyn_info.dt_pltrelsz = d.d_un.d_val;
			break;
		case DT_PLTGOT:
			eo->dyn_info.dt_pltgot = d.d_un.d_ptr;
			break;
		case DT_HASH:
			eo->dyn_info.dt_hash = d.d_un.d_ptr;
			break;
		case DT_STRTAB:
			eo->dyn_info.dt_strtab = d.d_un.d_ptr;
			break;
		case DT_SYMTAB:
			eo->dyn_info.dt_symtab = d.d_un.d_ptr;
			break;
		case DT_RELA:
			eo->dyn_info.dt_rela = d.d_un.d_ptr;
			break;
		case DT_RELR:
			eo->dyn_info.dt_relr = d.d_un.d_ptr;
			break;
		case DT_RELRSZ:
			eo->dyn_info.dt_relrsz = d.d_un.d_val;
			break;
		case DT_RELRENT:
			eo->dyn_info.dt_relrent = d.d_un.d_val;
			break;
		case DT_RELASZ:
			eo->dyn_info.dt_relasz = d.d_un.d_val;
			break;
		case DT_RELAENT:
			eo->dyn_info.dt_relaent = d.d_un.d_val;
			break;
		case DT_STRSZ:
			eo->dyn_info.dt_strsz = d.d_un.d_val;
			break;
		case DT_SYMENT:
			eo->dyn_info.dt_syment = d.d_un.d_val;
			break;
		case DT_REL:
			eo->dyn_info.dt_rel = d.d_un.d_ptr;
			break;
		case DT_RELSZ:
			eo->dyn_info.dt_relsz = d.d_un.d_val;
			break;
		case DT_RELENT:
			eo->dyn_info.dt_relent = d.d_un.d_val;
			break;
		case DT_PLTREL:
			eo->dyn_info.dt_pltrel = d.d_un.d_val;
			break;
		case DT_JMPREL:
			eo->dyn_info.dt_jmprel = d.d_un.d_ptr;
			break;
		case DT_MIPS_PLTGOT:
			eo->dyn_info.dt_mips_pltgot = d.d_un.d_ptr;
			break;
		case DT_CREL:
			eo->dyn_info.dt_crel = d.d_un.d_ptr;
			break;
		case DT_BIND_NOW:
			eo->dyn_info.dt_bind_now = true;
			break;
		case DT_FLAGS:
			eo->dyn_info.dt_flags = d.d_un.d_val;
			break;
		case DT_FLAGS_1:
			eo->dyn_info.dt_flags_1 = d.d_un.d_val;
			break;
		case DT_RPATH:
			eo->dyn_info.dt_rpath = d.d_un.d_val;
			break;
		case DT_RUNPATH:
			eo->dyn_info.dt_runpath = d.d_un.d_val;
			break;
		case DT_NEEDED:
			r_vector_push (&eo->dyn_info.dt_needed, &d.d_un.d_val);
			break;
		case DT_INIT:
		case DT_FINI:
		case DT_DEBUG:
		case DT_INIT_ARRAY:
		case DT_FINI_ARRAY:
		case DT_INIT_ARRAYSZ:
		case DT_FINI_ARRAYSZ:
		case DT_PREINIT_ARRAY:
		case DT_PREINIT_ARRAYSZ:
		case DT_SONAME:
		case DT_GNU_HASH:
			// common dynamic entries in ELF, but we don't need to
			// do anything with them.
			break;
		default:
			if (d.d_tag >= DT_VERSYM && d.d_tag <= DT_VERNEEDNUM) {
				eo->version_info[DT_VERSIONTAGIDX (d.d_tag)] = d.d_un.d_val;
			} else {
				R_LOG_DEBUG ("Dynamic tag %" PFMT64d " not handled", (ut64) d.d_tag);
			}
			break;
		}
		if (d.d_tag == DT_NULL) {
			break;
		}
	}
}

static int init_dynamic_section(ELFOBJ *eo) {
	set_default_value_dynamic_info(eo);

	R_RETURN_VAL_IF_FAIL (eo, false);
	if (!eo->phdr || !eo->ehdr.e_phnum) {
		return false;
	}

	Elf_(Phdr) *dyn_phdr = get_dynamic_segment (eo);
	if (!dyn_phdr) {
		return false;
	}

  ut64 loaded_offset = Elf_(v2p_new) (eo, dyn_phdr->p_vaddr);
  if (loaded_offset == UT64_MAX) {
	  return false;
  }

	ut64 dyn_size = dyn_phdr->p_filesz;

	if (!dyn_size || loaded_offset + dyn_size > eo->size) {
		return false;
	}

	fill_dynamic_entries (eo, loaded_offset, dyn_size);

	ut64 strtabaddr = 0;
	if (eo->dyn_info.dt_strtab != R_BIN_ELF_ADDR_MAX) {
		strtabaddr = Elf_(v2p_new) (eo, eo->dyn_info.dt_strtab);
	}

	size_t strsize = 0;
	if (eo->dyn_info.dt_strsz > 0) {
		strsize = eo->dyn_info.dt_strsz;
	}

	if (strtabaddr == UT64_MAX || strtabaddr > eo->size || strsize > ST32_MAX ||
		!strsize || strsize > eo->size || strtabaddr + strsize > eo->size) {
		if (!strtabaddr) {
			R_LOG_DEBUG ("DT_STRTAB not found or invalid");
		}
		return false;
	}

	char *strtab = calloc (1, strsize + 1);
	if (!strtab) {
		return false;
	}

	int r = r_buf_read_at (eo->b, strtabaddr, (ut8 *)strtab, strsize);
	if (r != strsize) {
		free (strtab);
		return false;
	}

	eo->strtab = strtab;
	eo->strtab_size = strsize;
	sdb_num_set (eo->kv, "elf_strtab.offset", strtabaddr, 0);
	sdb_num_set (eo->kv, "elf_strtab.size", strsize, 0);
	return true;
}

// TODO: a hashtable is slower than a vector, using memoization is faster and takes less memory
static RBinElfSection* get_section_by_name(ELFOBJ *eo, const char *name) {
	if (eo->sections_loaded) {
		if (eo->last_section && !strcmp (name, eo->last_section->name)) {
			return eo->last_section;
		}
		RBinElfSection *sec;
#if R2_590
		R_VEC_FOREACH (eo->g_sections_vec, sec) {
#else
		r_vector_foreach (&eo->g_sections, sec) {
#endif
			if (!strcmp (sec->name, name)) {
				eo->last_section = sec;
				return sec;
			}
		}
	}
	return NULL;
}

static char *get_ver_flags(ut32 flags) {
	if (flags == 0) {
		return strdup ("none");
	}
	RStrBuf *sb = r_strbuf_new (flags & VER_FLG_BASE ? "BASE" : "");
	if (flags & VER_FLG_WEAK) {
		r_strbuf_appendf (sb, "%sWEAK", r_strbuf_length (sb) > 0?" | ": "" );
	}
	if (flags & ~(VER_FLG_BASE | VER_FLG_WEAK)) {
		r_strbuf_appendf (sb, "%s<unknown>", r_strbuf_length (sb) > 0?" | ": "" );
	}
	return r_strbuf_drain (sb);
}

typedef struct e_data_state_t {
	Sdb *sdb;
	Elf_(Shdr) *shdr;
	const ut64 num_entries;
} EDataState;

static inline ut16 *_parse_edata(ELFOBJ *eo, EDataState *edata_state) {
	Sdb *sdb = edata_state->sdb;
	Elf_(Shdr) *shdr = edata_state->shdr;
	const ut64 num_entries = edata_state->num_entries;
	ut8 *edata = calloc (R_MAX (1, num_entries), 2 * sizeof (ut8));
	if (!edata) {
		return NULL;
	}

	ut16 *data = calloc (R_MAX (1, num_entries), sizeof (ut16));
	if (!data) {
		free (edata);
		return NULL;
	}

	ut64 off = Elf_(v2p) (eo, eo->version_info[DT_VERSIONTAGIDX (DT_VERSYM)]);
	const char *section_name = "";
	if (eo->shstrtab && shdr->sh_name < eo->shstrtab_size) {
		section_name = &eo->shstrtab[shdr->sh_name];
	}

	Elf_(Shdr) *link_shdr = &eo->shdr[shdr->sh_link];
	const char *link_section_name = "";
	if (eo->shstrtab && link_shdr->sh_name < eo->shstrtab_size) {
		link_section_name = &eo->shstrtab[link_shdr->sh_name];
	}
	edata[0] = 0;
	(void)r_buf_read_at (eo->b, off, edata, sizeof (ut16) * num_entries);
	sdb_set (sdb, "section_name", section_name, 0);
	sdb_num_set (sdb, "num_entries", num_entries, 0);
	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set (sdb, "link", shdr->sh_link, 0);
	sdb_set (sdb, "link_section_name", link_section_name, 0);

	size_t i = num_entries;
	while (i--) {
		data[i] = r_read_ble16 (&edata[i * sizeof (ut16)], eo->endian);
	}

	free (edata);
	return data;
}

typedef struct parse_vernaux_state_t {
	int i;
	int j;
	Sdb *sdb;
	ut16 *data;
	const char *tmp_val;
	const char *key;
	bool check_def;  // used as output parameter
} ParseVernauxState;

static inline bool _maybe_parse_aux_ver_needed_info(ELFOBJ *eo, ParseVernauxState *state) {
	if (!eo->version_info[DT_VERSIONTAGIDX (DT_VERNEED)]) {
		return true;
	}

	Elf_(Verneed) vn;
	ut64 offset = Elf_(v2p) (eo, eo->version_info[DT_VERSIONTAGIDX (DT_VERNEED)]);
	do {
		if (offset > eo->size || offset + sizeof (vn) > eo->size) {
			return false;
		}

		ut8 svn[sizeof (Elf_(Verneed))] = {0};
		if (r_buf_read_at (eo->b, offset, svn, sizeof (svn)) != sizeof (svn)) {
			R_LOG_DEBUG ("Cannot read Verneed for Versym");
			return false;
		}

		int k = 0;
		vn.vn_version = READ16 (svn, k);
		vn.vn_cnt = READ16 (svn, k);
		vn.vn_file = READ32 (svn, k);
		vn.vn_aux = READ32 (svn, k);
		vn.vn_next = READ32 (svn, k);

		const int i = state->i;
		const int j = state->j;
		const ut16 *data = state->data;

		Elf_(Vernaux) vna;
		ut64 a_off = offset + vn.vn_aux;
		do {
			if (a_off > eo->size || a_off + sizeof (vna) > eo->size) {
				return false;
			}

			ut8 svna[sizeof (Elf_(Vernaux))] = {0};
			if (r_buf_read_at (eo->b, a_off, svna, sizeof (svna)) != sizeof (svna)) {
				R_LOG_DEBUG ("Cannot read Vernaux for Versym");
				return false;
			}
			k = 0;
			vna.vna_hash = READ32 (svna, k);
			vna.vna_flags = READ16 (svna, k);
			vna.vna_other = READ16 (svna, k);
			vna.vna_name = READ32 (svna, k);
			vna.vna_next = READ32 (svna, k);
			a_off += vna.vna_next;
		} while (vna.vna_other != data[i + j] && vna.vna_next != 0);

		if (vna.vna_other == data[i + j]) {
			if (vna.vna_name > eo->strtab_size) {
				return false;
			}
			char *val = r_str_newf ("%s(%s)", state->tmp_val, eo->strtab + vna.vna_name);
			sdb_set (state->sdb, state->key, val, 0);
			free (val);
			state->check_def = false;
			return true;
		}
		offset += vn.vn_next;
	} while (vn.vn_next);

	return true;
}

typedef struct parse_ver_def_state_t {
	int i;
	int j;
	Sdb *sdb;
	const char *key;
	const char *tmp_val;
	ut16 *data;
} ParseVerDefState;

static inline bool _maybe_parse_version_definition_info(ELFOBJ *eo, ParseVerDefState *state) {
	const int i = state->i;
	const int j = state->j;
	const ut16 *data = state->data;
	const ut64 vinfoaddr = eo->version_info[DT_VERSIONTAGIDX (DT_VERDEF)];
	if (!(data[i + j] != 0x8001 && vinfoaddr)) {
		return true;
	}

	Elf_(Verdef) vd;
	ut8 svd[sizeof (Elf_(Verdef))] = {0};
	ut64 offset = Elf_(v2p) (eo, vinfoaddr);
	if (offset > eo->size || offset + sizeof (vd) > eo->size) {
		return false;
	}

	do {
		if (r_buf_read_at (eo->b, offset, svd, sizeof (svd)) != sizeof (svd)) {
			R_LOG_DEBUG ("Cannot read Verdef for Versym");
			return false;
		}

		int k = 0;
		vd.vd_version = READ16 (svd, k);
		vd.vd_flags = READ16 (svd, k);
		vd.vd_ndx = READ16 (svd, k);
		vd.vd_cnt = READ16 (svd, k);
		vd.vd_hash = READ32 (svd, k);
		vd.vd_aux = READ32 (svd, k);
		vd.vd_next = READ32 (svd, k);
		offset += vd.vd_next;
	} while (vd.vd_ndx != (data[i + j] & 0x7FFF) && vd.vd_next != 0);

	if (vd.vd_ndx == (data[i + j] & 0x7FFF)) {
		Elf_(Verdaux) vda;
		ut8 svda[sizeof (Elf_(Verdaux))] = {0};
		ut64 off_vda = offset - vd.vd_next + vd.vd_aux;
		if (off_vda > eo->size || off_vda + sizeof (vda) > eo->size) {
			return false;
		}

		if (r_buf_read_at (eo->b, off_vda, svda, sizeof (svda)) != sizeof (svda)) {
			R_LOG_DEBUG ("Cannot read Verdaux for Versym");
			return false;
		}

		int k = 0;
		vda.vda_name = READ32 (svda, k);
		vda.vda_next = READ32 (svda, k);
		if (vda.vda_name > eo->strtab_size) {
			return false;
		}

		const char *name = eo->strtab + vda.vda_name;
		if (name) {
			char *fname = r_str_newf ("%s(%s%-*s)", state->tmp_val, name, (int)(12 - strlen (name)),")");
			sdb_set (state->sdb, state->key, fname, 0);
			free (fname);
		}
	}

	return true;
}

static Sdb *store_versioninfo_gnu_versym(ELFOBJ *eo, Elf_(Shdr) *shdr, int sz) {
	if (!eo->version_info[DT_VERSIONTAGIDX (DT_VERSYM)]) {
		return NULL;
	}
	if (shdr->sh_link >= eo->ehdr.e_shnum) {
		return NULL;
	}

	Sdb *sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}

	const ut64 num_entries = sz / sizeof (Elf_(Versym));
	EDataState edata_state = { .shdr = shdr, .sdb = sdb, .num_entries = num_entries };
	ut16* data = _parse_edata (eo, &edata_state);
	if (!data) {
		sdb_free (sdb);
		return NULL;
	}

	char *tmp_val = NULL;
	size_t i;
	for (i = 0; i < num_entries; i += 4) {
		size_t j;
		for (j = 0; j < 4 && i + j < num_entries; j++) {
			char key[32] = {0};
			snprintf (key, sizeof (key), "entry%d", (int)(i + j));
			switch (data[i + j]) {
			case 0:
				sdb_set (sdb, key, "0 (*local*)", 0);
				break;
			case 1:
				sdb_set (sdb, key, "1 (*global*)", 0);
				break;
			default:
				free (tmp_val);
				tmp_val = r_str_newf ("%x ", data[i + j] & 0x7FFF);
				ParseVernauxState vernaux_state = {
					.i = i,
					.j = j,
					.sdb = sdb,
					.data = data,
					.tmp_val = tmp_val,
					.key = key,
					.check_def = true,
				};
				if (!_maybe_parse_aux_ver_needed_info (eo, &vernaux_state)) {
					free (tmp_val);
					free (data);
					return sdb;
				}

				ParseVerDefState parse_vd_state = { .i = i, .j = j, .sdb = sdb, .key = key, .tmp_val = tmp_val, .data = data };
				if (vernaux_state.check_def && !_maybe_parse_version_definition_info (eo, &parse_vd_state)) {
					free (tmp_val);
					free (data);
					return sdb;
				}
			}
		}
		R_FREE (tmp_val);
	}

	free (data);
	return sdb;
}

typedef struct process_verdef_state_t {
	Elf_(Half) vd_cnt;
	int i;
	const char *const end;
	Elf_(Shdr) *shdr;
	Elf_(Verdaux) *aux;
	Elf_(Verdef) *verdef;
	const char *vstart;
	size_t vstart_off;
	Sdb *sdb_verdef;
} ProcessVerdefState;

static inline bool _process_verdef(ELFOBJ *eo, ProcessVerdefState *state) {
	const char *vstart = state->vstart;
	size_t vstart_off = state->vstart_off;
	Elf_(Shdr) *shdr = state->shdr;
	Elf_(Verdaux) *aux = state->aux;
	int isum = state->i + state->verdef->vd_aux;

	int j;
	for (j = 1; j < state->vd_cnt; j++) {
		if (shdr->sh_size - vstart_off < aux->vda_next) {
			return false;
		}

		isum += aux->vda_next;
		vstart += aux->vda_next;
		vstart_off += aux->vda_next;
		if (vstart > state->end || shdr->sh_size - sizeof (Elf_(Verdaux)) < vstart_off) {
			return false;
		}

		int k = 0;
		aux->vda_name = READ32 (vstart, k);
		aux->vda_next = READ32 (vstart, k);
		if (aux->vda_name > eo->dynstr_size) {
			return false;
		}

		Sdb *sdb_parent = sdb_new0 ();
		if (!sdb_parent) {
			return false;
		}

		sdb_num_set (sdb_parent, "idx", isum, 0);
		sdb_num_set (sdb_parent, "parent", j, 0);
		sdb_set (sdb_parent, "vda_name", &eo->dynstr[aux->vda_name], 0);
		char key[32] = {0};
		snprintf (key, sizeof (key), "parent%d", j - 1);
		sdb_ns_set (state->sdb_verdef, key, sdb_parent);
	}

	return true;
}

typedef struct process_verdefs_state_t {
	Sdb *sdb;
	Elf_(Verdef) *defs;
	Elf_(Shdr) *shdr;
	size_t shsize;
} ProcessVerdefsState;

static inline bool _process_verdefs(ELFOBJ *eo, ProcessVerdefsState *state) {
	Elf_(Shdr) *shdr = state->shdr;
	char *end = (char *)state->defs + state->shsize; //& shdr->sh_size;
	ut32 cnt;
	size_t i;
	for (cnt = 0, i = 0; cnt < shdr->sh_info && i < shdr->sh_size; cnt++) {
		char *vstart = (char*)state->defs + i;

		if (vstart + sizeof (Elf_(Verdef)) > end) {
			break;
		}

		ut8 dfs[sizeof (Elf_(Verdef))] = {0};
		r_buf_read_at (eo->b, shdr->sh_offset + i, dfs, sizeof (dfs));

		int j = 0;
		Elf_(Verdef) *verdef = (Elf_(Verdef)*)vstart;
		verdef->vd_version = READ16 (dfs, j);
		verdef->vd_flags = READ16 (dfs, j);
		verdef->vd_ndx = READ16 (dfs, j);
		verdef->vd_cnt = READ16 (dfs, j);
		verdef->vd_hash = READ32 (dfs, j);
		verdef->vd_aux = READ32 (dfs, j);
		verdef->vd_next = READ32 (dfs, j);

		int vdaux = verdef->vd_aux;
		size_t vstart_off = i;
		if (vdaux < 1 || shdr->sh_size - vstart_off < vdaux) {
			return false;
		}

		vstart += vdaux;
		vstart_off += vdaux;
		if (vstart > end || shdr->sh_size - sizeof (Elf_(Verdaux)) < vstart_off) {
			return false;
		}

		j = 0;
		Elf_(Verdaux) aux = {0};
		aux.vda_name = READ32 (vstart, j);
		aux.vda_next = READ32 (vstart, j);

		if (aux.vda_name > eo->dynstr_size) {
			return false;
		}

		Sdb *sdb_verdef = sdb_new0 ();
		if (!sdb_verdef) {
			return false;
		}

		sdb_num_set (sdb_verdef, "idx", i, 0);
		sdb_num_set (sdb_verdef, "vd_version", verdef->vd_version, 0);
		sdb_num_set (sdb_verdef, "vd_ndx", verdef->vd_ndx, 0);
		sdb_num_set (sdb_verdef, "vd_cnt", verdef->vd_cnt, 0);
		sdb_set (sdb_verdef, "vda_name", &eo->dynstr[aux.vda_name], 0);
		sdb_set_owned (sdb_verdef, "flags", get_ver_flags (verdef->vd_flags), 0);

		ProcessVerdefState verdef_state = {
			.i = i,
			.end = end,
			.vd_cnt = verdef->vd_cnt,
			.aux = &aux,
			.shdr = shdr,
			.verdef = verdef,
			.vstart = vstart,
			.vstart_off = vstart_off,
			.sdb_verdef = sdb_verdef,
		};
		if (!_process_verdef (eo, &verdef_state)) {
			sdb_free (sdb_verdef);
			return false;
		}

		if (!verdef->vd_next || shdr->sh_size - i < verdef->vd_next) {
			sdb_free (sdb_verdef);
			return false;
		}

		if ((st32)verdef->vd_next < 1) {
			R_LOG_DEBUG ("Invalid vd_next in the ELF version");
			sdb_free (sdb_verdef);
			break;
		}

		char key[32] = {0};
		snprintf (key, sizeof (key), "verdef%u", cnt);
		sdb_ns_set (state->sdb, key, sdb_verdef);

		i += verdef->vd_next;
	}

	return true;
}

static Sdb *store_versioninfo_gnu_verdef(ELFOBJ *eo, Elf_(Shdr) *shdr, int sz) {
	if (shdr->sh_link >= eo->ehdr.e_shnum) {
		return false;
	}
	if (shdr->sh_size < sizeof (Elf_(Verdef)) || shdr->sh_size < sizeof (Elf_(Verdaux))) {
		return false;
	}
	if (shdr->sh_size > ST32_MAX) {
		return false;
	}

	Elf_(Verdef) *defs = calloc (shdr->sh_size, 1);
	if (!defs) {
		R_LOG_DEBUG ("Cannot allocate memory (Check Elf_(Verdef))");
		return false;
	}

	Sdb *sdb = sdb_new0 ();
	if (!sdb) {
		free (defs);
		return false;
	}

	size_t shsize = shdr->sh_size;
	if (shdr->sh_size > eo->size) {
		R_LOG_DEBUG ("Truncating shsize from %d to %d", (int)shdr->sh_size, (int)eo->size);
		shsize = eo->size > shdr->sh_offset ? eo->size - shdr->sh_offset : eo->size;
	}

	Elf_(Shdr) *link_shdr = &eo->shdr[shdr->sh_link];
	const char *link_section_name = link_shdr && eo->shstrtab && link_shdr->sh_name < eo->shstrtab_size
		? &eo->shstrtab[link_shdr->sh_name] : "";
	const char *section_name = eo->shstrtab && shdr->sh_name < eo->shstrtab_size
		? section_name = &eo->shstrtab[shdr->sh_name] : "";
	sdb_set (sdb, "section_name", section_name, 0);
	sdb_num_set (sdb, "entries", shdr->sh_info, 0);
	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set (sdb, "link", shdr->sh_link, 0);
	sdb_set (sdb, "link_section_name", link_section_name, 0);

	ProcessVerdefsState state = { .sdb = sdb, .shdr = shdr, .defs = defs, .shsize = shsize };
	if (!_process_verdefs (eo, &state)) {
		free (defs);
		sdb_free (sdb);
		return NULL;
	}

	free (defs);
	return sdb;
}

typedef struct process_verneed_state_t {
	Sdb *sdb;
	ut8* need;
	Elf_(Shdr) *shdr;
} ProcessVerneedState;

#define USE_SINGLE_SDB 0
#if USE_SINGLE_SDB
static inline bool _process_verneed_state(ELFOBJ *eo, ProcessVerneedState *state) {
	// R2_590
	// TODO: rewrite the function to use only one SDB instead of 65000 with mutated.
}
#else

static inline bool _process_verneed_state(ELFOBJ *eo, ProcessVerneedState *state) {
	Elf_(Shdr) *shdr = state->shdr;
	ut8* need = state->need;
	ut8 *end = need + shdr->sh_size;
	int cnt;
	ut64 i;
	ut8 *fend = need - shdr->sh_offset + eo->size;
	end = R_MIN (fend, end);

	char key[32] = {0};

	//XXX we should use DT_VERNEEDNUM instead of sh_info
	//TODO https://sourceware.org/ml/binutils/2014-11/msg00353.html
	for (i = 0, cnt = 0; cnt < shdr->sh_info; cnt++) {
		ut8 *vstart = need + i;
		Elf_(Verneed) vvn = {0};
		if (vstart + sizeof (Elf_(Verneed)) > end) {
			return false;
		}

		Elf_(Verneed) *entry = &vvn;
		Sdb *sdb_version = sdb_new0 ();
		if (!sdb_version) {
			sdb_free (sdb_version);
			return false;
		}

		int j = 0;
		vvn.vn_version = READ16 (vstart, j);
		vvn.vn_cnt = READ16 (vstart, j);
		vvn.vn_file = READ32 (vstart, j);
		vvn.vn_aux = READ32 (vstart, j);
		vvn.vn_next = READ32 (vstart, j);
		sdb_num_set (sdb_version, "vn_version", entry->vn_version, 0);
		sdb_num_set (sdb_version, "idx", i, 0);

		if (entry->vn_file > eo->dynstr_size) {
			sdb_free (sdb_version);
			return false;
		}

		const char *const file_name = r_str_ndup (&eo->dynstr[entry->vn_file], 16);
		sdb_set (sdb_version, "file_name", file_name, 0);
		free ((void*) file_name);

		sdb_num_set (sdb_version, "cnt", entry->vn_cnt, 0);
		st32 vnaux = entry->vn_aux;
		if (vnaux < 1) {
			sdb_free (sdb_version);
			return false;
		}

		vstart += vnaux;
		ut32 vn_cnt = entry->vn_cnt;
		int isum = i + entry->vn_aux;
		for (j = 0; j < vn_cnt && vstart + sizeof (Elf_(Vernaux)) <= end; j++) {
			Elf_(Vernaux) vaux = {0};
			Elf_(Vernaux) *aux = NULL;
			aux = (Elf_(Vernaux)*)&vaux;
			int k = 0;
			vaux.vna_hash = READ32 (vstart, k);
			vaux.vna_flags = READ16 (vstart, k);
			vaux.vna_other = READ16 (vstart, k);
			vaux.vna_name = READ32 (vstart, k);
			vaux.vna_next = READ32 (vstart, k);
			if (aux->vna_name > eo->dynstr_size) {
				sdb_free (sdb_version);
				return false;
			}
			// XXX this is awfully slow and unnecessary
			Sdb *sdb_vernaux = sdb_new0 ();
			if (!sdb_vernaux) {
				sdb_free (sdb_vernaux);
				sdb_free (sdb_version);
				return false;
			}

			sdb_num_set (sdb_vernaux, "idx", isum, 0);
			if (aux->vna_name > 0 && aux->vna_name + 8 < eo->dynstr_size) {
				char name [16];
				r_str_ncpy (name, eo->dynstr + aux->vna_name, sizeof (name));
				sdb_set (sdb_vernaux, "name", name, 0);
			}

			sdb_set_owned (sdb_vernaux, "flags", get_ver_flags (aux->vna_flags), 0);
			sdb_num_set (sdb_vernaux, "version", aux->vna_other, 0);
			isum += aux->vna_next;
			vstart += aux->vna_next;
			char key[32] = {0};
			snprintf (key, sizeof (key), "vernaux%d", j);
			sdb_ns_set (sdb_version, key, sdb_vernaux);
			if ((int)aux->vna_next < 1) {
				break;
			}
		}

		snprintf (key, sizeof (key), "version%d", cnt);
		sdb_ns_set (state->sdb, key, sdb_version);

		i += entry->vn_next;
		// break if entry->vn_next is 0, otherwise it will iterate infinitely
		if (!entry->vn_next) {
			break;
		}
	}

	return true;
}
#endif

static Sdb *store_versioninfo_gnu_verneed(ELFOBJ *eo, Elf_(Shdr) *shdr, int sz) {
	if (!eo || !eo->dynstr) {
		return NULL;
	}
	if (shdr->sh_link >= eo->ehdr.e_shnum) {
		return NULL;
	}
#ifdef R_BIN_ELF64
	// R2_590 delete the else block , this chk must be generic
	if ((int)shdr->sh_size < 1 || shdr->sh_size > SIZE_MAX) {
		return NULL;
	}
#else
	if ((int)shdr->sh_size < 1) {
		return NULL;
	}
#endif
	size_t shsz = R_MAX (1, shdr->sh_size);
	if (shsz > eo->size) {
		return NULL;
	}

	Sdb *sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}

	Elf_(Shdr) *link_shdr = &eo->shdr[shdr->sh_link];
	const char *link_section_name = eo->shstrtab && link_shdr->sh_name < eo->shstrtab_size
		? &eo->shstrtab[link_shdr->sh_name] : "";
	const char *section_name = eo->shstrtab && shdr->sh_name < eo->shstrtab_size
		? &eo->shstrtab[shdr->sh_name] : "";
	sdb_set (sdb, "section_name", section_name, 0);
	sdb_num_set (sdb, "num_entries", shdr->sh_info, 0);
	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set (sdb, "link", shdr->sh_link, 0);
	sdb_set (sdb, "link_section_name", link_section_name, 0);

	if (shdr->sh_offset > eo->size || shdr->sh_offset + shdr->sh_size > eo->size) {
		sdb_free (sdb);
		return NULL;
	}
	if (shdr->sh_offset + shdr->sh_size < shdr->sh_size) {
		sdb_free (sdb);
		return NULL;
	}

	ut8 *need = calloc (shsz, sizeof (ut8));
	if (!need) {
		R_LOG_ERROR ("Cannot allocate memory for Elf_(Verneed)");
		sdb_free (sdb);
		return NULL;
	}

	int count = r_buf_read_at (eo->b, shdr->sh_offset, need, shdr->sh_size);
	if (count != shdr->sh_size) {
		free (need);
		sdb_free (sdb);
		return NULL;
	}

	ProcessVerneedState state = { .sdb = sdb, .need = need, .shdr = shdr };
	if (!_process_verneed_state (eo, &state)) {
		free (need);
		sdb_free (sdb);
		return NULL;
	}

	free (need);
	return sdb;
}

static Sdb *store_versioninfo(ELFOBJ *eo) {
	if (!eo || !eo->shdr) {
		return NULL;
	}

	Sdb *sdb_versioninfo = sdb_new0 ();
	if (!sdb_versioninfo) {
		return NULL;
	}

	int num_verdef = 0;
	int num_verneed = 0;
	int num_versym = 0;
	size_t i;
	for (i = 0; i < eo->ehdr.e_shnum; i++) {
		int size = eo->shdr[i].sh_size;

		if (size - (i * sizeof (Elf_(Shdr)) > eo->size)) {
			size = eo->size - (i*sizeof (Elf_(Shdr)));
		}

		int left = size - (i * sizeof (Elf_(Shdr)));
		left = R_MIN (left, eo->shdr[i].sh_size);
		if (left < 0) {
			break;
		}

		Sdb *sdb = NULL;
		char key[32] = {0};
		switch (eo->shdr[i].sh_type) {
		case SHT_GNU_verdef:
			sdb = store_versioninfo_gnu_verdef (eo, &eo->shdr[i], left);
			snprintf (key, sizeof (key), "verdef%d", num_verdef++);
			sdb_ns_set (sdb_versioninfo, key, sdb);
			break;
		case SHT_GNU_verneed:
			sdb = store_versioninfo_gnu_verneed (eo, &eo->shdr[i], left);
			snprintf (key, sizeof (key), "verneed%d", num_verneed++);
			sdb_ns_set (sdb_versioninfo, key, sdb);
			break;
		case SHT_GNU_versym:
			sdb = store_versioninfo_gnu_versym (eo, &eo->shdr[i], left);
			snprintf (key, sizeof (key), "versym%d", num_versym++);
			sdb_ns_set (sdb_versioninfo, key, sdb);
			break;
		}
	}

	return sdb_versioninfo;
}

static bool init_dynstr(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, false);
	if (!eo->shdr || !eo->shstrtab) {
		R_LOG_DEBUG ("no section header or sh string tab");
		return false;
	}

	ut8 name[128] = {0};
	int i;
	for (i = 0; i < eo->ehdr.e_shnum; i++) {
		const size_t sh_name = eo->shdr[i].sh_name;
		const size_t shstrtab_size = eo->shstrtab_size;
		bool inshstrtab = (sh_name < shstrtab_size);
#if 0
		if (eo->shdr[i].sh_name > eo->shstrtab_size) {
			return false;
		}
#endif
		if (sh_name >= eo->size) {
			R_LOG_DEBUG ("section %d name is beyond eof", i);
			return false;
		}
		const char *section_name = NULL;
		if (inshstrtab) {
			section_name = eo->shstrtab + eo->shdr[i].sh_name;
		} else {
			R_LOG_DEBUG ("section name is beyond the sh string tab section size");
			ut64 at = eo->shstrtab_section->sh_offset + sh_name;
			(void)r_buf_read_at (eo->b, at, name, sizeof (name));
			name[sizeof (name) - 1] = 0;
			section_name = (const char *)name;
		}
		if (eo->shdr[i].sh_type == SHT_STRTAB && !strcmp (section_name, ".dynstr")) {
			const ut64 dyn_addr = eo->shdr[i].sh_offset;
			const ut64 dyn_size = eo->shdr[i].sh_size;
			size_t shsz = dyn_size;
			if (dyn_addr >= eo->size) {
				R_LOG_ERROR ("Invalid address for the dynamic strings");
				return false;
			}
			ut64 left = eo->size - dyn_addr;
			if (dyn_size > left) {
				R_LOG_WARN ("Shrinking the dynstr size to file bounds");
				shsz = left;
			}
			if (!(eo->dynstr = (char*) calloc (shsz + 1, sizeof (char)))) {
				R_LOG_ERROR ("Cannot allocate 0x%x bytes for strings", (int)shsz);
				return true;
			}
			if (eo->shdr[i].sh_offset > eo->size) {
				R_LOG_DEBUG ("section offset is beyond eof");
				return false;
			}
			if (eo->shdr[i].sh_offset + eo->shdr[i].sh_size > eo->size) {
				R_LOG_DEBUG ("section end is beyond eof");
				return false;
			}
			if (eo->shdr[i].sh_offset + eo->shdr[i].sh_size < eo->shdr[i].sh_size) {
				R_LOG_DEBUG ("section end is beyond section boundaries");
				return false;
			}
			int r = r_buf_read_at (eo->b, eo->shdr[i].sh_offset, (ut8*)eo->dynstr, eo->shdr[i].sh_size);
			if (r < 1) {
				R_LOG_DEBUG ("cannot read the dynstr");
				R_FREE (eo->dynstr);
				eo->dynstr_size = 0;
				return false;
			}
			eo->dynstr_size = eo->shdr[i].sh_size;
			return true;
		}
	}
	return false;
}

static const RVector *_load_elf_sections(ELFOBJ *eo);

static void relro_insdb(ELFOBJ *eo) {
	int r = Elf_(has_relro) (eo);
	switch (r) {
	case R_ELF_FULL_RELRO:
		sdb_set (eo->kv, "elf.relro", "full", 0);
		break;
	case R_ELF_PART_RELRO:
		sdb_set (eo->kv, "elf.relro", "partial", 0);
		break;
	default:
		sdb_set (eo->kv, "elf.relro", "no", 0);
		break;
	}
}

/* Look down */
static void sdb_init_const(ELFOBJ *eo);

static bool elf_init(ELFOBJ *eo) {
	// eo is not an ELF
	if (!init_ehdr (eo)) {
		return false;
	}

	sdb_init_const (eo);

	if (!init_phdr (eo) && !is_bin_etrel (eo)) {
		R_LOG_DEBUG ("Cannot initialize program headers");
	}

	if (eo->ehdr.e_type != ET_CORE) {
		if (!init_shdr (eo)) {
			R_LOG_DEBUG ("Cannot initialize section headers");
		}
		if (!init_strtab (eo)) {
			R_LOG_DEBUG ("Cannot initialize strings table");
		}
		if (!init_dynstr (eo) && !is_bin_etrel (eo)) {
			R_LOG_DEBUG ("Cannot initialize dynamic strings");
		}
		eo->baddr = Elf_(get_baddr) (eo);
		if (!init_dynamic_section (eo) && !Elf_(is_static) (eo) && !is_bin_etrel (eo)) {
			R_LOG_DEBUG ("Cannot initialize dynamic section");
		}
	}
	relro_insdb (eo);

	eo->imports_by_ord_size = 0;
	eo->imports_by_ord = NULL;
	eo->symbols_by_ord_size = 0;
	eo->symbols_by_ord = NULL;
	(void) _load_elf_sections (eo);
	eo->boffset = Elf_(get_boffset) (eo);
	eo->rel_cache = ht_uu_new0 ();
	(void) Elf_(load_relocs) (eo);
	sdb_ns_set (eo->kv, "versioninfo", store_versioninfo (eo));
	reloc_fill_local_address (eo);
	return true;
}

ut64 Elf_(get_section_offset)(ELFOBJ *eo, const char *section_name) {
	RBinElfSection *section = get_section_by_name (eo, section_name);
	return section? section->offset: UT64_MAX;
}

ut64 Elf_(get_section_addr)(ELFOBJ *eo, const char *section_name) {
	RBinElfSection *section = get_section_by_name (eo, section_name);
	return section? section->rva: UT64_MAX;
}

ut64 Elf_(get_section_addr_end)(ELFOBJ *eo, const char *section_name) {
	RBinElfSection *section = get_section_by_name (eo, section_name);
	return section? section->rva + section->size: UT64_MAX;
}

ut64 Elf_(get_section_size)(ELFOBJ *eo, const char *section_name) {
	RBinElfSection *section = get_section_by_name (eo, section_name);
	return section? section->size: UT64_MAX;
}

static ut64 get_got_entry(ELFOBJ *eo, RBinElfReloc *rel) {
	if (!rel || !rel->rva || rel->rva == UT64_MAX) {
		return UT64_MAX;
	}
	ut64 p_sym_got_addr = Elf_(v2p_new) (eo, rel->rva);
	ut64 addr = R_BIN_ELF_BREADWORD (eo->b, p_sym_got_addr);
	return (!addr || addr == R_BIN_ELF_WORD_MAX) ? UT64_MAX : addr;
}

static ut64 get_import_addr_qdsp6(ELFOBJ *eo, RBinElfReloc *rel) {
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
	case R_QDSP6_JUMP_SLOT:
		return plt_addr + pos * 16 + 32;
	}
	return UT64_MAX;
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
			return (plt_addr + pos * 16 + 32) + rel->addend;
		}
		// same as fallback to JUMP_SLOT
		return plt_addr + pos * 16 + 32;
	case R_AARCH64_JUMP_SLOT:
		return plt_addr + pos * 16 + 32;
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
		ut64 p_plt_addr = Elf_(v2p_new) (bin, plt_addr);
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

static ut64 get_import_addr_riscv(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 got_addr = bin->dyn_info.dt_pltgot;
	if (got_addr != R_BIN_ELF_ADDR_MAX) {
		ut64 plt_addr = get_got_entry (bin, rel);
		if (plt_addr != UT64_MAX) {
			ut64 pos = COMPUTE_PLTGOT_POSITION (rel, got_addr, 2);
			return plt_addr + RISCV_PLT_OFFSET + pos * RISCV_PLT_ENTRY_SIZE;
		}
	}
	return UT64_MAX;
}

static ut64 get_import_addr_loongarch(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 got_addr = bin->dyn_info.dt_pltgot;
	if (got_addr != R_BIN_ELF_ADDR_MAX) {
		ut64 plt_addr = get_got_entry (bin, rel);
		if (plt_addr != UT64_MAX) {
			ut64 pos = COMPUTE_PLTGOT_POSITION (rel, got_addr, 2);
			return plt_addr + LOONGARCH_PLT_OFFSET + pos * LOONGARCH_PLT_ENTRY_SIZE;
		}
	}
	return UT64_MAX;
}

static size_t get_size_rel_mode(Elf_(Xword) mode) {
	if (mode == DT_RELA) {
		return sizeof (Elf_(Rela));
	} else if (mode == DT_REL) {
		return sizeof (Elf_(Rel));
	} else if (mode == DT_CREL) {
		// CREL uses variable-length encoding, but we need to return a size for alignment
		// This is just a placeholder - actual parsing will be different
		return sizeof (Elf_(Rela));
	} else if (mode == DT_RELR) {
		// RELR entries are the size of an address
		return sizeof (Elf_(Addr));
	}
	return 0;
}

static ut64 get_num_relocs_dynamic_plt(ELFOBJ *eo) {
	if (eo->dyn_info.dt_pltrelsz) {
		const ut64 size = eo->dyn_info.dt_pltrelsz;
		const ut64 relsize = get_size_rel_mode (eo->dyn_info.dt_pltrel);
		return relsize ? size / relsize : 0;
	}
	return 0;
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

static ut64 get_import_addr_ppc(ELFOBJ *eo, RBinElfReloc *rel) {
	ut64 plt_addr = eo->dyn_info.dt_pltgot;
	if (plt_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	if (rel->rva < plt_addr) {
		ut64 orva = rel->rva;
		int delta = plt_addr - rel->rva;
		orva += (2* delta);
		// orva += 0xef0;
		R_LOG_DEBUG ("Massaged pointer below plt from 0x%"PFMT64x" to 0x%"PFMT64x, rel->rva, orva);
		return orva;
	}

	ut64 p_plt_addr = Elf_(v2p_new) (eo, plt_addr);
	if (p_plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 base = r_buf_read_ble32_at (eo->b, p_plt_addr, eo->endian);
	if (base == UT32_MAX) {
		return UT64_MAX;
	}

	ut64 nrel = get_num_relocs_dynamic_plt (eo);
	ut64 pos = COMPUTE_PLTGOT_POSITION (rel, plt_addr, 0x0);

	if (eo->endian) {
#if 0
		base += plt_addr;
		base -= (nrel * 16);
		base += (pos * 8);
#else
		base -= (nrel * 16);
		base += (pos * 16);
#endif
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

	ut64 got_offset = Elf_(v2p_new) (eo, got_addr);
	if (got_offset == UT64_MAX) {
		return UT64_MAX;
	}

	//XXX HACK ALERT!!!! full relro?? try to fix it
	//will there always be .plt.got, what would happen if is .got.plt?
	RBinElfSection *s = get_section_by_name (eo, ".plt.got");
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

		size_t i = 0;
		plt_sym_addr = R_BIN_ELF_READWORD (buf, i);

		//relative address
		if ((plt_addr + 6 + Elf_(v2p) (eo, plt_sym_addr)) == rel->rva) {
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
	RBinElfSection *pltsec = get_section_by_name (eo, ".plt.sec");
	if (pltsec) {
		ut64 got_addr = eo->dyn_info.dt_pltgot;
		ut64 pos = COMPUTE_PLTGOT_POSITION (rel, got_addr, 3);
		return pltsec->rva + pos * X86_PLT_ENTRY_SIZE;
	}
	return tmp + X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr(ELFOBJ *eo, int sym) {
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
	RBinElfReloc *rel = r_vector_at (&eo->g_relocs, index - 1);
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
		return get_import_addr_loongarch (eo, rel);
	case EM_SBPF:
		// sBPF relocations are handled in patch_reloc, return the offset for imports
		return rel->offset;
	case EM_BPF:
		return rel->offset;
	default:
		R_LOG_WARN ("Unsupported relocs type %" PFMT64u " for arch %d",
				(ut64) rel->type, eo->ehdr.e_machine);
		return UT64_MAX;
	}
}

bool Elf_(has_nobtcfi)(ELFOBJ *eo) {
	return eo->has_nobtcfi;
}

/// XXX this is O(n) and can be cached to avoid walking the sections again
bool Elf_(has_nx)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, 0);

	if (eo && eo->phdr) {
		size_t i;
		for (i = 0; i < eo->ehdr.e_phnum; i++) {
			if (eo->phdr[i].p_type == PT_GNU_STACK) {
				return (!(eo->phdr[i].p_flags & 1))? 1: 0;
			}
		}
	}
	return 0;
}

int Elf_(has_relro)(ELFOBJ *bin) {
	R_RETURN_VAL_IF_FAIL (bin, R_ELF_NO_RELRO);
	if (bin->phdr) {
		bool have_bind_now = false;
		if (bin->dyn_info.dt_bind_now) {
			have_bind_now = true;
		} else if (bin->dyn_info.dt_flags != R_BIN_ELF_XWORD_MAX && bin->dyn_info.dt_flags != R_BIN_ELF_XWORD_MAX) {
			have_bind_now = bin->dyn_info.dt_flags_1 & DF_1_NOW;
		}
		size_t i;
		for (i = 0; i < bin->ehdr.e_phnum; i++) {
			if (bin->phdr[i].p_type == PT_GNU_RELRO) {
				return have_bind_now? R_ELF_FULL_RELRO: R_ELF_PART_RELRO;
			}
		}
	}
	return R_ELF_NO_RELRO;
}

/*
To compute the base address, one determines the memory
address associated with the lowest p_vaddr value for a
PT_LOAD segment. One then obtains the base address by
truncating the memory address to the nearest multiple
of the maximum page size
*/

ut64 Elf_(get_baddr)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, 0);

	ut64 base = UT64_MAX;
	if (eo->phdr) {
		size_t i;
		for (i = 0; i < eo->ehdr.e_phnum; i++) {
			if (eo->phdr[i].p_type == PT_LOAD) {
				ut64 tmp = (ut64)eo->phdr[i].p_vaddr & ELF_PAGE_MASK;
				tmp = tmp - (tmp % ELF_PAGE_SIZE);
				if (tmp < base) {
					base = tmp;
				}
			}
		}
	}

	if (base == UT64_MAX && is_bin_etrel (eo)) {
		// we return our own base address for ET_REL type
		// we act as a loader for ELF
		return 0x08000000;
	}

	return base;
}

ut64 Elf_(get_boffset)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, 0);

	if (!eo->phdr) {
		return 0; // TODO: should return ut64.max
	}

	ut64 base = UT64_MAX;
	size_t i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		if (eo->phdr[i].p_type == PT_LOAD) {
			ut64 tmp = (ut64)eo->phdr[i].p_offset & ELF_PAGE_MASK;
			tmp = tmp - (tmp % ELF_PAGE_SIZE);
			if (tmp < base) {
				base = tmp;
			}
		}
	}
	return base;
}

ut64 Elf_(get_init_offset)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, UT64_MAX);
	if (is_intel (eo)) { // push // x86 only
		ut64 entry = Elf_(get_entry_offset) (eo);
		if (entry == UT64_MAX) {
			return UT64_MAX;
		}
		ut8 buf[64];
		if (r_buf_read_at (eo->b, entry + 16, buf, sizeof (buf)) == sizeof (buf)) {
			if (*buf == 0x68) {
				memmove (buf, buf + 1, 4);
				ut64 addr = (ut64) r_read_le32 (buf);
				return Elf_(v2p) (eo, addr);
			}
		}
	}
	return 0; // XXX should be UT64_MAX
}

ut64 Elf_(get_fini_offset)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, UT64_MAX);
	if (is_intel (eo)) { // push // x86 only
		ut64 entry = Elf_(get_entry_offset) (eo);
		if (entry == UT64_MAX) {
			return UT64_MAX;
		}
		ut8 buf[512]; // can we lower this to 64 or 128?
		if (r_buf_read_at (eo->b, entry + 11, buf, sizeof (buf)) == -1) {
			R_LOG_ERROR ("read (get_fini)");
			return 0;
		}
		if (*buf == 0x68) { // push // x86/32 only
			memmove (buf, buf + 1, 4);
			ut64 addr = (ut64) r_read_le32 (buf);
			return Elf_(v2p) (eo, addr);
		}
	}
	return 0; // XXX should be UT64_MAX
}

static ut64 get_entry_offset_from_shdr(ELFOBJ *eo) {
	ut64 sectionOffset = Elf_(get_section_offset)(eo, ".init.text");
	if (sectionOffset != UT64_MAX) {
		return sectionOffset;
	}
	sectionOffset = Elf_(get_section_offset)(eo, ".text");
	if (sectionOffset != UT64_MAX) {
		return sectionOffset;
	}
	sectionOffset = Elf_(get_section_offset)(eo, ".text");
	if (sectionOffset != UT64_MAX) {
		return sectionOffset;
	}
	return UT64_MAX;
}

ut64 Elf_(get_entry_offset)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, UT64_MAX);

	if (!Elf_(is_executable) (eo)) {
		return UT64_MAX;
	}

	ut64 entry = eo->ehdr.e_entry;
	if (entry) {
		return Elf_(v2p) (eo, entry);
	}

	return get_entry_offset_from_shdr (eo);
}

static ut64 lookup_main_symbol_offset(ELFOBJ *eo) {
	if (Elf_(load_symbols) (eo)) {
		RBinElfSymbol *symbol;
		RVecRBinElfSymbol *symbols = eo->g_symbols_vec;
		R_VEC_FOREACH (symbols, symbol) {
			if (!strcmp (symbol->name, "main")) {
				return symbol->offset;
			}
		}
	}
	return UT64_MAX;
}

ut64 Elf_(get_main_offset)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, UT64_MAX);

	ut64 entry = Elf_(get_entry_offset) (eo);
	if (entry == UT64_MAX) {
		return UT64_MAX;
	}

	ut8 buf[256];
	if (entry > eo->size || (entry + sizeof (buf)) > eo->size) {
		return UT64_MAX;
	}

	// unnecessary to read 256 bytes imho
	if (r_buf_read_at (eo->b, entry, buf, sizeof (buf)) < 1) {
		R_LOG_ERROR ("read (main)");
		return UT64_MAX;
	}

	// ARM64
	if (buf[0x18 + 3] == 0x58 && buf[0x2f] == 0x00) {
		ut32 entry_vaddr = Elf_(p2v) (eo, entry);
		ut32 main_addr = r_read_le32 (&buf[0x30]);
		if ((main_addr >> 16) == (entry_vaddr >> 16)) {
			return Elf_(v2p) (eo, main_addr);
		}
	}

	// TODO: Use arch to identify arch before memcmp's

	// ARM Glibc
	if (entry & 1) {
		int delta = 0;
		// thumb entry points
		if (!memcmp (buf, "\xf0\x00\x0b\x4f\xf0\x00\x0e\x02\xbc\x6a\x46", 11)) {
			// newer versions of gcc use push/pop
			delta = 0x28;
		} else if (!memcmp (buf, "\xf0\x00\x0b\x4f\xf0\x00\x0e\x5d\xf8\x04\x1b", 11)) {
			// older versions of gcc (4.5.x) use ldr/str
			delta = 0x30;
		}
		if (delta) {
			ut64 pa = r_read_le32 (&buf[delta - 1]);
			bool thumb = pa & 1;
			if (thumb) {
				pa = Elf_(v2p) (eo, pa & ~1);
				pa++;
			} else {
				pa = Elf_(v2p) (eo, pa);
			}
			if (pa < r_buf_size (eo->b)) {
				return pa;
			}
		}
	} else {
		// non-thumb entry points
		if (!memcmp (buf, "\x00\xb0\xa0\xe3\x00\xe0\xa0\xe3", 8)) {
			if (buf[0x40 + 2] == 0xff && buf[0x40 + 3] == 0xeb) {
				// nothing may happen
			} else if (!memcmp (buf + 0x28 + 2, "\xff\xeb", 2)) {
				return Elf_(v2p) (eo, r_read_le32 (&buf[0x34]) & ~1);
			}
		}
		if (!memcmp (buf, "\x24\xc0\x9f\xe5\x00\xb0\xa0\xe3", 8)) {
			return Elf_(v2p) (eo, r_read_le32 (&buf[0x30]) & ~1);
		}
	}

	// MIPS
	// get .got, calculate offset of main symbol
	if (!memcmp (buf, "\x21\x00\xe0\x03\x01\x00\x11\x04", 8)) {
		/*
		    assuming the startup code looks like
		        got = gp-0x7ff0
		        got[index__libc_start_main] ( got[index_main] );

		    looking for the instruction generating the first argument to find main
		        lw a0, offset(gp)
		*/

		ut64 got_offset;
		if ((got_offset = Elf_(get_section_offset) (eo, ".got")) != UT64_MAX ||
		    (got_offset = Elf_(get_section_offset) (eo, ".got.plt")) != UT64_MAX)
		{
			const ut64 gp = got_offset + 0x7ff0;
			size_t len = sizeof (buf) / sizeof (buf[0]);
			size_t i;
			for (i = 0; i < len; i += 4) {
				const ut32 instr = r_read_le32 (&buf[i]);
				if ((instr & 0xffff0000) == 0x8f840000) { // lw a0, offset(gp)
					const short delta = instr & 0x0000ffff;
					r_buf_read_at (eo->b, /* got_entry_offset = */ gp + delta, buf, 4);
					return Elf_(v2p) (eo, r_read_le32 (&buf[0]));
				}
			}
		}

		return 0;
	}

	// X86-CGC
	if (buf[0] == 0xe8 && !memcmp (buf + 5, "\x50\xe8\x00\x00\x00\x00\xb8\x01\x00\x00\x00\x53", 12)) {
		size_t SIZEOF_CALL = 5;
		ut64 rel_addr = (ut64)((int)(buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24)));
		const ut64 addr = Elf_(p2v)(eo, entry + SIZEOF_CALL) + rel_addr;
		return Elf_(v2p) (eo, addr);
	}

	// X86-PIE
	if (buf[0x00] == 0x48 && buf[0x1e] == 0x8d && buf[0x11] == 0xe8) {
		ut32 *pmain = (ut32*)(buf + 0x30);
		ut64 vmain = Elf_(p2v) (eo, (ut64)*pmain);
		ut64 ventry = Elf_(p2v) (eo, entry);
		if (vmain >> 16 == ventry >> 16) {
			return (ut64) vmain;
		}
	}

	// X86-PIE
	if (buf[0x1d] == 0x48 && buf[0x1e] == 0x8b) {
		if (!memcmp (buf, "\x31\xed\x49\x89", 4)) { // linux
			ut8 n32s[sizeof (ut32)] = {0};
			ut64 maddr = entry + 0x24 + r_read_le32 (buf + 0x20);
			if (r_buf_read_at (eo->b, maddr, n32s, sizeof (ut32)) == UT64_MAX) {
				R_LOG_ERROR ("read (maddr) 2");
				return 0;
			}

			maddr = (ut64) r_read_le32 (&n32s[0]);
			ut64 baddr = (eo->ehdr.e_entry >> 16) << 16;
			if (eo->phdr) {
				baddr = Elf_(get_baddr) (eo);
			}
			maddr += baddr;
			return maddr;
		}
	}

	// X86-NONPIE
#if R_BIN_ELF64
	if (!memcmp (buf, "\x49\x89\xd9", 3) && buf[156] == 0xe8) { // openbsd
		return r_read_le32 (&buf[157]) + entry + 156 + 5;
	}
	if (!memcmp (buf + 29, "\x48\xc7\xc7", 3)) { // linux
		ut64 addr = (ut64)r_read_le32 (&buf[29 + 3]);
		return Elf_(v2p) (eo, addr);
	}
#else
	if (buf[23] == '\x68') {
		ut64 addr = (ut64)r_read_le32 (&buf[23 + 1]);
		return Elf_(v2p) (eo, addr);
	}
#endif
	// linux64 pie main -- probably buggy in some cases
	int bo = 29; // Begin offset may vary depending on the entry prelude
	// endbr64 - fedora bins have this
	if (buf[0] == 0xf3 && buf[1] == 0x0f && buf[2] == 0x1e && buf[3] == 0xfa) {
		// Change begin offset if binary starts with 'endbr64'
		bo = 33;
	}
	if (buf[bo] != 0x48) {
		bo -= 9;
	}
	if (buf[bo] == 0x48) {
		ut8 ch = buf[bo + 1];
		if (ch == 0x8d) { // lea rdi, qword [rip-0x21c4]
			ut8 *p = buf + bo + 3;
			st32 maindelta = (st32)r_read_le32 (p);
			ut64 vmain = (ut64)(entry + bo + maindelta) + 7;
			ut64 ventry = Elf_(p2v) (eo, entry);
			if ((vmain >> 16) == (ventry >> 16)) {
				return (ut64)vmain;
			}
		} else if (ch == 0xc7) { // mov rdi, 0xADDR
			ut8 *p = buf + bo + 3;
			return (ut64)(ut32)r_read_le32 (p);
		}
	}
	return lookup_main_symbol_offset (eo);
}

bool Elf_(get_stripped)(ELFOBJ *eo, bool *have_lines, bool *have_syms) {
	*have_lines = false;
	*have_syms = false;
	if (!eo->shdr) {
		return true;
	}
	RBinElfSection *sec = get_section_by_name (eo, ".gnu_debugdata");
	// R_BIN_DBG_LINENUMS
	*have_lines = (sec && sec->size > 16);
	size_t i;
	for (i = 0; i < eo->ehdr.e_shnum; i++) {
		if (eo->shdr[i].sh_type == SHT_SYMTAB) {
			// R_BIN_DBG_SYMS
			*have_syms = true;
			break;
		}
	}
	// TODO: check for named relocs and return R_BIN_DBG_RELOCS
	if (*have_lines || *have_syms) {
		return false;
	}
	return true;
}

char *Elf_(intrp)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);
	if (!eo->phdr) {
		return NULL;
	}

	int i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		if (eo->phdr[i].p_type != PT_INTERP) {
			continue;
		}

		ut64 addr = eo->phdr[i].p_offset;
		int sz = eo->phdr[i].p_filesz;
		sdb_num_set (eo->kv, "elf_header.intrp_addr", addr, 0);
		sdb_num_set (eo->kv, "elf_header.intrp_size", sz, 0);
		if (sz < 1 || sz > r_buf_size (eo->b)) {
			return NULL;
		}

		char *str = malloc (sz + 1);
		if (!str) {
			break;
		}
		if (r_buf_read_at (eo->b, addr, (ut8*)str, sz) < 1) {
			R_LOG_ERROR ("read (main)");
			free (str);
			return 0;
		}

		str[sz] = 0;
		sdb_set (eo->kv, "elf_header.intrp", str, 0);
		return str;
	}

	return NULL;
}

bool Elf_(is_static)(ELFOBJ *eo) {
	if (!eo->phdr) {
		return false;
	}
	size_t i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		if (eo->phdr[i].p_type == PT_INTERP || eo->phdr[i].p_type == PT_DYNAMIC) {
			return false;
		}
	}
	return true;
}

char* Elf_(get_data_encoding)(ELFOBJ *eo) {
	switch (eo->ehdr.e_ident[EI_DATA]) {
	case ELFDATANONE: return strdup ("none");
	case ELFDATA2LSB: return strdup ("2's complement, little endian");
	case ELFDATA2MSB: return strdup ("2's complement, big endian");
	default: return r_str_newf ("<unknown: %x>", eo->ehdr.e_ident[EI_DATA]);
	}
}

int Elf_(has_va)(ELFOBJ *eo) {
	return true;
}

char* Elf_(get_arch)(ELFOBJ *eo) {
	const char *arch = "unknown";
	switch (eo->ehdr.e_machine) {
	case EM_ARC:
	case EM_ARC_A5:
		arch = "arc";
		break;
	case EM_AVR:
		arch = "avr";
		break;
	case EM_BA2_NON_STANDARD:
	case EM_BA2:
		arch = "ba2";
		break;
	case EM_BPF:
		arch = "bpf";
		break;
	case EM_SBPF:
		arch = "sbpf";
		break;
	case EM_CRIS:
		arch = "cris";
		break;
	case EM_68K:
		arch = "m68k";
		break;
	case EM_MIPS:
	case EM_MIPS_RS3_LE:
	case EM_MIPS_X:
		arch = "mips";
		break;
	case EM_MCST_ELBRUS:
		arch = "elbrus";
		break;
	case EM_TRICORE:
		arch = "tricore";
		break;
	case EM_RCE:
		arch = "mcore";
		break;
	case EM_ARM:
	case EM_AARCH64:
		arch = "arm";
		break;
	case EM_QDSP6: // EM_HEXAGON
		arch = "hexagon";
		break;
	case EM_BLACKFIN:
		arch = "blackfin";
		break;
	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		arch = "sparc";
		break;
	case EM_PPC:
	case EM_PPC64:
		arch = "ppc";
		break;
	case EM_PARISC:
		arch = "hppa";
		break;
	case EM_PROPELLER:
		arch = "propeller";
		break;
	case EM_MICROBLAZE:
		arch = "microblaze.gnu";
		break;
	case EM_RISCV:
		arch = "riscv";
		break;
	case EM_VAX:
		arch = "vax";
		break;
	case EM_XTENSA:
		arch = "xtensa";
		break;
	case EM_LANAI:
		arch = "lanai";
		break;
	case EM_VIDEOCORE3:
	case EM_VIDEOCORE4:
		arch = "vc4";
		break;
	case EM_MSP430:
		arch = "msp430";
		break;
	case EM_SH:
		arch = "sh";
		break;
	case EM_V800:
		arch = "v850";
		break;
	case EM_V850:
		arch = "v850";
		break;
	case EM_IA_64:
		arch = "ia64";
		break;
	case EM_S390:
		arch = "s390";
		break;
	case EM_KVX:
		arch = "kvx";
		break;
	case EM_LOONGARCH:
		arch = "loongarch";
		break;
	case EM_NDS32:
		arch = "nds32";
		break;
	case EM_386:
	case EM_X86_64:
	case EM_IAMCU:
		arch = "x86";
		break;
	case EM_NONE:
		arch = "null";
		break;
	case EM_TI_C6000:
	case EM_TI_C2000:
	case EM_TI_C5500:
		arch = "tms320";
		break;
	default:
		// should be NULL instead
		R_LOG_ERROR ("Unknown e_machine 0x%02x", eo->ehdr.e_machine);
		break;
	}
	return strdup (arch);
}

char* Elf_(get_abi)(ELFOBJ *eo) {
	Elf_(Ehdr)* ehdr = &eo->ehdr;
	ut32 eflags = eo->ehdr.e_flags;

	switch (ehdr->e_machine) {
	case EM_68K:
		if (eflags & 0x1000000) {
			return strdup ("68000");
		}
		if (eflags & 0x810000) {
			return strdup ("cpu32");
		}
		if (eflags == 0) {
			return strdup ("68020");
		}
		break;
	case EM_ARM:
		{
			int v = (eflags >> 24);
			const char *arg = "";
			if (eflags & 0x800000) {
				arg = " be8";
			} else if (eflags & 0x400000) {
				arg = " le8";
			}
			return r_str_newf ("eabi%d%s", v, arg);
		}
		break;
	case EM_MIPS:
		{
			if (is_elfclass64 (ehdr)) {
				return strdup ("n64");
			}
			if (is_mips_n32 (ehdr)) {
				return strdup ("n32");
			}
			if (is_mips_o32 (ehdr)) {
				return strdup ("o32");
			}
			if (is_mips_micro (ehdr)) {
				return strdup ("micro");
			}
		}
		break;
	case EM_V800:
	case EM_V850:
		break;
	case EM_SBPF:
		return r_str_newf ("sbpfv%d", eflags);
	}
	return NULL;
}

static char *mips_flags_to_cpu(ut32 mipsType) {
	switch (mipsType) {
	case EF_MIPS_ARCH_1: return "mips1";
	case EF_MIPS_ARCH_2: return "mips2";
	case EF_MIPS_ARCH_3: return "mips3";
	case EF_MIPS_ARCH_4: return "mips4";
	case EF_MIPS_ARCH_5: return "mips5";
	case EF_MIPS_ARCH_32: return "mips32";
	case EF_MIPS_ARCH_64: return "mips64";
	case EF_MIPS_ARCH_32R2: return "mips32r2";
	case EF_MIPS_ARCH_64R2: return "mips64r2";
	default: return "Unknown mips ISA";
	}
}

// XXX remove?
#if 0
// Flags for the st_other field.
#define V850_OTHER_SDA		0x10	// Symbol had SDA relocations.
#define V850_OTHER_ZDA		0x20	// Symbol had ZDA relocations.
#define V850_OTHER_TDA		0x40	// Symbol had TDA relocations.
#define V850_OTHER_ERROR	0x80	// Symbol had an error reported.
#endif

#define EF_V850_ARCH		0xf0000000
#define E_V850_ARCH		0x00000000
#define E_V850E_ARCH		0x10000000
#define E_V850E1_ARCH		0x20000000
#define E_V850E2_ARCH		0x30000000
#define E_V850E2V3_ARCH		0x40000000
#define E_V850E3V5_ARCH		0x60000000

static const char *v850_flags_to_cpu(ut32 type) {
	switch (type) {
	case E_V850_ARCH: return "0";
	case E_V850E_ARCH: return "e";
	case E_V850E1_ARCH: return "e1";
	case E_V850E2_ARCH: return "e2";
	case E_V850E2V3_ARCH: return "e2v3";
	case EF_V850_ARCH: return "e1"; // type = 0xf0
	}
	return NULL;
}

char* Elf_(get_cpu)(ELFOBJ *eo) {
	char *cpu = NULL;

	switch (eo->ehdr.e_machine) {
	case EM_MIPS:
		if (is_mips_micro (&eo->ehdr)) {
			cpu = strdup ("micro");
		} else if (eo->phdr) {
			const char *mips_cpu = mips_flags_to_cpu (eo->ehdr.e_flags & EF_MIPS_ARCH);
			if (mips_cpu) {
				cpu = strdup (mips_cpu);
			}
		}
		break;
	case EM_V800:
	case EM_V850:
	{
		const char *v850_cpu = v850_flags_to_cpu (eo->ehdr.e_flags & EF_V850_ARCH);
		if (v850_cpu) {
			cpu = strdup (v850_cpu);
		}
	}
		break;
	case EM_SBPF:
		cpu = r_str_newf ("sbpfv%d", eo->ehdr.e_flags);
		break;
	default:
		break;
	}
	return cpu;
}

// https://www.sco.com/developers/gabi/latest/ch4.eheader.html

char* Elf_(get_machine_name)(ELFOBJ *eo) {
	switch (eo->ehdr.e_machine) {
	case EM_NONE:          return strdup ("No machine");
	case EM_M32:           return strdup ("AT&T WE 32100");
	case EM_SPARC:         return strdup ("SUN SPARC");
	case EM_386:           return strdup ("Intel 80386");
	case EM_68K:           return strdup ("Motorola m68k family");
	case EM_88K:           return strdup ("Motorola m88k family");
	case EM_IAMCU:         return strdup ("Intel 80486");
	case EM_860:           return strdup ("Intel 80860");
	case EM_MIPS:          return strdup ("MIPS R3000");
	case EM_S370:          return strdup ("IBM System/370");
	case EM_MIPS_RS3_LE:   return strdup ("MIPS R3000 little-endian");
	case EM_PARISC:        return strdup ("HPPA");
	case EM_VPP500:        return strdup ("Fujitsu VPP500");
	case EM_SPARC32PLUS:   return strdup ("Sun's \"v8plus\"");
	case EM_960:           return strdup ("Intel 80960");
	case EM_PPC:           return strdup ("PowerPC");
	case EM_PPC64:         return strdup ("PowerPC 64-bit");
	case EM_S390:          return strdup ("IBM S390");
	case EM_V800:          return strdup ("NEC V800 series");
	case EM_FR20:          return strdup ("Fujitsu FR20");
	case EM_RH32:          return strdup ("TRW RH-32");
	case EM_RCE:           return strdup ("Motorola RCE");
	case EM_ARM:           return strdup ("ARM");
	case EM_BLACKFIN:      return strdup ("Analog Devices Blackfin");
	case EM_FAKE_ALPHA:    return strdup ("Digital Alpha");
	case EM_SH:            return strdup ("Hitachi SH");
	case EM_SPARCV9:       return strdup ("SPARC v9 64-bit");
	case EM_TRICORE:       return strdup ("Siemens Tricore");
	case EM_ARC:           return strdup ("Argonaut RISC Core");
	case EM_H8_300:        return strdup ("Hitachi H8/300");
	case EM_H8_300H:       return strdup ("Hitachi H8/300H");
	case EM_H8S:           return strdup ("Hitachi H8S");
	case EM_H8_500:        return strdup ("Hitachi H8/500");
	case EM_IA_64:         return strdup ("Intel Merced");
	case EM_MIPS_X:        return strdup ("Stanford MIPS-X");
	case EM_COLDFIRE:      return strdup ("Motorola Coldfire");
	case EM_68HC12:        return strdup ("Motorola M68HC12");
	case EM_MMA:           return strdup ("Fujitsu MMA Multimedia Accelerator");
	case EM_PCP:           return strdup ("Siemens PCP");
	case EM_NCPU:          return strdup ("Sony nCPU embeeded RISC");
	case EM_NDR1:          return strdup ("Denso NDR1 microprocessor");
	case EM_STARCORE:      return strdup ("Motorola Start*Core processor");
	case EM_ME16:          return strdup ("Toyota ME16 processor");
	case EM_ST100:         return strdup ("STMicroelectronic ST100 processor");
	case EM_TINYJ:         return strdup ("Advanced Logic Corp. Tinyj emb.fam");
	case EM_X86_64:        return strdup ("AMD x86-64 architecture");
	case EM_LANAI:         return strdup ("32bit LANAI architecture");
	case EM_PDSP:          return strdup ("Sony DSP Processor");
	case EM_PDP10:         return strdup ("Digital Equipment Corp. PDP-10");
	case EM_PDP11:         return strdup ("Digital Equipment Corp. PDP-11");
	case EM_FX66:          return strdup ("Siemens FX66 microcontroller");
	case EM_ST9PLUS:       return strdup ("STMicroelectronics ST9+ 8/16 mc");
	case EM_ST7:           return strdup ("STmicroelectronics ST7 8 bit mc");
	case EM_68HC16:        return strdup ("Motorola MC68HC16 microcontroller");
	case EM_68HC11:        return strdup ("Motorola MC68HC11 microcontroller");
	case EM_68HC08:        return strdup ("Motorola MC68HC08 microcontroller");
	case EM_68HC05:        return strdup ("Motorola MC68HC05 microcontroller");
	case EM_SVX:           return strdup ("Silicon Graphics SVx");
	case EM_ST19:          return strdup ("STMicroelectronics ST19 8 bit mc");
	case EM_VAX:           return strdup ("Digital VAX");
	case EM_CRIS:          return strdup ("Axis Communications 32-bit embedded processor");
	case EM_JAVELIN:       return strdup ("Infineon Technologies 32-bit embedded processor");
	case EM_FIREPATH:      return strdup ("Element 14 64-bit DSP Processor");
	case EM_ZSP:           return strdup ("LSI Logic 16-bit DSP Processor");
	case EM_MMIX:          return strdup ("Donald Knuth's educational 64-bit processor");
	case EM_HUANY:         return strdup ("Harvard University machine-independent object files");
	case EM_PRISM:         return strdup ("SiTera Prism");
	case EM_AVR:           return strdup ("Atmel AVR 8-bit microcontroller");
	case EM_FR30:          return strdup ("Fujitsu FR30");
	case EM_D10V:          return strdup ("Mitsubishi D10V");
	case EM_D30V:          return strdup ("Mitsubishi D30V");
	case EM_V850:          return strdup ("NEC v850");
	case EM_M32R:          return strdup ("Mitsubishi M32R");
	case EM_MN10300:       return strdup ("Matsushita MN10300");
	case EM_MN10200:       return strdup ("Matsushita MN10200");
	case EM_PJ:            return strdup ("picoJava");
	case EM_OPENRISC:      return strdup ("OpenRISC 32-bit embedded processor");
	case EM_ARC_A5:        return strdup ("ARC Cores Tangent-A5");
	case EM_XTENSA:        return strdup ("Tensilica Xtensa Architecture");
	case EM_AARCH64:       return strdup ("ARM aarch64");
	case EM_PROPELLER:     return strdup ("Parallax Propeller");
	case EM_MICROBLAZE:    return strdup ("Xilinx MicroBlaze");
	case EM_RISCV:         return strdup ("RISC V");
	case EM_VIDEOCORE3:    return strdup ("VideoCore III");
	case EM_VIDEOCORE4:    return strdup ("VideoCore IV");
	case EM_LATTICEMICO32: return strdup ("RISC processor for Lattice FPGA architecture");
	case EM_SE_C17:        return strdup ("Seiko Epson C17 family");
	case EM_TI_C6000:      return strdup ("The Texas Instruments TMS320C6000 DSP family");
	case EM_TI_C2000:      return strdup ("The Texas Instruments TMS320C2000 DSP family");
	case EM_TI_C5500:      return strdup ("The Texas Instruments TMS320C55x DSP family");
	case EM_TI_ARP32:      return strdup ("Texas Instruments Application Specific RISC Processor, 32bit fetch");
	case EM_TI_PRU:        return strdup ("Texas Instruments Programmable Realtime Unit");
	case EM_MMDSP_PLUS:    return strdup ("STMicroelectronics 64bit VLIW Data Signal Processor");
	case EM_CYPRESS_M8C:   return strdup ("Cypress M8C microprocessor");
	case EM_R32C:          return strdup ("Renesas R32C series microprocessors");
	case EM_TRIMEDIA:      return strdup ("NXP Semiconductors TriMedia architecture family");
	case EM_QDSP6:         return strdup ("QUALCOMM DSP6 Processor");  // Nonstandard
	case EM_8051:          return strdup ("Intel 8051 and variants");
	case EM_STXP7X:        return strdup ("STMicroelectronics STxP7x family of configurable and extensible RISC processors");
	case EM_NDS32:         return strdup ("Andes Technology compact code size embedded RISC processor family");
	case EM_ECOG1:         return strdup ("Cyan Technology eCOG1X family");
	// case EM_ECOG1X:        return strdup ("Cyan Technology eCOG1X family");  // Nonstandard
	case EM_MAXQ30:        return strdup ("Dallas Semiconductor MAXQ30 Core Micro-controllers");
	case EM_XIMO16:        return strdup ("New Japan Radio (NJR) 16-bit DSP Processor");
	case EM_MANIK:         return strdup ("M2000 Reconfigurable RISC Microprocessor");
	case EM_CRAYNV2:       return strdup ("Cray Inc. NV2 vector architecture");
	case EM_RX:            return strdup ("Renesas RX family");
	case EM_METAG:         return strdup ("Imagination Technologies META processor architecture");
	case EM_MCST_ELBRUS:   return strdup ("MCST Elbrus general purpose hardware architecture");
	case EM_ECOG16:        return strdup ("Cyan Technology eCOG16 family");
	case EM_CR16:          return strdup ("National Semiconductor CompactRISC CR16 16-bit microprocessor");
	case EM_ETPU:          return strdup ("Freescale Extended Time Processing Unit");
	case EM_SLE9X:         return strdup ("Infineon Technologies SLE9X core");
	case EM_L10M:          return strdup ("Intel L10M");
	case EM_K10M:          return strdup ("Intel K10M");
	// case EM_AARCH64:       return strdup ("ARM 64-bit architecture (AARCH64)");  // Nonstandard
	case EM_AVR32:         return strdup ("Atmel Corporation 32-bit microprocessor family");
	case EM_STM8:          return strdup ("STMicroeletronics STM8 8-bit microcontroller");
	case EM_TILE64:        return strdup ("Tilera TILE64 multicore architecture family");
	case EM_TILEPRO:       return strdup ("Tilera TILEPro multicore architecture family");
	// case EM_MICROBLAZE:    return strdup ("Xilinx MicroBlaze 32-bit RISC soft processor core");  // Nonstandard
	case EM_CUDA:          return strdup ("NVIDIA CUDA architecture");
	case EM_TILEGX:        return strdup ("Tilera TILE-Gx multicore architecture family");
	case EM_CLOUDSHIELD:   return strdup ("CloudShield architecture family");
	case EM_COREA_1ST:     return strdup ("KIPO-KAIST Core-A 1st generation processor family");
	case EM_COREA_2ND:     return strdup ("KIPO-KAIST Core-A 2nd generation processor family");
	case EM_ARC_COMPACT2:  return strdup ("Synopsys ARCompact V2");
	case EM_OPEN8:         return strdup ("Open8 8-bit RISC soft processor core");
	case EM_RL78:          return strdup ("Renesas RL78 family");
	case EM_VIDEOCORE5:    return strdup ("Broadcom VideoCore V processor");
	case EM_78KOR:         return strdup ("Renesas 78KOR family");
	// case EM_56800EX:       return strdup ("Freescale 56800EX Digital Signal Controller (DSC)");  // Nonstandard
	case EM_BA1:           return strdup ("Beyond BA1 CPU architecture");
	case EM_BA2_NON_STANDARD:
	case EM_BA2:           return strdup ("Beyond BA2 CPU architecture");
	case EM_XCORE:         return strdup ("XMOS xCORE processor family");
	case EM_MCHP_PIC:      return strdup ("Microchip 8-bit PIC(r) family");
	case EM_INTEL205:      return strdup ("Reserved by Intel");
	case EM_INTEL206:      return strdup ("Reserved by Intel");
	case EM_INTEL207:      return strdup ("Reserved by Intel");
	case EM_INTEL208:      return strdup ("Reserved by Intel");
	case EM_INTEL209:      return strdup ("Reserved by Intel");
	case EM_KM32:          return strdup ("KM211 KM32 32-bit processor");
	case EM_KMX32:         return strdup ("KM211 KMX32 32-bit processor");
	case EM_KMX16:         return strdup ("KM211 KMX16 16-bit processor");
	case EM_KMX8:          return strdup ("KM211 KMX8 8-bit processor");
	case EM_KVARC:         return strdup ("KM211 KVARC processor");
	case EM_CDP:           return strdup ("Paneve CDP architecture family");
	case EM_COGE:          return strdup ("Cognitive Smart Memory Processor");
	case EM_COOL:          return strdup ("Bluechip Systems CoolEngine");
	case EM_NORC:          return strdup ("Nanoradio Optimized RISC");
	case EM_CSR_KALIMBA:   return strdup ("CSR Kalimba architecture family");
	case EM_Z80:           return strdup ("Zilog Z80");
	case EM_VISIUM:        return strdup ("Controls and Data Services VISIUMcore processor");
	case EM_FT32:          return strdup ("FTDI Chip FT32 high performance 32-bit RISC architecture");
	case EM_MOXIE:         return strdup ("Moxie processor family");
	case EM_AMDGPU:        return strdup ("AMD GPU architecture");
	case EM_BPF:           return strdup ("Berkeley Packet Filter");
	case EM_SBPF:          return strdup ("Solana Berkeley Packet Filter");
	case EM_LOONGARCH:     return strdup ("Loongson Loongarch");
	default:               return r_str_newf ("<unknown>: 0x%x", eo->ehdr.e_machine);
	}
}

char* Elf_(get_file_type)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);

	ut64 e_type = (ut64)eo->ehdr.e_type; // cast to avoid warn in iphone-gcc, must be ut16
	switch (e_type) {
	case ET_NONE: return strdup ("NONE (None)");
	case ET_REL:  return strdup ("REL (Relocatable file)");
	case ET_EXEC: return strdup ("EXEC (Executable file)");
	case ET_DYN:  return strdup ("DYN (Shared object file)");
	case ET_CORE: return strdup ("CORE (Core file)");
	}

	if ((e_type >= ET_LOPROC) && (e_type <= ET_HIPROC)) {
		return r_str_newf ("Processor Specific: 0x%"PFMT64x, e_type);
	}

	if ((e_type >= ET_LOOS) && (e_type <= ET_HIOS)) {
		return r_str_newf ("OS Specific: 0x%"PFMT64x, e_type);
	}

	return r_str_newf ("<unknown>: 0x%"PFMT64x, e_type);
}

char* Elf_(get_elf_class)(ELFOBJ *eo) {
	switch (eo->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASSNONE: return strdup ("none");
	case ELFCLASS32:   return strdup ("ELF32");
	case ELFCLASS64:   return strdup ("ELF64");
	default:           return r_str_newf ("<unknown: %x>", eo->ehdr.e_ident[EI_CLASS]);
	}
}

int Elf_(get_bits)(ELFOBJ *eo) {
	// Hack for ARCompact
	if (eo->ehdr.e_machine == EM_ARC_A5) {
		return 16;
	}

	// Hack for Ps2
	if (eo->phdr && eo->ehdr.e_machine == EM_MIPS) {
		const ut32 mips_type = eo->ehdr.e_flags & EF_MIPS_ARCH;
		if (eo->ehdr.e_type == ET_EXEC) {
			bool have_interp = false;
			int i;
			for (i = 0; i < eo->ehdr.e_phnum; i++) {
				if (eo->phdr[i].p_type == PT_INTERP) {
					have_interp = true;
					break;
				}
			}

			if (!have_interp && mips_type == EF_MIPS_ARCH_3) {
				// Playstation2 Hack
				return 64;
			}
		}
		// TODO: show this specific asm.cpu somewhere in bininfo (mips1, mips2, mips3, mips32r2, ...)
		switch (mips_type) {
		case EF_MIPS_ARCH_1:
		case EF_MIPS_ARCH_2:
		case EF_MIPS_ARCH_3:
		case EF_MIPS_ARCH_4:
		case EF_MIPS_ARCH_5:
		case EF_MIPS_ARCH_32:
			return 32;
		case EF_MIPS_ARCH_64:
			return 64;
		case EF_MIPS_ARCH_32R2:
			return 32;
		case EF_MIPS_ARCH_64R2:
			return 64;
		}
		return 32;
	}

	// Hack for Thumb
	if (eo->ehdr.e_machine == EM_ARM) {
		if (eo->ehdr.e_type != ET_EXEC) {
			RVecRBinElfSymbol *symbols = NULL;
			if (Elf_(load_symbols) (eo)) {
				symbols = eo->g_symbols_vec;
			}
			if (symbols) {
				RBinElfSymbol *symbol;
				R_VEC_FOREACH (symbols, symbol) {
					ut64 paddr = symbol->offset;
					if (paddr & 1) {
						return 16;
					}
				}
			}
		}

		ut64 entry = Elf_(get_entry_offset) (eo);
		if (entry & 1) {
			return 16;
		}
	}

	if (eo->ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
		return 64;
	}

	return 32;
}

static inline int noodle(ELFOBJ *eo, const char *s) {
	if (r_buf_size (eo->b) >= 64)  {
		ut8 tmp[64] = {0};
		if (r_buf_read_at (eo->b, r_buf_size (eo->b) - 64, tmp, 64) == 64) {
			return (bool) r_mem_mem (tmp, 64, (const ut8 *)s, strlen (s));
		}
	}

	return false;
}

static inline bool needle(ELFOBJ *eo, const char *s) {
	if (eo->shstrtab) {
		ut32 len = eo->shstrtab_size;
		if (len > 4096) {
			len = 4096; // avoid slow loading .. can be buggy?
		}
		return (bool) r_mem_mem ((const ut8*)eo->shstrtab, len, (const ut8*)s, strlen (s));
	}
	return false;
}

static char* guess_osabi_name(ELFOBJ *eo) {
	switch (eo->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_LINUX: return strdup ("linux");
	case ELFOSABI_SOLARIS: return strdup ("solaris");
	case ELFOSABI_FREEBSD: return strdup ("freebsd");
	case ELFOSABI_HPUX: return strdup ("hpux");
	}

	if (eo->shdr && eo->shstrtab) {
		size_t num = eo->ehdr.e_shnum;
		size_t i;
		for (i = 0; i < num; i++) {
			if (eo->shdr[i].sh_type == SHT_NOTE && eo->shdr[i].sh_name < eo->shstrtab_size) {
				const char *section_name = &eo->shstrtab[eo->shdr[i].sh_name];
				if (!strcmp (section_name, ".note.openbsd.ident")) {
					return strdup ("openbsd");
				}
				if (!strcmp (section_name, ".note.minix.ident")) {
					return strdup ("minix");
				}
				if (!strcmp (section_name, ".note.netbsd.ident")) {
					return strdup ("netbsd");
				}
				if (!strcmp (section_name, ".note.android.ident")) {
					return strdup ("android");
				}
			}
		}
	}

	// Hack to identify OS
	if (needle (eo, "freebsd")) {
		return strdup ("freebsd");
	}
	if (noodle (eo, "BEOS:APP_VERSION")) {
		return strdup ("beos");
	}
	if (needle (eo, "GNU")) {
		return strdup ("linux");
	}
	// if a lib is "liblog.so", lets assume android again.
	RBinElfLib *it;
	const RVector *libs = Elf_(load_libs)(eo);
	if (libs) {
		r_vector_foreach (libs, it) {
			if (!strcmp (it->name, "liblog.so")) {
				return strdup ("android");
			}
		}
	}
	return strdup ("linux");
}

// TODO: make it const char *
char* Elf_(get_osabi_name)(ELFOBJ *eo) {
	if (eo->osabi) {
		return strdup (eo->osabi);
	}
	eo->osabi = guess_osabi_name (eo);
	return strdup (eo->osabi);
}

typedef struct reg_offset_state {
	size_t i;
	ut64 offset;  // used as output parameter
} RegOffsetState;

static inline bool _calculate_reg_offset(ELFOBJ *eo, RegOffsetState *state) {
	bool success = true;
	ut64 offset = 0;
	while (true) {
		Elf_(Nhdr) elf_nhdr = {0};
		const size_t elf_nhdr_size = sizeof (Elf_(Nhdr));
		int ret = r_buf_read_at (eo->b, eo->phdr[state->i].p_offset + offset, (ut8*) &elf_nhdr, elf_nhdr_size);
		if (ret != elf_nhdr_size) {
			R_LOG_DEBUG ("Cannot read NOTES hdr from CORE file");
			success = false;
			break;
		}

		ut32 n_type = elf_nhdr.n_type;
		if (n_type == NT_PRSTATUS) {
			break;
		}

		ut32 n_descsz = round_up (elf_nhdr.n_descsz);
		ut32 n_namesz = round_up (elf_nhdr.n_namesz);
		offset += elf_nhdr_size + n_descsz + n_namesz;
	}

	state->offset = offset;
	return success;
}

ut8 *Elf_(grab_regstate)(ELFOBJ *eo, int *len) {
	if (!eo->phdr) {
		R_LOG_DEBUG ("Cannot find NOTE section");
		return NULL;
	}

	size_t i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		if (eo->phdr[i].p_type != PT_NOTE) {
			continue;
		}

		RegOffsetState state = { .i = i, .offset = 0 };
		if (!_calculate_reg_offset (eo, &state)) {
			break;
		}

		ut64 offset = state.offset;
		int regdelta = 0;
		int regsize = 0;
		switch (eo->ehdr.e_machine) {
		case EM_AARCH64:
			regsize = reginf[AARCH64].regsize;
			regdelta = reginf[AARCH64].regdelta;
			break;
		case EM_ARM:
			regsize = reginf[ARM].regsize;
			regdelta = reginf[ARM].regdelta;
			break;
		case EM_386:
		case EM_IAMCU:
			regsize = reginf[X86].regsize;
			regdelta = reginf[X86].regdelta;
			break;
		case EM_X86_64:
			regsize = reginf[X86_64].regsize;
			regdelta = reginf[X86_64].regdelta;
			break;
		}

		ut8 *buf = malloc (regsize);
		if (!buf) {
			break;
		}
		if (r_buf_read_at (eo->b, eo->phdr[i].p_offset + offset + regdelta, buf, regsize) != regsize) {
			free (buf);
			R_LOG_DEBUG ("Cannot read register state from CORE file");
			break;
		}
		if (len) {
			*len = regsize;
		}
		return buf;
	}

	R_LOG_DEBUG ("Cannot find NOTE section");
	return NULL;
}

int Elf_(is_big_endian)(ELFOBJ *eo) {
	return eo->ehdr.e_ident[EI_DATA] == ELFDATA2MSB;
}

/* XXX Init dt_strtab? */
char *Elf_(get_rpath)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);

	if (!eo->phdr || !eo->strtab) {
		return NULL;
	}

	Elf_(Xword) val;
	if (eo->dyn_info.dt_rpath != R_BIN_ELF_XWORD_MAX)  {
		val = eo->dyn_info.dt_rpath;
	} else if (eo->dyn_info.dt_runpath != R_BIN_ELF_XWORD_MAX) {
		val = eo->dyn_info.dt_runpath;
	} else {
		return NULL;
	}
	if (val >= eo->strtab_size) {
		return NULL;
	}

	size_t maxlen = R_MIN (ELF_STRING_LENGTH, (eo->strtab_size - val));
	return r_str_ndup (eo->strtab + val, maxlen);
}

static bool has_valid_section_header(ELFOBJ *eo, size_t pos) {
	RBinElfSection *section = r_vector_at (&eo->g_sections, pos);
	return section->info < eo->ehdr.e_shnum && eo->shdr;
}

static void fix_rva_and_offset_relocable_file(ELFOBJ *eo, RBinElfReloc *r, size_t pos) {
	if (has_valid_section_header (eo, pos)) {
		RBinElfSection *section = r_vector_at (&eo->g_sections, pos);
		size_t idx = section->info;
		if (idx < eo->ehdr.e_shnum) {
			ut64 pa = eo->shdr[idx].sh_offset + r->offset;
			r->offset = pa;
			r->rva = Elf_(p2v) (eo, pa);
		} else {
			R_LOG_WARN ("fix_rva_and_offset_reloc have an invalid index");
		}
	} else {
		r->rva = r->offset;
	}
}


static void fix_rva_and_offset_exec_file(ELFOBJ *eo, RBinElfReloc *r) {
	r->rva = r->offset;
	r->offset = Elf_(v2p)(eo, r->offset);
}

static void fix_rva_and_offset(ELFOBJ *eo, RBinElfReloc *r, size_t pos) {
	if (is_bin_etrel (eo)) {
		fix_rva_and_offset_relocable_file (eo, r, pos);
	} else {
		fix_rva_and_offset_exec_file (eo, r);
	}
}

// Function to read one byte of ULEB128 encoded data
static ut64 read_uleb128(const ut8 *data, int data_size, ut64 *val, int *read_bytes) {
	ut64 result = 0;
	int shift = 0;
	int count = 0;
	while (count < data_size) {
		ut8 b = data[count++];
		result |= ((ut64)(b & 0x7f)) << shift;
		if (!(b & 0x80)) {
			break;
		}
		shift += 7;
		if (shift >= 64) {
			break;
		}
	}
	if (val) {
		*val = result;
	}
	if (read_bytes) {
		*read_bytes = count;
	}
	return result;
}

// Function to read one byte of SLEB128 encoded data
static st64 read_sleb128(const ut8 *data, int data_size, st64 *val, int *read_bytes) {
	ut64 result = 0;
	int shift = 0;
	int count = 0;
	ut8 b = 0;
	while (count < data_size) {
		b = data[count++];
		result |= (ut64)((b & 0x7f)) << shift;
		shift += 7;
		if (!(b & 0x80)) {
			break;
		}
		if (shift >= 64) {
			break;
		}
	}
	// Sign extend if needed
	if ((b & 0x40) && shift > 0 && shift < 64) {
		result |= ~0ULL << shift;
	}
	if (val) {
		*val = (st64)result;
	}
	if (read_bytes) {
		*read_bytes = count;
	}
	return (st64)result;
}

// Structure to track CREL state
typedef struct {
	ut64 count;       // Number of relocations
	ut8 addend_bit;   // Addend bit flag (0 or 1)
	ut8 shift;        // Shift value (0 to 3)
	ut64 offset;      // Current offset
	ut32 symidx;      // Current symbol index
	ut32 type;        // Current relocation type
	st64 addend;      // Current addend
	ut64 section_offset; // File offset of the section
	ut64 current_pos; // Current position within the section
	bool header_read; // Whether header has been read
} CrelInfo;

// Helper function to initialize a CrelInfo structure
static bool init_crel_info(ELFOBJ *eo, ut64 section_offset, CrelInfo *info) {
	R_RETURN_VAL_IF_FAIL (eo && info, false);
	memset (info, 0, sizeof (CrelInfo));
	info->section_offset = section_offset;
	info->current_pos = section_offset;
	info->header_read = false;
	return true;
}

// Function to read a CREL header
static bool read_crel_header(ELFOBJ *eo, CrelInfo *info) {
	if (!info || info->header_read) {
		return false;
	}
	ut8 header_buf[16] = {0}; // Max ULEB128 size for 64-bit
	int res = r_buf_read_at (eo->b, info->current_pos, header_buf, sizeof (header_buf));
	if (res <= 0) {
		return false;
	}
	ut64 header_val = 0;
	int bytes_read = 0;
	read_uleb128 (header_buf, sizeof (header_buf), &header_val, &bytes_read);
	info->count = header_val >> 3;
	info->addend_bit = (header_val >> 2) & 1;
	info->shift = header_val & 3;
	info->current_pos += bytes_read;
	info->header_read = true;
	return true;
}

// Function to read a CREL relocation entry
static bool read_crel_reloc(ELFOBJ *eo, RBinElfReloc *r, ut64 vaddr, ut64 *next_offset) {
	static CrelInfo crel_info = {0};
	static ut64 last_section_offset = 0;
	ut64 offset = Elf_(v2p_new) (eo, vaddr);
	if (offset == UT64_MAX) {
		return false;
	}
	// Check if we're processing a new section
	if (offset != last_section_offset && offset != crel_info.current_pos) {
		init_crel_info(eo, offset, &crel_info);
		last_section_offset = offset;
	}
	// Read the CREL header if we haven't already
	if (!crel_info.header_read) {
		if (!read_crel_header(eo, &crel_info)) {
			return false;
		}
	}
	// Make sure we have relocations left to read
	if (crel_info.count <= 0) {
		return false;
	}
	// Read the next relocation entry
	ut8 buf[64] = {0}; // Buffer for reading relocation data
	int res = r_buf_read_at (eo->b, crel_info.current_pos, buf, sizeof (buf));
	if (res <= 0) {
		return false;
	}
	// Parse delta offset and flags
	int read_pos = 0;
	ut8 b = buf[read_pos++];
	// Extract flags
	int flag_bits = crel_info.addend_bit ? 3 : 2;
	ut8 flags = b & ((1 << flag_bits) - 1);
	// Extract delta offset
	ut64 delta_offset = b >> flag_bits;
	if (b & 0x80) {
		// Handle large delta_offset
		int bytes_read = 0;
		ut64 high_bits = 0;
		read_uleb128 (&buf[read_pos], sizeof (buf) - read_pos, &high_bits, &bytes_read);
		read_pos += bytes_read;
		delta_offset = delta_offset | (high_bits << (7 - flag_bits));
		delta_offset -= (0x80 >> flag_bits);
	}
	// Apply shift to delta_offset
	crel_info.offset += (delta_offset << crel_info.shift);
	// Handle delta symbol index if present
	if (flags & 1) {
		st64 delta_symidx = 0;
		int bytes_read = 0;
		read_sleb128 (&buf[read_pos], sizeof (buf) - read_pos, &delta_symidx, &bytes_read);
		read_pos += bytes_read;
		crel_info.symidx += delta_symidx;
	}
	// Handle delta type if present
	if (flags & 2) {
		st64 delta_type = 0;
		int bytes_read = 0;
		read_sleb128 (&buf[read_pos], sizeof (buf) - read_pos, &delta_type, &bytes_read);
		read_pos += bytes_read;
		crel_info.type += delta_type;
	}
	// Handle delta addend if present and addend_bit is set
	if ((flags & 4) && crel_info.addend_bit) {
		st64 delta_addend = 0;
		int bytes_read = 0;
		read_sleb128 (&buf[read_pos], sizeof (buf) - read_pos, &delta_addend, &bytes_read);
		read_pos += bytes_read;
		crel_info.addend += delta_addend;
	}
	// Update position for next read
	crel_info.current_pos += read_pos;
	crel_info.count--;
	// Fill in the relocation structure
	r->mode = DT_CREL;
	r->offset = crel_info.offset;  // This is the file offset
	r->rva = crel_info.offset;     // Also store as RVA for now, will be adjusted in fix_rva_and_offset
	r->sym = crel_info.symidx;
	r->type = crel_info.type;
	r->addend = crel_info.addend_bit ? crel_info.addend : 0;
	// Return next offset if requested
	if (next_offset) {
		*next_offset = crel_info.current_pos - offset;
	}
	return true;
}

typedef struct {
	ut64 next_addr;
	bool has_next_addr;
} RelrInfo;

static bool read_relr_entry(ELFOBJ *eo, RBinElfReloc *r, ut64 vaddr, ut64 entry, RelrInfo *info) {
	R_RETURN_VAL_IF_FAIL (eo && r && info, false);
	bool arm64 = eo->ehdr.e_machine == EM_AARCH64;

	// If entry is even (LSB == 0), it's an address to relocate
	if ((entry & 1) == 0) {
		r->mode = DT_RELR;
		r->offset = entry;
		r->rva = entry;
		r->type = arm64? R_AARCH64_RELATIVE: R_X86_64_RELATIVE;
		r->sym = 0; // RELR relocations don't refer to symbols
		r->addend = 0;
		// Set next_addr to the word after the one pointed to by entry
		info->next_addr = entry + sizeof (Elf_(Addr));
		info->has_next_addr = true;
		return true;
	}
	// It's a bitmap - only process if we have a valid next_addr
	if (!info->has_next_addr) {
		return false;
	}
	// Find first set bit in bitmap (skipping LSB which is always 1)
	ut64 bitmap = entry >> 1;
	int bit_pos = 0;
	while (bitmap) {
		if (bitmap & 1) {
			r->mode = DT_RELR;
			r->offset = info->next_addr + (bit_pos * sizeof (Elf_(Addr)));
			r->rva = r->offset;
			r->type = arm64? R_AARCH64_RELATIVE: R_X86_64_RELATIVE;
			r->sym = 0; // RELR relocations don't refer to symbols
			r->addend = 0;
			return true;
		}
		bitmap >>= 1;
		bit_pos++;
	}
	// No bits set or all processed - update next_addr for next bitmap
	info->next_addr += (sizeof (Elf_(Addr)) * 8 - 1) * sizeof (Elf_(Addr));
	return false;
}

static bool read_reloc(ELFOBJ *eo, RBinElfReloc *r, Elf_(Xword) rel_mode, ut64 vaddr) {
	static RelrInfo relr_info = {0};
	// Handle RELR entries
	if (rel_mode == DT_RELR) {
		size_t i;
		ut64 offset = Elf_(v2p_new) (eo, vaddr);
		if (offset == UT64_MAX) {
			return false;
		}
		ut8 buf[sizeof (Elf_(Addr))] = {0};
		int res = r_buf_read_at (eo->b, offset, buf, sizeof (Elf_(Addr)));
		if (res != sizeof (Elf_(Addr))) {
			return false;
		}
		ut64 entry = 0;
		for (i = 0; i < sizeof (Elf_(Addr)); i++) {
			entry |= (ut64)(buf[i]) << (i * 8);
		}
		return read_relr_entry (eo, r, vaddr, entry, &relr_info);
	}
	// Handle CREL entries differently
	if (rel_mode == DT_CREL) {
		ut64 next_offset = 0;
		return read_crel_reloc (eo, r, vaddr, &next_offset);
	}
	// Regular REL/RELA processing
	ut64 offset = Elf_(v2p_new) (eo, vaddr);
	if (offset == UT64_MAX) {
		return false;
	}
	size_t size_struct = get_size_rel_mode (rel_mode);
	ut8 buf[sizeof (Elf_(Rela))] = {0};
	int res = r_buf_read_at (eo->b, offset, buf, size_struct);
	if (res != size_struct) {
		return false;
	}
	size_t i = 0;
	Elf_(Rela) reloc_info;
	reloc_info.r_offset = R_BIN_ELF_READWORD (buf, i);
	reloc_info.r_info = R_BIN_ELF_READWORD (buf, i);
	if (rel_mode == DT_RELA) {
		reloc_info.r_addend = R_BIN_ELF_READWORD (buf, i);
		r->addend = reloc_info.r_addend;
	}
	r->mode = rel_mode;
	r->offset = reloc_info.r_offset;
	r->sym = ELF_R_SYM (reloc_info.r_info);
	r->type = ELF_R_TYPE (reloc_info.r_info);
	return true;
}

static size_t get_num_relocs_dynamic(ELFOBJ *eo) {
	size_t res = 0;

	if (eo->dyn_info.dt_relaent) {
		res += eo->dyn_info.dt_relasz / eo->dyn_info.dt_relaent;
	}

	if (eo->dyn_info.dt_relent) {
		res += eo->dyn_info.dt_relsz / eo->dyn_info.dt_relent;
	}
	// Add RELR relocations count estimation
	// Each RELR entry is the size of an address, but bitmap entries can encode multiple relocations
	// So we use a conservative estimate of the number of relocations
	if (eo->dyn_info.dt_relrent && eo->dyn_info.dt_relrsz) {
		// Estimate the number of relocations - in worst case, each entry is just a single relocation
		res += eo->dyn_info.dt_relrsz / eo->dyn_info.dt_relrent;
	} else if (eo->dyn_info.dt_relrsz) {
		// If relrent is not set, assume it's the size of an address
		res += eo->dyn_info.dt_relrsz / sizeof (Elf_(Addr));
	}

	return res + get_num_relocs_dynamic_plt (eo);
}

static bool section_is_valid(ELFOBJ *eo, RBinElfSection *sect) {
	return sect->offset + sect->size <= eo->size;
}

static Elf_(Xword) get_section_mode(ELFOBJ *eo, size_t pos) {
	RBinElfSection *section = r_vector_at (&eo->g_sections, pos);
	if (r_str_startswith (section->name, ".rela.")) {
		return DT_RELA;
	}
	if (r_str_startswith (section->name, ".rel.")) {
		return DT_REL;
	}
	if ((section->type & 0xff) == SHT_CREL) {
		// Check for .crel. prefix to ensure we're dealing with CREL sections
		if (r_str_startswith (section->name, ".crel.")) {
			return DT_CREL;
		}
	}
	if (r_str_startswith (section->name, ".relr.") || section->type == SHT_RELR) {
		return DT_RELR;
	}
	return 0;
}

static bool is_reloc_section(Elf_(Xword) rel_mode) {
	return rel_mode == DT_REL || rel_mode == DT_RELA || rel_mode == DT_CREL || rel_mode == DT_RELR;
}

static size_t get_num_relocs_sections(ELFOBJ *eo) {
	if (!eo->sections_loaded) {
		return 0;
	}

	size_t ret = 0;
	size_t i = 0;
	RBinElfSection *section;
	r_vector_foreach (&eo->g_sections, section) {
		if (!section_is_valid (eo, section)) {
			i++;
			continue;
		}

		Elf_(Xword) rel_mode = get_section_mode (eo, i);
		if (!is_reloc_section (rel_mode)) {
			i++;
			continue;
		}

		size_t size = get_size_rel_mode (rel_mode);
		if (size > 0) {
			ret += NUMENTRIES_ROUNDUP (section->size, size);
		}
		i++;
	}

	return ret;
}

static size_t get_num_relocs_approx(ELFOBJ *eo) {
	size_t total = get_num_relocs_dynamic (eo) + get_num_relocs_sections (eo);
	if (total > eo->size) {
		return eo->size / 2;
	}
	return total;
}

static size_t populate_relocs_record_from_dynamic(ELFOBJ *eo, size_t pos, size_t num_relocs) {
	size_t size = get_size_rel_mode (eo->dyn_info.dt_pltrel);
	ut64 offset;
	ut64 offset_end = eo->dyn_info.dt_pltrelsz;
	// order matters
	// parse pltrel
	for (offset = 0; offset < offset_end && pos < num_relocs; offset += size, pos++) {
		RBinElfReloc *reloc = r_vector_end (&eo->g_relocs);
		if (!reloc) {
			break;
		}
		if (!read_reloc (eo, reloc, eo->dyn_info.dt_pltrel, eo->dyn_info.dt_jmprel + offset)) {
			r_vector_pop (&eo->g_relocs, NULL);
			break;
		}

		// XXX reloc is a weak pointer we can't own it!
		int index = r_vector_index (&eo->g_relocs);
		ht_uu_insert (eo->rel_cache, reloc->sym + 1, index + 1);
		fix_rva_and_offset_exec_file (eo, reloc);
	}
	// parse relr - Relative relocations
	if (eo->dyn_info.dt_relr != R_BIN_ELF_ADDR_MAX) {
		offset = 0;
		while (offset < eo->dyn_info.dt_relrsz && pos < num_relocs) {
			RBinElfReloc *reloc = r_vector_end (&eo->g_relocs);
			if (!read_reloc (eo, reloc, DT_RELR, eo->dyn_info.dt_relr + offset)) {
				// If read_reloc fails for RELR, it might be processing a bitmap entry
				// Try the next entry
				r_vector_pop (&eo->g_relocs, NULL);
				offset += sizeof (Elf_(Addr));
				continue;
			}
			int index = r_vector_index (&eo->g_relocs);
			ht_uu_insert (eo->rel_cache, reloc->sym + 1, index + 1);
			fix_rva_and_offset_exec_file (eo, reloc);
			pos++;
			offset += sizeof (Elf_(Addr));
		}
	}
	// parse rela
	for (offset = 0; offset < eo->dyn_info.dt_relasz && pos < num_relocs; offset += eo->dyn_info.dt_relaent, pos++) {
		RBinElfReloc *reloc = r_vector_end (&eo->g_relocs);
		if (!read_reloc (eo, reloc, DT_RELA, eo->dyn_info.dt_rela + offset)) {
			r_vector_pop (&eo->g_relocs, NULL);
			break;
		}
		int index = r_vector_index (&eo->g_relocs);
		ht_uu_insert (eo->rel_cache, reloc->sym + 1, index + 1);
		fix_rva_and_offset_exec_file (eo, reloc);
	}

	for (offset = 0; offset < eo->dyn_info.dt_relsz && pos < num_relocs; offset += eo->dyn_info.dt_relent, pos++) {
		RBinElfReloc *reloc = r_vector_end (&eo->g_relocs);
		if (!read_reloc (eo, reloc, DT_REL, eo->dyn_info.dt_rel + offset)) {
			r_vector_pop (&eo->g_relocs, NULL);
			break;
		}
		int index = r_vector_index (&eo->g_relocs);
		ht_uu_insert (eo->rel_cache, reloc->sym + 1, index + 1);
		fix_rva_and_offset_exec_file (eo, reloc);
	}
	// parse crel - Compact Relocations
	if (eo->dyn_info.dt_crel != R_BIN_ELF_ADDR_MAX) {
		// CREL uses variable-length encoding, so we can't use the same approach as above
		ut64 next_offset = 0;
		while (pos < num_relocs) {
			RBinElfReloc *reloc = r_vector_end (&eo->g_relocs);
			if (!read_crel_reloc (eo, reloc, eo->dyn_info.dt_crel + next_offset, &next_offset)) {
				r_vector_pop (&eo->g_relocs, NULL);
				break;
			}
			int index = r_vector_index (&eo->g_relocs);
			ht_uu_insert (eo->rel_cache, reloc->sym + 1, index + 1);
			// For CREL relocations from dynamic table, we need to convert offset to address
			ut64 vaddr = Elf_(p2v) (eo, reloc->offset);
			reloc->rva = vaddr;  // Ensure rva is properly set
			fix_rva_and_offset_exec_file (eo, reloc);
			pos++;
		}
	}
	return pos;
}

static ut64 get_next_not_analysed_offset(ELFOBJ *eo, size_t section_vaddr, size_t offset) {
	size_t gvaddr = section_vaddr + offset;

	if (eo->dyn_info.dt_rela != R_BIN_ELF_ADDR_MAX \
		&& gvaddr >= eo->dyn_info.dt_rela \
		&& gvaddr < eo->dyn_info.dt_rela + eo->dyn_info.dt_relasz) {
		return eo->dyn_info.dt_rela + eo->dyn_info.dt_relasz - section_vaddr;
	}

	if (eo->dyn_info.dt_rel != R_BIN_ELF_ADDR_MAX \
		&& gvaddr >= eo->dyn_info.dt_rel \
		&& gvaddr < eo->dyn_info.dt_rel + eo->dyn_info.dt_relsz) {
		return eo->dyn_info.dt_rel + eo->dyn_info.dt_relsz - section_vaddr;
	}

	if (eo->dyn_info.dt_jmprel != R_BIN_ELF_ADDR_MAX \
		&& gvaddr >= eo->dyn_info.dt_jmprel \
		&& gvaddr < eo->dyn_info.dt_jmprel + eo->dyn_info.dt_pltrelsz) {
		return eo->dyn_info.dt_jmprel + eo->dyn_info.dt_pltrelsz - section_vaddr;
	}

	// Add support for CREL sections
	if (eo->dyn_info.dt_crel != R_BIN_ELF_ADDR_MAX \
		&& gvaddr >= eo->dyn_info.dt_crel) {
		// Since CREL sections use variable-length encoding, we can't easily
		// determine the end offset. For now, we'll just skip the section entirely.
		return UT64_MAX;
	}
	// Add support for RELR sections
	if (eo->dyn_info.dt_relr != R_BIN_ELF_ADDR_MAX \
		&& gvaddr >= eo->dyn_info.dt_relr \
		&& gvaddr < eo->dyn_info.dt_relr + eo->dyn_info.dt_relrsz) {
		return eo->dyn_info.dt_relr + eo->dyn_info.dt_relrsz - section_vaddr;
	}

	return offset;
}

#if 0
static bool populate_relocs_record_from_section(ELFOBJ *eo, Elf_(Shdr) *shdr) {
	if (!eo || !shdr) {
		return false;
	}

	switch (shdr->sh_type) {
	case SHT_REL:
	case SHT_RELA:
		return read_reloc (eo, shdr);

	case SHT_CREL: // New section type for compact reloc
		return parse_crel_section (eo, shdr);
	default:
		return false;
	}
}
#endif

static size_t populate_relocs_record_from_section(ELFOBJ *eo, size_t pos, size_t num_relocs) {
	if (!eo->sections_loaded) {
		return pos;
	}

	size_t i = 0;
	RBinElfSection *section;
	r_vector_foreach (&eo->g_sections, section) {
		Elf_(Xword) rel_mode = get_section_mode (eo, i);
		if (!is_reloc_section (rel_mode)) {
			i++;
			continue;
		}
		if (section->size > eo->size || section->offset > eo->size) {
			i++;
			continue;
		}

		// Handle CREL sections differently since they use variable-length encoding
		if (rel_mode == DT_CREL) {
			ut64 next_offset = 0;
			ut64 j = 0;
			// Process all CREL relocations in the section
			while (j < section->size && pos <= num_relocs) {
				RBinElfReloc *reloc = r_vector_end (&eo->g_relocs);
				if (!read_crel_reloc (eo, reloc, section->rva + j, &next_offset)) {
					// If read_crel_reloc returns false, either we're done or encountered an error
					// In either case, break the loop
					r_vector_pop (&eo->g_relocs, NULL);
					break;
				}

				int index = r_vector_index (&eo->g_relocs);
				ht_uu_insert (eo->rel_cache, reloc->sym, index);
				// For CREL relocations from sections, make sure rva is properly set
				if (is_bin_etrel (eo)) {
					// For relocatable files, find target section
					if (has_valid_section_header (eo, i)) {
						RBinElfSection *target_section = r_vector_at (&eo->g_sections, i);
						size_t idx = target_section->info;
						if (idx < eo->ehdr.e_shnum) {
							// Map file offset to virtual address in target section
							reloc->rva = eo->shdr[idx].sh_addr + reloc->offset;
						}
					}
				} else {
					// For executables, offset is target address
					reloc->rva = reloc->offset;
				}
				fix_rva_and_offset (eo, reloc, i);
				pos++;

				// Move to next relocation
				j += next_offset;
			}
		} else {
			// Standard REL/RELA handling
			size_t size = get_size_rel_mode (rel_mode);
			if (!size) {
				continue;
			}
			ut64 dim_relocs = section->size / size;
			dim_relocs = R_MIN (dim_relocs, num_relocs) + 2;
			ut64 j;
			for (j = get_next_not_analysed_offset (eo, section->rva, 0);
				j < section->size && pos <= dim_relocs;
				j = get_next_not_analysed_offset (eo, section->rva, j + size)) {

				RBinElfReloc *reloc = r_vector_end (&eo->g_relocs);
				if (!read_reloc (eo, reloc, rel_mode, section->rva + j)) {
					r_vector_pop (&eo->g_relocs, NULL);
					break;
				}

				int index = r_vector_index (&eo->g_relocs);
				ht_uu_insert (eo->rel_cache, reloc->sym, index);
				fix_rva_and_offset (eo, reloc, i);
				pos++;
			}
		}

		i++;
	}

	return pos;
}

static bool populate_relocs_record(ELFOBJ *eo) {
	r_vector_init (&eo->g_relocs, sizeof (RBinElfReloc), NULL, NULL);
	size_t num_relocs = get_num_relocs_approx (eo);

	if (!r_vector_reserve (&eo->g_relocs, num_relocs)) {
		// In case we can't allocate enough memory for all the claimed
		// relocation entries, try to parse only the ones specified in
		// the dynamic segment.
		num_relocs = get_num_relocs_dynamic (eo);
		if (!r_vector_reserve (&eo->g_relocs, num_relocs)) {
			return false;
		}
	}

	size_t i = 0;
	i = populate_relocs_record_from_dynamic (eo, i, num_relocs);
	i = populate_relocs_record_from_section (eo, i, num_relocs);
	eo->g_reloc_num = i;
	return true;
}

const RVector *Elf_(load_relocs) (ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);
	if (eo->relocs_loaded) {
		return &eo->g_relocs;
	}
	eo->relocs_loaded = true;
	if (!populate_relocs_record (eo)) {
		return NULL;
	}
	return &eo->g_relocs;
}

const RVector* Elf_(load_libs)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);

	if (eo->libs_loaded) {
		return &eo->g_libs;
	}

	eo->libs_loaded = true;
	r_vector_init (&eo->g_libs, sizeof (RBinElfLib), NULL, NULL);

	if (!eo->phdr || !eo->strtab || (eo->strtab[0] && eo->strtab[1] == '0')) {
		return NULL;
	}

	Elf_(Off) *it = NULL;
	r_vector_foreach (&eo->dyn_info.dt_needed, it) {
		Elf_(Off) val = *it;
		if (val > eo->strtab_size) {
			r_vector_clear (&eo->g_libs);
			return NULL;
		}

		const char *const name = (eo->strtab + val);
		if (!name[0]) {
			continue;
		}

		RBinElfLib *lib = r_vector_end (&eo->g_libs);
		r_str_ncpy (lib->name, name, ELF_STRING_LENGTH);
		lib->name[ELF_STRING_LENGTH - 1] = '\0';
	}

	return &eo->g_libs;
}

static void create_section_from_phdr(ELFOBJ *eo, const char *name, ut64 addr, ut64 sz) {
	R_RETURN_IF_FAIL (eo);
	if (addr && addr != UT64_MAX) {
		RBinElfSection *section = r_vector_end (&eo->g_sections);
		section->offset = Elf_(v2p_new) (eo, addr);
		section->rva = addr;
		section->size = sz;
		r_str_ncpy (section->name, name, R_ARRAY_SIZE (section->name) - 1);
	}
}

static const RVector *load_sections_from_phdr(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo && eo->phdr, NULL);

	if (!eo->ehdr.e_phnum) {
		return NULL;
	}

	size_t num_sections = 0;
	ut64 reldyn = 0, relava = 0, pltgotva = 0, relva = 0;
	ut64 reldynsz = 0, relasz = 0, pltgotsz = 0;
	ut64 relr = 0, relrsz = 0;

	if (eo->dyn_info.dt_rel != R_BIN_ELF_ADDR_MAX) {
		reldyn = eo->dyn_info.dt_rel;
		num_sections++;
	}
	if (eo->dyn_info.dt_rela != R_BIN_ELF_ADDR_MAX) {
		relva = eo->dyn_info.dt_rela;
		num_sections++;
	}
	if (eo->dyn_info.dt_relr != R_BIN_ELF_ADDR_MAX) {
		relr = eo->dyn_info.dt_relr;
		num_sections++;
	}
	if (eo->dyn_info.dt_relsz) {
		reldynsz = eo->dyn_info.dt_relsz;
	}
	if (eo->dyn_info.dt_relrsz) {
		relrsz = eo->dyn_info.dt_relrsz;
	}
	if (eo->dyn_info.dt_relasz) {
		relasz = eo->dyn_info.dt_relasz;
	}
	if (eo->dyn_info.dt_pltgot != R_BIN_ELF_ADDR_MAX) {
		pltgotva = eo->dyn_info.dt_pltgot;
		num_sections++;
	}
	if (eo->dyn_info.dt_pltrelsz) {
		pltgotsz = eo->dyn_info.dt_pltrelsz;  // XXX pltrel or pltgot?
	}
	if (eo->dyn_info.dt_jmprel != R_BIN_ELF_ADDR_MAX) {
		relava = eo->dyn_info.dt_jmprel;
		num_sections++;
	}

	if (!r_vector_reserve (&eo->g_sections, num_sections)) {
		return NULL;
	}

	create_section_from_phdr (eo, ".rel.dyn", reldyn, reldynsz);
	create_section_from_phdr (eo, ".rela.plt", relava, pltgotsz);
	create_section_from_phdr (eo, ".relr.dyn", relr, relrsz);
	create_section_from_phdr (eo, ".rel.plt", relva, relasz);
	create_section_from_phdr (eo, ".got.plt", pltgotva, pltgotsz);
	return &eo->g_sections;
}

static const RVector *_load_elf_sections(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);
	if (eo->sections_loaded) {
		return &eo->g_sections;
	}

	eo->sections_loaded = true;
	r_vector_init (&eo->g_sections, sizeof (RBinElfSection), NULL, NULL);

	if (!eo->shdr && eo->phdr) {
		// we don't give up search in phdr section
		return load_sections_from_phdr (eo);
	}

	if (!eo->shdr) {
		return NULL;
	}

	ut32 count = eo->ehdr.e_shnum;
	if (!r_vector_reserve (&eo->g_sections, count)) {
		return NULL;
	}

	int unknown_count = 0, invalid_count = 0;
	int i;
	for (i = 0; i < count; i++) {
		RBinElfSection *section = r_vector_end (&eo->g_sections);
		section->offset = eo->shdr[i].sh_offset;
		section->size = eo->shdr[i].sh_size;
		section->align = eo->shdr[i].sh_addralign;
		section->flags = eo->shdr[i].sh_flags;
		section->link = eo->shdr[i].sh_link;
		section->info = eo->shdr[i].sh_info;
		section->type = eo->shdr[i].sh_type;

		if (is_bin_etrel (eo)) {
			section->rva = eo->baddr + eo->shdr[i].sh_offset;
		} else {
			section->rva = eo->shdr[i].sh_addr;
		}

		const int SHNAME = (int)eo->shdr[i].sh_name;
		const int SHSIZE = (int)eo->shstrtab_size;
		int nidx = SHNAME;
		if (nidx < 0 || !eo->shstrtab_section || !eo->shstrtab_size || nidx > eo->shstrtab_size) {
			char invalid_s[32];
			snprintf (invalid_s, sizeof (invalid_s), "invalid%d", invalid_count);
			strncpy (section->name, invalid_s, sizeof (section->name) - 1);
			invalid_count++;
		} else if (eo->shstrtab && (SHNAME > 0) && (SHNAME < SHSIZE)) {
			strncpy (section->name, &eo->shstrtab[SHNAME], sizeof (section->name) - 1);
		} else if (eo->shdr[i].sh_type == SHT_NULL) {
			//to follow the same behaviour as readelf
			section->name[0] = '\0';
		} else {
			char unknown_s[32];
			snprintf (unknown_s, sizeof (unknown_s), "unknown%d", unknown_count);
			strncpy (section->name, unknown_s, sizeof (section->name) - 1);
			unknown_count++;
		}
		section->name[ELF_STRING_LENGTH - 1] = '\0';
	}

	return &eo->g_sections;
}

static int elf_flags_to_section_perms(int flags) {
	int perm = 0;
	if (R_BIN_ELF_SCN_IS_EXECUTABLE (flags)) {
		perm |= R_PERM_X;
	}
	if (R_BIN_ELF_SCN_IS_WRITABLE (flags)) {
		perm |= R_PERM_W;
	}
	if (R_BIN_ELF_SCN_IS_READABLE (flags)) {
		perm |= R_PERM_R;
	}
	return perm;
}

static bool is_data_section(const char *name) {
	if (strstr (name, "data") && !strstr (name, "rel") && !strstr (name, "pydata")) {
		return true;
	}
#if 0
	// we use Css in this section->format to avoid the flags and just add the meta
	if (!strcmp (name, ".dynstr")) {
		return true;
	}
#endif
	if (!strcmp (name, "C")) {
		return true;
	}
	return false;
}

static bool is_wordable_section(const char *name) {
	// R2R db/cmd/cmd_ie
	const char *sections[] = {
		".init_array",
		".fini_array",
		".data.rel.ro",
		".hash",
		".dynsym",
		".dynamic",
		".rel.plt",
		".got",
		".rela.plt"
	};
	int i;
	for (i = 0; i < R_ARRAY_SIZE (sections); i++) {
		if (!strcmp (name, sections[i])) {
			return true;
		}
	}

	return !!strstr (name, ".rela.");
}

static void dtproceed(RBinFile *bf, ut64 preinit_addr, ut64 preinit_size, int symtype) {
	ELFOBJ *eo = R_UNWRAP3 (bf, bo, bin_obj);
	RListIter *iter;
	RBinAddr *ba;
	r_list_foreach (eo->inits, iter, ba) {
		if (preinit_addr == ba->paddr) {
			return;
		}
	}

	int big_endian = Elf_(is_big_endian) (eo);
	ut64 _baddr = Elf_(get_baddr) (bf->bo->bin_obj);
	ut64 from = Elf_(v2p) (eo, preinit_addr);
	ut64 to = from + preinit_size;
	if (to > eo->size) {
		to = eo->size;
	}
	ut64 at;
	for (at = from; at < to; at += R_BIN_ELF_WORDSIZE) {
		ut64 addr = 0;
		if (R_BIN_ELF_WORDSIZE == 8) {
			addr = r_buf_read_ble64_at (bf->buf, at, big_endian);
		} else {
			addr = r_buf_read_ble32_at (bf->buf, at, big_endian);
		}
		if (!addr || addr == UT64_MAX) {
			R_LOG_DEBUG ("invalid dynamic init address at 0x%08"PFMT64x, at);
			break;
		}
		ut64 caddr = Elf_(v2p) (eo, addr);
		if (!caddr) {
			R_LOG_DEBUG ("v2p failed for 0x%08"PFMT64x, caddr);
			break;
		}
		ba = R_NEW0 (RBinAddr);
		ba->paddr = caddr;
		ba->vaddr = addr;
		ba->hpaddr = at;
		ba->hvaddr = at + _baddr;
		ba->bits = R_BIN_ELF_WORDSIZE * 8;
		ba->type = symtype;
		r_list_append (eo->inits, ba);
	}
}

static bool parse_pt_dynamic(RBinFile *bf, RBinSection *ptr) {
	ELFOBJ *eo = R_UNWRAP3 (bf, bo, bin_obj);
	int big_endian = Elf_(is_big_endian) (eo);
	Elf_(Dyn) entry;
	ut64 preinit_addr = UT64_MAX;
	ut64 preinit_size = UT64_MAX;
	ut64 init_addr = UT64_MAX;
	ut64 init_size = UT64_MAX;
	ut64 fini_addr = UT64_MAX;
	ut64 fini_size = UT64_MAX;

	ut64 paddr = ptr->paddr;
	ut64 paddr_end = paddr + ptr->size;
	if (paddr_end > eo->size) {
		paddr_end = eo->size;
	}
	ut64 at;
	for (at = paddr; at < paddr_end; at += sizeof (Elf_(Dyn))) {
#if R_BIN_ELF64
		entry.d_tag = r_buf_read_ble64_at (bf->buf, at, big_endian);
		if (entry.d_tag == UT64_MAX) {
			R_LOG_DEBUG ("Corrupted elf tag");
			break;
		}
		entry.d_un.d_val = r_buf_read_ble64_at (bf->buf, at + sizeof (entry.d_tag), big_endian);
#else
		entry.d_tag = r_buf_read_ble32_at (bf->buf, at, big_endian);
		if (entry.d_tag == UT32_MAX) {
			R_LOG_DEBUG ("Corrupted elf tag");
			break;
		}
		entry.d_un.d_val = r_buf_read_ble32_at (bf->buf, at + sizeof (entry.d_tag), big_endian);
#endif
		if (entry.d_tag == DT_NULL) {
			break;
		}
		switch (entry.d_tag) {
		case DT_RELR:
			R_LOG_DEBUG ("RELR section found at 0x%08"PFMT64x, entry.d_un.d_ptr);
			eo->dyn_info.dt_relr = entry.d_un.d_ptr;
			break;
		case DT_RELRSZ:
			R_LOG_DEBUG ("RELR section size: 0x%08"PFMT64x, entry.d_un.d_val);
			eo->dyn_info.dt_relrsz = entry.d_un.d_val;
			break;
		case DT_RELRENT:
			R_LOG_DEBUG ("RELR entry size: 0x%08"PFMT64x, entry.d_un.d_val);
			eo->dyn_info.dt_relrent = entry.d_un.d_val;
			break;
		case DT_INIT_ARRAY:
			R_LOG_DEBUG ("init array");
			init_addr = entry.d_un.d_val;
			if (init_size != UT64_MAX) {
				dtproceed (bf, init_addr, init_size, R_BIN_ENTRY_TYPE_INIT);
				init_addr = UT64_MAX;
				init_size = UT64_MAX;
			}
			break;
		case DT_INIT_ARRAYSZ:
			init_size = entry.d_un.d_val;
			R_LOG_DEBUG ("init array size");
			if (init_addr != UT64_MAX) {
				dtproceed (bf, init_addr, init_size, R_BIN_ENTRY_TYPE_INIT);
				init_addr = UT64_MAX;
				init_size = UT64_MAX;
			}
			break;
		case DT_FINI_ARRAY:
			R_LOG_DEBUG ("fini array");
			fini_addr = entry.d_un.d_val;
			if (fini_size != UT64_MAX) {
				dtproceed (bf, fini_addr, fini_size, R_BIN_ENTRY_TYPE_FINI);
				fini_addr = UT64_MAX;
				fini_size = UT64_MAX;
			}
			break;
		case DT_FINI_ARRAYSZ:
			fini_size = entry.d_un.d_val;
			R_LOG_DEBUG ("fini array size");
			if (fini_addr != UT64_MAX) {
				dtproceed (bf, fini_addr, fini_size, R_BIN_ENTRY_TYPE_FINI);
				fini_addr = UT64_MAX;
				fini_size = UT64_MAX;
			}
			break;
		case DT_PREINIT_ARRAY:
			R_LOG_DEBUG ("preinit array");
			preinit_addr = entry.d_un.d_val;
			if (preinit_size != UT64_MAX) {
				dtproceed (bf, preinit_addr, preinit_size, R_BIN_ENTRY_TYPE_PREINIT);
				preinit_addr = UT64_MAX;
				preinit_size = UT64_MAX;
			}
			break;
		case DT_PREINIT_ARRAYSZ:
			R_LOG_DEBUG ("preinit array size");
			preinit_size = entry.d_un.d_val;
			if (preinit_addr != UT64_MAX) {
				dtproceed (bf, preinit_addr, preinit_size, R_BIN_ENTRY_TYPE_PREINIT);
				preinit_addr = UT64_MAX;
				preinit_size = UT64_MAX;
			}
			break;
		default:
			R_LOG_DEBUG ("add dt.dyn.entry tag=%d value=0x%08"PFMT64x, entry.d_tag, (ut64)entry.d_un.d_val);
			break;
		}
	}
	return true;
}

static const char *elf_section_type_tostring(int shtype) {
	switch (shtype) {
	case SHT_NULL: return "NULL";
	case SHT_DYNAMIC: return "DYNAMIC";
	case SHT_GNU_versym: return "GNU_VERSYM";
	case SHT_GNU_verneed: return "GNU_VERNEED";
	case SHT_GNU_verdef: return "GNU_VERDEF";
	case SHT_GNU_ATTRIBUTES: return "GNU_ATTR";
	case SHT_GNU_LIBLIST: return "GNU_LIBLIST";
	case SHT_CHECKSUM: return "SHT_CHECKSUM";
	case SHT_LOSUNW: return "SHT_LOSUNW";
	case SHT_GNU_HASH: return "GNU_HASH";
	case SHT_SYMTAB: return "SYMTAB";
	case SHT_PROGBITS: return "PROGBITS";
	case SHT_NOTE: return "NOTE";
	case SHT_STRTAB: return "STRTAB";
	case SHT_RELA: return "RELA";
	case SHT_HASH: return "HASH";
	case SHT_NOBITS: return "NOBITS";
	case SHT_REL: return "REL";
	case SHT_SHLIB: return "SHLIB";
	case SHT_DYNSYM: return "DYNSYM";
	case SHT_LOPROC: return "LOPROC";
	case SHT_HIPROC: return "HIPROC";
	case SHT_LOUSER: return "LOUSER";
	case SHT_HIUSER: return "HIUSER";
	case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
	case SHT_GROUP: return "GROUP";
	case SHT_SYMTAB_SHNDX: return "SYMTAB_SHNDX";
	case SHT_NUM: return "NUM";
	case SHT_INIT_ARRAY: return "INIT_ARRAY";
	case SHT_FINI_ARRAY: return "FINI_ARRAY";
	}
	return "";
}

static char *setphname(ut16 mach, Elf_(Word) ptyp) {
	const char *s = "UNKNOWN";
	// TODO to complete over time
	if (mach == EM_ARM) {
		if (ptyp == SHT_ARM_EXIDX) {
			s = "EXIDX";
		}
	} else if (mach == EM_MIPS) {
		if (ptyp == PT_MIPS_ABIFLAGS) {
			s = "ABIFLAGS";
		} else if (ptyp == PT_MIPS_REGINFO) {
			s = "REGINFO";
		}
	}
	return strdup (s);
}

static void _store_bin_sections(ELFOBJ *eo, const RVector *elf_bin_sections) {
	r_vector_reserve (&eo->cached_sections, r_vector_length (elf_bin_sections));

	RBinElfSection *section;
	r_vector_foreach (elf_bin_sections, section) {
		RBinSection *ptr = r_vector_end (&eo->cached_sections);
		if (!ptr) {
			break;
		}
		ptr->name = strdup ((char*)section->name);
		ptr->is_data = is_data_section (ptr->name);
		if (is_wordable_section (ptr->name)) {
			ptr->format = r_str_newf ("Cd %d[%"PFMT64d"]",
				R_BIN_ELF_WORDSIZE, section->size / R_BIN_ELF_WORDSIZE);
		} else if (!strcmp (ptr->name, ".dynstr")) {
			ptr->format = r_str_newf ("Css %"PFMT64d, section->size);
		}
		ptr->size = section->type != SHT_NOBITS ? section->size : 0;
		ptr->vsize = section->size;
		ptr->paddr = section->offset;
		ptr->vaddr = section->rva;
		ptr->type = elf_section_type_tostring (section->type);
		ptr->add = !eo->phdr; // Load sections if there is no PHDR
		ptr->perm = elf_flags_to_section_perms (section->flags);
		ptr->flags = section->flags;
#if 0
TODO: ptr->flags = elf_flags_tostring (section->flags);
#define SHF_WRITE	     (1 << 0)	/* Writable */
#define SHF_ALLOC	     (1 << 1)	/* Occupies memory during execution */
#define SHF_EXECINSTR	     (1 << 2)	/* Executable */
#define SHF_MERGE	     (1 << 4)	/* Might be merged */
#define SHF_STRINGS	     (1 << 5)	/* Contains nul-terminated strings */
#define SHF_INFO_LINK	     (1 << 6)	/* `sh_info' contains SHT index */
#define SHF_LINK_ORDER	     (1 << 7)	/* Preserve order after combining */
#define SHF_OS_NONCONFORMING (1 << 8)	/* Non-standard OS specific handling
					   required */
#define SHF_GROUP	     (1 << 9)	/* Section is member of a group.  */
#define SHF_TLS		     (1 << 10)	/* Section hold thread-local data.  */
#define SHF_COMPRESSED	     (1 << 11)	/* Section with compressed data. */
#define SHF_MASKOS	     0x0ff00000	/* OS-specific.  */
#define SHF_MASKPROC	     0xf0000000	/* Processor-specific */
#define SHF_ORDERED	     (1 << 30)	/* Special ordering requirement (Solaris) */
#define SHF_EXCLUDE	     (1U << 31)	/* Section is excluded unless */
#endif
	}
}

static bool _add_sections_from_phdr(RBinFile *bf, ELFOBJ *eo, bool *found_load) {
	Elf_(Phdr) *phdr = eo->phdr;
	// program headers is another section
	ut16 mach = eo->ehdr.e_machine;

	ut64 num = Elf_(get_phnum) (eo);
	if (!r_vector_reserve (&eo->cached_sections, r_vector_length (&eo->cached_sections) + num)) {
		return false;
	}

	const int limit = bf->rbin->options.limit;
	if (limit > 0 && num > limit) {
		R_LOG_WARN ("eo.limit reached for sections");
		num = limit;
	}

	int i = 0, n = 0;

	for (i = 0; i < num; i++) {
		RBinSection *ptr = r_vector_end (&eo->cached_sections);
		if (!ptr) {
			return false;
		}
		ptr->add = false;
		ptr->size = phdr[i].p_filesz;
		ptr->vsize = phdr[i].p_memsz;
		ptr->paddr = phdr[i].p_offset;
		ptr->vaddr = phdr[i].p_vaddr;

		ptr->perm = phdr[i].p_flags; // perm  are rwx like x=1, w=2, r=4, aka no need to convert from r2's R_PERM
		ptr->is_segment = true;
		switch (phdr[i].p_type) {
		case PT_DYNAMIC:
			ptr->name = strdup ("DYNAMIC");
			parse_pt_dynamic (bf, ptr);
			break;
		case PT_LOOS:
			ptr->name = r_str_newf ("LOOS");
			break;
		case PT_LOAD:
			ptr->name = r_str_newf ("LOAD%d", n++);
			ptr->perm |= R_PERM_R;
			*found_load = true;
			ptr->add = true;
			break;
		case PT_INTERP:
			ptr->name = strdup ("INTERP");
			break;
		case PT_GNU_STACK:
			ptr->name = strdup ("GNU_STACK");
			break;
		case PT_GNU_RELRO:
			ptr->name = strdup ("GNU_RELRO");
			break;
		case PT_GNU_PROPERTY:
			ptr->name = strdup ("GNU_PROPERTY");
			break;
		case PT_GNU_EH_FRAME:
			ptr->name = strdup ("GNU_EH_FRAME");
			break;
		case PT_PHDR:
			ptr->name = strdup ("PHDR");
			break;
		case PT_TLS:
			ptr->name = strdup ("TLS");
			break;
		case PT_NOTE:
			ptr->name = strdup ("NOTE");
			break;
		case PT_LOPROC:
			ptr->name = strdup ("LOPROC");
			break;
		case PT_SUNWBSS:
			ptr->name = strdup ("SUNWBSS");
			break;
		case PT_HISUNW:
			ptr->name = strdup ("HISUNW");
			break;
		case PT_SUNWSTACK:
			ptr->name = strdup ("SUNWSTACK");
			break;
		case PT_HIPROC:
			ptr->name = strdup ("HIPROC");
			break;
		case PT_OPENBSD_NOBTCFI:
			ptr->name = strdup ("OPENBSD_NOBTCFI");
			break;
		case PT_OPENBSD_RANDOMIZE:
			ptr->name = strdup ("OPENBSD_RANDOMIZE");
			break;
		case PT_OPENBSD_WXNEEDED:
			ptr->name = strdup ("OPENBSD_WXNEEDED");
			break;
		case PT_OPENBSD_BOOTDATA:
			ptr->name = strdup ("OPENBSD_BOOTDATA");
			break;
		default:
			if (ptr->size == 0 && ptr->vsize == 0) {
				ptr->name = strdup ("NONE");
			} else {
				ptr->name = setphname (mach, phdr[i].p_type);
			}
			break;
		}
	}

	return true;
}

static void _add_ehdr_section(RBinFile *bf, ELFOBJ *eo) {
	// add entry for ehdr
	RBinSection *ptr = r_vector_end (&eo->cached_sections);
	if (!ptr) {
		return;
	}

	ut64 ehdr_size = sizeof (eo->ehdr);
	if (bf->size < ehdr_size) {
		ehdr_size = bf->size;
	}
	ptr->name = strdup ("ehdr");
	ptr->paddr = 0;
	ptr->vaddr = eo->baddr;
	ptr->size = ehdr_size;
	ptr->vsize = ehdr_size;
	ptr->add = eo->ehdr.e_type == ET_REL;
	ptr->perm = R_PERM_RW;
	ptr->is_segment = true;
}

static void _cache_bin_sections(RBinFile *bf, ELFOBJ *eo, const RVector *elf_bin_sections) {
	if (elf_bin_sections) {
		_store_bin_sections (eo, elf_bin_sections);
	}

	eo->inits = r_list_newf ((RListFree) free);

	bool found_load = false;
	if (eo->phdr) {
		if (!_add_sections_from_phdr (bf, eo, &found_load)) {
			return;
		}
	}

	if (r_vector_empty (&eo->cached_sections)) {
		if (!bf->size) {
			ELFOBJ *eo = bf->bo->bin_obj;
			bf->size = eo? eo->size: 0x9999;
		}
		if (!found_load) {
			RBinSection *ptr = r_vector_end (&eo->cached_sections);
			if (!ptr) {
				return;
			}
			ptr->name = strdup ("uphdr");
			ptr->size = bf->size;
			ptr->vsize = bf->size;
			ptr->paddr = 0;
			ptr->vaddr = 0x10000;
			ptr->add = true;
			ptr->perm = R_PERM_RWX;
		}
	}

	_add_ehdr_section (bf, eo);
}

static void _fini_bin_section(RBinSection *section, void *user) {
	if (section) {
		free (section->name);
		free (section->format);
	}
}

const RVector* Elf_(load_sections)(RBinFile *bf, ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (bf && eo, NULL);
	if (!eo->sections_cached) {
		const RVector *sections = _load_elf_sections (eo);
		r_vector_init (&eo->cached_sections, sizeof (RBinSection), (RVectorFree) _fini_bin_section, NULL);
		_cache_bin_sections (bf, eo, sections);
		eo->sections_cached = true;
	}
	return &eo->cached_sections;
}

static bool is_special_arm_symbol(ELFOBJ *eo, Elf_(Sym) *sym, const char *name) {
	R_RETURN_VAL_IF_FAIL (eo && sym && name, false);
	const char ch0 = name[0];
	const char ch1 = name[1];
	if (!ch0 || !ch1) {
		return false;
	}
	if (ch0 != '$') {
		return false;
	}
	if (ch1 == 'a' || ch1 == 't' || ch1 == 'd' || ch1 == 'x') {
		const char ch2 = name[2];
		return (!ch2 || ch2 == '.') &&
			ELF_ST_TYPE (sym->st_info) == STT_NOTYPE &&
			ELF_ST_BIND (sym->st_info) == STB_LOCAL &&
			ELF_ST_VISIBILITY (sym->st_info) == STV_DEFAULT;
	}
	return false;
}

static bool is_special_symbol(ELFOBJ *eo, Elf_(Sym) *sym, const char *name) {
	switch (eo->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
		return is_special_arm_symbol (eo, sym, name);
	default:
		return false;
	}
}

static const char *bind2str(Elf_(Sym) *sym) {
	switch (ELF_ST_BIND (sym->st_info)) {
	case STB_LOCAL:  return R_BIN_BIND_LOCAL_STR;
	case STB_GLOBAL: return R_BIN_BIND_GLOBAL_STR;
	case STB_WEAK:   return R_BIN_BIND_WEAK_STR;
	case STB_NUM:    return R_BIN_BIND_NUM_STR;
	case STB_LOOS:   return R_BIN_BIND_LOOS_STR;
	case STB_HIOS:   return R_BIN_BIND_HIOS_STR;
	case STB_LOPROC: return R_BIN_BIND_LOPROC_STR;
	case STB_HIPROC: return R_BIN_BIND_HIPROC_STR;
	default:         return R_BIN_BIND_UNKNOWN_STR;
	}
}

static const char *type2str(ELFOBJ *eo, struct r_bin_elf_symbol_t *ret, Elf_(Sym) *sym) {
	if (eo && ret && is_special_symbol (eo, sym, ret->name)) {
		return R_BIN_TYPE_SPECIAL_SYM_STR;
	}
	switch (ELF_ST_TYPE (sym->st_info)) {
	case STT_NOTYPE: return R_BIN_TYPE_NOTYPE_STR;
	case STT_OBJECT: return R_BIN_TYPE_OBJECT_STR;
	case STT_FUNC: return R_BIN_TYPE_FUNC_STR;
	case STT_SECTION: return R_BIN_TYPE_SECTION_STR;
	case STT_FILE: return R_BIN_TYPE_FILE_STR;
	case STT_COMMON: return R_BIN_TYPE_COMMON_STR;
	case STT_TLS: return R_BIN_TYPE_TLS_STR;
	case STT_NUM: return R_BIN_TYPE_NUM_STR;
	case STT_LOOS: return R_BIN_TYPE_LOOS_STR;
	case STT_HIOS: return R_BIN_TYPE_HIOS_STR;
	case STT_LOPROC: return R_BIN_TYPE_LOPROC_STR;
	case STT_HIPROC: return R_BIN_TYPE_HIPROC_STR;
	default: return R_BIN_TYPE_UNKNOWN_STR;
	}
}

static void fill_symbol_bind_and_type(ELFOBJ *eo, struct r_bin_elf_symbol_t *ret, Elf_(Sym) *sym) {
	ret->bind = bind2str (sym);
	ret->type = type2str (eo, ret, sym);
}

typedef struct {
	int type;
	int nsym;
	RVecRBinElfSymbol *ret;
	Elf_(Addr) addr_sym_table;
} ReadPhdrSymbolState;

static bool _read_symbols_from_phdr(ELFOBJ *eo, ReadPhdrSymbolState *state) {
	int type = state->type;
	RVecRBinElfSymbol *ret = state->ret; // TODO: rename to elf_symbols_vec
	Elf_(Addr) addr_sym_table = state->addr_sym_table;
	int i;
	for (i = 1; i < state->nsym; i++) {
		// Read in one entry
		ut8 s[sizeof (Elf_(Sym))] = {0};
		int r = r_buf_read_at (eo->b, addr_sym_table + i * sizeof (Elf_(Sym)), s, sizeof (Elf_(Sym)));
		if (r < 1) {
			return false;
		}

		int j = 0;
		Elf_(Sym) new_symbol = {0};
#if R_BIN_ELF64
		new_symbol.st_name = READ32 (s, j);
		new_symbol.st_info = READ8 (s, j);
		new_symbol.st_other = READ8 (s, j);
		new_symbol.st_shndx = READ16 (s, j);
		new_symbol.st_value = READ64 (s, j);
		new_symbol.st_size = READ64 (s, j);
#else
		new_symbol.st_name = READ32 (s, j);
		new_symbol.st_value = READ32 (s, j);
		new_symbol.st_size = READ32 (s, j);
		new_symbol.st_info = READ8 (s, j);
		new_symbol.st_other = READ8 (s, j);
		new_symbol.st_shndx = READ16 (s, j);
#endif
		bool is_sht_null = false;
		bool is_vaddr = false;
		int tsize;
		ut64 toffset = 0;
		// Zero symbol is always empty
		// Examine entry and maybe store
		if (type == R_BIN_ELF_IMPORT_SYMBOLS && (new_symbol.st_shndx == SHT_NULL || new_symbol.st_shndx == SHT_DYNSYM)) {
			if (new_symbol.st_value) {
				toffset = new_symbol.st_value;
			} else if ((toffset = get_import_addr (eo, i)) == UT64_MAX) {
				// toffset = 0;
			}
			tsize = 16;
		} else if (type == R_BIN_ELF_ALL_SYMBOLS) {
			tsize = new_symbol.st_size;
			toffset = (ut64) new_symbol.st_value;
			is_sht_null = new_symbol.st_shndx == SHT_NULL;
		} else {
			// why continue here?
			continue;
		}

		// Since we don't know the size of the sym table in this case,
		// let's stop at the first invalid entry
		if (!strcmp (bind2str (&new_symbol), R_BIN_BIND_UNKNOWN_STR) ||
			!strcmp (type2str (NULL, NULL, &new_symbol), R_BIN_TYPE_UNKNOWN_STR)) {
			break;
		}

		ut64 tmp_offset = Elf_(v2p_new) (eo, toffset);
		if (tmp_offset == UT64_MAX) {
			tmp_offset = toffset;
			is_vaddr = true;
		}

		if (new_symbol.st_name + 2 > eo->strtab_size) {
			R_LOG_DEBUG ("Symbol name outside the strtab section");
			// Since we are reading beyond the symbol table what's happening
			// is that some entry is trying to dereference the strtab beyond its capacity
			// this can't be a symbol so this is the end
			break;
		}

		// R2_590 - getting symbol name requires a unified function to read outside strtab, current code is wrong
		// get name before alocating it in the vector
		int st_name = new_symbol.st_name;
		const size_t rest = ELF_STRING_LENGTH - 1;
		int maxsize = eo->size; //R_MIN (eo->size, eo->strtab_size);
		int namelen = 0;
		if (st_name < 0 || st_name >= maxsize) {
			namelen = 0;
		} else {
			namelen = r_str_nlen (eo->strtab + st_name, rest) + 1;
		}
		const char *symname;
		if (namelen < 1) {
#if PERMIT_UNNAMED_SYMBOLS
			symname = "unksym";
#else
			R_LOG_DEBUG ("empty symbol name");
			continue;
#endif
		} else {
			symname = eo->strtab + st_name;
		}

		RBinElfSymbol *psym = RVecRBinElfSymbol_emplace_back (ret);
		if (!psym) {
			return false;
		}

		memset (psym, 0, sizeof (RBinElfSymbol));
		psym->offset = tmp_offset;
		psym->size = tsize;
		r_str_ncpy (psym->name, symname, R_MIN (rest, namelen));

		psym->ordinal = i;
		psym->in_shdr = false;
		fill_symbol_bind_and_type (eo, psym, &new_symbol);
		psym->is_sht_null = is_sht_null;
		psym->is_vaddr = is_vaddr;
	}
	return true;
}

static RVecRBinElfSymbol* load_symbols_from_phdr(ELFOBJ *eo, int type) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);

	if (!eo->phdr || !eo->ehdr.e_phnum) {
		return NULL;
	}
	if (eo->dyn_info.dt_symtab == R_BIN_ELF_ADDR_MAX || !eo->dyn_info.dt_syment) {
		return NULL;
	}

	Elf_(Addr) addr_sym_table = Elf_(v2p) (eo, eo->dyn_info.dt_symtab);
	ut32 sym_size = eo->dyn_info.dt_syment;
	if (!sym_size) {
		return NULL;
	}

	// since ELF doesn't specify the symbol table size we may read until the end of the buffer
	int nsym = (eo->size - addr_sym_table) / sym_size;
	if (nsym < 1) {
		return NULL;
	}
	ut32 size = 0;
	if (!UT32_MUL (&size, nsym, sizeof (Elf_ (Sym)))) {
		return NULL;
	}
	if (size < 1 || addr_sym_table > eo->size || addr_sym_table + size > eo->size || nsym < 1) {
		return NULL;
	}

	// we reserve room for 4096 and grow as needed.
	// const size_t initial_capacity = 4096;
	// RVector *ret = r_vector_new (sizeof (RBinElfSymbol), NULL, NULL);
	RVecRBinElfSymbol *ret = RVecRBinElfSymbol_new ();
	if (!ret) { //  || !r_vector_reserve (ret, initial_capacity))
		return NULL;
	}

	const int limit = eo->limit;
	if (limit > 0 && nsym > limit) {
		R_LOG_WARN ("eo.limit reached for phdr symbols");
		nsym = limit;
	}
	ReadPhdrSymbolState state = { .type = type, .ret = ret, .nsym = nsym, .addr_sym_table = addr_sym_table, };
	if (!_read_symbols_from_phdr (eo, &state)) {
		RVecRBinElfSymbol_free (ret);
		return NULL;
	}
	RVecRBinElfSymbol_shrink_to_fit (ret);
	// XXX refactor this code, also allocated in another place, but this is used in other situations..
	size_t ret_size = RVecRBinElfSymbol_length (ret) + 1;  // + 1 because ordinals are 1-based
	if (type == R_BIN_ELF_IMPORT_SYMBOLS && !eo->imports_by_ord_size) {
		eo->imports_by_ord_size = ret_size;
		if (ret_size > 0) {
			eo->imports_by_ord = (RBinImport**) calloc (ret_size, sizeof (RBinImport*));
		} else {
			eo->imports_by_ord = NULL;
		}
	} else if (type == R_BIN_ELF_ALL_SYMBOLS && !eo->symbols_by_ord_size) {
		eo->symbols_by_ord_size = ret_size;
		if (ret_size > 0) {
			eo->symbols_by_ord = (RBinSymbol**) calloc (ret_size, sizeof (RBinSymbol*));
		} else {
			eo->symbols_by_ord = NULL;
		}
	}

	return ret;
}

static RVecRBinElfSymbol *Elf_(load_phdr_symbols)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);
	if (!eo->phdr_symbols_vec) {
		eo->phdr_symbols_vec = load_symbols_from_phdr (eo, R_BIN_ELF_ALL_SYMBOLS);
	}
	return eo->phdr_symbols_vec;
}

static RVecRBinElfSymbol *Elf_(load_phdr_imports)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);
	if (!eo->phdr_imports_vec) {
		eo->phdr_imports_vec = load_symbols_from_phdr (eo, R_BIN_ELF_IMPORT_SYMBOLS);
	}
	return eo->phdr_imports_vec;
}

static RVecRBinElfSymbol *Elf_(load_symbols_type)(ELFOBJ *eo, int type) {
	return (type == R_BIN_ELF_IMPORT_SYMBOLS)
		? Elf_(load_phdr_imports) (eo)
		: Elf_(load_phdr_symbols) (eo);
}

static int Elf_(fix_symbols)(ELFOBJ *eo, int nsym, int type, RVecRBinElfSymbol *symbols) {
	int result = -1;
	HtUP *phd_offset_map = ht_up_new0 ();
	HtUP *phd_ordinal_map = ht_up_new0 ();
	RVecRBinElfSymbol *uhsymbols = Elf_(load_symbols_type) (eo, type);
	if (uhsymbols) {
		RBinElfSymbol *symbol;
		R_VEC_FOREACH (symbols, symbol) {
			ht_up_insert (phd_offset_map, symbol->offset, symbol);
			ht_up_insert (phd_ordinal_map, symbol->ordinal, symbol);
		}
		R_VEC_FOREACH (uhsymbols, symbol) {
			// find match in phdr
			RBinElfSymbol *d = ht_up_find (phd_offset_map, symbol->offset, NULL);
			if (!d) {
				d = ht_up_find (phd_ordinal_map, symbol->ordinal, NULL);
			}
			if (d) {
				symbol->in_shdr = true;
				if (*symbol->name && *d->name == '$') {
					strcpy (d->name, symbol->name);
				}
			}
		}

		int count = 0;
		R_VEC_FOREACH (uhsymbols, symbol) {
			if (!symbol->in_shdr) {
				count++;
			}
		}

		// Take those symbols that are not present in the shdr but are present in phdr
		// This should only should happen with fucked up binaries
		if (count > 0) {
			// what happens if a shdr says it has only one symbol? we should look anyway into phdr
			if (!RVecRBinElfSymbol_reserve (symbols, nsym + count)) {
				result = -1;
				ht_up_free (phd_offset_map);
				ht_up_free (phd_ordinal_map);
				return result;
			}
			R_VEC_FOREACH (uhsymbols, symbol) {
				if (!symbol->in_shdr) {
					RVecRBinElfSymbol_push_back (symbols, symbol);
					// memcpy (r_vector_end (symbols), symbol, sizeof (RBinElfSymbol));
					nsym++;
				}
			}
		}
	}
	result = nsym;
	ht_up_free (phd_offset_map);
	ht_up_free (phd_ordinal_map);
	return result;
}

static bool is_section_local_sym(ELFOBJ *eo, Elf_(Sym) *sym) {
	if (sym->st_name != 0) {
		return false;
	}
	if (ELF_ST_TYPE (sym->st_info) != STT_SECTION) {
		return false;
	}
	if (ELF_ST_BIND (sym->st_info) != STB_LOCAL) {
		return false;
	}
	if (!is_shidx_valid (eo, sym->st_shndx)) {
		return false;
	}
	return true;
	// Elf_(Word) sh_name = eo->shdr[sym->st_shndx].sh_name;
	// return eo->shstrtab && sh_name < eo->shstrtab_size;
}

static void setsymord(ELFOBJ* eobj, ut32 ord, RBinSymbol *ptr) {
	if (eobj->symbols_by_ord && ord < eobj->symbols_by_ord_size) {
		r_bin_symbol_free (eobj->symbols_by_ord[ord]);
		eobj->symbols_by_ord[ord] = ptr;
	}
}

static void _set_arm_thumb_bits(struct Elf_(obj_t) *eo, RBinSymbol **symp) {
	int bin_bits = Elf_(get_bits) (eo);
	RBinSymbol *sym = *symp;
	const char *name = r_bin_name_tostring2 (sym->name, 'o');
	int len = strlen (name);
	if (name[0] == '$' && (len >= 2 && !name[2])) {
		switch (name[1]) {
		case 'a' : // arm
			sym->bits = 32;
			return;
		case 't': // thumb
			sym->bits = 16;
			if (sym->vaddr & 1) {
				sym->vaddr--;
			}
			if (sym->paddr & 1) {
				sym->paddr--;
			}
			return;
		case 'd': // data
			return;
		default:
			break;
		}
	}
	sym->bits = bin_bits;
	if (bin_bits != 64) {
		sym->bits = 32;
		if (sym->paddr != UT64_MAX) {
			if (sym->vaddr & 1) {
				sym->vaddr--;
				sym->bits = 16;
			}
			if (sym->paddr & 1) {
				sym->paddr--;
				sym->bits = 16;
			}
		}
	}
}

// XXX this is slow because we can directly use RBinSymbol instead of RBinElfSymbol imho
RBinSymbol *Elf_(convert_symbol)(ELFOBJ *eo, RBinElfSymbol *symbol) {
	ut64 paddr, vaddr;
	const ut64 baddr = Elf_(get_baddr) (eo);
	if (baddr && baddr != UT64_MAX && symbol->offset && symbol->offset != UT64_MAX) {
		if (symbol->is_vaddr && symbol->offset < baddr) {
			symbol->is_vaddr = false;
		}
	}
	if (symbol->is_vaddr) {
		paddr = UT64_MAX;
		vaddr = symbol->offset;
	} else {
		paddr = symbol->offset;
		ut64 va = Elf_(p2v_new) (eo, paddr);
		if (va != UT64_MAX) {
			vaddr = va;
		} else {
			vaddr = paddr;
		}
	}

	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	ptr->name = r_bin_name_new (symbol->name);
	ptr->forwarder = "NONE";
	ptr->bind = symbol->bind;
	ptr->type = symbol->type;
	ptr->is_imported = symbol->is_imported;
	ptr->paddr = paddr;
	ptr->vaddr = vaddr;
	ptr->size = symbol->size;
	ptr->ordinal = symbol->ordinal;
	// detect thumb
	if (eo->ehdr.e_machine == EM_ARM) {
		_set_arm_thumb_bits (eo, &ptr);
	}
	return ptr;
}

static RBinElfSection *getsection_byname(ELFOBJ *eo, const char *name, size_t *_i) {
	RBinElfSection *s;
	size_t i = 0;
	r_vector_foreach (&eo->g_sections, s) {
		if (!strcmp (s->name, name)) {
			return s;
		}
		i++;
	}
	*_i = i;
	return NULL;
}

static RVecRBinElfSymbol *parse_gnu_debugdata(ELFOBJ *eo, size_t *ret_size) {
	if (ret_size) {
		*ret_size = 0;
	}
	if (!eo->sections_loaded) {
		// parse sections pls
		_load_elf_sections (eo);
	}
	size_t rs = 0;
	RBinElfSection *section = getsection_byname (eo, ".gnu_debugdata", &rs);
	if (!section) {
		return NULL;
	}
	ut64 addr = section->offset;
	ut64 size = section->size;
	if (size < 10) {
		return NULL;
	}
	ut8 *data = malloc (size + 1);
	if (!data) {
		return NULL;
	}
	if (r_buf_read_at (eo->b, addr, data, size) != size) {
		R_LOG_ERROR ("Cannot read");
	}
	size_t osize;
	ut8 *odata = r_sys_unxz (data, size, &osize);
	if (odata) {
		RBuffer *newelf = r_buf_new_with_pointers (odata, osize, false);
		ELFOBJ* newobj = Elf_(new_buf) (newelf, eo->user_baddr, false);
		RVecRBinElfSymbol *symbols = NULL;
		if (newobj) {
			newobj->limit = eo->limit;
			if (Elf_(load_symbols) (newobj)) {
				symbols = newobj->g_symbols_vec;
				newobj->g_symbols_vec = NULL;
			}
			Elf_(free)(newobj);
		}
		if (ret_size) {
			*ret_size = rs;
		}
		r_buf_free (newelf);
		free (odata);
		free (data);
		return symbols;
	}
	free (data);
	return NULL;
}

static bool section_matters(ELFOBJ *eo, int i, int type, ut32 shdr_size) {
	bool is_symtab = ((type & R_BIN_ELF_SYMTAB_SYMBOLS) && (eo->shdr[i].sh_type == SHT_SYMTAB));
	bool is_dyntab = ((type & R_BIN_ELF_DYNSYM_SYMBOLS) && (eo->shdr[i].sh_type == SHT_DYNSYM));
	if (is_symtab || is_dyntab) {
		if (eo->shdr[i].sh_link < 1 || eo->shdr[i].sh_link * sizeof (Elf_(Shdr)) >= shdr_size) {
			// oops. fix out of range pointers
			return false;
		}
		return true;
	}
	return false;
}

static int _find_max_symbol_ordinal(const RVecRBinElfSymbol *symbols) {
	int max = 0;
	RBinElfSymbol *symbol;
	R_VEC_FOREACH (symbols, symbol) {
		int ordinal = (int) symbol->ordinal;
		if (ordinal > max) {
			max = ordinal;
		}
	}
	return max;
}

typedef struct elf_symbol_memory_t {
	RVecRBinElfSymbol *symbols_vec;
	Elf_(Sym) *sym;
} ElfSymbolMemory;

static void _symbol_memory_free(ElfSymbolMemory *em) {
	// RVecRBinElfSymbol_fini (em->symbols_vec, NULL, NULL);
	R_FREE (em->sym);
}

typedef struct import_info_t {
	ElfSymbolMemory memory;
	RVecRBinElfSymbol *ret; // very bad name
	int ret_ctr;
	int import_ret_ctr;
	int nsym;
} ImportInfo;

static RVecRBinElfSymbol *_load_additional_imported_symbols(ELFOBJ *eo, ImportInfo *ii) {
	// Elf_(fix_symbols) may find additional symbols, some of which could be
	// imported symbols. Let's reserve additional space for them.
	int ret_ctr = ii->ret_ctr;
	R_WARN_IF_FAIL (ii->nsym >= ret_ctr);

	int nsym = _find_max_symbol_ordinal (ii->memory.symbols_vec);
	if (nsym < 0) {
		return NULL;
	}

	R_FREE (eo->imports_by_ord);
	eo->imports_by_ord_size = nsym + 1;
	eo->imports_by_ord = (RBinImport**)calloc (nsym + 1, sizeof (RBinImport*));

	R_FREE (eo->symbols_by_ord);
	eo->symbols_by_ord_size = nsym + 1;
	eo->symbols_by_ord = (RBinSymbol**)calloc (nsym + 1, sizeof (RBinSymbol*));
	if (ret_ctr > ii->import_ret_ctr + nsym) {
		return NULL;
	}

	RVecRBinElfSymbol *imports = NULL; // ii->ret;
	if (!imports) {
		imports = RVecRBinElfSymbol_new ();
	}
	const int import_ret_ctr = ii->import_ret_ctr + nsym - ret_ctr;
	if (!imports || !RVecRBinElfSymbol_reserve (imports, import_ret_ctr)) {
		R_LOG_DEBUG ("Cannot allocate %d symbols", nsym);
		_symbol_memory_free (&ii->memory);
		RVecRBinElfSymbol_free (imports);
		return NULL;
	}

	RBinElfSymbol *symbol;
	const int limit = eo->limit;
	int count = 0;
	R_VEC_FOREACH (ii->memory.symbols_vec, symbol) {
		RBinSymbol *isym = Elf_(convert_symbol) (eo, symbol);
		if (!isym) {
			continue;
		}
		setsymord (eo, isym->ordinal, isym);
		if (symbol->is_imported) {
			if (limit > 0 && count++ > limit) {
				R_LOG_WARN ("eo.limit reached for imports");
				free (isym);
				break;
			}
			RVecRBinElfSymbol_push_back (imports, symbol);
		}
	}

	_symbol_memory_free (&ii->memory);
	return imports;
}

typedef struct process_section_state_t {
	int i;
	ElfSymbolMemory *const memory;
	RVecRBinElfSymbol **ret;
	size_t *const ret_ctr;
	size_t *const import_ret_ctr;
} ProcessSectionState;

static bool _process_symbols_and_imports_in_section(ELFOBJ *eo, int type, ProcessSectionState *state) {
	int i = state->i;
	ElfSymbolMemory *const memory = state->memory;
	size_t *const ret_ctr = state->ret_ctr;
	size_t *const import_ret_ctr = state->import_ret_ctr;

	Elf_(Shdr) *strtab_section = &eo->shdr[eo->shdr[i].sh_link];
	if (strtab_section->sh_size > ST32_MAX || strtab_section->sh_size + 8 > eo->size) {
		R_LOG_ERROR ("size (syms strtab)");
		return false;
	}
	int nsym = (int)(eo->shdr[i].sh_size / sizeof (Elf_(Sym)));
	if (nsym < 1) {
		R_LOG_ERROR ("nsym < 1");
		return false;
	}

	if (strtab_section->sh_offset > eo->size || strtab_section->sh_offset + strtab_section->sh_size > eo->size) {
		R_LOG_ERROR ("invalid sh size");
		return false;
	}

	// TODO don't calloc and copy from buf, read from buf directly
	char *strtab = calloc (1, 8 + strtab_section->sh_size);
	if (!strtab) {
		R_LOG_ERROR ("malloc (syms strtab)");
		return false;
	}

	if (r_buf_read_at (eo->b, strtab_section->sh_offset, (ut8*)strtab, strtab_section->sh_size) == -1) {
		R_LOG_ERROR ("read (syms strtab)");
		free (strtab);
		return false;
	}

	// bounds check
	int newsize = 1 + eo->shdr[i].sh_size;
	if (newsize < 0 || newsize > eo->size) {
		R_LOG_ERROR ("invalid shdr %d size", i);
		free (strtab);
		return false;
	}

	const ut64 sh_begin = eo->shdr[i].sh_offset;
	const ut64 sh_end = sh_begin + eo->shdr[i].sh_size;
	if (sh_begin > eo->size) {
		R_LOG_ERROR ("invalid sh egin");
		free (strtab);
		return false;
	}

	if (sh_end > eo->size) {
		st64 newshsize = eo->size - sh_begin;
		nsym = (int)(newshsize / sizeof (Elf_(Sym)));
		if (nsym < 1) {
			R_LOG_ERROR ("nsym < 1 again");
			free (strtab);
			return false;
		}
	}
	const int limit = eo->limit;
	if (limit > 0 && nsym > limit) {
		R_LOG_WARN ("eo.limit for symbols");
		nsym = limit;
	}

	memory->sym = calloc (nsym, sizeof (Elf_(Sym)));
	if (!memory->sym) {
		R_LOG_ERROR ("calloc (syms)");
		free (strtab);
		return false;
	}

	ut32 size = 0;
	if (!UT32_MUL (&size, nsym, sizeof (Elf_(Sym)))) {
		R_LOG_ERROR ("mul overflow");
		free (strtab);
		return false;
	}
	if (size < 1 || size > eo->size) {
		R_LOG_ERROR ("wrong size");
		free (strtab);
		return false;
	}
	if (eo->shdr[i].sh_offset > eo->size || eo->shdr[i].sh_offset + size > eo->size) {
		R_LOG_ERROR ("inval");
		free (strtab);
		return false;
	}

	int j;
	for (j = 0; j < nsym; j++) {
		int k = 0;
		ut8 s[sizeof (Elf_(Sym))] = {0};
		ut64 sym_addr = eo->shdr[i].sh_offset + (j * sizeof (Elf_(Sym)));
		int r = r_buf_read_at (eo->b, sym_addr, s, sizeof (Elf_(Sym)));
		if (r < 1) {
			R_LOG_ERROR ("read (sym)");
			free (strtab);
			return false;
		}
#if R_BIN_ELF64
		memory->sym[j].st_name = READ32 (s, k);
		memory->sym[j].st_info = READ8 (s, k);
		memory->sym[j].st_other = READ8 (s, k);
		memory->sym[j].st_shndx = READ16 (s, k);
		memory->sym[j].st_value = READ64 (s, k);
		memory->sym[j].st_size = READ64 (s, k);
#else
		memory->sym[j].st_name = READ32 (s, k);
		memory->sym[j].st_value = READ32 (s, k);
		memory->sym[j].st_size = READ32 (s, k);
		memory->sym[j].st_info = READ8 (s, k);
		memory->sym[j].st_other = READ8 (s, k);
		memory->sym[j].st_shndx = READ16 (s, k);
#endif
	}

	if (!(*state->ret)) {
		RVecRBinElfSymbol *ret = RVecRBinElfSymbol_new ();
		if (!ret) {
			free (strtab);
			return false;
		}
		*state->ret = ret;
		memory->symbols_vec = ret;
	}

	RVecRBinElfSymbol *ret = *state->ret;
	int increment = nsym;
	ut64 len = RVecRBinElfSymbol_length (ret);
	if (!RVecRBinElfSymbol_reserve (ret, increment + len)) {
		R_LOG_ERROR ("Cannot allocate %d symbols", (int)(nsym + increment));
		free (strtab);
		return false;
	}

	int k;
	for (k = 1; k < nsym; k++, (*ret_ctr)++) {
		ut64 toffset;
		int tsize;
		RBinElfSymbol *es = RVecRBinElfSymbol_emplace_back (ret); // r_vector_end (ret);
		memset (es, 0, sizeof (RBinElfSymbol));
		bool is_sht_null = false;
		bool is_vaddr = false;
		bool is_imported = false;

		if (type == R_BIN_ELF_IMPORT_SYMBOLS) {
			if (memory->sym[k].st_value) {
				toffset = memory->sym[k].st_value;
			} else if ((toffset = get_import_addr (eo, k)) == UT64_MAX) {
				// toffset = 0;
			}
			tsize = 16;
			is_imported = memory->sym[k].st_shndx == STN_UNDEF;
		} else {
			tsize = memory->sym[k].st_size;
			toffset = (ut64)memory->sym[k].st_value;
			is_sht_null = memory->sym[k].st_shndx == SHT_NULL;
		}

		if (is_bin_etrel (eo)) {
			if (memory->sym[k].st_shndx < eo->ehdr.e_shnum) {
				es->offset = memory->sym[k].st_value + eo->shdr[memory->sym[k].st_shndx].sh_offset;
			}
		} else {
			es->offset = Elf_(v2p_new) (eo, toffset);
			if (es->offset == UT64_MAX) {
				es->offset = toffset;
				is_vaddr = true;
			}
		}

		es->size = tsize;
		if (memory->sym[k].st_name + 1 > strtab_section->sh_size) {
			R_LOG_DEBUG ("index out of strtab range (%"PFMT64d" / %"PFMT64d")",
				(ut64)memory->sym[k].st_name, (ut64)strtab_section->sh_size);
			continue;
		}

		const size_t st_name = memory->sym[k].st_name;
		int maxsize = strtab_section->sh_size; // R_MIN (r_buf_size (eo->b), strtab_section->sh_size);
		if (is_section_local_sym (eo, &memory->sym[k])) {
			const size_t sym_section = memory->sym[k].st_shndx;
			if (eo->shstrtab) {
				size_t ss = eo->shstrtab_size;
				size_t name_off = eo->shdr[sym_section].sh_name;
				if (name_off > 0 && name_off < ss) {
					const char *shname = eo->shstrtab + name_off;
					size_t left = R_MIN (ELF_STRING_LENGTH - 1, ss - name_off);
					r_str_ncpy (es->name, shname, left);
				} else {
					es->name[0] = 0;
				}
			} else {
				const ut64 at = strtab_section->sh_offset + eo->shdr[sym_section].sh_name;
				r_buf_read_at (eo->b, at, (ut8*)es->name, sizeof (es->name));
			}
		} else if (st_name <= 0 || st_name >= maxsize) {
			es->name[0] = 0;
		} else {
			r_str_ncpy (es->name, &strtab[st_name], ELF_STRING_LENGTH - 1);
			es->type = type2str (eo, es, &memory->sym[k]);
		}

		es->ordinal = k;
		es->name[ELF_STRING_LENGTH - 1] = '\0';
		fill_symbol_bind_and_type (eo, es, &memory->sym[k]);
		es->is_sht_null = is_sht_null;
		es->is_vaddr = is_vaddr;
		es->is_imported = is_imported;
		if (type == R_BIN_ELF_IMPORT_SYMBOLS && is_imported) {
			(*import_ret_ctr)++;
		}
	}
	free (strtab);
	return true;
}

// TODO: return RList<RBinSymbol*> .. or run a callback with that symbol constructed, so we don't have to do it twice
static RVecRBinElfSymbol *Elf_(load_symbols_from)(ELFOBJ *eo, int type) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);

	if (!eo->shdr || !eo->ehdr.e_shnum || eo->ehdr.e_shnum == 0xffff) {
		R_LOG_DEBUG ("invalid section header value");
		return Elf_(load_symbols_type) (eo, type);
	}

	ut32 shdr_size = 0;
	if (!UT32_MUL (&shdr_size, eo->ehdr.e_shnum, sizeof (Elf_(Shdr)))) {
		R_LOG_DEBUG ("shnum mul overflow");
		return NULL;
	}
	if (shdr_size + 8 > eo->size) {
		R_LOG_DEBUG ("skipping section headers after file size");
		return NULL;
	}

	size_t import_ret_ctr = 0;
	size_t ret_ctr = 0; // amount of symbols stored in ret
	RVecRBinElfSymbol *ret = parse_gnu_debugdata (eo, &ret_ctr);
	ElfSymbolMemory memory = { .symbols_vec = ret, .sym = NULL };
	int i;
	size_t shnum = eo->ehdr.e_shnum;
	for (i = 0; i < shnum; i++) {
		if (!section_matters (eo, i, type, shdr_size)) {
			continue;
		}
		ProcessSectionState state = {
			.i = i,
			.memory = &memory,
			.ret = &ret,
			.ret_ctr = &ret_ctr,
			.import_ret_ctr = &import_ret_ctr,
		};
		if (!_process_symbols_and_imports_in_section (eo, type, &state)) {
			R_LOG_ERROR ("failed parsing imports in section");
			_symbol_memory_free (&memory);
			RVecRBinElfSymbol_free (ret);
			return NULL;
		}

		R_FREE (memory.sym);

		if (type == R_BIN_ELF_IMPORT_SYMBOLS) {
			break;
		}
	}

	if (!ret) {
		return Elf_(load_symbols_type) (eo, type);
	}

	int nsym = Elf_(fix_symbols) (eo, ret_ctr, type, ret);
	if (nsym == -1) {
		RVecRBinElfSymbol_free (ret);
		_symbol_memory_free (&memory);
		return NULL;
	}

	if (type == R_BIN_ELF_IMPORT_SYMBOLS) {
		ImportInfo ii = {
			.memory = memory,
			//.ret = ret,
			.ret_ctr = ret_ctr,
			.import_ret_ctr = import_ret_ctr,
			.nsym = nsym,
		};
		RVecRBinElfSymbol *res = _load_additional_imported_symbols (eo, &ii);
		RVecRBinElfSymbol_free (ret);
		return res;
	}

	return ret;
}

bool Elf_(load_symbols)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, false);
	if (!eo->g_symbols_vec) {
		eo->g_symbols_vec = Elf_(load_symbols_from) (eo, R_BIN_ELF_ALL_SYMBOLS);
	}
	return eo->g_symbols_vec != NULL;
}

bool Elf_(load_imports)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, false);
	if (!eo->g_imports_vec) {
		eo->g_imports_vec = Elf_(load_symbols_from) (eo, R_BIN_ELF_IMPORT_SYMBOLS);
	}
	return eo->g_imports_vec != NULL;
}

const RVector* Elf_(load_fields)(ELFOBJ *eo) {
	R_RETURN_VAL_IF_FAIL (eo, NULL);

	if (eo->fields_loaded) {
		return &eo->g_fields;
	}

	eo->fields_loaded = true;
	r_vector_init (&eo->g_fields, sizeof (RBinElfLib), NULL, NULL);

	ut64 num_fields = eo->ehdr.e_phnum + 3;
	if (!(r_vector_reserve (&eo->g_fields, num_fields))) {
		return NULL;
	}

	RBinElfField *new_field = r_vector_end (&eo->g_fields);
	r_str_ncpy (new_field->name, "ehdr", ELF_STRING_LENGTH);
	new_field->offset = 0;

	new_field = r_vector_end (&eo->g_fields);
	r_str_ncpy (new_field->name, "shoff", ELF_STRING_LENGTH);
	new_field->offset = eo->ehdr.e_shoff;

	new_field = r_vector_end (&eo->g_fields);
	r_str_ncpy (new_field->name, "phoff", ELF_STRING_LENGTH);
	new_field->offset = eo->ehdr.e_phoff;

	int i;
	for (i = 0; eo->phdr && i < eo->ehdr.e_phnum; i++) {
		new_field = r_vector_end (&eo->g_fields);
		snprintf (new_field->name, ELF_STRING_LENGTH, "phdr_%i", i);
		new_field->offset = eo->phdr[i].p_offset;
	}
	return &eo->g_fields;
}

void Elf_(free)(ELFOBJ* eo) {
	if (!eo) {
		return;
	}
	r_list_free (eo->relocs_list);
	if (eo->imports_by_ord) {
		int i;
		for (i = 0; i < eo->imports_by_ord_size; i++) {
			RBinImport *imp = eo->imports_by_ord[i];
			if (imp) {
				r_bin_import_free (eo->imports_by_ord[i]);
				eo->imports_by_ord[i] = NULL;
			}
		}
		eo->imports_by_ord_size = 0;
		R_FREE (eo->imports_by_ord);
	}
	free (eo->osabi);
	free (eo->phdr);
	free (eo->shdr);
	free (eo->strtab);
	free (eo->shstrtab);
	free (eo->dynstr);
	r_vector_fini (&eo->dyn_info.dt_needed);
	//free (eo->strtab_section);
	if (eo->imports_by_ord) {
		size_t i;
		for (i = 0; i < eo->imports_by_ord_size; i++) {
			free (eo->imports_by_ord[i]);
		}
		free (eo->imports_by_ord);
	}
	if (eo->symbols_by_ord) {
		size_t i;
		for (i = 0; i < eo->symbols_by_ord_size; i++) {
			r_bin_symbol_free (eo->symbols_by_ord[i]);
		}
		free (eo->symbols_by_ord);
	}
	r_buf_free (eo->b);
	RVecRBinElfSymbol_free (eo->phdr_symbols_vec);
	eo->phdr_symbols_vec = NULL;
	RVecRBinElfSymbol_free (eo->phdr_imports_vec);
	eo->phdr_imports_vec = NULL;
	RVecRBinElfSymbol_free (eo->g_symbols_vec);
	eo->g_symbols_vec = NULL;
	RVecRBinElfSymbol_free (eo->g_imports_vec);
	eo->g_imports_vec = NULL;
#if 0
	// R2_590
	r_vector_free (eo->g_symbols);
	eo->g_symbols = NULL;
	// eo->phdr_symbols = NULL;

	if (eo->phdr_imports != eo->g_imports) {
		r_vector_free (eo->phdr_imports);
	}
	eo->phdr_imports = NULL;
	r_vector_free (eo->g_imports);
	eo->g_imports = NULL;
#endif
	if (eo->sections_loaded) {
		r_vector_fini (&eo->g_sections);
	}
	if (eo->sections_cached) {
		r_vector_fini (&eo->cached_sections);
	}
	if (eo->libs_loaded) {
		r_vector_fini (&eo->g_libs);
	}
	if (eo->relocs_loaded) {
		r_vector_fini (&eo->g_relocs);
	}
	if (eo->fields_loaded) {
		r_vector_fini (&eo->g_fields);
	}
	ht_uu_free (eo->rel_cache);
	eo->rel_cache = NULL;
	sdb_free (eo->kv);
	r_list_free (eo->inits);
	free (eo);
}

ELFOBJ* Elf_(new_buf)(RBuffer *buf, ut64 baddr, bool verbose) {
	ELFOBJ *eo = R_NEW0 (ELFOBJ);
	eo->kv = sdb_new0 ();
	eo->size = r_buf_size (buf);
	eo->verbose = verbose;
	eo->b = r_buf_ref (buf);
	eo->user_baddr = baddr;
	if (!elf_init (eo)) {
		Elf_(free) (eo);
		return NULL;
	}
	return eo;
}

static int is_in_pphdr(Elf_(Phdr) *p, ut64 addr) {
	return addr >= p->p_offset && addr < p->p_offset + p->p_filesz;
}

static int is_in_vphdr(Elf_(Phdr) *p, ut64 addr) {
	return addr >= p->p_vaddr && addr < p->p_vaddr + p->p_filesz;
}

// Deprecated temporarily. Use r_bin_elf_p2v_new in new code for now.
ut64 Elf_(p2v) (ELFOBJ *eo, ut64 paddr) {
	R_RETURN_VAL_IF_FAIL (eo, 0);

	if (!eo->phdr) {
		if (is_bin_etrel (eo)) {
			return eo->baddr + paddr;
		}
		return paddr;
	}

	size_t i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &eo->phdr[i];
		if (p->p_type == PT_LOAD && is_in_pphdr (p, paddr)) {
			if (!p->p_vaddr && !p->p_offset) {
				continue;
			}
			ut64 vaddr = p->p_vaddr + paddr - p->p_offset;
			return vaddr;
		}
	}

	return paddr;
}

// Deprecated temporarily. Use r_bin_elf_v2p_new in new code for now.
ut64 Elf_(v2p)(ELFOBJ *eo, ut64 vaddr) {
	R_RETURN_VAL_IF_FAIL (eo, 0); // UT64_MAX or vaddr?
	if (!eo->phdr) {
		if (is_bin_etrel (eo)) {
			return vaddr - eo->baddr;
		}
		return vaddr;
	}

	size_t i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &eo->phdr[i];
		if (p->p_type == PT_LOAD && is_in_vphdr (p, vaddr)) {
			if (!p->p_offset && !p->p_vaddr) {
				continue;
			}
			return p->p_offset + vaddr - p->p_vaddr;
		}
	}
	return vaddr;
}

/* converts a physical address to the virtual address, looking
 * at the program headers in the binary bin */
ut64 Elf_(p2v_new) (ELFOBJ *eo, ut64 paddr) {
	R_RETURN_VAL_IF_FAIL (eo, UT64_MAX);

	if (!eo->phdr) {
		return is_bin_etrel (eo) ? eo->baddr + paddr : UT64_MAX;
	}

	size_t i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &eo->phdr[i];
		if (p->p_type == PT_LOAD && is_in_pphdr (p, paddr)) {
			return p->p_vaddr + paddr - p->p_offset;
		}
	}

	return UT64_MAX;
}

/* converts a virtual address to the relative physical address, looking
 * at the program headers in the binary bin */
ut64 Elf_(v2p_new) (ELFOBJ *eo, ut64 vaddr) {
	R_RETURN_VAL_IF_FAIL (eo, UT64_MAX);

	if (!eo->phdr) {
		return is_bin_etrel (eo) ? vaddr - eo->baddr : UT64_MAX;
	}

	size_t i;
	for (i = 0; i < eo->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &eo->phdr[i];
		if (p->p_type == PT_LOAD && is_in_vphdr (p, vaddr)) {
			return p->p_offset + vaddr - p->p_vaddr;
		}
	}

	return UT64_MAX;
}

static bool get_nt_file_maps(ELFOBJ *eo, RList *core_maps) {
	ut16 ph;
	for (ph = 0; ph < eo->ehdr.e_phnum; ph++) {
		Elf_(Phdr) *p = &eo->phdr[ph];
		if (p->p_type != PT_NOTE) {
			continue;
		}

		const size_t elf_nhdr_size = sizeof (Elf_(Nhdr));
		void *elf_nhdr = calloc (elf_nhdr_size, 1);
		if (!elf_nhdr) {
			return false;
		}

		ut64 offset = 0;
		bool found = false;
		while (!found) {
			int ret = r_buf_read_at (eo->b, eo->phdr[ph].p_offset + offset, elf_nhdr, elf_nhdr_size);
			if (ret != elf_nhdr_size) {
				R_LOG_ERROR ("Cannot read more NOTES header from CORE");
				free (elf_nhdr);
				return false;
			}

			ut32 n_descsz = round_up (((Elf_(Nhdr)*)elf_nhdr)->n_descsz);
			ut32 n_namesz = round_up (((Elf_(Nhdr)*)elf_nhdr)->n_namesz);
			ut32 n_type = ((Elf_(Nhdr)*)elf_nhdr)->n_type;

			if (n_type == NT_FILE) {
				found = true;
				offset += elf_nhdr_size + n_namesz;
				free (elf_nhdr);
			} else {
				offset += elf_nhdr_size + n_descsz + n_namesz;
			}
		}
		ut64 i = eo->phdr[ph].p_offset + offset;
		ut64 n_maps = R_BIN_ELF_BREADWORD (eo->b, i);
		(void)R_BIN_ELF_BREADWORD (eo->b, i);

		const size_t size_of = sizeof (Elf_(Addr));
		const ut64 jump = ((size_of * 3) * n_maps) + i;
		int len_str = 0;
		while (n_maps > 0) {
			ut64 addr = R_BIN_ELF_BREADWORD (eo->b, i);
			if (addr == UT64_MAX) {
				break;
			}
			char str[512] = {0};
			(void)r_buf_read_at (eo->b, jump + len_str, (ut8*)str, sizeof (str) - 1);
			str[sizeof (str) - 1] = 0; // null terminate string
			RListIter *iter;
			RBinMap *p;
			r_list_foreach (core_maps, iter, p) {
				if (p->addr == addr) {
					p->file = strdup (str);
				}
			}
			len_str += strlen (str) + 1;
			n_maps--;
			i += (size_of * 2);
		}
	}

	return true;
}

static void r_bin_elf_map_free(RBinMap *map) {
	if (map) {
		free (map->file);
		free (map);
	}
}

RList *Elf_(get_maps)(ELFOBJ *eo) {
	if (!eo->phdr) {
		return NULL;
	}

	RList *maps = r_list_newf ((RListFree)r_bin_elf_map_free);
	if (!maps) {
		return NULL;
	}

	ut16 ph_num = eo->ehdr.e_phnum; //Skip PT_NOTE
	ut16 ph;
	for (ph = 0; ph < ph_num; ph++) {
		Elf_(Phdr) *p = &eo->phdr[ph];
		if (p->p_type != PT_LOAD) {
			continue;
		}

		RBinMap *map = R_NEW0 (RBinMap);
		map->addr = p->p_vaddr;
		map->size = p->p_memsz;
		map->perms = p->p_flags;
		map->offset = p->p_offset;
		map->file = NULL;
		r_list_append (maps, map);
	}

	if (!r_list_empty (maps)) {
		if (!get_nt_file_maps (eo, maps)) {
			R_LOG_ERROR ("Could not retrieve the names of all maps from NT_FILE");
		}
	}

	return maps;
}

char *Elf_(compiler)(ELFOBJ *eo) {
	RBinElfSection *section = get_section_by_name (eo, ".comment");
	if (!section) {
		return NULL;
	}

	ut32 sz = R_MIN (section->size, 128);
	if (sz < 1) {
		return NULL;
	}

	char *buf = malloc (sz + 1);
	if (!buf) {
		return NULL;
	}

	ut64 off = section->offset;
	if (r_buf_read_at (eo->b, off, (ut8*)buf, sz) != sz) {
		free (buf);
		return NULL;
	}
	buf[sz] = 0;

	const size_t buflen = strlen (buf);
	char *nullbyte = buf + buflen;
	if (buflen != sz && nullbyte[1] && buflen < sz) {
		nullbyte[0] = ' ';
	}
	buf[sz] = 0;
	r_str_trim (buf);
	char *res = r_str_escape (buf);
	free (buf);
	return res;
}

bool Elf_(is_executable)(ELFOBJ *eo) {
	const int t = eo->ehdr.e_type;
	return t == ET_EXEC || t == ET_DYN;
}

typedef struct {
	bool got;
	ut64 got_min;
	ut64 got_max;
	ut64 got_va;
	bool plt;
	ut64 plt_min;
	ut64 plt_max;
	ut64 plt_va;
} GotPltBounds;

static bool is_important(RBinElfReloc *reloc) {
	switch (reloc->type) {
	case 21:
	case 22:
	case 28: // R_ARM_CALL
	case 1026:
		return true;
	}
	// ignored
	switch (reloc->type) {
	case 7:
		return false;
	}

	R_LOG_DEBUG ("Reloc type %d not used for imports", reloc->type);
	return false;
}

static bool reloc_fill_local_address(ELFOBJ *eo) {
	RBinElfReloc *reloc;
	GotPltBounds ri = {0};
	RBinElfSection *s;

	// find got/plt section bounadries
	r_vector_foreach (&eo->g_sections, s) {
		if (!strcmp (s->name, ".got")) {
			ri.got = true;
			ri.got_min = s->offset;
			ri.got_max = s->offset + s->size;
			ri.got_va = s->rva;
		}
		if (!strcmp (s->name, ".plt")) {
			ri.plt_min = s->offset;
			ri.plt_max = s->offset + s->size;
			ri.plt_va = s->rva;
			ri.plt = true;
		}
		if (ri.got && ri.plt) {
			break;
		}
	}
	if (!ri.got || !ri.plt) {
		return false;
	}
	ut64 baddr = eo->user_baddr; // 0x10000;
	if (baddr == UT64_MAX) {
		baddr = eo->baddr;
	}
	int index = -2;
	// resolve got and plt
	r_vector_foreach (&eo->g_relocs, reloc) {
		const ut64 raddr = reloc->offset;
		if (raddr < ri.got_min || raddr >= ri.got_max) {
			continue;
		}
		ut64 rvaddr = reloc->offset; // rva (eo, reloc->offset, reloc->rva);
		ut64 pltptr = 0; // relocated buf tells the section to look at
#if R_BIN_ELF64
		r_buf_read_at (eo->b, rvaddr, (ut8*)&pltptr, 8);
#else
		ut32 n32 = 0;
		r_buf_read_at (eo->b, rvaddr, (ut8*)&n32, 4);
		pltptr = n32;
#endif
		bool ismagic = is_important (reloc);
		if (ismagic) {
			// text goes after the plt. so its possible that some symbols are pointed locally, thats all lsym is about
			if (pltptr > baddr) {
				pltptr -= baddr;
			}
			if (pltptr >= ri.plt_min && pltptr < ri.plt_max) {
#if 0
				ut64 saddr = reloc->rva - ri.got_va;
				if ((int)saddr < 4) {
					index = 0;
					continue;
				} else {
					index = (saddr / 4) - 4;
				}
#else
				index++;
#endif
				// TODO: if (reloc->type == 22) { // on arm!  // extra check of bounds
				ut64 naddr = baddr + pltptr + (index * 12) + 0x20;
				if (reloc->type == 1026) {
					naddr = baddr + pltptr + (index * 16) + 64 - 16;
				}
				if (naddr != UT64_MAX) {
					// this thing registers an 'rsym.${importname}' as a flag when loading the relocs from core/cbin.c
					reloc->laddr = naddr;
				} else {
					R_LOG_DEBUG ("Cannot resolve reloc reference");
				}
			}
		}
	}
	return true;
}

static void sdb_init_dtypes(ELFOBJ *eo) {
	sdb_set (eo->kv, "elf_type.cparse",
		"enum elf_type {"
			"ET_NONE=0,"
			"ET_REL=1,"
			"ET_EXEC=2,"
			"ET_DYN=3,"
			"ET_CORE=4,"
			"ET_LOOS=0xfe00,"
			"ET_HIOS=0xfeff,"
			"ET_LOPROC=0xff00,"
			"ET_HIPROC=0xffff"
		"};", 0);

	sdb_set (eo->kv, "elf_machine.cparse",
		"enum elf_machine {"
			"EM_NONE=0,"
			"EM_M32=1,"
			"EM_SPARC=2,"
			"EM_386=3,"
			"EM_68K=4,"
			"EM_88K=5,"
			"EM_IAMCU=6,"
			"EM_860=7,"
			"EM_MIPS=8,"
			"EM_S370=9,"
			"EM_MIPS_RS3_LE=10,"
			"EM_RS6000=11,"
			"EM_PARISC=15,"
			"EM_nCUBE=16,"
			"EM_VPP500=17,"
			"EM_SPARC32PLUS=18,"
			"EM_960=19,"
			"EM_PPC=20,"
			"EM_PPC64=21,"
			"EM_S390=22,"
			"EM_SPU=23,"
			"EM_V800=36,"
			"EM_FR20=37,"
			"EM_RH32=38,"
			"EM_RCE=39,"
			"EM_ARM=40,"
			"EM_ALPHA=41,"
			"EM_SH=42,"
			"EM_SPARCV9=43,"
			"EM_TRICORE=44,"
			"EM_ARC=45,"
			"EM_H8_300=46,"
			"EM_H8_300H=47,"
			"EM_H8S=48,"
			"EM_H8_500=49,"
			"EM_IA_64=50,"
			"EM_MIPS_X=51,"
			"EM_COLDFIRE=52,"
			"EM_68HC12=53,"
			"EM_MMA=54,"
			"EM_PCP=55,"
			"EM_NCPU=56,"
			"EM_NDR1=57,"
			"EM_STARCORE=58,"
			"EM_ME16=59,"
			"EM_ST100=60,"
			"EM_TINYJ=61,"
			"EM_X86_64=62,"
			"EM_PDSP=63,"
			"EM_PDP10=64,"
			"EM_PDP11=65,"
			"EM_FX66=66,"
			"EM_ST9PLUS=67,"
			"EM_ST7=68,"
			"EM_68HC16=69,"
			"EM_68HC11=70,"
			"EM_68HC08=71,"
			"EM_68HC05=72,"
			"EM_SVX=73,"
			"EM_ST19=74,"
			"EM_VAX=75,"
			"EM_CRIS=76,"
			"EM_JAVELIN=77,"
			"EM_FIREPATH=78,"
			"EM_ZSP=79,"
			"EM_MMIX=80,"
			"EM_HUANY=81,"
			"EM_PRISM=82,"
			"EM_AVR=83,"
			"EM_FR30=84,"
			"EM_D10V=85,"
			"EM_D30V=86,"
			"EM_V850=87,"
			"EM_M32R=88,"
			"EM_MN10300=89,"
			"EM_MN10200=90,"
			"EM_PJ=91,"
			"EM_OPENRISC=92,"
			"EM_ARC_COMPACT=93,"
			"EM_XTENSA=94,"
			"EM_VIDEOCORE=95,"
			"EM_TMM_GPP=96,"
			"EM_NS32K=97,"
			"EM_TPC=98,"
			"EM_SNP1K=99,"
			"EM_ST200=100,"
			"EM_IP2K=101,"
			"EM_MAX=102,"
			"EM_CR=103,"
			"EM_F2MC16=104,"
			"EM_MSP430=105,"
			"EM_BLACKFIN=106,"
			"EM_SE_C33=107,"
			"EM_SEP=108,"
			"EM_ARCA=109,"
			"EM_UNICORE=110,"
			"EM_EXCESS=111,"
			"EM_DXP=112,"
			"EM_ALTERA_NIOS2=113,"
			"EM_CRX=114,"
			"EM_XGATE=115,"
			"EM_C166=116,"
			"EM_M16C=117,"
			"EM_DSPIC30F=118,"
			"EM_CE=119,"
			"EM_M32C=120,"
			"EM_TSK3000=131,"
			"EM_RS08=132,"
			"EM_SHARC=133,"
			"EM_ECOG2=134,"
			"EM_SCORE7=135,"
			"EM_DSP24=136,"
			"EM_VIDEOCORE3=137,"
			"EM_LATTICEMICO32=138,"
			"EM_SE_C17=139,"
			"EM_TI_C6000=140,"
			"EM_TI_C2000=141,"
			"EM_TI_C5500=142,"
			"EM_TI_ARP32=143,"
			"EM_TI_PRU=144,"
			"EM_MMDSP_PLUS=160,"
			"EM_CYPRESS_M8C=161,"
			"EM_R32C=162,"
			"EM_TRIMEDIA=163,"
			"EM_QDSP6=164,"
			"EM_8051=165,"
			"EM_STXP7X=166,"
			"EM_NDS32=167,"
			"EM_ECOG1X=168,"
			"EM_MAXQ30=169,"
			"EM_XIMO16=170,"
			"EM_MANIK=171,"
			"EM_CRAYNV2=172,"
			"EM_RX=173,"
			"EM_METAG=174,"
			"EM_MCST_ELBRUS=175,"
			"EM_ECOG16=176,"
			"EM_CR16=177,"
			"EM_ETPU=178,"
			"EM_SLE9X=179,"
			"EM_L10M=180,"
			"EM_K10M=181,"
			"EM_AARCH64=183,"
			"EM_AVR32=185,"
			"EM_STM8=186,"
			"EM_TILE64=187,"
			"EM_TILEPRO=188,"
			"EM_CUDA=190,"
			"EM_TILEGX=191,"
			"EM_CLOUDSHIELD=192,"
			"EM_COREA_1ST=193,"
			"EM_COREA_2ND=194,"
			"EM_ARC_COMPACT2=195,"
			"EM_OPEN8=196,"
			"EM_RL78=197,"
			"EM_VIDEOCORE5=198,"
			"EM_78KOR=199,"
			"EM_56800EX=200,"
			"EM_BA1=201,"
			"EM_BA2=202,"
			"EM_XCORE=203,"
			"EM_MCHP_PIC=204,"
			"EM_INTEL205=205,"
			"EM_INTEL206=206,"
			"EM_INTEL207=207,"
			"EM_INTEL208=208,"
			"EM_INTEL209=209,"
			"EM_KM32=210,"
			"EM_KMX32=211,"
			"EM_KMX16=212,"
			"EM_KMX8=213,"
			"EM_KVARC=214,"
			"EM_CDP=215,"
			"EM_COGE=216,"
			"EM_COOL=217,"
			"EM_NORC=218,"
			"EM_CSR_KALIMBA=219,"
			"EM_AMDGPU=224,"
			"EM_RISCV=243,"
			"EM_LANAI=244,"
			"EM_BPF=247,"
			"EM_SBPF=263,"
			"EM_CSKY=252,"
			"EM_KVX=256,"
			"EM_LOONGARCH=258"
		"}", 0);

	sdb_set (eo->kv, "elf_class.cparse",
		"enum elf_class {"
			"ELFCLASSNONE=0,"
			"ELFCLASS32=1,"
			"ELFCLASS64=2"
		"};", 0);

	sdb_set (eo->kv, "elf_data.cparse",
		"enum elf_data {"
			"ELFDATANONE=0,"
			"ELFDATA2LSB=1,"
			"ELFDATA2MSB=2"
		"};", 0);

	sdb_set (eo->kv, "elf_hdr_version.cparse",
		"enum elf_hdr_version {"
			"EV_NONE=0,"
			"EV_CURRENT=1"
		"};", 0);

	sdb_set (eo->kv, "elf_obj_version.cparse",
		"enum elf_obj_version {"
			"EV_NONE=0,"
			"EV_CURRENT=1"
		"};", 0);
}

static void sdb_init_fmt(ELFOBJ *eo) {
	sdb_set (eo->kv, "elf_ident.format", "[4]z[1]E[1]E[1]E.::"
			" magic (elf_class)class (elf_data)data (elf_hdr_version)version", 0);

#if R_BIN_ELF64
	sdb_set (eo->kv, "elf_header.format", "?[2]E[2]E[4]EqqqxN2N2N2N2N2N2"
			" (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
			" entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx", 0);
#else
	sdb_set (eo->kv, "elf_header.format", "?[2]E[2]E[4]ExxxxN2N2N2N2N2N2"
			" (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
			" entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx", 0);
#endif
}

static void sdb_init_const(ELFOBJ *eo) {
	sdb_init_dtypes (eo);
	sdb_init_fmt (eo);
}
