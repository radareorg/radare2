/* radare - LGPL - Copyright 2008-2017 - nibble, pancake, alvaro_fe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <r_types.h>
#include <r_util.h>
#include "elf.h"

#ifdef IFDBG
#undef IFDBG
#endif

#define DO_THE_DBG 0
#define IFDBG if (DO_THE_DBG)
#define IFINT if (0)

#define ELF_PAGE_MASK 0xFFFFFFFFFFFFF000LL
#define ELF_PAGE_SIZE 12

#define R_ELF_NO_RELRO 0
#define R_ELF_PART_RELRO 1
#define R_ELF_FULL_RELRO 2

#define bprintf if(bin->verbose)eprintf

#define READ8(x, i) r_read_ble8(x + i); i += 1;
#define READ16(x, i) r_read_ble16(x + i, bin->endian); i += 2;
#define READ32(x, i) r_read_ble32(x + i, bin->endian); i += 4;
#define READ64(x, i) r_read_ble64(x + i, bin->endian); i += 8;

#define GROWTH_FACTOR (1.5)

static inline int __strnlen(const char *str, int len) {
	int l = 0;
	while (IS_PRINTABLE (*str) && --len) {
		if (((ut8)*str) == 0xff) {
			break;
		}
		str++;
		l++;
	}
	return l + 1;
}

static int handle_e_ident(ELFOBJ *bin) {
	return !strncmp ((char *)bin->ehdr.e_ident, ELFMAG, SELFMAG) ||
		   !strncmp ((char *)bin->ehdr.e_ident, CGCMAG, SCGCMAG);
}

static int init_ehdr(ELFOBJ *bin) {
	ut8 e_ident[EI_NIDENT];
	ut8 ehdr[sizeof (Elf_(Ehdr))] = {0};
	int i, len;
	if (r_buf_read_at (bin->b, 0, e_ident, EI_NIDENT) == -1) {
		bprintf ("Warning: read (magic)\n");
		return false;
	}
	sdb_set (bin->kv, "elf_type.cparse", "enum elf_type { ET_NONE=0, ET_REL=1,"
			" ET_EXEC=2, ET_DYN=3, ET_CORE=4, ET_LOOS=0xfe00, ET_HIOS=0xfeff,"
			" ET_LOPROC=0xff00, ET_HIPROC=0xffff };", 0);
	sdb_set (bin->kv, "elf_machine.cparse", "enum elf_machine{EM_NONE=0, EM_M32=1,"
			" EM_SPARC=2, EM_386=3, EM_68K=4, EM_88K=5, EM_486=6, "
			" EM_860=7, EM_MIPS=8, EM_S370=9, EM_MIPS_RS3_LE=10, EM_RS6000=11,"
			" EM_UNKNOWN12=12, EM_UNKNOWN13=13, EM_UNKNOWN14=14, "
			" EM_PA_RISC=15, EM_PARISC=EM_PA_RISC, EM_nCUBE=16, EM_VPP500=17,"
			" EM_SPARC32PLUS=18, EM_960=19, EM_PPC=20, EM_PPC64=21, "
			" EM_S390=22, EM_UNKNOWN22=EM_S390, EM_UNKNOWN23=23, EM_UNKNOWN24=24,"
			" EM_UNKNOWN25=25, EM_UNKNOWN26=26, EM_UNKNOWN27=27, EM_UNKNOWN28=28,"
			" EM_UNKNOWN29=29, EM_UNKNOWN30=30, EM_UNKNOWN31=31, EM_UNKNOWN32=32,"
			" EM_UNKNOWN33=33, EM_UNKNOWN34=34, EM_UNKNOWN35=35, EM_V800=36,"
			" EM_FR20=37, EM_RH32=38, EM_RCE=39, EM_ARM=40, EM_ALPHA=41, EM_SH=42,"
			" EM_SPARCV9=43, EM_TRICORE=44, EM_ARC=45, EM_H8_300=46, EM_H8_300H=47,"
			" EM_H8S=48, EM_H8_500=49, EM_IA_64=50, EM_MIPS_X=51, EM_COLDFIRE=52,"
			" EM_68HC12=53, EM_MMA=54, EM_PCP=55, EM_NCPU=56, EM_NDR1=57,"
			" EM_STARCORE=58, EM_ME16=59, EM_ST100=60, EM_TINYJ=61, EM_AMD64=62,"
			" EM_X86_64=EM_AMD64, EM_PDSP=63, EM_UNKNOWN64=64, EM_UNKNOWN65=65,"
			" EM_FX66=66, EM_ST9PLUS=67, EM_ST7=68, EM_68HC16=69, EM_68HC11=70,"
			" EM_68HC08=71, EM_68HC05=72, EM_SVX=73, EM_ST19=74, EM_VAX=75, "
			" EM_CRIS=76, EM_JAVELIN=77, EM_FIREPATH=78, EM_ZSP=79, EM_MMIX=80,"
			" EM_HUANY=81, EM_PRISM=82, EM_AVR=83, EM_FR30=84, EM_D10V=85, EM_D30V=86,"
			" EM_V850=87, EM_M32R=88, EM_MN10300=89, EM_MN10200=90, EM_PJ=91,"
			" EM_OPENRISC=92, EM_ARC_A5=93, EM_XTENSA=94, EM_NUM=95};", 0);
	sdb_num_set (bin->kv, "elf_header.offset", 0, 0);
	sdb_num_set (bin->kv, "elf_header.size", sizeof (Elf_(Ehdr)), 0);
#if R_BIN_ELF64
	sdb_set (bin->kv, "elf_header.format", "[16]z[2]E[2]Exqqqxwwwwww"
		" ident (elf_type)type (elf_machine)machine version entry phoff shoff flags ehsize"
		" phentsize phnum shentsize shnum shstrndx", 0);
#else
	sdb_set (bin->kv, "elf_header.format", "[16]z[2]E[2]Exxxxxwwwwww"
		" ident (elf_type)type (elf_machine)machine version entry phoff shoff flags ehsize"
		" phentsize phnum shentsize shnum shstrndx", 0);
#endif
	bin->endian = (e_ident[EI_DATA] == ELFDATA2MSB)? 1: 0;
	memset (&bin->ehdr, 0, sizeof (Elf_(Ehdr)));

	len = r_buf_read_at (bin->b, 0, ehdr, sizeof (Elf_(Ehdr)));
	if (len < 1) {
		bprintf ("Warning: read (ehdr)\n");
		return false;
	}
	memcpy (&bin->ehdr.e_ident, ehdr, 16);
	i = 16;
	bin->ehdr.e_type = READ16 (ehdr, i)
	bin->ehdr.e_machine = READ16 (ehdr, i)
	bin->ehdr.e_version = READ32 (ehdr, i)
#if R_BIN_ELF64
	bin->ehdr.e_entry = READ64 (ehdr, i)
	bin->ehdr.e_phoff = READ64 (ehdr, i)
	bin->ehdr.e_shoff = READ64 (ehdr, i)
#else
	bin->ehdr.e_entry = READ32 (ehdr, i)
	bin->ehdr.e_phoff = READ32 (ehdr, i)
	bin->ehdr.e_shoff = READ32 (ehdr, i)
#endif
	bin->ehdr.e_flags = READ32 (ehdr, i)
	bin->ehdr.e_ehsize = READ16 (ehdr, i)
	bin->ehdr.e_phentsize = READ16 (ehdr, i)
	bin->ehdr.e_phnum = READ16 (ehdr, i)
	bin->ehdr.e_shentsize = READ16 (ehdr, i)
	bin->ehdr.e_shnum = READ16 (ehdr, i)
	bin->ehdr.e_shstrndx = READ16 (ehdr, i)
	return handle_e_ident (bin);
	// Usage example:
	// > td `k bin/cur/info/elf_type.cparse`; td `k bin/cur/info/elf_machine.cparse`
	// > pf `k bin/cur/info/elf_header.format` @ `k bin/cur/info/elf_header.offset`
}

static int init_phdr(ELFOBJ *bin) {
	ut32 phdr_size;
	ut8 phdr[sizeof (Elf_(Phdr))] = {0};
	int i, j, len;
	if (!bin->ehdr.e_phnum) {
		return false;
	}
	if (bin->phdr) {
		return true;
	}
	if (!UT32_MUL (&phdr_size, (ut32)bin->ehdr.e_phnum, sizeof (Elf_(Phdr)))) {
		return false;
	}
	if (!phdr_size) {
		return false;
	}
	if (phdr_size > bin->size) {
		return false;
	}
	if (phdr_size > (ut32)bin->size) {
		return false;
	}
	if (bin->ehdr.e_phoff > bin->size) {
		return false;
	}
	if (bin->ehdr.e_phoff + phdr_size > bin->size) {
		return false;
	}
	if (!(bin->phdr = calloc (phdr_size, 1))) {
		perror ("malloc (phdr)");
		return false;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		j = 0;
		len = r_buf_read_at (bin->b, bin->ehdr.e_phoff + i * sizeof (Elf_(Phdr)), phdr, sizeof (Elf_(Phdr)));
		if (len < 1) {
			bprintf ("Warning: read (phdr)\n");
			R_FREE (bin->phdr);
			return false;
		}
		bin->phdr[i].p_type = READ32 (phdr, j)
#if R_BIN_ELF64
		bin->phdr[i].p_flags = READ32 (phdr, j)
		bin->phdr[i].p_offset = READ64 (phdr, j)
		bin->phdr[i].p_vaddr = READ64 (phdr, j)
		bin->phdr[i].p_paddr = READ64 (phdr, j)
		bin->phdr[i].p_filesz = READ64 (phdr, j)
		bin->phdr[i].p_memsz = READ64 (phdr, j)
		bin->phdr[i].p_align = READ64 (phdr, j)
#else
		bin->phdr[i].p_offset = READ32 (phdr, j)
		bin->phdr[i].p_vaddr = READ32 (phdr, j)
		bin->phdr[i].p_paddr = READ32 (phdr, j)
		bin->phdr[i].p_filesz = READ32 (phdr, j)
		bin->phdr[i].p_memsz = READ32 (phdr, j)
		bin->phdr[i].p_flags = READ32 (phdr, j)
		bin->phdr[i].p_align = READ32 (phdr, j)
#endif
	}
	sdb_num_set (bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_num_set (bin->kv, "elf_phdr.size", sizeof (Elf_(Phdr)), 0);
	sdb_set (bin->kv, "elf_p_type.cparse", "enum elf_p_type {PT_NULL=0,PT_LOAD=1,PT_DYNAMIC=2,"
			"PT_INTERP=3,PT_NOTE=4,PT_SHLIB=5,PT_PHDR=6,PT_LOOS=0x60000000,"
			"PT_HIOS=0x6fffffff,PT_LOPROC=0x70000000,PT_HIPROC=0x7fffffff};", 0);
	sdb_set (bin->kv, "elf_p_flags.cparse", "enum elf_p_flags {PF_None=0,PF_Exec=1,"
			"PF_Write=2,PF_Write_Exec=3,PF_Read=4,PF_Read_Exec=5,PF_Read_Write=6,"
			"PF_Read_Write_Exec=7};", 0);
#if R_BIN_ELF64
	sdb_set (bin->kv, "elf_phdr.format", "[4]E[4]Eqqqqqq (elf_p_type)type (elf_p_flags)flags"
			" offset vaddr paddr filesz memsz align", 0);
#else
	sdb_set (bin->kv, "elf_phdr.format", "[4]Exxxxx[4]Ex (elf_p_type)type offset vaddr paddr"
			" filesz memsz (elf_p_flags)flags align", 0);
#endif
	return true;
	// Usage example:
	// > td `k bin/cur/info/elf_p_type.cparse`; td `k bin/cur/info/elf_p_flags.cparse`
	// > pf `k bin/cur/info/elf_phdr.format` @ `k bin/cur/info/elf_phdr.offset`
}


static int init_shdr(ELFOBJ *bin) {
	ut32 shdr_size;
	ut8 shdr[sizeof (Elf_(Shdr))] = {0};
	int i, j, len;

	if (!bin || bin->shdr) {
		return true;
	}
	if (!UT32_MUL (&shdr_size, bin->ehdr.e_shnum, sizeof (Elf_(Shdr)))) {
		return false;
	}
	if (shdr_size < 1) {
		return false;
	}
	if (shdr_size > bin->size) {
		return false;
	}
	if (bin->ehdr.e_shoff > bin->size) {
		return false;
	}
	if (bin->ehdr.e_shoff + shdr_size > bin->size) {
		return false;
	}
	if (!(bin->shdr = calloc (1, shdr_size + 1))) {
		perror ("malloc (shdr)");
		return false;
	}
	sdb_num_set (bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff, 0);
	sdb_num_set (bin->kv, "elf_shdr.size", sizeof (Elf_(Shdr)), 0);
	sdb_set (bin->kv, "elf_s_type.cparse", "enum elf_s_type {SHT_NULL=0,SHT_PROGBITS=1,"
			"SHT_SYMTAB=2,SHT_STRTAB=3,SHT_RELA=4,SHT_HASH=5,SHT_DYNAMIC=6,SHT_NOTE=7,"
			"SHT_NOBITS=8,SHT_REL=9,SHT_SHLIB=10,SHT_DYNSYM=11,SHT_LOOS=0x60000000,"
			"SHT_HIOS=0x6fffffff,SHT_LOPROC=0x70000000,SHT_HIPROC=0x7fffffff};", 0);

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		j = 0;
		len = r_buf_read_at (bin->b, bin->ehdr.e_shoff + i * sizeof (Elf_(Shdr)), shdr, sizeof (Elf_(Shdr)));
		if (len < 1) {
			bprintf ("Warning: read (shdr) at 0x%"PFMT64x"\n", (ut64) bin->ehdr.e_shoff);
			R_FREE (bin->shdr);
			return false;
		}
		bin->shdr[i].sh_name = READ32 (shdr, j)
		bin->shdr[i].sh_type = READ32 (shdr, j)
#if R_BIN_ELF64
		bin->shdr[i].sh_flags = READ64 (shdr, j)
		bin->shdr[i].sh_addr = READ64 (shdr, j)
		bin->shdr[i].sh_offset = READ64 (shdr, j)
		bin->shdr[i].sh_size = READ64 (shdr, j)
		bin->shdr[i].sh_link = READ32 (shdr, j)
		bin->shdr[i].sh_info = READ32 (shdr, j)
		bin->shdr[i].sh_addralign = READ64 (shdr, j)
		bin->shdr[i].sh_entsize = READ64 (shdr, j)
#else
		bin->shdr[i].sh_flags = READ32 (shdr, j)
		bin->shdr[i].sh_addr = READ32 (shdr, j)
		bin->shdr[i].sh_offset = READ32 (shdr, j)
		bin->shdr[i].sh_size = READ32 (shdr, j)
		bin->shdr[i].sh_link = READ32 (shdr, j)
		bin->shdr[i].sh_info = READ32 (shdr, j)
		bin->shdr[i].sh_addralign = READ32 (shdr, j)
		bin->shdr[i].sh_entsize = READ32 (shdr, j)
#endif
	}

#if R_BIN_ELF64
	sdb_set (bin->kv, "elf_s_flags_64.cparse", "enum elf_s_flags_64 {SF64_None=0,SF64_Exec=1,"
			"SF64_Alloc=2,SF64_Alloc_Exec=3,SF64_Write=4,SF64_Write_Exec=5,"
			"SF64_Write_Alloc=6,SF64_Write_Alloc_Exec=7};", 0);
	sdb_set (bin->kv, "elf_shdr.format", "x[4]E[8]Eqqqxxqq name (elf_s_type)type"
			" (elf_s_flags_64)flags addr offset size link info addralign entsize", 0);
#else
	sdb_set (bin->kv, "elf_s_flags_32.cparse", "enum elf_s_flags_32 {SF32_None=0,SF32_Exec=1,"
			"SF32_Alloc=2,SF32_Alloc_Exec=3,SF32_Write=4,SF32_Write_Exec=5,"
			"SF32_Write_Alloc=6,SF32_Write_Alloc_Exec=7};", 0);
	sdb_set (bin->kv, "elf_shdr.format", "x[4]E[4]Exxxxxxx name (elf_s_type)type"
			" (elf_s_flags_32)flags addr offset size link info addralign entsize", 0);
#endif
	return true;
	// Usage example:
	// > td `k bin/cur/info/elf_s_type.cparse`; td `k bin/cur/info/elf_s_flags_64.cparse`
	// > pf `k bin/cur/info/elf_shdr.format` @ `k bin/cur/info/elf_shdr.offset`
}

static int init_strtab(ELFOBJ *bin) {
	if (bin->strtab || !bin->shdr) {
		return false;
	}
	if (bin->ehdr.e_shstrndx != SHN_UNDEF &&
		(bin->ehdr.e_shstrndx >= bin->ehdr.e_shnum ||
		(bin->ehdr.e_shstrndx >= SHN_LORESERVE &&
		bin->ehdr.e_shstrndx < SHN_HIRESERVE)))
		return false;

	/* sh_size must be lower than UT32_MAX and not equal to zero, to avoid bugs on malloc() */
	if (bin->shdr[bin->ehdr.e_shstrndx].sh_size > UT32_MAX) {
		return false;
	}
	if (!bin->shdr[bin->ehdr.e_shstrndx].sh_size) {
		return false;
	}
	bin->shstrtab_section = bin->strtab_section = &bin->shdr[bin->ehdr.e_shstrndx];
	bin->shstrtab_size = bin->strtab_section->sh_size;
	if (bin->shstrtab_size > bin->size) {
		return false;
	}
	if (!(bin->shstrtab = calloc (1, bin->shstrtab_size + 1))) {
		perror ("malloc");
		bin->shstrtab = NULL;
		return false;
	}
	if (bin->shstrtab_section->sh_offset > bin->size) {
		R_FREE (bin->shstrtab);
		return false;
	}

	if (bin->shstrtab_section->sh_offset +
		bin->shstrtab_section->sh_size  > bin->size) {
		R_FREE (bin->shstrtab);
		return false;
	}
	if (r_buf_read_at (bin->b, bin->shstrtab_section->sh_offset, (ut8*)bin->shstrtab,
				bin->shstrtab_section->sh_size + 1) < 1) {
		bprintf ("Warning: read (shstrtab) at 0x%"PFMT64x"\n",
				(ut64) bin->shstrtab_section->sh_offset);
		R_FREE (bin->shstrtab);
		return false;
	}
	bin->shstrtab[bin->shstrtab_section->sh_size] = '\0';

	sdb_num_set (bin->kv, "elf_shstrtab.offset", bin->shstrtab_section->sh_offset, 0);
	sdb_num_set (bin->kv, "elf_shstrtab.size", bin->shstrtab_section->sh_size, 0);

	return true;
}

static int init_dynamic_section(struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Dyn) *dyn = NULL;
	Elf_(Dyn) d = {0};
	Elf_(Addr) strtabaddr = 0;
	ut64 offset = 0;
	char *strtab = NULL;
	size_t relentry = 0, strsize = 0;
	int entries;
	int i, j, len, r;
	ut8 sdyn[sizeof (Elf_(Dyn))] = {0};
	ut32 dyn_size = 0;

	if (!bin || !bin->phdr || !bin->ehdr.e_phnum) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_phnum ; i++) {
		if (bin->phdr[i].p_type == PT_DYNAMIC) {
			dyn_size = bin->phdr[i].p_filesz;
			break;
		}
	}
	if (i == bin->ehdr.e_phnum) {
		return false;
	}
	if (bin->phdr[i].p_filesz > bin->size) {
		return false;
	}
	if (bin->phdr[i].p_offset > bin->size) {
		return false;
	}
	if (bin->phdr[i].p_offset + sizeof(Elf_(Dyn)) > bin->size) {
		return false;
	}
	for (entries = 0; entries < (dyn_size / sizeof (Elf_(Dyn))); entries++) {
		j = 0;
		len = r_buf_read_at (bin->b, bin->phdr[i].p_offset + entries * sizeof (Elf_(Dyn)), sdyn, sizeof (Elf_(Dyn)));
		if (len < 1) {
			goto beach;
		}
#if R_BIN_ELF64
		d.d_tag = READ64 (sdyn, j)
#else
		d.d_tag = READ32 (sdyn, j)
#endif
		if (d.d_tag == DT_NULL) {
			break;
		}
	}
	if (entries < 1) {
		return false;
	}
	dyn = (Elf_(Dyn)*)calloc (entries, sizeof (Elf_(Dyn)));
	if (!dyn) {
		return false;
	}
	if (!UT32_MUL (&dyn_size, entries, sizeof (Elf_(Dyn)))) {
		goto beach;
	}
	if (!dyn_size) {
		goto beach;
	}
	offset = Elf_(r_bin_elf_v2p) (bin, bin->phdr[i].p_vaddr);
	if (offset > bin->size || offset + dyn_size > bin->size) {
		goto beach;
	}
	for (i = 0; i < entries; i++) {
		j = 0;
		r_buf_read_at (bin->b, offset + i * sizeof (Elf_(Dyn)), sdyn, sizeof (Elf_(Dyn)));
		if (len < 1) {
			bprintf("Warning: read (dyn)\n");
		}
#if R_BIN_ELF64
		dyn[i].d_tag = READ64 (sdyn, j)
		dyn[i].d_un.d_ptr = READ64 (sdyn, j)
#else
		dyn[i].d_tag = READ32 (sdyn, j)
		dyn[i].d_un.d_ptr = READ32 (sdyn, j)
#endif

		switch (dyn[i].d_tag) {
		case DT_STRTAB: strtabaddr = Elf_(r_bin_elf_v2p) (bin, dyn[i].d_un.d_ptr); break;
		case DT_STRSZ: strsize = dyn[i].d_un.d_val; break;
		case DT_PLTREL: bin->is_rela = dyn[i].d_un.d_val; break;
		case DT_RELAENT: relentry = dyn[i].d_un.d_val; break;
		default:
			if ((dyn[i].d_tag >= DT_VERSYM) && (dyn[i].d_tag <= DT_VERNEEDNUM)) {
				bin->version_info[DT_VERSIONTAGIDX (dyn[i].d_tag)] = dyn[i].d_un.d_val;
			}
			break;
		}
	}
	if (!bin->is_rela) {
		bin->is_rela = sizeof (Elf_(Rela)) == relentry? DT_RELA : DT_REL;
	}
	if (!strtabaddr || strtabaddr > bin->size || strsize > ST32_MAX || !strsize || strsize > bin->size) {
		if (!strtabaddr) {
			bprintf ("Warning: section.shstrtab not found or invalid\n");
		}
		goto beach;
	}
	strtab = (char *)calloc (1, strsize + 1);
	if (!strtab) {
		goto beach;
	}
	if (strtabaddr + strsize > bin->size) {
		free (strtab);
		goto beach;
	}
	r = r_buf_read_at (bin->b, strtabaddr, (ut8 *)strtab, strsize);
	if (r < 1) {
		free (strtab);
		goto beach;
	}
	bin->dyn_buf = dyn;
	bin->dyn_entries = entries;
	bin->strtab = strtab;
	bin->strtab_size = strsize;
	r = Elf_(r_bin_elf_has_relro)(bin);
	switch (r) {
	case R_ELF_FULL_RELRO:
		sdb_set (bin->kv, "elf.relro", "full", 0);
		break;
	case R_ELF_PART_RELRO:
		sdb_set (bin->kv, "elf.relro", "partial", 0);
		break;
	default:
		sdb_set (bin->kv, "elf.relro", "no", 0);
		break;
	}
	sdb_num_set (bin->kv, "elf_strtab.offset", strtabaddr, 0);
	sdb_num_set (bin->kv, "elf_strtab.size", strsize, 0);
	return true;
beach:
	free (dyn);
	return false;
}

static RBinElfSection* get_section_by_name(ELFOBJ *bin, const char *section_name) {
	int i;
	if (!bin->g_sections) {
		return NULL;
	}
	for (i = 0; !bin->g_sections[i].last; i++) {
		if (!strncmp (bin->g_sections[i].name, section_name, ELF_STRING_LENGTH-1)) {
			return &bin->g_sections[i];
		}
	}
	return NULL;
}

static char *get_ver_flags(ut32 flags) {
	static char buff[32];
	buff[0] = 0;

	if (!flags) {
		return "none";
	}
	if (flags & VER_FLG_BASE) {
		strcpy (buff, "BASE ");
	}
	if (flags & VER_FLG_WEAK) {
		if (flags & VER_FLG_BASE) {
			strcat (buff, "| ");
		}
		strcat (buff, "WEAK ");
	}

	if (flags & ~(VER_FLG_BASE | VER_FLG_WEAK)) {
		strcat (buff, "| <unknown>");
	}
	return buff;
}

static Sdb *store_versioninfo_gnu_versym(ELFOBJ *bin, Elf_(Shdr) *shdr, int sz) {
	int i;
	const ut64 num_entries = sz / sizeof (Elf_(Versym));
	const char *section_name = "";
	const char *link_section_name = "";
	Elf_(Shdr) *link_shdr = NULL;
	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	if (!bin->version_info[DT_VERSIONTAGIDX (DT_VERSYM)]) {
		sdb_free (sdb);
		return NULL;
	}
	if (shdr->sh_link > bin->ehdr.e_shnum) {
		sdb_free (sdb);
		return NULL;
	}
	link_shdr = &bin->shdr[shdr->sh_link];
	ut8 *edata = (ut8*) calloc (R_MAX (1, num_entries), sizeof (ut16));
	if (!edata) {
		sdb_free (sdb);
		return NULL;
	}
	ut16 *data = (ut16*) calloc (R_MAX (1, num_entries), sizeof (ut16));
	if (!data) {
		free (edata);
		sdb_free (sdb);
		return NULL;
	}
	ut64 off = Elf_(r_bin_elf_v2p) (bin, bin->version_info[DT_VERSIONTAGIDX (DT_VERSYM)]);
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	r_buf_read_at (bin->b, off, edata, sizeof (ut16) * num_entries);
	sdb_set (sdb, "section_name", section_name, 0);
	sdb_num_set (sdb, "num_entries", num_entries, 0);
	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set (sdb, "link", shdr->sh_link, 0);
	sdb_set (sdb, "link_section_name", link_section_name, 0);
	for (i = num_entries; i--;) {
		data[i] = r_read_ble16 (&edata[i * sizeof (ut16)], bin->endian);
	}
	R_FREE (edata);
	for (i = 0; i < num_entries; i += 4) {
		int j;
		int check_def;
		char key[32] = {0};
		Sdb *sdb_entry = sdb_new0 ();
		snprintf (key, sizeof (key), "entry%d", i / 4);
		sdb_ns_set (sdb, key, sdb_entry);
		sdb_num_set (sdb_entry, "idx", i, 0);

		for (j = 0; (j < 4) && (i + j) < num_entries; ++j) {
			int k;
			char *tmp_val = NULL;
			snprintf (key, sizeof (key), "value%d", j);
			switch (data[i + j]) {
			case 0:
				sdb_set (sdb_entry, key, "0 (*local*)", 0);
				break;
			case 1:
				sdb_set (sdb_entry, key, "1 (*global*)", 0);
				break;
			default:
				tmp_val = sdb_fmt (0, "%x ", data[i+j] & 0x7FFF);
				check_def = true;
				if (bin->version_info[DT_VERSIONTAGIDX (DT_VERNEED)]) {
					Elf_(Verneed) vn;
					ut8 svn[sizeof (Elf_(Verneed))] = {0};
					ut64 offset = Elf_(r_bin_elf_v2p) (bin, bin->version_info[DT_VERSIONTAGIDX (DT_VERNEED)]);
					do {
						Elf_(Vernaux) vna;
						ut8 svna[sizeof (Elf_(Vernaux))] = {0};
						ut64 a_off;
						if (offset > bin->size || offset + sizeof (vn) > bin->size) {
							goto beach;
						}
						if (r_buf_read_at (bin->b, offset, svn, sizeof (svn)) < 0) {
							bprintf ("Warning: Cannot read Verneed for Versym\n");
							goto beach;
						}
						k = 0;
						vn.vn_version = READ16 (svn, k)
						vn.vn_cnt = READ16 (svn, k)
						vn.vn_file = READ32 (svn, k)
						vn.vn_aux = READ32 (svn, k)
						vn.vn_next = READ32 (svn, k)
						a_off = offset + vn.vn_aux;
						do {
							if (a_off > bin->size || a_off + sizeof (vna) > bin->size) {
								goto beach;
							}
							if (r_buf_read_at (bin->b, a_off, svna, sizeof (svna)) < 0) {
								bprintf ("Warning: Cannot read Vernaux for Versym\n");
								goto beach;
							}
							k = 0;
							vna.vna_hash = READ32 (svna, k)
							vna.vna_flags = READ16 (svna, k)
							vna.vna_other = READ16 (svna, k)
							vna.vna_name = READ32 (svna, k)
							vna.vna_next = READ32 (svna, k)
							a_off += vna.vna_next;
						} while (vna.vna_other != data[i + j] && vna.vna_next != 0);

						if (vna.vna_other == data[i + j]) {
							if (vna.vna_name > bin->strtab_size) {
								goto beach;
							}
							sdb_set (sdb_entry, key, sdb_fmt (0, "%s(%s)", tmp_val, bin->strtab + vna.vna_name), 0);
							check_def = false;
							break;
						}
						offset += vn.vn_next;
					} while (vn.vn_next);
				}

				ut64 vinfoaddr = bin->version_info[DT_VERSIONTAGIDX (DT_VERDEF)];
				if (check_def && data[i + j] != 0x8001 && vinfoaddr) {
					Elf_(Verdef) vd;
					ut8 svd[sizeof (Elf_(Verdef))] = {0};
					ut64 offset = Elf_(r_bin_elf_v2p) (bin, vinfoaddr);
					if (offset > bin->size || offset + sizeof (vd) > bin->size) {
						goto beach;
					}
					do {
						if (r_buf_read_at (bin->b, offset, svd, sizeof (svd)) < 0) {
							bprintf ("Warning: Cannot read Verdef for Versym\n");
							goto beach;
						}
						k = 0;
						vd.vd_version = READ16 (svd, k)
						vd.vd_flags = READ16 (svd, k)
						vd.vd_ndx = READ16 (svd, k)
						vd.vd_cnt = READ16 (svd, k)
						vd.vd_hash = READ32 (svd, k)
						vd.vd_aux = READ32 (svd, k)
						vd.vd_next = READ32 (svd, k)
						offset += vd.vd_next;
					} while (vd.vd_ndx != (data[i + j] & 0x7FFF) && vd.vd_next != 0);

					if (vd.vd_ndx == (data[i + j] & 0x7FFF)) {
						Elf_(Verdaux) vda;
						ut8 svda[sizeof (Elf_(Verdaux))] = {0};
						ut64 off_vda = offset - vd.vd_next + vd.vd_aux;
						if (off_vda > bin->size || off_vda + sizeof (vda) > bin->size) {
							goto beach;
						}
						if (r_buf_read_at (bin->b, off_vda, svda, sizeof (svda)) < 0) {
							bprintf ("Warning: Cannot read Verdaux for Versym\n");
							goto beach;
						}
						k = 0;
						vda.vda_name = READ32 (svda, k)
						vda.vda_next = READ32 (svda, k)
						if (vda.vda_name > bin->strtab_size) {
							goto beach;
						}
						const char *name = bin->strtab + vda.vda_name;
						sdb_set (sdb_entry, key, sdb_fmt (0,"%s(%s%-*s)", tmp_val, name, (int)(12 - strlen (name)),")") , 0);
					}
				}
			}
		}
	}
beach:
	free (data);
	return sdb;
}

static Sdb *store_versioninfo_gnu_verdef(ELFOBJ *bin, Elf_(Shdr) *shdr, int sz) {
	const char *section_name = "";
	const char *link_section_name = "";
	char *end = NULL;
	Elf_(Shdr) *link_shdr = NULL;
	ut8 dfs[sizeof (Elf_(Verdef))] = {0};
	Sdb *sdb;
	int cnt, i;
	if (shdr->sh_link > bin->ehdr.e_shnum) {
		return false;
	}
	link_shdr = &bin->shdr[shdr->sh_link];
	if (shdr->sh_size < 1) {
		return false;
	}
	Elf_(Verdef) *defs = calloc (shdr->sh_size, sizeof (char));
	if (!defs) {
		return false;
	}
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (link_shdr && bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	if (!defs) {
		bprintf ("Warning: Cannot allocate memory (Check Elf_(Verdef))\n");
		return NULL;
	}
	sdb = sdb_new0 ();
	end = (char *)defs + shdr->sh_size;
	sdb_set (sdb, "section_name", section_name, 0);
	sdb_num_set (sdb, "entries", shdr->sh_info, 0);
	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set (sdb, "link", shdr->sh_link, 0);
	sdb_set (sdb, "link_section_name", link_section_name, 0);

	for (cnt = 0, i = 0; cnt < shdr->sh_info && ((char *)defs + i < end); ++cnt) {
		Sdb *sdb_verdef = sdb_new0 ();
		char *vstart = ((char*)defs) + i;
		char key[32] = {0};
		Elf_(Verdef) *verdef = (Elf_(Verdef)*)vstart;
		Elf_(Verdaux) aux = {0};
		int j = 0;
		int isum = 0;

		r_buf_read_at (bin->b, shdr->sh_offset + i, dfs, sizeof (Elf_(Verdef)));
		verdef->vd_version = READ16 (dfs, j)
		verdef->vd_flags = READ16 (dfs, j)
		verdef->vd_ndx = READ16 (dfs, j)
		verdef->vd_cnt = READ16 (dfs, j)
		verdef->vd_hash = READ32 (dfs, j)
		verdef->vd_aux = READ32 (dfs, j)
		verdef->vd_next = READ32 (dfs, j)
		vstart += verdef->vd_aux;
		if (vstart > end || vstart + sizeof (Elf_(Verdaux)) > end) {
			sdb_free (sdb_verdef);
			goto out_error;
		}

		j = 0;
		aux.vda_name = READ32 (vstart, j)
		aux.vda_next = READ32 (vstart, j)

		isum = i + verdef->vd_aux;
		if (aux.vda_name > bin->dynstr_size) {
			sdb_free (sdb_verdef);
			goto out_error;
		}

		sdb_num_set (sdb_verdef, "idx", i, 0);
		sdb_num_set (sdb_verdef, "vd_version", verdef->vd_version, 0);
		sdb_num_set (sdb_verdef, "vd_ndx", verdef->vd_ndx, 0);
		sdb_num_set (sdb_verdef, "vd_cnt", verdef->vd_cnt, 0);
		sdb_set (sdb_verdef, "vda_name", &bin->dynstr[aux.vda_name], 0);
		sdb_set (sdb_verdef, "flags", get_ver_flags (verdef->vd_flags), 0);

		for (j = 1; j < verdef->vd_cnt; ++j) {
			int k;
			Sdb *sdb_parent = sdb_new0 ();
			isum += aux.vda_next;
			vstart += aux.vda_next;
			if (vstart > end || vstart + sizeof(Elf_(Verdaux)) > end) {
				sdb_free (sdb_verdef);
				sdb_free (sdb_parent);
				goto out_error;
			}
			k = 0;
			aux.vda_name = READ32 (vstart, k)
			aux.vda_next = READ32 (vstart, k)
			if (aux.vda_name > bin->dynstr_size) {
				sdb_free (sdb_verdef);
				sdb_free (sdb_parent);
				goto out_error;
			}
			sdb_num_set (sdb_parent, "idx", isum, 0);
			sdb_num_set (sdb_parent, "parent", j, 0);
			sdb_set (sdb_parent, "vda_name", &bin->dynstr[aux.vda_name], 0);
			snprintf (key, sizeof (key), "parent%d", j - 1);
			sdb_ns_set (sdb_verdef, key, sdb_parent);
		}

		snprintf (key, sizeof (key), "verdef%d", cnt);
		sdb_ns_set (sdb, key, sdb_verdef);
		if (!verdef->vd_next) {
			sdb_free (sdb_verdef);
			goto out_error;
		}
		i += verdef->vd_next;
	}
	free (defs);
	return sdb;
out_error:
	free (defs);
	sdb_free (sdb);
	return NULL;
}

static Sdb *store_versioninfo_gnu_verneed(ELFOBJ *bin, Elf_(Shdr) *shdr, int sz) {
	ut8 *end, *need = NULL;
	const char *section_name = "";
	Elf_(Shdr) *link_shdr = NULL;
	const char *link_section_name = "";
	Sdb *sdb_vernaux = NULL;
	Sdb *sdb_version = NULL;
	Sdb *sdb = NULL;
	int i, cnt;

	if (!bin || !bin->dynstr) {
		return NULL;
	}
	if (shdr->sh_link > bin->ehdr.e_shnum) {
		return NULL;
	}
	if (shdr->sh_size < 1) {
		return NULL;
	}
	sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}
	link_shdr = &bin->shdr[shdr->sh_link];
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	if (!(need = (ut8*) calloc (R_MAX (1, shdr->sh_size), sizeof (ut8)))) {
		bprintf ("Warning: Cannot allocate memory for Elf_(Verneed)\n");
		goto beach;
	}
	end = need + shdr->sh_size;
	sdb_set (sdb, "section_name", section_name, 0);
	sdb_num_set (sdb, "num_entries", shdr->sh_info, 0);
	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set (sdb, "link", shdr->sh_link, 0);
	sdb_set (sdb, "link_section_name", link_section_name, 0);

	if (shdr->sh_offset > bin->size || shdr->sh_offset + shdr->sh_size > bin->size) {
		goto beach;
	}
	if (shdr->sh_offset + shdr->sh_size < shdr->sh_size) {
		goto beach;
	}
	i = r_buf_read_at (bin->b, shdr->sh_offset, need, shdr->sh_size);
	if (i < 0)
		goto beach;
	//XXX we should use DT_VERNEEDNUM instead of sh_info
	//TODO https://sourceware.org/ml/binutils/2014-11/msg00353.html
	for (i = 0, cnt = 0; cnt < shdr->sh_info; ++cnt) {
		int j, isum;
		ut8 *vstart = need + i;
		Elf_(Verneed) vvn = {0};
		if (vstart + sizeof (Elf_(Verneed)) > end) {
			goto beach;
		}
		Elf_(Verneed) *entry = &vvn;
		char key[32] = {0};
		sdb_version = sdb_new0 ();
		if (!sdb_version) {
			goto beach;
		}
		j = 0;
		vvn.vn_version = READ16 (vstart, j)
		vvn.vn_cnt = READ16 (vstart, j)
		vvn.vn_file = READ32 (vstart, j)
		vvn.vn_aux = READ32 (vstart, j)
		vvn.vn_next = READ32 (vstart, j)

		sdb_num_set (sdb_version, "vn_version", entry->vn_version, 0);
		sdb_num_set (sdb_version, "idx", i, 0);
		if (entry->vn_file > bin->dynstr_size) {
			goto beach;
		}
		{
			char *s = r_str_ndup (&bin->dynstr[entry->vn_file], 16);
			sdb_set (sdb_version, "file_name", s, 0);
			free (s);
		}
		sdb_num_set (sdb_version, "cnt", entry->vn_cnt, 0);
		vstart += entry->vn_aux;
		for (j = 0, isum = i + entry->vn_aux; j < entry->vn_cnt && vstart + sizeof (Elf_(Vernaux)) <= end; ++j) {
			int k;
			Elf_(Vernaux) * aux = NULL;
			Elf_(Vernaux) vaux = {0};
			sdb_vernaux = sdb_new0 ();
			if (!sdb_vernaux) {
				goto beach;
			}
			aux = (Elf_(Vernaux)*)&vaux;
			k = 0;
			vaux.vna_hash = READ32 (vstart, k)
			vaux.vna_flags = READ16 (vstart, k)
			vaux.vna_other = READ16 (vstart, k)
			vaux.vna_name = READ32 (vstart, k)
			vaux.vna_next = READ32 (vstart, k)
			if (aux->vna_name > bin->dynstr_size) {
				goto beach;
			}
			sdb_num_set (sdb_vernaux, "idx", isum, 0);
			if (aux->vna_name > 0 && aux->vna_name + 8 < bin->dynstr_size) {
				char name [16];
				strncpy (name, &bin->dynstr[aux->vna_name], sizeof (name)-1);
				name[sizeof(name)-1] = 0;
				sdb_set (sdb_vernaux, "name", name, 0);
			}
			sdb_set (sdb_vernaux, "flags", get_ver_flags (aux->vna_flags), 0);
			sdb_num_set (sdb_vernaux, "version", aux->vna_other, 0);
			isum += aux->vna_next;
			vstart += aux->vna_next;
			snprintf (key, sizeof (key), "vernaux%d", j);
			sdb_ns_set (sdb_version, key, sdb_vernaux);
		}
		if ((int)entry->vn_next < 0) {
			bprintf ("Invalid vn_next\n");
			break;
		}
		i += entry->vn_next;
		snprintf (key, sizeof (key), "version%d", cnt );
		sdb_ns_set (sdb, key, sdb_version);
		//if entry->vn_next is 0 it iterate infinitely
		if (!entry->vn_next) {
			break;
		}
	}
	free (need);
	return sdb;
beach:
	free (need);
	sdb_free (sdb_vernaux);
	sdb_free (sdb_version);
	sdb_free (sdb);
	return NULL;
}

static Sdb *store_versioninfo(ELFOBJ *bin) {
	Sdb *sdb_versioninfo = NULL;
	int num_verdef = 0;
	int num_verneed = 0;
	int num_versym = 0;
	int i;

	if (!bin || !bin->shdr) {
		return NULL;
	}
	if (!(sdb_versioninfo = sdb_new0 ())) {
		return NULL;
	}

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		Sdb *sdb = NULL;
		char key[32] = {0};
		int size = bin->shdr[i].sh_size;

		if (size - (i*sizeof(Elf_(Shdr)) > bin->size)) {
			size = bin->size - (i*sizeof(Elf_(Shdr)));
		}
		int left = size - (i * sizeof (Elf_(Shdr)));
		left = R_MIN (left, bin->shdr[i].sh_size);
		if (left < 0) {
			break;
		}
		switch (bin->shdr[i].sh_type) {
		case SHT_GNU_verdef:
			sdb = store_versioninfo_gnu_verdef (bin, &bin->shdr[i], left);
			snprintf (key, sizeof (key), "verdef%d", num_verdef++);
			sdb_ns_set (sdb_versioninfo, key, sdb);
			break;
		case SHT_GNU_verneed:
			sdb = store_versioninfo_gnu_verneed (bin, &bin->shdr[i], left);
			snprintf (key, sizeof (key), "verneed%d", num_verneed++);
			sdb_ns_set (sdb_versioninfo, key, sdb);
			break;
		case SHT_GNU_versym:
			sdb = store_versioninfo_gnu_versym (bin, &bin->shdr[i], left);
			snprintf (key, sizeof (key), "versym%d", num_versym++);
			sdb_ns_set (sdb_versioninfo, key, sdb);
			break;
		}
	}

	return sdb_versioninfo;
}

static bool init_dynstr(ELFOBJ *bin) {
	int i, r;
	const char *section_name = NULL;
	if (!bin || !bin->shdr) {
		return false;
	}
	if (!bin->shstrtab) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_shnum; ++i) {
		if (bin->shdr[i].sh_name > bin->shstrtab_size) {
			return false;
		}
		section_name = &bin->shstrtab[bin->shdr[i].sh_name];
		if (bin->shdr[i].sh_type == SHT_STRTAB && !strcmp (section_name, ".dynstr")) {
			if (!(bin->dynstr = (char*) calloc (bin->shdr[i].sh_size + 1, sizeof (char)))) {
				bprintf("Warning: Cannot allocate memory for dynamic strings\n");
				return false;
			}
			if (bin->shdr[i].sh_offset > bin->size) {
				return false;
			}
			if (bin->shdr[i].sh_offset + bin->shdr[i].sh_size > bin->size) {
				return false;
			}
			if (bin->shdr[i].sh_offset + bin->shdr[i].sh_size < bin->shdr[i].sh_size) {
				return false;
			}
			r = r_buf_read_at (bin->b, bin->shdr[i].sh_offset, (ut8*)bin->dynstr, bin->shdr[i].sh_size);
			if (r < 1) {
				R_FREE (bin->dynstr);
				bin->dynstr_size = 0;
				return false;
			}
			bin->dynstr_size = bin->shdr[i].sh_size;
			return true;
		}
	}
	return false;
}

static int elf_init(ELFOBJ *bin) {
	bin->phdr = NULL;
	bin->shdr = NULL;
	bin->strtab = NULL;
	bin->shstrtab = NULL;
	bin->strtab_size = 0;
	bin->strtab_section = NULL;
	bin->dyn_buf = NULL;
	bin->dynstr = NULL;
	ZERO_FILL (bin->version_info);

	bin->g_sections = NULL;
	bin->g_symbols = NULL;
	bin->g_imports = NULL;
	/* bin is not an ELF */
	if (!init_ehdr (bin)) {
		return false;
	}
	if (!init_phdr (bin)) {
		bprintf ("Warning: Cannot initialize program headers\n");
	}
	if (!init_shdr (bin)) {
		bprintf ("Warning: Cannot initialize section headers\n");
	}
	if (!init_strtab (bin)) {
		bprintf ("Warning: Cannot initialize strings table\n");
	}
	if (!init_dynstr (bin)) {
		bprintf ("Warning: Cannot initialize dynamic strings\n");
	}
	bin->baddr = Elf_(r_bin_elf_get_baddr) (bin);
	if (!init_dynamic_section (bin) && !Elf_(r_bin_elf_get_static)(bin))
		bprintf ("Warning: Cannot initialize dynamic section\n");

	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;
	bin->symbols_by_ord_size = 0;
	bin->symbols_by_ord = NULL;
	bin->g_sections = Elf_(r_bin_elf_get_sections) (bin);
	bin->boffset = Elf_(r_bin_elf_get_boffset) (bin);
	sdb_ns_set (bin->kv, "versioninfo", store_versioninfo (bin));

	return true;
}

ut64 Elf_(r_bin_elf_get_section_offset)(ELFOBJ *bin, const char *section_name) {
	RBinElfSection *section = get_section_by_name (bin, section_name);
	if (!section) return UT64_MAX;
	return section->offset;
}

ut64 Elf_(r_bin_elf_get_section_addr)(ELFOBJ *bin, const char *section_name) {
	RBinElfSection *section = get_section_by_name (bin, section_name);
	return section? section->rva: UT64_MAX;
}

ut64 Elf_(r_bin_elf_get_section_addr_end)(ELFOBJ *bin, const char *section_name) {
	RBinElfSection *section = get_section_by_name (bin, section_name);
	return section? section->rva + section->size: UT64_MAX;
}
#define REL (is_rela ? (void*)rela : (void*)rel)
#define REL_BUF is_rela ? (ut8*)(&rela[k]) : (ut8*)(&rel[k])
#define REL_OFFSET is_rela ? rela[k].r_offset : rel[k].r_offset
#define REL_TYPE is_rela ? rela[k].r_info  : rel[k].r_info

static ut64 get_import_addr(ELFOBJ *bin, int sym) {
	Elf_(Rel) *rel = NULL;
	Elf_(Rela) *rela = NULL;
	ut8 rl[sizeof (Elf_(Rel))] = {0};
	ut8 rla[sizeof (Elf_(Rela))] = {0};
	RBinElfSection *rel_sec = NULL;
	Elf_(Addr) plt_sym_addr = -1;
	ut64 got_addr, got_offset;
	ut64 plt_addr;
	int j, k, tsize, len, nrel;
	bool is_rela = false;
	const char *rel_sect[] = { ".rel.plt", ".rela.plt", ".rel.dyn", ".rela.dyn", NULL };
	const char *rela_sect[] = { ".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn", NULL };

	if ((!bin->shdr || !bin->strtab) && !bin->phdr) {
		return -1;
	}
	if ((got_offset = Elf_(r_bin_elf_get_section_offset) (bin, ".got")) == -1 &&
		(got_offset = Elf_(r_bin_elf_get_section_offset) (bin, ".got.plt")) == -1) {
		return -1;
	}
	if ((got_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".got")) == -1 &&
		(got_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".got.plt")) == -1) {
		return -1;
	}
	if (bin->is_rela == DT_REL) {
		j = 0;
		while (!rel_sec && rel_sect[j]) {
			rel_sec = get_section_by_name (bin, rel_sect[j++]);
		}
		tsize = sizeof (Elf_(Rel));
	} else if (bin->is_rela == DT_RELA) {
		j = 0;
		while (!rel_sec && rela_sect[j]) {
			rel_sec = get_section_by_name (bin, rela_sect[j++]);
		}
		is_rela = true;
		tsize = sizeof (Elf_(Rela));
	}
	if (!rel_sec) {
		return -1;
	}
	if (rel_sec->size < 1) {
		return -1;
	}
	nrel = (ut32)((int)rel_sec->size / (int)tsize);
	if (nrel < 1) {
		return -1;
	}
	if (is_rela) {
		rela = calloc (nrel, tsize);
		if (!rela) {
			return -1;
		}
	} else {
		rel = calloc (nrel, tsize);
		if (!rel) {
			return -1;
		}
	}
	for (j = k = 0; j < rel_sec->size && k < nrel; j += tsize, k++) {
		int l = 0;
		if (rel_sec->offset + j > bin->size) {
			goto out;
		}
		if (rel_sec->offset + j + tsize > bin->size) {
			goto out;
		}
		len = r_buf_read_at (
			bin->b, rel_sec->offset + j, is_rela ? rla : rl,
			is_rela ? sizeof (Elf_ (Rela)) : sizeof (Elf_ (Rel)));
		if (len < 1) {
			goto out;
		}
#if R_BIN_ELF64
		if (is_rela) {
			rela[k].r_offset = READ64 (rla, l)
			rela[k].r_info = READ64 (rla, l)
			rela[k].r_addend = READ64 (rla, l)
		} else {
			rel[k].r_offset = READ64 (rl, l)
			rel[k].r_info = READ64 (rl, l)
		}
#else
		if (is_rela) {
			rela[k].r_offset = READ32 (rla, l)
			rela[k].r_info = READ32 (rla, l)
			rela[k].r_addend = READ32 (rla, l)
		} else {
			rel[k].r_offset = READ32 (rl, l)
			rel[k].r_info = READ32 (rl, l)
		}
#endif
		int reloc_type = ELF_R_TYPE (REL_TYPE);
		int reloc_sym = ELF_R_SYM (REL_TYPE);

		if (reloc_sym == sym) {
			int of = REL_OFFSET;
			of = of - got_addr + got_offset;
			switch (bin->ehdr.e_machine) {
			case EM_PPC:
			case EM_PPC64:
				{
					RBinElfSection *s = get_section_by_name (bin, ".plt");
					if (s) {
						ut8 buf[4];
						ut64 base;
						len = r_buf_read_at (bin->b, s->offset, buf, sizeof (buf));
						if (len < 4) {
							goto out;
						}
						base = r_read_be32 (buf);
						base -= (nrel * 16);
						base += (k * 16);
						plt_addr = base;
						free (REL);
						return plt_addr;
					}
				}
				break;
			case EM_SPARC:
			case EM_SPARCV9:
			case EM_SPARC32PLUS:
				plt_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".plt");
				if (plt_addr == -1) {
					free (rela);
					return -1;
				}
				if (reloc_type == R_386_PC16) {
					plt_addr += k * 12 + 20;
					// thumb symbol
					if (plt_addr & 1) {
						plt_addr--;
					}
					free (REL);
					return plt_addr;
				} else {
					bprintf ("Unknown sparc reloc type %d\n", reloc_type);
				}
				/* SPARC */
				break;
			case EM_ARM:
			case EM_AARCH64:
				plt_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".plt");
				if (plt_addr == -1) {
					free (rela);
					return UT32_MAX;
				}
				switch (reloc_type) {
				case R_386_8:
					{
						plt_addr += k * 12 + 20;
						// thumb symbol
						if (plt_addr & 1) {
							plt_addr--;
						}
						free (REL);
						return plt_addr;
					}
					break;
				case 1026: // arm64 aarch64
					plt_sym_addr = plt_addr + k * 16 + 32;
					goto done;
				default:
					bprintf ("Unsupported relocation type for imports %d\n", reloc_type);
					break;
				}
				break;
			case EM_386:
			case EM_X86_64:
				switch (reloc_type) {
				case 1: // unknown relocs found in voidlinux for x86-64
					// break;
				case R_386_GLOB_DAT:
				case R_386_JMP_SLOT:
					{
					ut8 buf[8];
					if (of + sizeof(Elf_(Addr)) < bin->size) {
						// ONLY FOR X86
						if (of > bin->size || of + sizeof (Elf_(Addr)) > bin->size) {
							goto out;
						}
						len = r_buf_read_at (bin->b, of, buf, sizeof (Elf_(Addr)));
						if (len < -1) {
							goto out;
						}
						plt_sym_addr = sizeof (Elf_(Addr)) == 4
									 ? r_read_le32 (buf)
									 : r_read_le64 (buf);

						if (!plt_sym_addr) {
							//XXX HACK ALERT!!!! full relro?? try to fix it 
							//will there always be .plt.got, what would happen if is .got.plt?
							RBinElfSection *s = get_section_by_name (bin, ".plt.got");
 							if (Elf_(r_bin_elf_has_relro)(bin) < R_ELF_PART_RELRO || !s) {
								goto done;
							}
							plt_addr = s->offset;
							of = of + got_addr - got_offset;
							while (plt_addr + 2 + 4 < s->offset + s->size) {
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
								len = r_buf_read_at (bin->b, plt_addr + 2, buf, 4);
								if (len < -1) {
									goto out;
								}
								plt_sym_addr = sizeof (Elf_(Addr)) == 4
										? r_read_le32 (buf)
										: r_read_le64 (buf);

								//relative address
								if ((plt_addr + 6 + Elf_(r_bin_elf_v2p) (bin, plt_sym_addr)) == of) {
									plt_sym_addr = plt_addr;
									goto done;
								} else if (plt_sym_addr == of) {
									plt_sym_addr = plt_addr;
									goto done;
								}
								plt_addr += 8;
							}
						} else {
							plt_sym_addr -= 6;
						}
						goto done;
					}
					break;
					}
				default:
					bprintf ("Unsupported relocation type for imports %d\n", reloc_type);
					free (REL);
					return of;
					break;
				}
				break;
			case 8:
				// MIPS32 BIG ENDIAN relocs
				{
					RBinElfSection *s = get_section_by_name (bin, ".rela.plt");
					if (s) {
						ut8 buf[1024];
						const ut8 *base;
						plt_addr = s->rva + s->size;
						len = r_buf_read_at (bin->b, s->offset + s->size, buf, sizeof (buf));
						if (len != sizeof (buf)) {
							// oops
						}
						base = r_mem_mem_aligned (buf, sizeof (buf), (const ut8*)"\x3c\x0f\x00", 3, 4);
						if (base) {
							plt_addr += (int)(size_t)(base - buf);
						} else {
							plt_addr += 108 + 8; // HARDCODED HACK
						}
						plt_addr += k * 16;
						free (REL);
						return plt_addr;
					}
				}
				break;
			default:
				bprintf ("Unsupported relocs type %d for arch %d\n",
					reloc_type, bin->ehdr.e_machine);
				break;
			}
		}
	}
done:
	free (REL);
	return plt_sym_addr;
out:
	free (REL);
	return -1;
}

int Elf_(r_bin_elf_has_nx)(ELFOBJ *bin) {
	int i;
	if (bin && bin->phdr) {
		for (i = 0; i < bin->ehdr.e_phnum; i++) {
			if (bin->phdr[i].p_type == PT_GNU_STACK) {
				return (!(bin->phdr[i].p_flags & 1))? 1: 0;
			}
		}
	}
	return 0;
}

int Elf_(r_bin_elf_has_relro)(ELFOBJ *bin) {
	int i;
	bool haveBindNow = false;
	bool haveGnuRelro = false;
	if (bin && bin->dyn_buf) {
		for (i = 0; i < bin->dyn_entries; i++) {
			switch (bin->dyn_buf[i].d_tag) {
			case DT_BIND_NOW:
				haveBindNow = true;
				break;
			case DT_FLAGS:
				for (i++; i < bin->dyn_entries ; i++) {
					ut32 dTag = bin->dyn_buf[i].d_tag;
					if (!dTag) {
						break;
					}
					switch (dTag) {
					case DT_FLAGS_1:
						if (bin->dyn_buf[i].d_un.d_val & DF_1_NOW) {
							haveBindNow = true;
							break;
						}
					}
				}
				break;
			}
		}
	}
	if (bin && bin->phdr) {
		for (i = 0; i < bin->ehdr.e_phnum; i++) {
			if (bin->phdr[i].p_type == PT_GNU_RELRO) {
				haveGnuRelro = true;
				break;
			}
		}
	}
	if (haveGnuRelro) {
		if (haveBindNow) {
			return R_ELF_FULL_RELRO;
		}
		return R_ELF_PART_RELRO;
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

ut64 Elf_(r_bin_elf_get_baddr)(ELFOBJ *bin) {
	int i;
	ut64 tmp, base = UT64_MAX;
	if (!bin) {
		return 0;
	}
	if (bin->phdr) {
		for (i = 0; i < bin->ehdr.e_phnum; i++) {
			if (bin->phdr[i].p_type == PT_LOAD) {
				tmp = (ut64)bin->phdr[i].p_vaddr & ELF_PAGE_MASK;
				tmp = tmp - (tmp % (1 << ELF_PAGE_SIZE));
				if (tmp < base) {
					base = tmp;
				}
			}
		}
	}
	if (base == UT64_MAX && bin->ehdr.e_type == ET_REL) {
		//we return our own base address for ET_REL type
		//we act as a loader for ELF
		return 0x08000000;
	}
	return base == UT64_MAX ? 0 : base;
}

ut64 Elf_(r_bin_elf_get_boffset)(ELFOBJ *bin) {
	int i;
	ut64 tmp, base = UT64_MAX;
	if (bin && bin->phdr) {
		for (i = 0; i < bin->ehdr.e_phnum; i++) {
			if (bin->phdr[i].p_type == PT_LOAD) {
				tmp =  (ut64)bin->phdr[i].p_offset & ELF_PAGE_MASK;
				tmp = tmp - (tmp % (1 << ELF_PAGE_SIZE));
				if (tmp < base) {
					base = tmp;
				}
			}
		}
	}
	return base == UT64_MAX ? 0 : base;
}

ut64 Elf_(r_bin_elf_get_init_offset)(ELFOBJ *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[512];
	if (!bin) {
		return 0LL;
	}
	if (r_buf_read_at (bin->b, entry + 16, buf, sizeof (buf)) < 1) {
		bprintf ("Warning: read (init_offset)\n");
		return 0;
	}
	if (buf[0] == 0x68) { // push // x86 only
		ut64 addr;
		memmove (buf, buf+1, 4);
		addr = (ut64)r_read_le32 (buf);
		return Elf_(r_bin_elf_v2p) (bin, addr);
	}
	return 0;
}

ut64 Elf_(r_bin_elf_get_fini_offset)(ELFOBJ *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[512];
	if (!bin) {
		return 0LL;
	}

	if (r_buf_read_at (bin->b, entry+11, buf, sizeof (buf)) == -1) {
		bprintf ("Warning: read (get_fini)\n");
		return 0;
	}
	if (*buf == 0x68) { // push // x86/32 only
		ut64 addr;
		memmove (buf, buf+1, 4);
		addr = (ut64)r_read_le32 (buf);
		return Elf_(r_bin_elf_v2p) (bin, addr);
	}
	return 0;
}

ut64 Elf_(r_bin_elf_get_entry_offset)(ELFOBJ *bin) {
	ut64 entry;
	if (!bin) {
		return 0LL;
	}
	entry = bin->ehdr.e_entry;
	if (!entry) {
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".init.text");
		if (entry != UT64_MAX) {
			return entry;
		}
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".text");
		if (entry != UT64_MAX) {
			return entry;
		}
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".init");
		if (entry != UT64_MAX) {
			return entry;
		}
		if (entry == UT64_MAX) {
			return 0;
		}
	}
	return Elf_(r_bin_elf_v2p) (bin, entry);
}

static ut64 getmainsymbol(ELFOBJ *bin) {
	struct r_bin_elf_symbol_t *symbol;
	int i;
	if (!(symbol = Elf_(r_bin_elf_get_symbols) (bin))) {
		return UT64_MAX;
	}
	for (i = 0; !symbol[i].last; i++) {
		if (!strcmp (symbol[i].name, "main")) {
			ut64 paddr = symbol[i].offset;
			return Elf_(r_bin_elf_p2v) (bin, paddr);
		}
	}
	return UT64_MAX;
}

ut64 Elf_(r_bin_elf_get_main_offset)(ELFOBJ *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[512];
	if (!bin) {
		return 0LL;
	}
	if (entry > bin->size || (entry + sizeof (buf)) > bin->size) {
		return 0;
	}
	if (r_buf_read_at (bin->b, entry, buf, sizeof (buf)) < 1) {
		bprintf ("Warning: read (main)\n");
		return 0;
	}
	// ARM64
	if (buf[0x18+3] == 0x58 && buf[0x2f] == 0x00) {
		ut32 entry_vaddr = Elf_(r_bin_elf_p2v) (bin, entry);
		ut32 main_addr = r_read_le32 (&buf[0x30]);
		if ((main_addr >> 16) == (entry_vaddr >> 16)) {
			return Elf_(r_bin_elf_v2p) (bin, main_addr);
		}
	}

	// TODO: Use arch to identify arch before memcmp's
	// ARM
	ut64 text = Elf_(r_bin_elf_get_section_offset)(bin, ".text");
	ut64 text_end = text + bin->size;

	// ARM-Thumb-Linux
	if (entry & 1 && !memcmp (buf, "\xf0\x00\x0b\x4f\xf0\x00", 6)) {
		ut32 * ptr = (ut32*)(buf+40-1);
		if (*ptr &1) {
			return Elf_(r_bin_elf_v2p) (bin, *ptr -1);
		}
	}
	if (!memcmp (buf, "\x00\xb0\xa0\xe3\x00\xe0\xa0\xe3", 8)) {
		// endian stuff here
		ut32 *addr = (ut32*)(buf+0x34);
		/*
		   0x00012000    00b0a0e3     mov fp, 0
		   0x00012004    00e0a0e3     mov lr, 0
		*/
		if (*addr > text && *addr < (text_end)) {
			return Elf_(r_bin_elf_v2p) (bin, *addr);
		}
	}

	// MIPS
	/* get .got, calculate offset of main symbol */
	if (!memcmp (buf, "\x21\x00\xe0\x03\x01\x00\x11\x04", 8)) {

		/*
		    assuming the startup code looks like
		        got = gp-0x7ff0
		        got[index__libc_start_main] ( got[index_main] );

		    looking for the instruction generating the first argument to find main
		        lw a0, offset(gp)
		*/

		ut64 got_offset;
		if ((got_offset = Elf_(r_bin_elf_get_section_offset) (bin, ".got")) != -1 ||
		    (got_offset = Elf_(r_bin_elf_get_section_offset) (bin, ".got.plt")) != -1)
		{
			const ut64 gp = got_offset + 0x7ff0;
			unsigned i;
			for (i = 0; i < sizeof(buf) / sizeof(buf[0]); i += 4) {
				const ut32 instr = r_read_le32 (&buf[i]);
				if ((instr & 0xffff0000) == 0x8f840000) { // lw a0, offset(gp)
					const short delta = instr & 0x0000ffff;
					r_buf_read_at (bin->b, /* got_entry_offset = */ gp + delta, buf, 4);
					return Elf_(r_bin_elf_v2p) (bin, r_read_le32 (&buf[0]));
				}
			}
		}

		return 0;
	}
	// ARM
	if (!memcmp (buf, "\x24\xc0\x9f\xe5\x00\xb0\xa0\xe3", 8)) {
		ut64 addr = r_read_le32 (&buf[48]);
		return Elf_(r_bin_elf_v2p) (bin, addr);
	}
	// X86-CGC
	if (buf[0] == 0xe8 && !memcmp (buf + 5, "\x50\xe8\x00\x00\x00\x00\xb8\x01\x00\x00\x00\x53", 12)) {
		size_t SIZEOF_CALL = 5;
		ut64 rel_addr = (ut64)((int)(buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24)));
		ut64 addr = Elf_(r_bin_elf_p2v)(bin, entry + SIZEOF_CALL);
		addr += rel_addr;
		return Elf_(r_bin_elf_v2p) (bin, addr);
	}
	// X86-PIE
	if (buf[0x00] == 0x48 && buf[0x1e] == 0x8d && buf[0x11] == 0xe8) {
		ut32 *pmain = (ut32*)(buf + 0x30);
		ut64 vmain = Elf_(r_bin_elf_p2v) (bin, (ut64)*pmain);
		ut64 ventry = Elf_(r_bin_elf_p2v) (bin, entry);
		if (vmain >> 16 == ventry >> 16) {
			return (ut64)vmain;
		}
	}
	// X86-PIE
	if (buf[0x1d] == 0x48 && buf[0x1e] == 0x8b) {
		if (!memcmp (buf, "\x31\xed\x49\x89", 4)) {// linux
			ut64 maddr, baddr;
			ut8 n32s[sizeof (ut32)] = {0};
			maddr = entry + 0x24 + r_read_le32 (buf + 0x20);
			if (r_buf_read_at (bin->b, maddr, n32s, sizeof (ut32)) == -1) {
				bprintf ("Warning: read (maddr) 2\n");
				return 0;
			}
			maddr = (ut64)r_read_le32 (&n32s[0]);
			baddr = (bin->ehdr.e_entry >> 16) << 16;
			if (bin->phdr) {
				baddr = Elf_(r_bin_elf_get_baddr) (bin);
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
	if (!memcmp (buf+29, "\x48\xc7\xc7", 3)) { // linux
		ut64 addr = (ut64)r_read_le32 (&buf[29 + 3]);
		return Elf_(r_bin_elf_v2p) (bin, addr);
	}
#else
	if (buf[23] == '\x68') {
		ut64 addr = (ut64)r_read_le32 (&buf[23 + 1]);
		return Elf_(r_bin_elf_v2p) (bin, addr);
	}
#endif
	/* linux64 pie main -- probably buggy in some cases */
	if (buf[29] == 0x48 && buf[30] == 0x8d) { // lea rdi, qword [rip-0x21c4]
		ut8 *p = buf + 32;
		st32 maindelta = (st32)r_read_le32 (p);
		ut64 vmain = (ut64)(entry + 29 + maindelta) + 7;
		ut64 ventry = Elf_(r_bin_elf_p2v) (bin, entry);
		if (vmain>>16 == ventry>>16) {
			return (ut64)vmain;
		}
	}
	/* find sym.main if possible */
	{
		ut64 m = getmainsymbol (bin);
		if (m != UT64_MAX) return m;
	}
	return UT64_MAX;
}

int Elf_(r_bin_elf_get_stripped)(ELFOBJ *bin) {
	int i;
	if (!bin->shdr) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_type == SHT_SYMTAB) {
			return false;
		}
	}
	return true;
}

char *Elf_(r_bin_elf_intrp)(ELFOBJ *bin) {
	int i;
	if (!bin || !bin->phdr) {
		return NULL;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_INTERP) {
			char *str = NULL;
			ut64 addr = bin->phdr[i].p_offset;
			int sz = bin->phdr[i].p_memsz;
			sdb_num_set (bin->kv, "elf_header.intrp_addr", addr, 0);
			sdb_num_set (bin->kv, "elf_header.intrp_size", sz, 0);
			if (sz < 1) {
				return NULL;
			}
			str = malloc (sz + 1);
			if (!str) {
				return NULL;
			}
			if (r_buf_read_at (bin->b, addr, (ut8*)str, sz) < 1) {
				bprintf ("Warning: read (main)\n");
				return 0;
			}
			str[sz] = 0;
			sdb_set (bin->kv, "elf_header.intrp", str, 0);
			return str;
		}
	}
	return NULL;
}

int Elf_(r_bin_elf_get_static)(ELFOBJ *bin) {
	int i;
	if (!bin->phdr) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_INTERP) {
			return false;
		}
	}
	return true;
}

char* Elf_(r_bin_elf_get_data_encoding)(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_DATA]) {
	case ELFDATANONE: return strdup ("none");
	case ELFDATA2LSB: return strdup ("2's complement, little endian");
	case ELFDATA2MSB: return strdup ("2's complement, big endian");
	default: return r_str_newf ("<unknown: %x>", bin->ehdr.e_ident[EI_DATA]);
	}
}

int Elf_(r_bin_elf_has_va)(ELFOBJ *bin) {
	return true;
}

char* Elf_(r_bin_elf_get_arch)(ELFOBJ *bin) {
	switch (bin->ehdr.e_machine) {
	case EM_ARC:
	case EM_ARC_A5:
		return strdup ("arc");
	case EM_AVR: return strdup ("avr");
	case EM_CRIS: return strdup ("cris");
	case EM_68K: return strdup ("m68k");
	case EM_MIPS:
	case EM_MIPS_RS3_LE:
	case EM_MIPS_X:
		return strdup ("mips");
	case EM_MCST_ELBRUS:
		return strdup ("elbrus");
	case EM_TRICORE:
		return strdup ("tricore");
	case EM_ARM:
	case EM_AARCH64:
		return strdup ("arm");
	case EM_HEXAGON:
		return strdup ("hexagon");
	case EM_BLACKFIN:
		return strdup ("blackfin");
	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		return strdup ("sparc");
	case EM_PPC:
	case EM_PPC64:
		return strdup ("ppc");
	case EM_PARISC:
		return strdup ("hppa");
	case EM_PROPELLER:
		return strdup ("propeller");
	case EM_MICROBLAZE:
		return strdup ("microblaze.gnu");
	case EM_RISCV:
		return strdup ("riscv");
	case EM_VAX:
		return strdup ("vax");
	case EM_XTENSA:
		return strdup ("xtensa");
	case EM_LANAI:
		return strdup ("lanai");
	case EM_VIDEOCORE3:
	case EM_VIDEOCORE4:
		return strdup ("vc4");
	case EM_SH:
		return strdup ("sh");
	case EM_V850:
		return strdup ("v850");
	case EM_IA_64:
		return strdup("ia64");
	default: return strdup ("x86");
	}
}

char* Elf_(r_bin_elf_get_machine_name)(ELFOBJ *bin) {
	switch (bin->ehdr.e_machine) {
	case EM_NONE:        return strdup ("No machine");
	case EM_M32:         return strdup ("AT&T WE 32100");
	case EM_SPARC:       return strdup ("SUN SPARC");
	case EM_386:         return strdup ("Intel 80386");
	case EM_68K:         return strdup ("Motorola m68k family");
	case EM_88K:         return strdup ("Motorola m88k family");
	case EM_860:         return strdup ("Intel 80860");
	case EM_MIPS:        return strdup ("MIPS R3000");
	case EM_S370:        return strdup ("IBM System/370");
	case EM_MIPS_RS3_LE: return strdup ("MIPS R3000 little-endian");
	case EM_PARISC:      return strdup ("HPPA");
	case EM_VPP500:      return strdup ("Fujitsu VPP500");
	case EM_SPARC32PLUS: return strdup ("Sun's \"v8plus\"");
	case EM_960:         return strdup ("Intel 80960");
	case EM_PPC:         return strdup ("PowerPC");
	case EM_PPC64:       return strdup ("PowerPC 64-bit");
	case EM_S390:        return strdup ("IBM S390");
	case EM_V800:        return strdup ("NEC V800 series");
	case EM_FR20:        return strdup ("Fujitsu FR20");
	case EM_RH32:        return strdup ("TRW RH-32");
	case EM_RCE:         return strdup ("Motorola RCE");
	case EM_ARM:         return strdup ("ARM");
	case EM_BLACKFIN:    return strdup ("Analog Devices Blackfin");
	case EM_FAKE_ALPHA:  return strdup ("Digital Alpha");
	case EM_SH:          return strdup ("Hitachi SH");
	case EM_SPARCV9:     return strdup ("SPARC v9 64-bit");
	case EM_TRICORE:     return strdup ("Siemens Tricore");
	case EM_ARC:         return strdup ("Argonaut RISC Core");
	case EM_H8_300:      return strdup ("Hitachi H8/300");
	case EM_H8_300H:     return strdup ("Hitachi H8/300H");
	case EM_H8S:         return strdup ("Hitachi H8S");
	case EM_H8_500:      return strdup ("Hitachi H8/500");
	case EM_IA_64:       return strdup ("Intel Merced");
	case EM_MIPS_X:      return strdup ("Stanford MIPS-X");
	case EM_COLDFIRE:    return strdup ("Motorola Coldfire");
	case EM_68HC12:      return strdup ("Motorola M68HC12");
	case EM_MMA:         return strdup ("Fujitsu MMA Multimedia Accelerator");
	case EM_PCP:         return strdup ("Siemens PCP");
	case EM_NCPU:        return strdup ("Sony nCPU embeeded RISC");
	case EM_NDR1:        return strdup ("Denso NDR1 microprocessor");
	case EM_STARCORE:    return strdup ("Motorola Start*Core processor");
	case EM_ME16:        return strdup ("Toyota ME16 processor");
	case EM_ST100:       return strdup ("STMicroelectronic ST100 processor");
	case EM_TINYJ:       return strdup ("Advanced Logic Corp. Tinyj emb.fam");
	case EM_X86_64:      return strdup ("AMD x86-64 architecture");
	case EM_LANAI:       return strdup ("32bit LANAI architecture");
	case EM_PDSP:        return strdup ("Sony DSP Processor");
	case EM_FX66:        return strdup ("Siemens FX66 microcontroller");
	case EM_ST9PLUS:     return strdup ("STMicroelectronics ST9+ 8/16 mc");
	case EM_ST7:         return strdup ("STmicroelectronics ST7 8 bit mc");
	case EM_68HC16:      return strdup ("Motorola MC68HC16 microcontroller");
	case EM_68HC11:      return strdup ("Motorola MC68HC11 microcontroller");
	case EM_68HC08:      return strdup ("Motorola MC68HC08 microcontroller");
	case EM_68HC05:      return strdup ("Motorola MC68HC05 microcontroller");
	case EM_SVX:         return strdup ("Silicon Graphics SVx");
	case EM_ST19:        return strdup ("STMicroelectronics ST19 8 bit mc");
	case EM_VAX:         return strdup ("Digital VAX");
	case EM_CRIS:        return strdup ("Axis Communications 32-bit embedded processor");
	case EM_JAVELIN:     return strdup ("Infineon Technologies 32-bit embedded processor");
	case EM_FIREPATH:    return strdup ("Element 14 64-bit DSP Processor");
	case EM_ZSP:         return strdup ("LSI Logic 16-bit DSP Processor");
	case EM_MMIX:        return strdup ("Donald Knuth's educational 64-bit processor");
	case EM_HUANY:       return strdup ("Harvard University machine-independent object files");
	case EM_PRISM:       return strdup ("SiTera Prism");
	case EM_AVR:         return strdup ("Atmel AVR 8-bit microcontroller");
	case EM_FR30:        return strdup ("Fujitsu FR30");
	case EM_D10V:        return strdup ("Mitsubishi D10V");
	case EM_D30V:        return strdup ("Mitsubishi D30V");
	case EM_V850:        return strdup ("NEC v850");
	case EM_M32R:        return strdup ("Mitsubishi M32R");
	case EM_MN10300:     return strdup ("Matsushita MN10300");
	case EM_MN10200:     return strdup ("Matsushita MN10200");
	case EM_PJ:          return strdup ("picoJava");
	case EM_OPENRISC:    return strdup ("OpenRISC 32-bit embedded processor");
	case EM_ARC_A5:      return strdup ("ARC Cores Tangent-A5");
	case EM_XTENSA:      return strdup ("Tensilica Xtensa Architecture");
	case EM_AARCH64:     return strdup ("ARM aarch64");
	case EM_PROPELLER:   return strdup ("Parallax Propeller");
	case EM_MICROBLAZE:  return strdup ("Xilinx MicroBlaze");
	case EM_RISCV:       return strdup ("RISC V");
	case EM_VIDEOCORE3:  return strdup ("VideoCore III");
	case EM_VIDEOCORE4:  return strdup ("VideoCore IV");
	default:             return r_str_newf ("<unknown>: 0x%x", bin->ehdr.e_machine);
	}
}

char* Elf_(r_bin_elf_get_file_type)(ELFOBJ *bin) {
	ut32 e_type;
	if (!bin) {
		return NULL;
	}
	e_type = (ut32)bin->ehdr.e_type; // cast to avoid warn in iphone-gcc, must be ut16
	switch (e_type) {
	case ET_NONE: return strdup ("NONE (None)");
	case ET_REL:  return strdup ("REL (Relocatable file)");
	case ET_EXEC: return strdup ("EXEC (Executable file)");
	case ET_DYN:  return strdup ("DYN (Shared object file)");
	case ET_CORE: return strdup ("CORE (Core file)");
	}
	if ((e_type >= ET_LOPROC) && (e_type <= ET_HIPROC)) {
		return r_str_newf ("Processor Specific: %x", e_type);
	}
	if ((e_type >= ET_LOOS) && (e_type <= ET_HIOS)) {
		return r_str_newf ("OS Specific: %x", e_type);
	}
	return r_str_newf ("<unknown>: %x", e_type);
}

char* Elf_(r_bin_elf_get_elf_class)(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASSNONE: return strdup ("none");
	case ELFCLASS32:   return strdup ("ELF32");
	case ELFCLASS64:   return strdup ("ELF64");
	default:           return r_str_newf ("<unknown: %x>", bin->ehdr.e_ident[EI_CLASS]);
	}
}

int Elf_(r_bin_elf_get_bits)(ELFOBJ *bin) {
	/* Hack for ARCompact */
	if (bin->ehdr.e_machine == EM_ARC_A5) {
		return 16;
	}
	/* Hack for Ps2 */
	if (bin->phdr && bin->ehdr.e_machine == EM_MIPS) {
		const ut32 mipsType = bin->ehdr.e_flags & EF_MIPS_ARCH;
		if (bin->ehdr.e_type == ET_EXEC) {
			int i;
			bool haveInterp = false;
			for (i = 0; i < bin->ehdr.e_phnum; i++) {
				if (bin->phdr[i].p_type == PT_INTERP) {
					haveInterp = true;
				}
			}
			if (!haveInterp && mipsType == EF_MIPS_ARCH_3) {
				// Playstation2 Hack
				return 64;
			}
		}
		// TODO: show this specific asm.cpu somewhere in bininfo (mips1, mips2, mips3, mips32r2, ...)
		switch (mipsType) {
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
			break;
		}
		return 32;
	}
	/* Hack for Thumb */
	if (bin->ehdr.e_machine == EM_ARM) {
		if (bin->ehdr.e_type != ET_EXEC) {
			struct r_bin_elf_symbol_t *symbol;
			if ((symbol = Elf_(r_bin_elf_get_symbols) (bin))) {
				int i = 0;
				for (i = 0; !symbol[i].last; i++) {
					ut64 paddr = symbol[i].offset;
					if (paddr & 1) {
						return 16;
					}
				}
			}
		}
		{
			ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
			if (entry & 1) {
				return 16;
			}
		}
	}
	switch (bin->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:   return 32;
	case ELFCLASS64:   return 64;
	case ELFCLASSNONE:
	default:           return 32; // defaults
	}
}

static inline int noodle(ELFOBJ *bin, const char *s) {
	const ut8 *p = bin->b->buf;
	if (bin->b->length > 64)  {
		p += bin->b->length - 64;
	} else {
		return 0;
	}
	return r_mem_mem (p, 64, (const ut8 *)s, strlen (s)) != NULL;
}

static inline int needle(ELFOBJ *bin, const char *s) {
	if (bin->shstrtab) {
		ut32 len = bin->shstrtab_size;
		if (len > 4096) {
			len = 4096; // avoid slow loading .. can be buggy?
		}
		return r_mem_mem ((const ut8*)bin->shstrtab, len,
				(const ut8*)s, strlen (s)) != NULL;
	}
	return 0;
}

// TODO: must return const char * all those strings must be const char os[LINUX] or so
char* Elf_(r_bin_elf_get_osabi_name)(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_LINUX: return strdup("linux");
	case ELFOSABI_SOLARIS: return strdup("solaris");
	case ELFOSABI_FREEBSD: return strdup("freebsd");
	case ELFOSABI_HPUX: return strdup("hpux");
	}
	/* Hack to identify OS */
	if (needle (bin, "openbsd")) return strdup ("openbsd");
	if (needle (bin, "netbsd")) return strdup ("netbsd");
	if (needle (bin, "freebsd")) return strdup ("freebsd");
	if (noodle (bin, "BEOS:APP_VERSION")) return strdup ("beos");
	if (needle (bin, "GNU")) return strdup ("linux");
	return strdup ("linux");
}

ut8 *Elf_(r_bin_elf_grab_regstate)(ELFOBJ *bin, int *len) {
	if (bin->phdr) {
		int i;
		int num = bin->ehdr.e_phnum;
		for (i = 0; i < num; i++) {
			if (bin->phdr[i].p_type != PT_NOTE) {
				continue;
			}
			int bits = Elf_(r_bin_elf_get_bits)(bin);
			int regdelta = (bits == 64)? 0x84: 0x40; // x64 vs x32
			int regsize = 160; // for x86-64
			ut8 *buf = malloc (regsize);
			if (r_buf_read_at (bin->b, bin->phdr[i].p_offset + regdelta, buf, regsize) != regsize) {
				free (buf);
				bprintf ("Cannot read register state from CORE file\n");
				return NULL;
			}
			if (len) {
				*len = regsize;
			}
			return buf;
		}
	}
	bprintf ("Cannot find NOTE section\n");
	return NULL;
}

int Elf_(r_bin_elf_is_big_endian)(ELFOBJ *bin) {
	return (bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB);
}

/* XXX Init dt_strtab? */
char *Elf_(r_bin_elf_get_rpath)(ELFOBJ *bin) {
	char *ret = NULL;
	int j;

	if (!bin || !bin->phdr || !bin->dyn_buf || !bin->strtab) {
		return NULL;
	}
	for (j = 0; j< bin->dyn_entries; j++) {
		if (bin->dyn_buf[j].d_tag == DT_RPATH || bin->dyn_buf[j].d_tag == DT_RUNPATH) {
			if (!(ret = calloc (1, ELF_STRING_LENGTH))) {
				perror ("malloc (rpath)");
				return NULL;
			}
			if (bin->dyn_buf[j].d_un.d_val > bin->strtab_size) {
				free (ret);
				return NULL;
			}
			strncpy (ret, bin->strtab + bin->dyn_buf[j].d_un.d_val, ELF_STRING_LENGTH);
			ret[ELF_STRING_LENGTH - 1] = '\0';
			break;
		}
	}
	return ret;
}


static size_t get_relocs_num(ELFOBJ *bin) {
	size_t i, size, ret = 0;
	/* we need to be careful here, in malformed files the section size might
	 * not be a multiple of a Rel/Rela size; round up so we allocate enough
	 * space.
	 */
#define NUMENTRIES_ROUNDUP(sectionsize, entrysize) (((sectionsize)+(entrysize)-1)/(entrysize))
	if (!bin->g_sections) {
		return 0;
	}
	size = bin->is_rela == DT_REL ? sizeof (Elf_(Rel)) : sizeof (Elf_(Rela));
	for (i = 0; !bin->g_sections[i].last; i++) {
		if (!strncmp (bin->g_sections[i].name, ".rela.", strlen (".rela."))) {
			if (!bin->is_rela) {
				size = sizeof (Elf_(Rela));
			}
			ret += NUMENTRIES_ROUNDUP (bin->g_sections[i].size, size);
		} else if (!strncmp (bin->g_sections[i].name, ".rel.", strlen (".rel."))){
			if (!bin->is_rela) {
				size = sizeof (Elf_(Rel));
			}
			ret += NUMENTRIES_ROUNDUP (bin->g_sections[i].size, size);
		}
	}
	return ret;
#undef NUMENTRIES_ROUNDUP
}

static int read_reloc(ELFOBJ *bin, RBinElfReloc *r, int is_rela, ut64 offset) {
	ut8 *buf = bin->b->buf;
	int j = 0;
	if (offset + sizeof (Elf_ (Rela)) >
		    bin->size || offset + sizeof (Elf_(Rela)) < offset) {
		return -1;
	}
	if (is_rela == DT_RELA) {
		Elf_(Rela) rela;
#if R_BIN_ELF64
		rela.r_offset = READ64 (buf + offset, j)
		rela.r_info = READ64 (buf + offset, j)
		rela.r_addend = READ64 (buf + offset, j)
#else
		rela.r_offset = READ32 (buf + offset, j)
		rela.r_info = READ32 (buf + offset, j)
		rela.r_addend = READ32 (buf + offset, j)
#endif
		r->is_rela = is_rela;
		r->offset = rela.r_offset;
		r->type = ELF_R_TYPE (rela.r_info);
		r->sym = ELF_R_SYM (rela.r_info);
		r->last = 0;
		r->addend = rela.r_addend;
		return sizeof (Elf_(Rela));
	} else {
		Elf_(Rel) rel;
#if R_BIN_ELF64
		rel.r_offset = READ64 (buf + offset, j)
		rel.r_info = READ64 (buf + offset, j)
#else
		rel.r_offset = READ32 (buf + offset, j)
		rel.r_info = READ32 (buf + offset, j)
#endif
		r->is_rela = is_rela;
		r->offset = rel.r_offset;
		r->type = ELF_R_TYPE (rel.r_info);
		r->sym = ELF_R_SYM (rel.r_info);
		r->last = 0;
		return sizeof (Elf_(Rel));
	}
}

RBinElfReloc* Elf_(r_bin_elf_get_relocs)(ELFOBJ *bin) {
	int res, rel, rela, i, j;
	size_t reloc_num = 0;
	RBinElfReloc *ret = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	reloc_num = get_relocs_num (bin);
	if (!reloc_num)	{
		return NULL;
	}
	bin->reloc_num = reloc_num;
	ret = (RBinElfReloc*)calloc ((size_t)reloc_num + 1, sizeof(RBinElfReloc));
	if (!ret) {
		return NULL;
	}
#if DEAD_CODE
	ut64 section_text_offset = Elf_(r_bin_elf_get_section_offset) (bin, ".text");
	if (section_text_offset == -1) {
		section_text_offset = 0;
	}
#endif
	for (i = 0, rel = 0; !bin->g_sections[i].last && rel < reloc_num ; i++) {
		bool is_rela = 0 == strncmp (bin->g_sections[i].name, ".rela.", strlen (".rela."));
		bool is_rel  = 0 == strncmp (bin->g_sections[i].name, ".rel.",  strlen (".rel."));
		if (!is_rela && !is_rel) {
			continue;
		}
		for (j = 0; j < bin->g_sections[i].size; j += res) {
			if (bin->g_sections[i].size > bin->size) {
				break;
			}
			if (bin->g_sections[i].offset > bin->size) {
				break;
			}
			if (rel >= reloc_num) {
				bprintf ("Internal error: ELF relocation buffer too small,"
				         "please file a bug report.");
				break;
			}
			if (!bin->is_rela) {
				rela = is_rela? DT_RELA : DT_REL;
			} else {
				rela = bin->is_rela;
			}
			res = read_reloc (bin, &ret[rel], rela, bin->g_sections[i].offset + j);
			if (j + res > bin->g_sections[i].size) {
				bprintf ("Warning: malformed file, relocation entry #%u is partially beyond the end of section %u.\n", rel, i);
			}
			if (bin->ehdr.e_type == ET_REL) {
				if (bin->g_sections[i].info < bin->ehdr.e_shnum && bin->shdr) {
					ret[rel].rva = bin->shdr[bin->g_sections[i].info].sh_offset + ret[rel].offset;
					ret[rel].rva = Elf_(r_bin_elf_p2v) (bin, ret[rel].rva);
				} else {
					ret[rel].rva = ret[rel].offset;
				}
			} else {
				ret[rel].rva = ret[rel].offset;
				ret[rel].offset = Elf_(r_bin_elf_v2p) (bin, ret[rel].offset);
			}
			ret[rel].last = 0;
			if (res < 0) {
				break;
			}
			rel++;
		}
	}
	ret[reloc_num].last = 1;
	return ret;
}

RBinElfLib* Elf_(r_bin_elf_get_libs)(ELFOBJ *bin) {
	RBinElfLib *ret = NULL;
	int j, k;

	if (!bin || !bin->phdr || !bin->dyn_buf || !bin->strtab || *(bin->strtab+1) == '0') {
		return NULL;
	}
	for (j = 0, k = 0; j < bin->dyn_entries; j++)
		if (bin->dyn_buf[j].d_tag == DT_NEEDED) {
			RBinElfLib *r = realloc (ret, (k + 1) * sizeof (RBinElfLib));
			if (!r) {
				perror ("realloc (libs)");
				free (ret);
				return NULL;
			}
			ret = r;
			if (bin->dyn_buf[j].d_un.d_val > bin->strtab_size) {
				free (ret);
				return NULL;
			}
			strncpy (ret[k].name, bin->strtab + bin->dyn_buf[j].d_un.d_val, ELF_STRING_LENGTH);
			ret[k].name[ELF_STRING_LENGTH - 1] = '\0';
   			ret[k].last = 0;
			if (ret[k].name[0]) {
				k++;
			}
		}
	RBinElfLib *r = realloc (ret, (k + 1) * sizeof (RBinElfLib));
	if (!r) {
		perror ("realloc (libs)");
		free (ret);
		return NULL;
	}
	ret = r;
	ret[k].last = 1;
	return ret;
}

static RBinElfSection* get_sections_from_phdr(ELFOBJ *bin) {
	RBinElfSection *ret;
	int i, num_sections = 0;
	ut64 reldyn = 0, relava = 0, pltgotva = 0, relva = 0;
	ut64 reldynsz = 0, relasz = 0, pltgotsz = 0;
	if (!bin || !bin->phdr || !bin->ehdr.e_phnum)
		return NULL;

	for (i = 0; i < bin->dyn_entries; i++) {
		switch (bin->dyn_buf[i].d_tag) {
		case DT_REL:
			reldyn = bin->dyn_buf[i].d_un.d_ptr;
			num_sections++;
			break;
		case DT_RELA:
			relva = bin->dyn_buf[i].d_un.d_ptr;
			num_sections++;
			break;
		case DT_RELSZ:
			reldynsz = bin->dyn_buf[i].d_un.d_val;
			break;
		case DT_RELASZ:
			relasz = bin->dyn_buf[i].d_un.d_val;
			break;
		case DT_PLTGOT:
			pltgotva = bin->dyn_buf[i].d_un.d_ptr;
			num_sections++;
			break;
		case DT_PLTRELSZ:
			pltgotsz = bin->dyn_buf[i].d_un.d_val;
			break;
		case DT_JMPREL:
			relava = bin->dyn_buf[i].d_un.d_ptr;
			num_sections++;
			break;
		default: break;
		}
	}
	ret = calloc (num_sections + 1, sizeof(RBinElfSection));
	if (!ret) {
		return NULL;
	}
	i = 0;
	if (reldyn) {
		ret[i].offset = Elf_(r_bin_elf_v2p) (bin, reldyn);
		ret[i].rva = reldyn;
		ret[i].size = reldynsz;
		strcpy (ret[i].name, ".rel.dyn");
		ret[i].last = 0;
		i++;
	}
	if (relava) {
		ret[i].offset = Elf_(r_bin_elf_v2p) (bin, relava);
		ret[i].rva = relava;
		ret[i].size = pltgotsz;
		strcpy (ret[i].name, ".rela.plt");
		ret[i].last = 0;
		i++;
	}
	if (relva) {
		ret[i].offset = Elf_(r_bin_elf_v2p) (bin, relva);
		ret[i].rva = relva;
		ret[i].size = relasz;
		strcpy (ret[i].name, ".rel.plt");
		ret[i].last = 0;
		i++;
	}
	if (pltgotva) {
		ret[i].offset = Elf_(r_bin_elf_v2p) (bin, pltgotva);
		ret[i].rva = pltgotva;
		ret[i].size = pltgotsz;
		strcpy (ret[i].name, ".got.plt");
		ret[i].last = 0;
		i++;
	}
	ret[i].last = 1;

	return ret;
}

RBinElfSection* Elf_(r_bin_elf_get_sections)(ELFOBJ *bin) {
	RBinElfSection *ret = NULL;
	char unknown_s[20], invalid_s[20];
	int i, nidx, unknown_c=0, invalid_c=0;
	if (!bin) {
		return NULL;
	}
	if (bin->g_sections) {
		return bin->g_sections;
	}
	if (!bin->shdr) {
		//we don't give up search in phdr section
		return get_sections_from_phdr (bin);
	}
	if (!(ret = calloc ((bin->ehdr.e_shnum + 1), sizeof (RBinElfSection)))) {
		return NULL;
	}
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		ret[i].offset = bin->shdr[i].sh_offset;
		ret[i].size = bin->shdr[i].sh_size;
		ret[i].align = bin->shdr[i].sh_addralign;
		ret[i].flags = bin->shdr[i].sh_flags;
		ret[i].link = bin->shdr[i].sh_link;
		ret[i].info = bin->shdr[i].sh_info;
		ret[i].type = bin->shdr[i].sh_type;
		if (bin->ehdr.e_type == ET_REL)	{
			ret[i].rva = bin->baddr + bin->shdr[i].sh_offset;
		} else {
			ret[i].rva = bin->shdr[i].sh_addr;
		}
		nidx = bin->shdr[i].sh_name;
#define SHNAME (int)bin->shdr[i].sh_name
#define SHNLEN ELF_STRING_LENGTH - 4
#define SHSIZE (int)bin->shstrtab_size
		if (nidx < 0 || !bin->shstrtab_section || !bin->shstrtab_size || nidx > bin->shstrtab_size) {
			snprintf (invalid_s, sizeof (invalid_s) - 4, "invalid%d", invalid_c);
			strncpy (ret[i].name, invalid_s, SHNLEN);
			invalid_c++;
		} else {
			if (bin->shstrtab && (SHNAME > 0) && (SHNAME < SHSIZE)) {
				strncpy (ret[i].name, &bin->shstrtab[SHNAME], SHNLEN);
			} else {
				if (bin->shdr[i].sh_type == SHT_NULL) {
					//to follow the same behaviour as readelf
					strncpy (ret[i].name, "", sizeof (ret[i].name) - 4);
				} else {
					snprintf (unknown_s, sizeof (unknown_s)-4, "unknown%d", unknown_c);
					strncpy (ret[i].name, unknown_s, sizeof (ret[i].name)-4);
					unknown_c++;
				}
			}
		}
		ret[i].name[ELF_STRING_LENGTH-2] = '\0';
		ret[i].last = 0;
	}
	ret[i].last = 1;
	return ret;
}

static void fill_symbol_bind_and_type (struct r_bin_elf_symbol_t *ret, Elf_(Sym) *sym) {
	#define s_bind(x) ret->bind = x
	#define s_type(x) ret->type = x
	switch (ELF_ST_BIND(sym->st_info)) {
	case STB_LOCAL:  s_bind ("LOCAL"); break;
	case STB_GLOBAL: s_bind ("GLOBAL"); break;
	case STB_WEAK:   s_bind ("WEAK"); break;
	case STB_NUM:    s_bind ("NUM"); break;
	case STB_LOOS:   s_bind ("LOOS"); break;
	case STB_HIOS:   s_bind ("HIOS"); break;
	case STB_LOPROC: s_bind ("LOPROC"); break;
	case STB_HIPROC: s_bind ("HIPROC"); break;
	default:         s_bind ("UNKNOWN");
	}
	switch (ELF_ST_TYPE (sym->st_info)) {
	case STT_NOTYPE:  s_type ("NOTYPE"); break;
	case STT_OBJECT:  s_type ("OBJECT"); break;
	case STT_FUNC:    s_type ("FUNC"); break;
	case STT_SECTION: s_type ("SECTION"); break;
	case STT_FILE:    s_type ("FILE"); break;
	case STT_COMMON:  s_type ("COMMON"); break;
	case STT_TLS:     s_type ("TLS"); break;
	case STT_NUM:     s_type ("NUM"); break;
	case STT_LOOS:    s_type ("LOOS"); break;
	case STT_HIOS:    s_type ("HIOS"); break;
	case STT_LOPROC:  s_type ("LOPROC"); break;
	case STT_HIPROC:  s_type ("HIPROC"); break;
	default:          s_type ("UNKNOWN");
	}
}

static RBinElfSymbol* get_symbols_from_phdr(ELFOBJ *bin, int type) {
	Elf_(Sym) *sym = NULL;
	Elf_(Addr) addr_sym_table = 0;
	ut8 s[sizeof (Elf_(Sym))] = {0};
	RBinElfSymbol *ret = NULL;
	int i, j, r, tsize, nsym, ret_ctr;
	ut64 toffset = 0, tmp_offset;
	ut32 size, sym_size = 0;

	if (!bin || !bin->phdr || !bin->ehdr.e_phnum) {
		return NULL;
	}
	for (j = 0; j < bin->dyn_entries; j++) {
		switch (bin->dyn_buf[j].d_tag) {
		case (DT_SYMTAB):
			addr_sym_table = Elf_(r_bin_elf_v2p) (bin, bin->dyn_buf[j].d_un.d_ptr);
			break;
		case (DT_SYMENT):
			sym_size = bin->dyn_buf[j].d_un.d_val;
			break;
		default:
			break;
		}
	}
	if (!addr_sym_table) {
		return NULL;
	}
	if (!sym_size) {
		return NULL;
	}
	//since ELF doesn't specify the symbol table size we may read until the end of the buffer
	nsym = (bin->size - addr_sym_table) / sym_size;
	if (!UT32_MUL (&size, nsym, sizeof (Elf_ (Sym)))) {
		goto beach;
	}
	if (size < 1) {
		goto beach;
	}
	if (addr_sym_table > bin->size || addr_sym_table + size > bin->size) {
		goto beach;
	}
	if (nsym < 1) {
		return NULL;
	}
	// we reserve room for 4096 and grow as needed.
	size_t capacity1 = 4096;
	size_t capacity2 = 4096;
	sym = (Elf_(Sym)*) calloc (capacity1, sym_size);
	ret = (RBinElfSymbol *) calloc (capacity2, sizeof (struct r_bin_elf_symbol_t));
	if (!sym || !ret) {
		goto beach;
	}
	for (i = 1, ret_ctr = 0; i < nsym; i++) {
		if (i >= capacity1) { // maybe grow
			// You take what you want, but you eat what you take.
			Elf_(Sym)* temp_sym = (Elf_(Sym)*) realloc(sym, (capacity1 * GROWTH_FACTOR) * sym_size);
			if (!temp_sym) {
				goto beach;
			}
			sym = temp_sym;
			capacity1 *= GROWTH_FACTOR;
		}
		if (ret_ctr >= capacity2) { // maybe grow
			RBinElfSymbol *temp_ret = realloc (ret, capacity2 * GROWTH_FACTOR * sizeof (struct r_bin_elf_symbol_t));
			if (!temp_ret) {
				goto beach;
			}
			ret = temp_ret;
			capacity2 *= GROWTH_FACTOR;
		}
		// read in one entry
		r = r_buf_read_at (bin->b, addr_sym_table + i * sizeof (Elf_ (Sym)), s, sizeof (Elf_ (Sym)));
		if (r < 1) {
			goto beach;
		}
		int j = 0;
#if R_BIN_ELF64
		sym[i].st_name = READ32 (s, j);
		sym[i].st_info = READ8 (s, j);
		sym[i].st_other = READ8 (s, j);
		sym[i].st_shndx = READ16 (s, j);
		sym[i].st_value = READ64 (s, j);
		sym[i].st_size = READ64 (s, j);
#else
		sym[i].st_name = READ32 (s, j);
		sym[i].st_value = READ32 (s, j);
		sym[i].st_size = READ32 (s, j);
		sym[i].st_info = READ8 (s, j);
		sym[i].st_other = READ8 (s, j);
		sym[i].st_shndx = READ16 (s, j);
#endif
		// zero symbol is always empty
		// Examine entry and maybe store
		if (type == R_BIN_ELF_IMPORTS && sym[i].st_shndx == STN_UNDEF) {
			if (sym[i].st_value) {
				toffset = sym[i].st_value;
			} else if ((toffset = get_import_addr (bin, i)) == -1){
				toffset = 0;
			}
			tsize = 16;
		} else if (type == R_BIN_ELF_SYMBOLS &&
		           sym[i].st_shndx != STN_UNDEF &&
		           ELF_ST_TYPE (sym[i].st_info) != STT_SECTION &&
		           ELF_ST_TYPE (sym[i].st_info) != STT_FILE) {
			tsize = sym[i].st_size;
			toffset = (ut64) sym[i].st_value;
		} else {
			continue;
		}
		tmp_offset = Elf_(r_bin_elf_v2p) (bin, toffset);
		if (tmp_offset > bin->size) {
			goto done;
		}
		if (sym[i].st_name + 2 > bin->strtab_size) {
			// Since we are reading beyond the symbol table what's happening
			// is that some entry is trying to dereference the strtab beyond its capacity
			// is not a symbol so is the end
			goto done;
		}
		ret[ret_ctr].offset = tmp_offset;
		ret[ret_ctr].size = tsize;
		{
			int rest = ELF_STRING_LENGTH - 1;
			int st_name = sym[i].st_name;
			int maxsize = R_MIN (bin->size, bin->strtab_size);
			if (st_name < 0 || st_name >= maxsize) {
				ret[ret_ctr].name[0] = 0;
			} else {
				const int len = __strnlen (bin->strtab + st_name, rest);
				memcpy (ret[ret_ctr].name, &bin->strtab[st_name], len);
			}
		}
		ret[ret_ctr].ordinal = i;
		ret[ret_ctr].in_shdr = false;
		ret[ret_ctr].name[ELF_STRING_LENGTH - 2] = '\0';
		fill_symbol_bind_and_type (&ret[ret_ctr], &sym[i]);
		ret[ret_ctr].last = 0;
		ret_ctr++;
	}
done:
	ret[ret_ctr].last = 1;
	// Size everything down to only what is used
	{
		nsym = i > 0 ? i : 1;
		Elf_ (Sym) * temp_sym = (Elf_ (Sym)*) realloc (sym, (nsym * GROWTH_FACTOR) * sym_size);
		if (!temp_sym) {
			goto beach;
		}
		sym = temp_sym;
	}
	{
		ret_ctr = ret_ctr > 0 ? ret_ctr : 1;
		RBinElfSymbol *p = (RBinElfSymbol *) realloc (ret, (ret_ctr + 1) * sizeof (RBinElfSymbol));
		if (!p) {
			goto beach;
		}
		ret = p;
	}
	if (type == R_BIN_ELF_IMPORTS && !bin->imports_by_ord_size) {
		bin->imports_by_ord_size = ret_ctr + 1;
		if (ret_ctr > 0) {
			bin->imports_by_ord = (RBinImport * *) calloc (ret_ctr + 1, sizeof (RBinImport*));
		} else {
			bin->imports_by_ord = NULL;
		}
	} else if (type == R_BIN_ELF_SYMBOLS && !bin->symbols_by_ord_size && ret_ctr) {
		bin->symbols_by_ord_size = ret_ctr + 1;
		if (ret_ctr > 0) {
			bin->symbols_by_ord = (RBinSymbol * *) calloc (ret_ctr + 1, sizeof (RBinSymbol*));
		}else {
			bin->symbols_by_ord = NULL;
		}
	}
	free (sym);
	return ret;
beach:
	free (sym);
	free (ret);
	return NULL;
}

static RBinElfSymbol *Elf_(r_bin_elf_get_phdr_symbols)(ELFOBJ *bin) {
	if (!bin) {
		return NULL;
	}
	if (bin->phdr_symbols) {
		return bin->phdr_symbols;
	}
	bin->phdr_symbols = get_symbols_from_phdr (bin, R_BIN_ELF_SYMBOLS);
	return bin->phdr_symbols;
}

static RBinElfSymbol *Elf_(r_bin_elf_get_phdr_imports)(ELFOBJ *bin) {
	if (!bin) {
		return NULL;
	}
	if (bin->phdr_imports) {
		return bin->phdr_imports;
	}
	bin->phdr_imports = get_symbols_from_phdr (bin, R_BIN_ELF_IMPORTS);
	return bin->phdr_imports;
}

static int Elf_(fix_symbols)(ELFOBJ *bin, int nsym, int type, RBinElfSymbol **sym) {
	int count = 0;
	RBinElfSymbol *ret = *sym;
	RBinElfSymbol *phdr_symbols = (type == R_BIN_ELF_SYMBOLS)
				? Elf_(r_bin_elf_get_phdr_symbols) (bin)
				: Elf_(r_bin_elf_get_phdr_imports) (bin);
	RBinElfSymbol *tmp, *p;
	if (phdr_symbols) {
		RBinElfSymbol *d = ret;
		while (!d->last) {
			/* find match in phdr */
			p = phdr_symbols;
			while (!p->last) {
				if (p->offset && d->offset == p->offset) {
					p->in_shdr = true;
					if (*p->name && strcmp (d->name, p->name)) {
						strcpy (d->name, p->name);
					}
				}
				p++;
			}
			d++;
		}
		p = phdr_symbols;
		while (!p->last) {
			if (!p->in_shdr) {
				count++;
			}
			p++;
		}
		/*Take those symbols that are not present in the shdr but yes in phdr*/
		/*This should only should happen with fucked up binaries*/
		if (count > 0) {
			/*what happens if a shdr says it has only one symbol? we should look anyway into phdr*/
			tmp = (RBinElfSymbol*)realloc (ret, (nsym + count + 1) * sizeof (RBinElfSymbol));
			if (!tmp) {
				return -1;
			}
			ret = tmp;
			ret[nsym--].last = 0;
			p = phdr_symbols;
			while (!p->last) {
				if (!p->in_shdr) {
					memcpy (&ret[++nsym], p, sizeof (RBinElfSymbol));
				}
				p++;
			}
			ret[nsym + 1].last = 1;
		}
		*sym = ret;
		return nsym + 1;
	}
	return nsym;
}

static RBinElfSymbol* Elf_(_r_bin_elf_get_symbols_imports)(ELFOBJ *bin, int type) {
	ut32 shdr_size;
	int tsize, nsym, ret_ctr = 0, i, j, r, k, newsize;
	ut64 toffset;
	ut32 size = 0;
	RBinElfSymbol  *ret = NULL;
	Elf_(Shdr) *strtab_section = NULL;
	Elf_(Sym) *sym = NULL;
	ut8 s[sizeof (Elf_(Sym))] = { 0 };
	char *strtab = NULL;

	if (!bin || !bin->shdr || !bin->ehdr.e_shnum || bin->ehdr.e_shnum == 0xffff) {
		return (type == R_BIN_ELF_SYMBOLS)
				? Elf_(r_bin_elf_get_phdr_symbols) (bin)
				: Elf_(r_bin_elf_get_phdr_imports) (bin);
	}
	if (!UT32_MUL (&shdr_size, bin->ehdr.e_shnum, sizeof (Elf_(Shdr)))) {
		return false;
	}
	if (shdr_size + 8 > bin->size) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if ((type == R_BIN_ELF_IMPORTS && bin->shdr[i].sh_type == (bin->ehdr.e_type == ET_REL ? SHT_SYMTAB : SHT_DYNSYM)) ||
				(type == R_BIN_ELF_SYMBOLS && bin->shdr[i].sh_type == (Elf_(r_bin_elf_get_stripped) (bin) ? SHT_DYNSYM : SHT_SYMTAB))) {
			if (bin->shdr[i].sh_link < 1) {
				/* oops. fix out of range pointers */
				continue;
			}
			// hack to avoid asan cry
			if ((bin->shdr[i].sh_link * sizeof(Elf_(Shdr))) >= shdr_size) {
				/* oops. fix out of range pointers */
				continue;
			}
			strtab_section = &bin->shdr[bin->shdr[i].sh_link];
			if (strtab_section->sh_size > ST32_MAX || strtab_section->sh_size+8 > bin->size) {
				bprintf ("size (syms strtab)");
				free (ret);
				free (strtab);
				return NULL;
			}
			if (!strtab) {
				if (!(strtab = (char *)calloc (1, 8 + strtab_section->sh_size))) {
					bprintf ("malloc (syms strtab)");
					goto beach;
				}
				if (strtab_section->sh_offset > bin->size ||
						strtab_section->sh_offset + strtab_section->sh_size > bin->size) {
					goto beach;
				}
				if (r_buf_read_at (bin->b, strtab_section->sh_offset,
							(ut8*)strtab, strtab_section->sh_size) == -1) {
					bprintf ("Warning: read (syms strtab)\n");
					goto beach;
				}
			}

			newsize = 1 + bin->shdr[i].sh_size;
			if (newsize < 0 || newsize > bin->size) {
				bprintf ("invalid shdr %d size\n", i);
				goto beach;
			}
			nsym = (int)(bin->shdr[i].sh_size / sizeof (Elf_(Sym)));
			if (nsym < 0) {
				goto beach;
			}
			if (!(sym = (Elf_(Sym) *)calloc (nsym, sizeof (Elf_(Sym))))) {
				bprintf ("calloc (syms)");
				goto beach;
			}
			if (!UT32_MUL (&size, nsym, sizeof (Elf_(Sym)))) {
				goto beach;
			}
			if (size < 1 || size > bin->size) {
				goto beach;
			}
			if (bin->shdr[i].sh_offset > bin->size) {
				goto beach;
			}
			if (bin->shdr[i].sh_offset + size > bin->size) {
				goto beach;
			}
			for (j = 0; j < nsym; j++) {
				int k = 0;
				r = r_buf_read_at (bin->b, bin->shdr[i].sh_offset + j * sizeof (Elf_(Sym)), s, sizeof (Elf_(Sym)));
				if (r < 1) {
					bprintf ("Warning: read (sym)\n");
					goto beach;
				}
#if R_BIN_ELF64
				sym[j].st_name = READ32 (s, k)
				sym[j].st_info = READ8 (s, k)
				sym[j].st_other = READ8 (s, k)
				sym[j].st_shndx = READ16 (s, k)
				sym[j].st_value = READ64 (s, k)
				sym[j].st_size = READ64 (s, k)
#else
				sym[j].st_name = READ32 (s, k)
				sym[j].st_value = READ32 (s, k)
				sym[j].st_size = READ32 (s, k)
				sym[j].st_info = READ8 (s, k)
				sym[j].st_other = READ8 (s, k)
				sym[j].st_shndx = READ16 (s, k)
#endif
			}
			free (ret);
			ret = calloc (nsym, sizeof (RBinElfSymbol));
			if (!ret) {
				bprintf ("Cannot allocate %d symbols\n", nsym);
				goto beach;
			}
			for (k = 1, ret_ctr = 0; k < nsym; k++) {
				if (type == R_BIN_ELF_IMPORTS && sym[k].st_shndx == STN_UNDEF) {
					if (sym[k].st_value) {
						toffset = sym[k].st_value;
					} else if ((toffset = get_import_addr (bin, k)) == -1){
						toffset = 0;
					}
					tsize = 16;
				} else if (type == R_BIN_ELF_SYMBOLS &&
					   sym[k].st_shndx != STN_UNDEF &&
					   ELF_ST_TYPE (sym[k].st_info) != STT_SECTION &&
					   ELF_ST_TYPE (sym[k].st_info) != STT_FILE) {
					//int idx = sym[k].st_shndx;
					tsize = sym[k].st_size;
					toffset = (ut64)sym[k].st_value; 
				} else {
					continue;
				}
				if (bin->ehdr.e_type == ET_REL) {
					if (sym[k].st_shndx < bin->ehdr.e_shnum)
						ret[ret_ctr].offset = sym[k].st_value + bin->shdr[sym[k].st_shndx].sh_offset;
				} else {
					ret[ret_ctr].offset = Elf_(r_bin_elf_v2p) (bin, toffset);
				}
				ret[ret_ctr].size = tsize;
				if (sym[k].st_name + 2 > strtab_section->sh_size) {
					bprintf ("Warning: index out of strtab range\n");
					goto beach;
				}
				{
					int rest = ELF_STRING_LENGTH - 1;
					int st_name = sym[k].st_name;
					int maxsize = R_MIN (bin->b->length, strtab_section->sh_size);
					if (st_name < 0 || st_name >= maxsize) {
						ret[ret_ctr].name[0] = 0;
					} else {
						const size_t len = __strnlen (strtab + sym[k].st_name, rest);
						memcpy (ret[ret_ctr].name, &strtab[sym[k].st_name], len);
					}
				}
				ret[ret_ctr].ordinal = k;
				ret[ret_ctr].name[ELF_STRING_LENGTH - 2] = '\0';
				fill_symbol_bind_and_type (&ret[ret_ctr], &sym[k]);
				ret[ret_ctr].last = 0;
				ret_ctr++;
			}
			ret[ret_ctr].last = 1; // ugly dirty hack :D
			R_FREE (strtab);
			R_FREE (sym);
		}
	}
	if (!ret) {
		return (type == R_BIN_ELF_SYMBOLS)
				? Elf_(r_bin_elf_get_phdr_symbols) (bin)
				: Elf_(r_bin_elf_get_phdr_imports) (bin);
	}
	int max = -1;
	RBinElfSymbol *aux = NULL;
	nsym = Elf_(fix_symbols) (bin, ret_ctr, type, &ret);
	if (nsym == -1) {
		goto beach;
	}
	aux = ret;
	while (!aux->last) {
		if ((int)aux->ordinal > max) {
			max = aux->ordinal;
		}
		aux++;
	}
	nsym = max;
	if (type == R_BIN_ELF_IMPORTS) {
		R_FREE (bin->imports_by_ord);
		bin->imports_by_ord_size = nsym + 1;
		bin->imports_by_ord = (RBinImport**)calloc (R_MAX (1, nsym + 1), sizeof (RBinImport*));
	} else if (type == R_BIN_ELF_SYMBOLS) {
		R_FREE (bin->symbols_by_ord);
		bin->symbols_by_ord_size = nsym + 1;
		bin->symbols_by_ord = (RBinSymbol**)calloc (R_MAX (1, nsym + 1), sizeof (RBinSymbol*));
	}
	return ret;
beach:
	free (ret);
	free (sym);
	free (strtab);
	return NULL;
}

RBinElfSymbol *Elf_(r_bin_elf_get_symbols)(ELFOBJ *bin) {
	if (!bin->g_symbols) {
		bin->g_symbols = Elf_(_r_bin_elf_get_symbols_imports) (bin, R_BIN_ELF_SYMBOLS);
	}
	return bin->g_symbols;
}


RBinElfSymbol *Elf_(r_bin_elf_get_imports)(ELFOBJ *bin) {
	if (!bin->g_imports) {
		bin->g_imports = Elf_(_r_bin_elf_get_symbols_imports) (bin, R_BIN_ELF_IMPORTS);
	}
	return bin->g_imports;
}

RBinElfField* Elf_(r_bin_elf_get_fields)(ELFOBJ *bin) {
	RBinElfField *ret = NULL;
	int i = 0, j;
	if (!bin || !(ret = calloc ((bin->ehdr.e_phnum + 3 + 1), sizeof (RBinElfField)))) {
		return NULL;
	}
	strncpy (ret[i].name, "ehdr", ELF_STRING_LENGTH);
	ret[i].offset = 0;
	ret[i++].last = 0;
	strncpy (ret[i].name, "shoff", ELF_STRING_LENGTH);
	ret[i].offset = bin->ehdr.e_shoff;
	ret[i++].last = 0;
	strncpy (ret[i].name, "phoff", ELF_STRING_LENGTH);
	ret[i].offset = bin->ehdr.e_phoff;
	ret[i++].last = 0;
	for (j = 0; bin->phdr && j < bin->ehdr.e_phnum; i++, j++) {
		snprintf (ret[i].name, ELF_STRING_LENGTH, "phdr_%i", j);
		ret[i].offset = bin->phdr[j].p_offset;
		ret[i].last = 0;
	}
	ret[i].last = 1;
	return ret;
}

void* Elf_(r_bin_elf_free)(ELFOBJ* bin) {
	int i;
	if (!bin) {
		return NULL;
	}
	free (bin->phdr);
	free (bin->shdr);
	free (bin->strtab);
	free (bin->dyn_buf);
	free (bin->shstrtab);
	free (bin->dynstr);
	//free (bin->strtab_section);
	if (bin->imports_by_ord) {
		for (i = 0; i<bin->imports_by_ord_size; i++) {
			free (bin->imports_by_ord[i]);
		}
		free (bin->imports_by_ord);
	}
	if (bin->symbols_by_ord) {
		for (i = 0; i<bin->symbols_by_ord_size; i++) {
			free (bin->symbols_by_ord[i]);
		}
		free (bin->symbols_by_ord);
	}
	r_buf_free (bin->b);
	if (bin->g_symbols != bin->phdr_symbols) {
		R_FREE (bin->phdr_symbols);
	}
	if (bin->g_imports != bin->phdr_imports) {
		R_FREE (bin->phdr_imports);
	}
	R_FREE (bin->g_sections);
	R_FREE (bin->g_symbols);
	R_FREE (bin->g_imports);
	free (bin);
	return NULL;
}

ELFOBJ* Elf_(r_bin_elf_new)(const char* file, bool verbose) {
	ut8 *buf;
	int size;
	ELFOBJ *bin = R_NEW0 (ELFOBJ);
	if (!bin) {
		return NULL;
	}
	memset (bin, 0, sizeof (ELFOBJ));
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &size))) {
		return Elf_(r_bin_elf_free) (bin);
	}
	bin->size = size;
	bin->verbose = verbose;
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return Elf_(r_bin_elf_free) (bin);
	}
	if (!elf_init (bin)) {
		free (buf);
		return Elf_(r_bin_elf_free) (bin);
	}
	free (buf);
	return bin;
}

ELFOBJ* Elf_(r_bin_elf_new_buf)(RBuffer *buf, bool verbose) {
	ELFOBJ *bin = R_NEW0 (ELFOBJ);
	bin->kv = sdb_new0 ();
	bin->b = r_buf_new ();
	bin->size = (ut32)buf->length;
	bin->verbose = verbose;
	if (!r_buf_set_bytes (bin->b, buf->buf, buf->length)) {
		return Elf_(r_bin_elf_free) (bin);
	}
	if (!elf_init (bin)) {
		return Elf_(r_bin_elf_free) (bin);
	}
	return bin;
}

static int is_in_pphdr (Elf_(Phdr) *p, ut64 addr) {
	return addr >= p->p_offset && addr < p->p_offset + p->p_memsz;
}

static int is_in_vphdr (Elf_(Phdr) *p, ut64 addr) {
	return addr >= p->p_vaddr && addr < p->p_vaddr + p->p_memsz;
}


/* converts a physical address to the virtual address, looking
 * at the program headers in the binary bin */
ut64 Elf_(r_bin_elf_p2v) (ELFOBJ *bin, ut64 paddr) {
	int i;

	if (!bin) return 0;

	if (!bin->phdr) {
		if (bin->ehdr.e_type == ET_REL) {
			return bin->baddr + paddr;
		}
		return paddr;
	}
	for (i = 0; i < bin->ehdr.e_phnum; ++i) {
		Elf_(Phdr) *p = &bin->phdr[i];
		if (!p) {
			break;
		}
		if (p->p_type == PT_LOAD && is_in_pphdr (p, paddr)) {
			if (!p->p_vaddr && !p->p_offset) {
				continue;
			}
			return p->p_vaddr + paddr - p->p_offset;
		}
	}

	return paddr;
}

/* converts a virtual address to the relative physical address, looking
 * at the program headers in the binary bin */
ut64 Elf_(r_bin_elf_v2p) (ELFOBJ *bin, ut64 vaddr) {
	int i;
	if (!bin) {
		return 0;
	}
	if (!bin->phdr) {
		if (bin->ehdr.e_type == ET_REL) {
			return vaddr - bin->baddr;
		}
		return vaddr;
	}
	for (i = 0; i < bin->ehdr.e_phnum; ++i) {
		Elf_(Phdr) *p = &bin->phdr[i];
		if (!p) {
			break;
		}
		if (p->p_type == PT_LOAD && is_in_vphdr (p, vaddr)) {
			if (!p->p_offset && !p->p_vaddr) {
				continue;
			}
			return p->p_offset + vaddr - p->p_vaddr;
		}
	}
	return vaddr;
}
