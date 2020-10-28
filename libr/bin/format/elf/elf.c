/* radare - LGPL - Copyright 2008-2020 - nibble, pancake, alvaro_fe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <r_types.h>
#include <r_util.h>
#include "elf.h"

#define MIPS_PLT_OFFSET 0x20
#define RISCV_PLT_OFFSET 0x20

#define RISCV_PLT_ENTRY_SIZE 0x10
#define X86_PLT_ENTRY_SIZE 0x10

#define SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6
#define X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR -0x6

#define ELF_PAGE_MASK 0xFFFFFFFFFFFFF000LL
#define ELF_PAGE_SIZE 12

#define R_ELF_NO_RELRO 0
#define R_ELF_PART_RELRO 1
#define R_ELF_FULL_RELRO 2

#define bprintf if(bin->verbose) R_LOG_WARN

#define MAX_REL_RELA_SZ (sizeof (Elf_(Rel)) > sizeof (Elf_(Rela))? sizeof (Elf_(Rel)): sizeof (Elf_(Rela)))

#define READ8(x, i) r_read_ble8((x) + (i)); (i) += 1
#define READ16(x, i) r_read_ble16((x) + (i), bin->endian); (i) += 2
#define READ32(x, i) r_read_ble32((x) + (i), bin->endian); (i) += 4
#define READ64(x, i) r_read_ble64((x) + (i), bin->endian); (i) += 8

#define BREAD8(x, i) r_buf_read_ble8_at (x, i); (i) += 1
#define BREAD16(x, i) r_buf_read_ble16_at (x, i, bin->endian); (i) += 2
#define BREAD32(x, i) r_buf_read_ble32_at (x, i, bin->endian); (i) += 4
#define BREAD64(x, i) r_buf_read_ble64_at (x, i, bin->endian); (i) += 8

#define NUMENTRIES_ROUNDUP(sectionsize, entrysize) (((sectionsize) + (entrysize)-1) / (entrysize))
#define COMPUTE_PLTGOT_POSITION(rel, pltgot_addr, n_initial_unused_entries) \
	((rel->rva - pltgot_addr - n_initial_unused_entries * R_BIN_ELF_WORDSIZE) / R_BIN_ELF_WORDSIZE)

#define GROWTH_FACTOR (1.5)

#define round_up(a) ((((a) + (4) - (1)) / (4)) * (4))

#define EF_MIPS_ABI_O32		0x00001000  /* O32 ABI.  */
#define EF_MIPS_ABI_O64		0x00002000  /* O32 extended for 64 bit.  */
#define EF_MIPS_ABI			0x0000f000

static inline bool is_elfclass64(Elf_(Ehdr) *h) {
	return h->e_ident[EI_CLASS] == ELFCLASS64;
}

static bool is_mips_o32(Elf_(Ehdr) *h) {
	if (h->e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}
	if ((h->e_flags & EF_MIPS_ABI2) != 0) {
		return false;
	}
	if (((h->e_flags & EF_MIPS_ABI) != 0) &&
		((h->e_flags & EF_MIPS_ABI) != EF_MIPS_ABI_O32)) {
		return false;
	}
	return true;
}

static bool is_mips_n32(Elf_(Ehdr) *h) {
	if (h->e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}
	if (((h->e_flags & EF_MIPS_ABI2) == 0) ||
		((h->e_flags & EF_MIPS_ABI) != 0)) {
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

static reginfo_t reginf[ARCH_LEN] = {
	{ 160, 0x5c },
	{ 216, 0x84 },
	{ 72, 0x5c },
	{ 272, 0x84 },
	{ 272, 0x84 }
};

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

static bool is_bin_etrel(ELFOBJ *bin) {
	return bin->ehdr.e_type == ET_REL;
}

static bool __is_valid_ident(ELFOBJ *bin) {
	return !strncmp ((char *)bin->ehdr.e_ident, ELFMAG, SELFMAG) ||
		!strncmp ((char *)bin->ehdr.e_ident, CGCMAG, SCGCMAG);
}

static bool init_ehdr(ELFOBJ *bin) {
	ut8 e_ident[EI_NIDENT];
	ut8 ehdr[sizeof (Elf_(Ehdr))] = { 0 };
	int i, len;
	if (r_buf_read_at (bin->b, 0, e_ident, EI_NIDENT) == -1) {
		bprintf ("read (magic)\n");
		return false;
	}
	sdb_set (bin->kv, "elf_type.cparse", "enum elf_type { ET_NONE=0, ET_REL=1,"
			" ET_EXEC=2, ET_DYN=3, ET_CORE=4, ET_LOOS=0xfe00, ET_HIOS=0xfeff,"
			" ET_LOPROC=0xff00, ET_HIPROC=0xffff };", 0);
	sdb_set (bin->kv, "elf_machine.cparse", "enum elf_machine {EM_NONE=0, EM_M32=1,"
			" EM_SPARC=2, EM_386=3, EM_68K=4, EM_88K=5, EM_IAMCU=6, EM_860=7, EM_MIPS=8,"
			" EM_S370=9, EM_MIPS_RS3_LE=10, EM_RS6000=11, EM_PARISC=15, EM_nCUBE=16,"
			" EM_VPP500=17, EM_SPARC32PLUS=18, EM_960=19, EM_PPC=20, EM_PPC64=21, EM_S390=22,"
			" EM_SPU=23, EM_V800=36, EM_FR20=37, EM_RH32=38, EM_RCE=39, EM_ARM=40,"
			" EM_ALPHA=41, EM_SH=42, EM_SPARCV9=43, EM_TRICORE=44, EM_ARC=45, EM_H8_300=46,"
			" EM_H8_300H=47, EM_H8S=48, EM_H8_500=49, EM_IA_64=50, EM_MIPS_X=51,"
			" EM_COLDFIRE=52, EM_68HC12=53, EM_MMA=54, EM_PCP=55, EM_NCPU=56, EM_NDR1=57,"
			" EM_STARCORE=58, EM_ME16=59, EM_ST100=60, EM_TINYJ=61, EM_X86_64=62, EM_PDSP=63,"
			" EM_PDP10=64, EM_PDP11=65, EM_FX66=66, EM_ST9PLUS=67, EM_ST7=68, EM_68HC16=69,"
			" EM_68HC11=70, EM_68HC08=71, EM_68HC05=72, EM_SVX=73, EM_ST19=74, EM_VAX=75,"
			" EM_CRIS=76, EM_JAVELIN=77, EM_FIREPATH=78, EM_ZSP=79, EM_MMIX=80, EM_HUANY=81,"
			" EM_PRISM=82, EM_AVR=83, EM_FR30=84, EM_D10V=85, EM_D30V=86, EM_V850=87,"
			" EM_M32R=88, EM_MN10300=89, EM_MN10200=90, EM_PJ=91, EM_OPENRISC=92,"
			" EM_ARC_COMPACT=93, EM_XTENSA=94, EM_VIDEOCORE=95, EM_TMM_GPP=96, EM_NS32K=97,"
			" EM_TPC=98, EM_SNP1K=99, EM_ST200=100, EM_IP2K=101, EM_MAX=102, EM_CR=103,"
			" EM_F2MC16=104, EM_MSP430=105, EM_BLACKFIN=106, EM_SE_C33=107, EM_SEP=108,"
			" EM_ARCA=109, EM_UNICORE=110, EM_EXCESS=111, EM_DXP=112, EM_ALTERA_NIOS2=113,"
			" EM_CRX=114, EM_XGATE=115, EM_C166=116, EM_M16C=117, EM_DSPIC30F=118, EM_CE=119,"
			" EM_M32C=120, EM_TSK3000=131, EM_RS08=132, EM_SHARC=133, EM_ECOG2=134,"
			" EM_SCORE7=135, EM_DSP24=136, EM_VIDEOCORE3=137, EM_LATTICEMICO32=138,"
			" EM_SE_C17=139, EM_TI_C6000=140, EM_TI_C2000=141, EM_TI_C5500=142,"
			" EM_TI_ARP32=143, EM_TI_PRU=144,"
			" EM_MMDSP_PLUS=160, EM_CYPRESS_M8C=161, EM_R32C=162, EM_TRIMEDIA=163,"
			" EM_QDSP6=164, EM_8051=165, EM_STXP7X=166, EM_NDS32=167,"
			" EM_ECOG1X=168, EM_MAXQ30=169, EM_XIMO16=170, EM_MANIK=171, EM_CRAYNV2=172,"
			" EM_RX=173, EM_METAG=174, EM_MCST_ELBRUS=175, EM_ECOG16=176, EM_CR16=177,"
			" EM_ETPU=178, EM_SLE9X=179, EM_L10M=180, EM_K10M=181, EM_AARCH64=183,"
			" EM_AVR32=185, EM_STM8=186, EM_TILE64=187, EM_TILEPRO=188, EM_CUDA=190,"
			" EM_TILEGX=191, EM_CLOUDSHIELD=192, EM_COREA_1ST=193, EM_COREA_2ND=194,"
			" EM_ARC_COMPACT2=195, EM_OPEN8=196, EM_RL78=197, EM_VIDEOCORE5=198,"
			" EM_78KOR=199, EM_56800EX=200, EM_BA1=201, EM_BA2=202, EM_XCORE=203,"
			" EM_MCHP_PIC=204, EM_INTEL205=205, EM_INTEL206=206, EM_INTEL207=207,"
			" EM_INTEL208=208, EM_INTEL209=209, EM_KM32=210, EM_KMX32=211, EM_KMX16=212,"
			" EM_KMX8=213, EM_KVARC=214, EM_CDP=215, EM_COGE=216, EM_COOL=217, EM_NORC=218,"
			" EM_CSR_KALIMBA=219, EM_AMDGPU=224, EM_RISCV=243, EM_LANAI=244, EM_BPF=247,"
			" EM_CSKY=252}", 0);
	sdb_set (bin->kv, "elf_class.cparse", "enum elf_class {ELFCLASSNONE=0, ELFCLASS32=1, ELFCLASS64=2};", 0);
	sdb_set (bin->kv, "elf_data.cparse", "enum elf_data {ELFDATANONE=0, ELFDATA2LSB=1, ELFDATA2MSB=2};", 0);
	sdb_set (bin->kv, "elf_hdr_version.cparse", "enum elf_hdr_version {EV_NONE=0, EV_CURRENT=1};", 0);
	sdb_set (bin->kv, "elf_obj_version.cparse", "enum elf_obj_version {EV_NONE=0, EV_CURRENT=1};", 0);
	sdb_num_set (bin->kv, "elf_header.offset", 0, 0);
	sdb_num_set (bin->kv, "elf_header.size", sizeof (Elf_(Ehdr)), 0);
	sdb_set (bin->kv, "elf_ident.format", "[4]z[1]E[1]E[1]E.::"
	         " magic (elf_class)class (elf_data)data (elf_hdr_version)version", 0);
#if R_BIN_ELF64
	sdb_set (bin->kv, "elf_header.format", "?[2]E[2]E[4]EqqqxN2N2N2N2N2N2"
		" (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
		" entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx", 0);
#else
	sdb_set (bin->kv, "elf_header.format", "?[2]E[2]E[4]ExxxxN2N2N2N2N2N2"
		" (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
		" entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx", 0);
#endif
	bin->endian = (e_ident[EI_DATA] == ELFDATA2MSB)? 1: 0;
	memset (&bin->ehdr, 0, sizeof (Elf_(Ehdr)));
	len = r_buf_read_at (bin->b, 0, ehdr, sizeof (ehdr));
	if (len < 32) { // tinyelf != sizeof (Elf_(Ehdr))) {
		bprintf ("read (ehdr)\n");
		return false;
	}
	// XXX no need to check twice
	memcpy (&bin->ehdr.e_ident, ehdr, 16);
	if (!__is_valid_ident (bin)) {
		return false;
	}
	i = 16;
	// TODO: use r_read or r_buf_read_ apis instead
	bin->ehdr.e_type = READ16 (ehdr, i);
	bin->ehdr.e_machine = READ16 (ehdr, i);
	bin->ehdr.e_version = READ32 (ehdr, i);
#if R_BIN_ELF64
	bin->ehdr.e_entry = READ64 (ehdr, i);
	bin->ehdr.e_phoff = READ64 (ehdr, i);
	bin->ehdr.e_shoff = READ64 (ehdr, i);
#else
	bin->ehdr.e_entry = READ32 (ehdr, i);
	bin->ehdr.e_phoff = READ32 (ehdr, i);
	bin->ehdr.e_shoff = READ32 (ehdr, i);
#endif
	bin->ehdr.e_flags = READ32 (ehdr, i);
	bin->ehdr.e_ehsize = READ16 (ehdr, i);
	bin->ehdr.e_phentsize = READ16 (ehdr, i);
	bin->ehdr.e_phnum = READ16 (ehdr, i);
	bin->ehdr.e_shentsize = READ16 (ehdr, i);
	bin->ehdr.e_shnum = READ16 (ehdr, i);
	bin->ehdr.e_shstrndx = READ16 (ehdr, i);
	return true;
	// [Outdated] Usage example:
	// > td `k bin/cur/info/elf_type.cparse`; td `k bin/cur/info/elf_machine.cparse`
	// > pf `k bin/cur/info/elf_header.format` @ `k bin/cur/info/elf_header.offset`
}

static bool read_phdr(ELFOBJ *bin, bool linux_kernel_hack) {
	bool phdr_found = false;
	int i;
#if R_BIN_ELF64
	const bool is_elf64 = true;
#else
	const bool is_elf64 = false;
#endif
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		ut8 phdr[sizeof (Elf_(Phdr))] = { 0 };
		int j = 0;
		const size_t rsize = bin->ehdr.e_phoff + i * sizeof (Elf_(Phdr));
		int len = r_buf_read_at (bin->b, rsize, phdr, sizeof (Elf_(Phdr)));
		if (len < 1) {
			bprintf ("read (phdr)\n");
			R_FREE (bin->phdr);
			return false;
		}
		bin->phdr[i].p_type = READ32 (phdr, j);
		if (bin->phdr[i].p_type == PT_PHDR) {
			phdr_found = true;
		}

		if (is_elf64) {
			bin->phdr[i].p_flags = READ32 (phdr, j);
		}
		bin->phdr[i].p_offset = R_BIN_ELF_READWORD (phdr, j);
		bin->phdr[i].p_vaddr = R_BIN_ELF_READWORD (phdr, j);
		bin->phdr[i].p_paddr = R_BIN_ELF_READWORD (phdr, j);
		bin->phdr[i].p_filesz = R_BIN_ELF_READWORD (phdr, j);
		bin->phdr[i].p_memsz = R_BIN_ELF_READWORD (phdr, j);
		if (!is_elf64) {
			bin->phdr[i].p_flags = READ32 (phdr, j);
		//	bin->phdr[i].p_flags |= 1; tiny.elf needs this somehow :? LOAD0 is always +x for linux?
		}
		bin->phdr[i].p_align = R_BIN_ELF_READWORD (phdr, j);
	}
	/* Here is the where all the fun starts.
	 * Linux kernel since 2005 calculates phdr offset wrongly
	 * adding it to the load address (va of the LOAD0).
	 * See `fs/binfmt_elf.c` file this line:
	 *    NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	 * So after the first read, we fix the address and read it again
	 */
	if (linux_kernel_hack && phdr_found) {
		ut64 load_addr = Elf_(r_bin_elf_get_baddr) (bin);
		bin->ehdr.e_phoff = Elf_(r_bin_elf_v2p) (bin, load_addr + bin->ehdr.e_phoff);
		return read_phdr (bin, false);
	}
	return true;
}

static int init_phdr(ELFOBJ *bin) {
	ut32 phdr_size;

	r_return_val_if_fail (!bin->phdr, false);

	if (!bin->ehdr.e_phnum) {
		return false;
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
	if (!(bin->phdr = R_NEWS0 (Elf_(Phdr), bin->ehdr.e_phnum))) {
		perror ("malloc (phdr)");
		return false;
	}

	bool linux_kern_hack = false;
	/* Enable this hack only for the X86 64bit ELFs */
	const int _128K = 1024 * 128;
	if (r_buf_size (bin->b) > _128K && (bin->ehdr.e_machine == EM_X86_64 || bin->ehdr.e_machine == EM_386)) {
		linux_kern_hack = true;
	}
	if (!read_phdr (bin, linux_kern_hack)) {
		return false;
	}

	sdb_num_set (bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_num_set (bin->kv, "elf_phdr.size", sizeof (Elf_(Phdr)), 0);
	sdb_set (bin->kv, "elf_p_type.cparse", "enum elf_p_type {PT_NULL=0,PT_LOAD=1,PT_DYNAMIC=2,"
		"PT_INTERP=3,PT_NOTE=4,PT_SHLIB=5,PT_PHDR=6,PT_LOOS=0x60000000,"
		"PT_HIOS=0x6fffffff,PT_LOPROC=0x70000000,PT_HIPROC=0x7fffffff};",
		0);
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
	ut8 shdr[sizeof (Elf_(Shdr))] = { 0 };
	int i, j, len;

	r_return_val_if_fail (bin && !bin->shdr, false);

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
	if (!(bin->shdr = R_NEWS0 (Elf_(Shdr), bin->ehdr.e_shnum))) {
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
			bprintf ("read (shdr) at 0x%" PFMT64x "\n", (ut64) bin->ehdr.e_shoff);
			R_FREE (bin->shdr);
			return false;
		}
		bin->shdr[i].sh_name = READ32 (shdr, j);
		bin->shdr[i].sh_type = READ32 (shdr, j);
		bin->shdr[i].sh_flags = R_BIN_ELF_READWORD (shdr, j);
		bin->shdr[i].sh_addr = R_BIN_ELF_READWORD (shdr, j);
		bin->shdr[i].sh_offset = R_BIN_ELF_READWORD (shdr, j);
		bin->shdr[i].sh_size = R_BIN_ELF_READWORD (shdr, j);
		bin->shdr[i].sh_link = READ32 (shdr, j);
		bin->shdr[i].sh_info = READ32 (shdr, j);
		bin->shdr[i].sh_addralign = R_BIN_ELF_READWORD (shdr, j);
		bin->shdr[i].sh_entsize = R_BIN_ELF_READWORD (shdr, j);
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

static bool is_shidx_valid(ELFOBJ *bin, Elf_(Half) value) {
	return value < bin->ehdr.e_shnum && !R_BETWEEN (SHN_LORESERVE, value, SHN_HIRESERVE);
}

static int init_strtab(ELFOBJ *bin) {
	r_return_val_if_fail (!bin->strtab, false);

	if (!bin->shdr) {
		return false;
	}

	Elf_(Half) shstrndx = bin->ehdr.e_shstrndx;
	if (shstrndx != SHN_UNDEF && !is_shidx_valid (bin, shstrndx)) {
		return false;
	}

	/* sh_size must be lower than UT32_MAX and not equal to zero, to avoid bugs on malloc() */
	if (bin->shdr[shstrndx].sh_size > UT32_MAX) {
		return false;
	}
	if (!bin->shdr[shstrndx].sh_size) {
		return false;
	}
	bin->shstrtab_section = bin->strtab_section = &bin->shdr[shstrndx];
	bin->shstrtab_size = bin->shstrtab_section->sh_size;
	if (bin->shstrtab_size > bin->size) {
		return false;
	}
	if (bin->shstrtab_section->sh_offset > bin->size) {
		return false;
	}
	if (bin->shstrtab_section->sh_offset + bin->shstrtab_section->sh_size > bin->size) {
		return false;
	}

	if (!(bin->shstrtab = calloc (1, bin->shstrtab_size + 1))) {
		perror ("malloc");
		bin->shstrtab = NULL;
		return false;
	}
	int res = r_buf_read_at (bin->b, bin->shstrtab_section->sh_offset, (ut8*)bin->shstrtab,
		bin->shstrtab_section->sh_size);
	if (res < 1) {
		bprintf ("read (shstrtab) at 0x%" PFMT64x "\n", (ut64) bin->shstrtab_section->sh_offset);
		R_FREE (bin->shstrtab);
		return false;
	}
	bin->shstrtab[bin->shstrtab_section->sh_size] = '\0';

	sdb_num_set (bin->kv, "elf_shstrtab.offset", bin->shstrtab_section->sh_offset, 0);
	sdb_num_set (bin->kv, "elf_shstrtab.size", bin->shstrtab_section->sh_size, 0);

	return true;
}

static Elf_(Phdr) *get_dynamic_segment(ELFOBJ *bin) {
	int i;
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_DYNAMIC) {
			if (bin->phdr[i].p_filesz > bin->size) {
				return NULL;
			}
			if (bin->phdr[i].p_offset > bin->size) {
				return NULL;
			}
			if (bin->phdr[i].p_offset + sizeof (Elf_(Dyn)) > bin->size) {
				return NULL;
			}
			return &bin->phdr[i];
		}
	}
	return NULL;
}

static void init_dynamic_section_sdb(ELFOBJ *bin, Elf_(Addr) strtabaddr, size_t strsize) {
	int r = Elf_(r_bin_elf_has_relro) (bin);
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
}

static void set_default_value_dynamic_info(ELFOBJ *bin) {
	bin->dyn_info.dt_pltrelsz = 0;
	bin->dyn_info.dt_pltgot = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_hash = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_strtab = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_symtab = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_rela = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_relasz = 0;
	bin->dyn_info.dt_relaent = 0;
	bin->dyn_info.dt_strsz = 0;
	bin->dyn_info.dt_syment = 0;
	bin->dyn_info.dt_rel = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_relsz = 0;
	bin->dyn_info.dt_relent = 0;
	bin->dyn_info.dt_pltrel = R_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_jmprel = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_pltgot = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_mips_pltgot = R_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_bind_now = false;
	bin->dyn_info.dt_flags = R_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_flags_1 = R_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_rpath = R_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_runpath = R_BIN_ELF_XWORD_MAX;
	r_vector_init(&bin->dyn_info.dt_needed, sizeof(Elf_(Off)), NULL, NULL);
}

static size_t get_maximum_number_of_dynamic_entries(ut64 dyn_size) {
	return dyn_size / sizeof (Elf_(Dyn));
}

static bool fill_dynamic_entry(ELFOBJ *bin, ut64 entry_offset, Elf_(Dyn) *d) {
	ut8 sdyn[sizeof (Elf_(Dyn))] = { 0 };
	int j = 0;
	int len = r_buf_read_at (bin->b, entry_offset, sdyn, sizeof (Elf_(Dyn)));
	if (len < 1) {
		return false;
	}

	d->d_tag = R_BIN_ELF_READWORD (sdyn, j);
	d->d_un.d_ptr = R_BIN_ELF_READWORD (sdyn, j);

	return true;
}

static void fill_dynamic_entries(ELFOBJ *bin, ut64 loaded_offset, ut64 dyn_size) {
	Elf_(Dyn) d = { 0 };
	size_t i;
	size_t number_of_entries = get_maximum_number_of_dynamic_entries(dyn_size);

	for (i = 0; i < number_of_entries; i++) {
		ut64 entry_offset = loaded_offset + i * sizeof (Elf_(Dyn));
		if (!fill_dynamic_entry (bin, entry_offset, &d)) {
			break;
		}

		switch (d.d_tag) {
		case DT_NULL:
			break;
		case DT_PLTRELSZ:
			bin->dyn_info.dt_pltrelsz = d.d_un.d_val;
			break;
		case DT_PLTGOT:
			bin->dyn_info.dt_pltgot = d.d_un.d_ptr;
			break;
		case DT_HASH:
			bin->dyn_info.dt_hash = d.d_un.d_ptr;
			break;
		case DT_STRTAB:
			bin->dyn_info.dt_strtab = d.d_un.d_ptr;
			break;
		case DT_SYMTAB:
			bin->dyn_info.dt_symtab = d.d_un.d_ptr;
			break;
		case DT_RELA:
			bin->dyn_info.dt_rela = d.d_un.d_ptr;
			break;
		case DT_RELASZ:
			bin->dyn_info.dt_relasz = d.d_un.d_val;
			break;
		case DT_RELAENT:
			bin->dyn_info.dt_relaent = d.d_un.d_val;
			break;
		case DT_STRSZ:
			bin->dyn_info.dt_strsz = d.d_un.d_val;
			break;
		case DT_SYMENT:
			bin->dyn_info.dt_syment = d.d_un.d_val;
			break;
		case DT_REL:
			bin->dyn_info.dt_rel = d.d_un.d_ptr;
			break;
		case DT_RELSZ:
			bin->dyn_info.dt_relsz = d.d_un.d_val;
			break;
		case DT_RELENT:
			bin->dyn_info.dt_relent = d.d_un.d_val;
			break;
		case DT_PLTREL:
			bin->dyn_info.dt_pltrel = d.d_un.d_val;
			break;
		case DT_JMPREL:
			bin->dyn_info.dt_jmprel = d.d_un.d_ptr;
			break;
		case DT_MIPS_PLTGOT:
			bin->dyn_info.dt_mips_pltgot = d.d_un.d_ptr;
			break;
		case DT_BIND_NOW:
			bin->dyn_info.dt_bind_now = true;
			break;
		case DT_FLAGS:
			bin->dyn_info.dt_flags = d.d_un.d_val;
			break;
		case DT_FLAGS_1:
			bin->dyn_info.dt_flags_1 = d.d_un.d_val;
			break;
		case DT_RPATH:
			bin->dyn_info.dt_rpath = d.d_un.d_val;
			break;
		case DT_RUNPATH:
			bin->dyn_info.dt_runpath = d.d_un.d_val;
			break;
		case DT_NEEDED:
			r_vector_push (&bin->dyn_info.dt_needed, &d.d_un.d_val);
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
			if ((d.d_tag >= DT_VERSYM) && (d.d_tag <= DT_VERNEEDNUM)) {
				bin->version_info[DT_VERSIONTAGIDX (d.d_tag)] = d.d_un.d_val;
			} else {
				R_LOG_DEBUG ("Dynamic tag %" PFMT64d " not handled\n", (ut64) d.d_tag);
			}
			break;
		}
		if (d.d_tag == DT_NULL) {
			break;
		}
	}
}

static int init_dynamic_section(ELFOBJ *bin) {
	ut64 strtabaddr = 0;
	char *strtab = NULL;
	size_t strsize = 0;
	int r;
	ut64 dyn_size = 0, loaded_offset;
	set_default_value_dynamic_info(bin);

	r_return_val_if_fail (bin, false);
	if (!bin->phdr || !bin->ehdr.e_phnum) {
		return false;
	}

	Elf_(Phdr) *dyn_phdr = get_dynamic_segment (bin);
	if (!dyn_phdr) {
		return false;
	}

	dyn_size = dyn_phdr->p_filesz;
	loaded_offset = Elf_(r_bin_elf_v2p_new) (bin, dyn_phdr->p_vaddr);
	if (loaded_offset == UT64_MAX) {
		return false;
	}

	if (!dyn_size || loaded_offset + dyn_size > bin->size) {
		return false;
	}

	fill_dynamic_entries (bin, loaded_offset, dyn_size);

	if (bin->dyn_info.dt_strtab != R_BIN_ELF_ADDR_MAX) {
		strtabaddr = Elf_(r_bin_elf_v2p_new) (bin, bin->dyn_info.dt_strtab);
	}

	if (bin->dyn_info.dt_strsz > 0) {
		strsize = bin->dyn_info.dt_strsz;
	}

	if (strtabaddr == UT64_MAX || strtabaddr > bin->size || strsize > ST32_MAX || !strsize || strsize > bin->size || strtabaddr + strsize > bin->size) {
		if (!strtabaddr) {
			bprintf ("DT_STRTAB not found or invalid\n");
		}
		return false;
	}
	strtab = (char *)calloc (1, strsize + 1);
	if (!strtab) {
		return false;
	}
	r = r_buf_read_at (bin->b, strtabaddr, (ut8 *)strtab, strsize);
	if (r < 1) {
		free (strtab);
		return false;
	}

	bin->strtab = strtab;
	bin->strtab_size = strsize;
	init_dynamic_section_sdb (bin, strtabaddr, strsize);
	return true;
}

static RBinElfSection* get_section_by_name(ELFOBJ *bin, const char *section_name) {
	if (bin->g_sections) {
		size_t i;
		for (i = 0; !bin->g_sections[i].last; i++) {
			if (!strncmp (bin->g_sections[i].name, section_name, ELF_STRING_LENGTH - 1)) {
				return &bin->g_sections[i];
			}
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
	size_t i;
	const ut64 num_entries = sz / sizeof (Elf_(Versym));
	const char *section_name = "";
	const char *link_section_name = "";
	Sdb *sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}
	if (!bin->version_info[DT_VERSIONTAGIDX (DT_VERSYM)]) {
		sdb_free (sdb);
		return NULL;
	}
	if (shdr->sh_link >= bin->ehdr.e_shnum) {
		sdb_free (sdb);
		return NULL;
	}
	Elf_(Shdr) *link_shdr = &bin->shdr[shdr->sh_link];
	ut8 *edata = (ut8*) calloc (R_MAX (1, num_entries), 2 * sizeof (ut8));
	if (!edata) {
		sdb_free (sdb);
		return NULL;
	}
	ut16 *data = (ut16 *)calloc (R_MAX (1, num_entries), sizeof (ut16));
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
	char *tmp_val = NULL;
	for (i = 0; i < num_entries; i += 4) {
		size_t j;
		int check_def;
		char key[32] = { 0 };

		for (j = 0; (j < 4) && (i + j) < num_entries; j++) {
			int k;
			snprintf (key, sizeof (key), "entry%zd", i + j);
			switch (data[i + j]) {
			case 0:
				sdb_set (sdb, key, "0 (*local*)", 0);
				break;
			case 1:
				sdb_set (sdb, key, "1 (*global*)", 0);
				break;
			default:
				free (tmp_val);
				tmp_val = strdup (sdb_fmt ("%x ", data[i+j] & 0x7FFF));
				check_def = true;
				if (bin->version_info[DT_VERSIONTAGIDX (DT_VERNEED)]) {
					Elf_(Verneed) vn;
					ut8 svn[sizeof (Elf_(Verneed))] = { 0 };
					ut64 offset = Elf_(r_bin_elf_v2p) (bin, bin->version_info[DT_VERSIONTAGIDX (DT_VERNEED)]);
					do {
						Elf_(Vernaux) vna;
						ut8 svna[sizeof (Elf_(Vernaux))] = { 0 };
						ut64 a_off;
						if (offset > bin->size || offset + sizeof (vn) > bin->size) {
							goto beach;
						}
						if (r_buf_read_at (bin->b, offset, svn, sizeof (svn)) < 0) {
							bprintf ("Cannot read Verneed for Versym\n");
							goto beach;
						}
						k = 0;
						vn.vn_version = READ16 (svn, k);
						vn.vn_cnt = READ16 (svn, k);
						vn.vn_file = READ32 (svn, k);
						vn.vn_aux = READ32 (svn, k);
						vn.vn_next = READ32 (svn, k);
						a_off = offset + vn.vn_aux;
						do {
							if (a_off > bin->size || a_off + sizeof (vna) > bin->size) {
								goto beach;
							}
							if (r_buf_read_at (bin->b, a_off, svna, sizeof (svna)) < 0) {
								bprintf ("Cannot read Vernaux for Versym\n");
								goto beach;
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
							if (vna.vna_name > bin->strtab_size) {
								goto beach;
							}
							sdb_set (sdb, key, sdb_fmt ("%s(%s)", tmp_val, bin->strtab + vna.vna_name), 0);
							check_def = false;
							break;
						}
						offset += vn.vn_next;
					} while (vn.vn_next);
				}

				ut64 vinfoaddr = bin->version_info[DT_VERSIONTAGIDX (DT_VERDEF)];
				if (check_def && data[i + j] != 0x8001 && vinfoaddr) {
					Elf_(Verdef) vd;
					ut8 svd[sizeof (Elf_(Verdef))] = { 0 };
					ut64 offset = Elf_(r_bin_elf_v2p) (bin, vinfoaddr);
					if (offset > bin->size || offset + sizeof (vd) > bin->size) {
						goto beach;
					}
					do {
						if (r_buf_read_at (bin->b, offset, svd, sizeof (svd)) < 0) {
							bprintf ("Cannot read Verdef for Versym\n");
							goto beach;
						}
						k = 0;
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
						ut8 svda[sizeof (Elf_(Verdaux))] = { 0 };
						ut64 off_vda = offset - vd.vd_next + vd.vd_aux;
						if (off_vda > bin->size || off_vda + sizeof (vda) > bin->size) {
							goto beach;
						}
						if (r_buf_read_at (bin->b, off_vda, svda, sizeof (svda)) < 0) {
							bprintf ("Cannot read Verdaux for Versym\n");
							goto beach;
						}
						k = 0;
						vda.vda_name = READ32 (svda, k);
						vda.vda_next = READ32 (svda, k);
						if (vda.vda_name > bin->strtab_size) {
							goto beach;
						}
						const char *name = bin->strtab + vda.vda_name;
						if (name) {
							const char *fname = sdb_fmt ("%s(%s%-*s)", tmp_val, name, (int)(12 - strlen (name)),")");
							sdb_set (sdb, key, fname, 0);
						}
					}
				}
			}
		}
		R_FREE (tmp_val);
	}
beach:
	R_FREE (tmp_val);
	free (data);
	return sdb;
}

static Sdb *store_versioninfo_gnu_verdef(ELFOBJ *bin, Elf_(Shdr) *shdr, int sz) {
	const char *section_name = "";
	const char *link_section_name = "";
	char *end = NULL;
	ut8 dfs[sizeof (Elf_(Verdef))] = { 0 };
	Sdb *sdb;
	ut32 cnt;
	size_t i;
	if (shdr->sh_link >= bin->ehdr.e_shnum) {
		return false;
	}
	Elf_(Shdr) *link_shdr = &bin->shdr[shdr->sh_link];
#ifdef R_BIN_ELF64
	if ((int)shdr->sh_size < 1 || shdr->sh_size > SIZE_MAX) {
#else
	if ((int)shdr->sh_size < 1) {
#endif
		return false;
	}
	if (shdr->sh_size < sizeof (Elf_(Verdef)) || shdr->sh_size < sizeof (Elf_(Verdaux))) {
		return false;
	}
	Elf_(Verdef) *defs = calloc (shdr->sh_size, 1);
	if (!defs) {
		bprintf ("Cannot allocate memory (Check Elf_(Verdef))\n");
		return false;
	}
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (link_shdr && bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	sdb = sdb_new0 ();
	end = (char *)defs + shdr->sh_size;
	sdb_set (sdb, "section_name", section_name, 0);
	sdb_num_set (sdb, "entries", shdr->sh_info, 0);
	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set (sdb, "link", shdr->sh_link, 0);
	sdb_set (sdb, "link_section_name", link_section_name, 0);

	for (cnt = 0, i = 0; cnt < shdr->sh_info && i < shdr->sh_size; cnt++) {
		Sdb *sdb_verdef = sdb_new0 ();
		char *vstart = ((char*)defs) + i;
		size_t vstart_off = i;
		char key[32] = { 0 };
		Elf_(Verdef) *verdef = (Elf_(Verdef)*)vstart;
		Elf_(Verdaux) aux = { 0 };
		int j = 0;
		int isum = 0;

		if (vstart + sizeof (*verdef) > end) {
			break;
		}
		r_buf_read_at (bin->b, shdr->sh_offset + i, dfs, sizeof (Elf_(Verdef)));
		verdef->vd_version = READ16 (dfs, j);
		verdef->vd_flags = READ16 (dfs, j);
		verdef->vd_ndx = READ16 (dfs, j);
		verdef->vd_cnt = READ16 (dfs, j);
		verdef->vd_hash = READ32 (dfs, j);
		verdef->vd_aux = READ32 (dfs, j);
		verdef->vd_next = READ32 (dfs, j);
		int vdaux = verdef->vd_aux;
		if (vdaux < 1 || shdr->sh_size - vstart_off < vdaux) {
			sdb_free (sdb_verdef);
			goto out_error;
		}
		vstart += vdaux;
		vstart_off += vdaux;
		if (vstart > end || shdr->sh_size - sizeof (Elf_(Verdaux)) < vstart_off) {
			sdb_free (sdb_verdef);
			goto out_error;
		}

		j = 0;
		aux.vda_name = READ32 (vstart, j);
		aux.vda_next = READ32 (vstart, j);

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

		for (j = 1; j < verdef->vd_cnt; j++) {
			int k;
			Sdb *sdb_parent = sdb_new0 ();
			if (shdr->sh_size - vstart_off < aux.vda_next) {
				sdb_free (sdb_verdef);
				sdb_free (sdb_parent);
				goto out_error;
			}
			isum += aux.vda_next;
			vstart += aux.vda_next;
			vstart_off += aux.vda_next;
			if (vstart > end || shdr->sh_size - sizeof (Elf_(Verdaux)) < vstart_off) {
				sdb_free (sdb_verdef);
				sdb_free (sdb_parent);
				goto out_error;
			}
			k = 0;
			aux.vda_name = READ32 (vstart, k);
			aux.vda_next = READ32 (vstart, k);
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

		snprintf (key, sizeof (key), "verdef%u", cnt);
		sdb_ns_set (sdb, key, sdb_verdef);
		if (!verdef->vd_next || shdr->sh_size - i < verdef->vd_next) {
			sdb_free (sdb_verdef);
			goto out_error;
		}
		if ((st32)verdef->vd_next < 1) {
			bprintf ("Invalid vd_next in the ELF version\n");
			break;
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
	ut64 i;
	int cnt;

	if (!bin || !bin->dynstr) {
		return NULL;
	}
	if (shdr->sh_link >= bin->ehdr.e_shnum) {
		return NULL;
	}
#ifdef R_BIN_ELF64
	if ((int)shdr->sh_size < 1 || shdr->sh_size > SIZE_MAX) {
#else
	if ((int)shdr->sh_size < 1) {
#endif
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
		bprintf ("Cannot allocate memory for Elf_(Verneed)\n");
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
	if (i < 1) {
		goto beach;
	}
	//XXX we should use DT_VERNEEDNUM instead of sh_info
	//TODO https://sourceware.org/ml/binutils/2014-11/msg00353.html
	for (i = 0, cnt = 0; cnt < shdr->sh_info; cnt++) {
		int j, isum;
		ut8 *vstart = need + i;
		Elf_(Verneed) vvn = { 0 };
		if (vstart + sizeof (Elf_(Verneed)) > end) {
			goto beach;
		}
		Elf_(Verneed) *entry = &vvn;
		char key[32] = { 0 };
		sdb_version = sdb_new0 ();
		if (!sdb_version) {
			goto beach;
		}
		j = 0;
		vvn.vn_version = READ16 (vstart, j);
		vvn.vn_cnt = READ16 (vstart, j);
		vvn.vn_file = READ32 (vstart, j);
		vvn.vn_aux = READ32 (vstart, j);
		vvn.vn_next = READ32 (vstart, j);

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
		st32 vnaux = entry->vn_aux;
		if (vnaux < 1) {
			goto beach;
		}
		vstart += vnaux;
		ut32 vn_cnt = entry->vn_cnt;
		for (j = 0, isum = i + entry->vn_aux; j < vn_cnt && vstart + sizeof (Elf_(Vernaux)) <= end; j++) {
			int k;
			Elf_(Vernaux) *aux = NULL;
			Elf_(Vernaux) vaux = {0};
			aux = (Elf_(Vernaux)*)&vaux;
			k = 0;
			vaux.vna_hash = READ32 (vstart, k);
			vaux.vna_flags = READ16 (vstart, k);
			vaux.vna_other = READ16 (vstart, k);
			vaux.vna_name = READ32 (vstart, k);
			vaux.vna_next = READ32 (vstart, k);
			if (aux->vna_name > bin->dynstr_size) {
				goto beach;
			}
#if 1
			sdb_vernaux = sdb_new0 ();
			if (!sdb_vernaux) {
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
#else
			char *key = r_str_newf ("vernaux%d", j);
			char *val = r_str_newf ("%d,%s", isum, get_ver_flags (aux->vna_flags));
			sdb_set (sdb_version, key, val, 0);
			free (key);
			free (val);
#endif
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
	size_t i;

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

		if (size - (i * sizeof (Elf_(Shdr)) > bin->size)) {
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
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_name > bin->shstrtab_size) {
			return false;
		}
		section_name = &bin->shstrtab[bin->shdr[i].sh_name];
		if (bin->shdr[i].sh_type == SHT_STRTAB && !strcmp (section_name, ".dynstr")) {
			if (!(bin->dynstr = (char*) calloc (bin->shdr[i].sh_size + 1, sizeof (char)))) {
				bprintf("Cannot allocate memory for dynamic strings\n");
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

static HtUP *rel_cache_new(RBinElfReloc *relocs, ut32 reloc_num) {
	if (!relocs || reloc_num == 0) {
		return NULL;
	}
	const int htsize = R_MIN (reloc_num, 1024);
	HtUP *rel_cache = ht_up_new_size (htsize, NULL, NULL, NULL);
	if (rel_cache) {
		size_t i;
		for (i = 0; i < reloc_num; i++) {
			RBinElfReloc *tmp = relocs + i;
			ht_up_insert (rel_cache, tmp->sym, tmp);
		}
	}
	return rel_cache;
}

static bool elf_init(ELFOBJ *bin) {
	/* bin is not an ELF */
	if (!init_ehdr (bin)) {
		return false;
	}
	if (!init_phdr (bin) && !is_bin_etrel (bin)) {
		bprintf ("Cannot initialize program headers\n");
	}
	if (bin->ehdr.e_type != ET_CORE) {
		if (!init_shdr (bin)) {
			bprintf ("Cannot initialize section headers\n");
		}
		if (!init_strtab (bin)) {
			bprintf ("Cannot initialize strings table\n");
		}
		if (!init_dynstr (bin) && !is_bin_etrel (bin)) {
			bprintf ("Cannot initialize dynamic strings\n");
		}
		bin->baddr = Elf_(r_bin_elf_get_baddr) (bin);
		if (!init_dynamic_section (bin) && !Elf_(r_bin_elf_is_static) (bin) && !is_bin_etrel (bin)) {
			bprintf ("Cannot initialize dynamic section\n");
		}
	}

	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;
	bin->symbols_by_ord_size = 0;
	bin->symbols_by_ord = NULL;
	bin->g_sections = Elf_(r_bin_elf_get_sections) (bin);
	bin->boffset = Elf_(r_bin_elf_get_boffset) (bin);
	bin->g_relocs = Elf_(r_bin_elf_get_relocs) (bin);
	bin->rel_cache = rel_cache_new (bin->g_relocs, bin->g_reloc_num);
	sdb_ns_set (bin->kv, "versioninfo", store_versioninfo (bin));
	return true;
}

ut64 Elf_(r_bin_elf_get_section_offset)(ELFOBJ *bin, const char *section_name) {
	RBinElfSection *section = get_section_by_name (bin, section_name);
	return section? section->offset: UT64_MAX;
}

ut64 Elf_(r_bin_elf_get_section_addr)(ELFOBJ *bin, const char *section_name) {
	RBinElfSection *section = get_section_by_name (bin, section_name);
	return section? section->rva: UT64_MAX;
}

ut64 Elf_(r_bin_elf_get_section_addr_end)(ELFOBJ *bin, const char *section_name) {
	RBinElfSection *section = get_section_by_name (bin, section_name);
	return section? section->rva + section->size: UT64_MAX;
}

static ut64 get_got_entry(ELFOBJ *bin, RBinElfReloc *rel) {
	if (!rel->rva) {
		return UT64_MAX;
	}

	ut64 p_sym_got_addr = Elf_(r_bin_elf_v2p_new) (bin, rel->rva);
	ut64 addr = R_BIN_ELF_BREADWORD (bin->b, p_sym_got_addr);

	return (!addr || addr == R_BIN_ELF_WORD_MAX) ? UT64_MAX : addr;
}

static bool is_thumb_symbol(ut64 plt_addr) {
	return plt_addr & 1;
}

static ut64 get_import_addr_arm(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 got_addr = bin->dyn_info.dt_pltgot;
	if (got_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry (bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x3);

	switch (rel->type) {
	case R_ARM_JUMP_SLOT: {
		plt_addr += pos * 12 + 20;
		if (is_thumb_symbol (plt_addr)) {
			plt_addr--;
		}
		return plt_addr;
	}
	case R_AARCH64_JUMP_SLOT:
		return plt_addr + pos * 16 + 32;
	default:
		bprintf ("Unsupported relocation type for imports %d\n", rel->type);
		return UT64_MAX;
	}
	return UT64_MAX;
}

static ut64 get_import_addr_mips(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 jmprel_addr = bin->dyn_info.dt_jmprel;
	ut64 got_addr = bin->dyn_info.dt_mips_pltgot;

	if (jmprel_addr == R_BIN_ELF_ADDR_MAX || got_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x2);

	ut8 buf[1024];
	ut64 plt_addr = jmprel_addr + bin->dyn_info.dt_pltrelsz;
	ut64 p_plt_addr = Elf_(r_bin_elf_v2p_new) (bin, plt_addr);
	int res = r_buf_read_at (bin->b, p_plt_addr, buf, sizeof (buf));
	if (res != sizeof (buf)) {
		return UT64_MAX;
	}

	const ut8 *base = r_mem_mem_aligned (buf, sizeof (buf), (const ut8 *)"\x3c\x0f\x00", 3, 4);
	plt_addr += base? (int)(size_t) (base - buf):  MIPS_PLT_OFFSET + 8; // HARDCODED HACK
	plt_addr += pos * 16;

	return plt_addr;
}

static size_t get_size_rel_mode(Elf_(Xword) rel_mode) {
	return rel_mode == DT_RELA? sizeof (Elf_(Rela)): sizeof (Elf_(Rel));
}

static ut64 get_num_relocs_dynamic_plt(ELFOBJ *bin) {
	if (bin->dyn_info.dt_pltrelsz) {
		const ut64 size = bin->dyn_info.dt_pltrelsz;
		const ut64 relsize = get_size_rel_mode (bin->dyn_info.dt_pltrel);
		return size / relsize;
	}
	return 0;
}

static ut64 get_import_addr_riscv(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 got_addr = bin->dyn_info.dt_pltgot;
	if (got_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 plt_addr = get_got_entry (bin, rel);
	if (plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x2);
	return plt_addr + RISCV_PLT_OFFSET + pos * RISCV_PLT_ENTRY_SIZE;
}

static ut64 get_import_addr_sparc(ELFOBJ *bin, RBinElfReloc *rel) {
	if (rel->type != R_SPARC_JMP_SLOT) {
		bprintf ("Unknown sparc reloc type %d\n", rel->type);
		return UT64_MAX;
	}
	ut64 tmp = get_got_entry (bin, rel);

	return (tmp == UT64_MAX) ? UT64_MAX : tmp + SPARC_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr_ppc(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 plt_addr = bin->dyn_info.dt_pltgot;
	if (plt_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}
	ut64 p_plt_addr = Elf_(r_bin_elf_v2p_new) (bin, plt_addr);
	if (p_plt_addr == UT64_MAX) {
		return UT64_MAX;
	}

	ut64 base = r_buf_read_ble32_at (bin->b, p_plt_addr, bin->endian);
	if (base == UT32_MAX) {
		return UT64_MAX;
	}

	ut64 nrel = get_num_relocs_dynamic_plt (bin);
	ut64 pos = COMPUTE_PLTGOT_POSITION(rel, plt_addr, 0x0);

	if (bin->endian) {
		base -= (nrel * 16);
		base += (pos * 16);
		return base;
	}

	base -= (nrel * 12) + 20;
	base += (pos * 8);
	return base;
}

static ut64 get_import_addr_x86_manual(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 got_addr = bin->dyn_info.dt_pltgot;
	if (got_addr == R_BIN_ELF_ADDR_MAX) {
		return UT64_MAX;
	}

	ut64 got_offset = Elf_(r_bin_elf_v2p_new) (bin, got_addr);
	if (got_offset == UT64_MAX) {
		return UT64_MAX;
	}

	//XXX HACK ALERT!!!! full relro?? try to fix it
	//will there always be .plt.got, what would happen if is .got.plt?
	RBinElfSection *s = get_section_by_name (bin, ".plt.got");
	if (Elf_(r_bin_elf_has_relro) (bin) < R_ELF_PART_RELRO || !s) {
		return UT64_MAX;
	}

	ut8 buf[sizeof (Elf_(Addr))] = { 0 };

	ut64 plt_addr = s->offset;
	ut64 plt_sym_addr;

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
		int res = r_buf_read_at (bin->b, plt_addr + 2, buf, sizeof (ut32));
		if (res < 0) {
			return UT64_MAX;
		}

		size_t i = 0;
		plt_sym_addr = R_BIN_ELF_READWORD (buf, i);

		//relative address
		if ((plt_addr + 6 + Elf_(r_bin_elf_v2p) (bin, plt_sym_addr)) == rel->rva) {
			return plt_addr;
		}
		if (plt_sym_addr == rel->rva) {
			return plt_addr;
		}
		plt_addr += 8;
	}

	return UT64_MAX;
}

static ut64 get_import_addr_x86(ELFOBJ *bin, RBinElfReloc *rel) {
	ut64 tmp = get_got_entry (bin, rel);
	if (tmp == UT64_MAX) {
		return get_import_addr_x86_manual (bin, rel);
	}

	RBinElfSection *pltsec_section = get_section_by_name (bin, ".plt.sec");

	if (pltsec_section) {
		ut64 got_addr = bin->dyn_info.dt_pltgot;
		ut64 pos = COMPUTE_PLTGOT_POSITION(rel, got_addr, 0x3);
		return pltsec_section->rva + pos * X86_PLT_ENTRY_SIZE;
	}

	return tmp + X86_OFFSET_PLT_ENTRY_FROM_GOT_ADDR;
}

static ut64 get_import_addr(ELFOBJ *bin, int sym) {
	if ((!bin->shdr || !bin->strtab) && !bin->phdr) {
		return UT64_MAX;
	}

	if (!bin->rel_cache) {
		return UT64_MAX;
	}

	// lookup the right rel/rela entry
	RBinElfReloc *rel = ht_up_find (bin->rel_cache, sym, NULL);

	if (!rel) {
		return UT64_MAX;
	}

	switch (bin->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
		return get_import_addr_arm (bin, rel);
	case EM_MIPS: // MIPS32 BIG ENDIAN relocs
		return get_import_addr_mips (bin, rel);
	case EM_RISCV:
		return get_import_addr_riscv (bin, rel);
	case EM_SPARC:
	case EM_SPARCV9:
	case EM_SPARC32PLUS:
		return get_import_addr_sparc (bin, rel);
	case EM_PPC:
	case EM_PPC64:
		return get_import_addr_ppc (bin, rel);
	case EM_386:
	case EM_X86_64:
		return get_import_addr_x86 (bin, rel);
	default:
		eprintf ("Unsupported relocs type %" PFMT64u " for arch %d\n",
				(ut64) rel->type, bin->ehdr.e_machine);
		return UT64_MAX;
	}
}

int Elf_(r_bin_elf_has_nx)(ELFOBJ *bin) {
	r_return_val_if_fail (bin, 0);
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
	r_return_val_if_fail (bin, R_ELF_NO_RELRO);
	bool haveBindNow = false;
	bool haveGnuRelro = false;

	if (bin->dyn_info.dt_bind_now) {
		haveBindNow = true;
	} else if (bin->dyn_info.dt_flags != R_BIN_ELF_XWORD_MAX && bin->dyn_info.dt_flags != R_BIN_ELF_XWORD_MAX) {
		haveBindNow = bin->dyn_info.dt_flags_1 & DF_1_NOW;
	}

	if (bin->phdr) {
		size_t i;
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
	ut64 tmp, base = UT64_MAX;
	if (!bin) {
		return 0;
	}
	if (bin->phdr) {
		size_t i;
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
	if (base == UT64_MAX && is_bin_etrel (bin)) {
		//we return our own base address for ET_REL type
		//we act as a loader for ELF
		return 0x08000000;
	}
	return base == UT64_MAX? 0: base;
}

ut64 Elf_(r_bin_elf_get_boffset)(ELFOBJ *bin) {
	ut64 tmp, base = UT64_MAX;
	r_return_val_if_fail (bin, 0);

	if (!bin->phdr) {
		return 0;
	}

	size_t i;
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_LOAD) {
			tmp = (ut64)bin->phdr[i].p_offset & ELF_PAGE_MASK;
			tmp = tmp - (tmp % (1 << ELF_PAGE_SIZE));
			if (tmp < base) {
				base = tmp;
			}
		}
	}
	return base == UT64_MAX? 0: base;
}

ut64 Elf_(r_bin_elf_get_init_offset)(ELFOBJ *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[128];
	if (!bin || entry == UT64_MAX) {
		return UT64_MAX;
	}
	if (r_buf_read_at (bin->b, entry + 16, buf, sizeof (buf)) < 1) {
		bprintf ("read (init_offset)\n");
		return 0;
	}
	if (buf[0] == 0x68) { // push // x86 only
		ut64 addr;
		memmove (buf, buf + 1, 4);
		addr = (ut64)r_read_le32 (buf);
		return Elf_(r_bin_elf_v2p) (bin, addr);
	}
	return 0;
}

ut64 Elf_(r_bin_elf_get_fini_offset)(ELFOBJ *bin) {
	r_return_val_if_fail (bin, UT64_MAX);
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	if (entry == UT64_MAX) {
		return UT64_MAX;
	}
	ut8 buf[512];
	if (r_buf_read_at (bin->b, entry + 11, buf, sizeof (buf)) == -1) {
		bprintf ("read (get_fini)\n");
		return 0;
	}
	if (*buf == 0x68) { // push // x86/32 only
		memmove (buf, buf + 1, 4);
		ut64 addr = (ut64)r_read_le32 (buf);
		return Elf_(r_bin_elf_v2p) (bin, addr);
	}
	return 0;
}

ut64 Elf_(r_bin_elf_get_entry_offset)(ELFOBJ *bin) {
	r_return_val_if_fail (bin, UT64_MAX);
	ut64 entry = bin->ehdr.e_entry;
	if (!entry) {
		if (!Elf_(r_bin_elf_is_executable) (bin)) {
			return UT64_MAX;
		}
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".init.text");
		if (entry != UT64_MAX) {
			return entry;
		}
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".text");
		if (entry != UT64_MAX) {
			return entry;
		}
		return Elf_(r_bin_elf_get_section_offset)(bin, ".init");
	}
	return Elf_(r_bin_elf_v2p) (bin, entry);
}

static ut64 getmainsymbol(ELFOBJ *bin) {
	struct r_bin_elf_symbol_t *symbol = Elf_(r_bin_elf_get_symbols) (bin);
	if (symbol) {
		size_t i;
		for (i = 0; !symbol[i].last; i++) {
			if (!strcmp (symbol[i].name, "main")) {
				return symbol[i].offset;
			}
		}
	}
	return UT64_MAX;
}

ut64 Elf_(r_bin_elf_get_main_offset)(ELFOBJ *bin) {
	r_return_val_if_fail (bin, UT64_MAX);
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	if (entry == UT64_MAX) {
		return UT64_MAX;
	}
	ut8 buf[256];
	if (entry > bin->size || (entry + sizeof (buf)) > bin->size) {
		return UT64_MAX;
	}
	// unnecessary to read 512 bytes imho
	if (r_buf_read_at (bin->b, entry, buf, sizeof (buf)) < 1) {
		bprintf ("read (main)\n");
		return UT64_MAX;
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

	// ARM Glibc
	if (entry & 1) {
		int delta = 0;
		/* thumb entry points */
		if (!memcmp (buf, "\xf0\x00\x0b\x4f\xf0\x00\x0e\x02\xbc\x6a\x46", 11)) {
			/* newer versions of gcc use push/pop */
			delta = 0x28;
		} else if (!memcmp (buf, "\xf0\x00\x0b\x4f\xf0\x00\x0e\x5d\xf8\x04\x1b", 11)) {
			/* older versions of gcc (4.5.x) use ldr/str */
			delta = 0x30;
		}
		if (delta) {
			ut64 pa = Elf_(r_bin_elf_v2p) (bin, r_read_le32 (&buf[delta-1]) & ~1);
			if (pa < r_buf_size (bin->b)) {
				return pa;
			}
		}
	} else {
		/* non-thumb entry points */
		if (!memcmp (buf, "\x00\xb0\xa0\xe3\x00\xe0\xa0\xe3", 8)) {
			return Elf_(r_bin_elf_v2p) (bin, r_read_le32 (&buf[0x34]) & ~1);
		}
		if (!memcmp (buf, "\x24\xc0\x9f\xe5\x00\xb0\xa0\xe3", 8)) {
			return Elf_(r_bin_elf_v2p) (bin, r_read_le32 (&buf[0x30]) & ~1);
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
			size_t i, len = sizeof (buf) / sizeof (buf[0]);
			for (i = 0; i < len; i += 4) {
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
				bprintf ("read (maddr) 2\n");
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
	int bo = 29; // Begin offset may vary depending on the entry prelude
	// endbr64 - fedora bins have this
	if (buf[0] == 0xf3 && buf[1] == 0x0f && buf[2] == 0x1e && buf[3] == 0xfa) {
		// Change begin offset if binary starts with 'endbr64'
		bo = 33;
	}
	if (buf[bo] == 0x48) {
		ut8 ch = buf[bo + 1];
		if (ch == 0x8d) { // lea rdi, qword [rip-0x21c4]
			ut8 *p = buf + bo + 3;
			st32 maindelta = (st32)r_read_le32 (p);
			ut64 vmain = (ut64)(entry + bo + maindelta) + 7;
			ut64 ventry = Elf_(r_bin_elf_p2v) (bin, entry);
			if (vmain>>16 == ventry>>16) {
				return (ut64)vmain;
			}
		} else if (0xc7) { // mov rdi, 0xADDR
			ut8 *p = buf + bo + 3;
			return (ut64)(ut32)r_read_le32 (p);
		}
	}

	/* find sym.main if possible */
	{
		ut64 m = getmainsymbol (bin);
		if (m != UT64_MAX) {
			return m;
		}
	}
	return UT64_MAX;
}

bool Elf_(r_bin_elf_get_stripped)(ELFOBJ *bin) {
	if (!bin->shdr) {
		return false;
	}
	size_t i;
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
			ut64 addr = bin->phdr[i].p_offset;
			int sz = bin->phdr[i].p_filesz;
			sdb_num_set (bin->kv, "elf_header.intrp_addr", addr, 0);
			sdb_num_set (bin->kv, "elf_header.intrp_size", sz, 0);
			if (sz < 1 || sz > r_buf_size (bin->b)) {
				return NULL;
			}
			char *str = malloc (sz + 1);
			if (!str) {
				return NULL;
			}
			if (r_buf_read_at (bin->b, addr, (ut8*)str, sz) < 1) {
				bprintf ("read (main)\n");
				free (str);
				return 0;
			}
			str[sz] = 0;
			sdb_set (bin->kv, "elf_header.intrp", str, 0);
			return str;
		}
	}
	return NULL;
}

bool Elf_(r_bin_elf_is_static)(ELFOBJ *bin) {
	size_t i;
	if (!bin->phdr) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_INTERP ||
			bin->phdr[i].p_type == PT_DYNAMIC) {
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
	case EM_BA2_NON_STANDARD:
	case EM_BA2: return strdup ("ba2");
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
	case EM_RCE:
		return strdup ("mcore");
	case EM_ARM:
	case EM_AARCH64:
		return strdup ("arm");
	case EM_QDSP6: // EM_HEXAGON
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
	case EM_MSP430:
		return strdup ("msp430");
	case EM_SH:
		return strdup ("sh");
	case EM_V800:
		return strdup ("v850");
	case EM_V850:
		return strdup ("v850");
	case EM_IA_64:
		return strdup("ia64");
	default: return strdup ("x86");
	}
}
char* Elf_(r_bin_elf_get_abi)(ELFOBJ *bin) {
	Elf_(Ehdr)* ehdr = (Elf_(Ehdr) *) &bin->ehdr;

	if (ehdr->e_machine == EM_MIPS) {
		if (is_elfclass64 (ehdr)) {
			return strdup ("n64");
		}
		if (is_mips_n32 (ehdr)) {
			return strdup ("n32");
		}
		if (is_mips_o32 (ehdr)) {
			return strdup ("o32");
		}
	}
	return NULL;
}

char* Elf_(r_bin_elf_get_cpu)(ELFOBJ *bin) {
	if (bin->phdr && bin->ehdr.e_machine == EM_MIPS) {
		const ut32 mipsType = bin->ehdr.e_flags & EF_MIPS_ARCH;
		switch (mipsType) {
		case EF_MIPS_ARCH_1:        return strdup ("mips1");
		case EF_MIPS_ARCH_2:        return strdup ("mips2");
		case EF_MIPS_ARCH_3:        return strdup ("mips3");
		case EF_MIPS_ARCH_4:        return strdup ("mips4");
		case EF_MIPS_ARCH_5:        return strdup ("mips5");
		case EF_MIPS_ARCH_32:       return strdup ("mips32");
		case EF_MIPS_ARCH_64:       return strdup ("mips64");
		case EF_MIPS_ARCH_32R2:     return strdup ("mips32r2");
		case EF_MIPS_ARCH_64R2:     return strdup ("mips64r2");
		default :                   return strdup (" Unknown mips ISA");
		}
	}
	return NULL;
}

char* Elf_(r_bin_elf_get_head_flag)(ELFOBJ *bin) {
	char *head_flag = NULL;
	char *str = Elf_(r_bin_elf_get_cpu) (bin);
	if (str) {
		head_flag = r_str_append (head_flag, str);
	}
	str = Elf_(r_bin_elf_get_abi) (bin);
	if (str) {
		head_flag = r_str_appendf (head_flag, " %s", str);
	}
	if (R_STR_ISEMPTY (head_flag)) {
		head_flag = r_str_append (head_flag, "unknown_flag");
	}
	return head_flag;
}

// http://www.sco.com/developers/gabi/latest/ch4.eheader.html

char* Elf_(r_bin_elf_get_machine_name)(ELFOBJ *bin) {
	switch (bin->ehdr.e_machine) {
	case EM_NONE:          return strdup ("No machine");
	case EM_M32:           return strdup ("AT&T WE 32100");
	case EM_SPARC:         return strdup ("SUN SPARC");
	case EM_386:           return strdup ("Intel 80386");
	case EM_68K:           return strdup ("Motorola m68k family");
	case EM_88K:           return strdup ("Motorola m88k family");
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

	default:             return r_str_newf ("<unknown>: 0x%x", bin->ehdr.e_machine);
	}
}

char* Elf_(r_bin_elf_get_file_type)(ELFOBJ *bin) {
	r_return_val_if_fail (bin, NULL);
	ut32 e_type = (ut32)bin->ehdr.e_type; // cast to avoid warn in iphone-gcc, must be ut16
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
		ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
		if (entry & 1) {
			return 16;
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
	if (r_buf_size (bin->b) <= 64)  {
		return 0;
	}
	ut8 tmp[64];
	r_buf_read_at (bin->b, r_buf_size (bin->b) - 64, tmp, 64);
	return r_mem_mem (tmp, 64, (const ut8 *)s, strlen (s)) != NULL;
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
	size_t i;
	size_t num = bin->ehdr.e_shnum;
	const char *section_name = NULL;
	switch (bin->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_LINUX: return strdup("linux");
	case ELFOSABI_SOLARIS: return strdup("solaris");
	case ELFOSABI_FREEBSD: return strdup("freebsd");
	case ELFOSABI_HPUX: return strdup("hpux");
	}

	if (bin->shdr && bin->shstrtab) {
		for (i = 0; i < num; i++) {
			if (bin->shdr[i].sh_type == SHT_NOTE && bin->shdr[i].sh_name < bin->shstrtab_size) {
				section_name = &bin->shstrtab[bin->shdr[i].sh_name];
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
	/* Hack to identify OS */
	if (needle (bin, "freebsd")) {
		return strdup ("freebsd");
	}
	if (noodle (bin, "BEOS:APP_VERSION")) {
		return strdup ("beos");
	}
	if (needle (bin, "GNU")) {
		return strdup ("linux");
	}
	return strdup ("linux");
}

ut8 *Elf_(r_bin_elf_grab_regstate)(ELFOBJ *bin, int *len) {
	if (bin->phdr) {
		size_t i;
		int num = bin->ehdr.e_phnum;
		for (i = 0; i < num; i++) {
			if (bin->phdr[i].p_type != PT_NOTE) {
				continue;
			}
			int bits = Elf_(r_bin_elf_get_bits)(bin);
			int elf_nhdr_size = (bits == 64) ? sizeof (Elf64_Nhdr) : sizeof (Elf32_Nhdr);
			void *elf_nhdr = calloc (elf_nhdr_size, 1);
			bool regs_found = false;
			ut64 offset = 0;

			while (!regs_found) {
				ut32 n_descsz, n_namesz, n_type;
				int ret;
				ret = r_buf_read_at (bin->b, bin->phdr[i].p_offset + offset, elf_nhdr, elf_nhdr_size);
				if (ret != elf_nhdr_size) {
					bprintf ("Cannot read NOTES hdr from CORE file\n");
					free (elf_nhdr);
					return NULL;
				}
				if (bits == 64) {
					n_descsz = round_up (((Elf64_Nhdr *)elf_nhdr)->n_descsz);
					n_namesz = round_up (((Elf64_Nhdr *)elf_nhdr)->n_namesz);
					n_type = ((Elf64_Nhdr *)elf_nhdr)->n_type;
				} else {
					n_descsz = round_up (((Elf32_Nhdr *)elf_nhdr)->n_descsz);
					n_namesz = round_up (((Elf32_Nhdr *)elf_nhdr)->n_namesz);
					n_type = ((Elf32_Nhdr *)elf_nhdr)->n_type;
				}
				if (n_type == NT_PRSTATUS) {
					regs_found = true;
					free (elf_nhdr);
				} else {
					offset += elf_nhdr_size + n_descsz + n_namesz;
				}
			}

			int regdelta = 0;
			int regsize = 0;
			switch (bin->ehdr.e_machine) {
				case EM_AARCH64:
					regsize = reginf[AARCH64].regsize;
					regdelta = reginf[AARCH64].regdelta;
					break;
				case EM_ARM:
					regsize = reginf[ARM].regsize;
					regdelta = reginf[ARM].regdelta;
					break;
				case EM_386:
					regsize = reginf[X86].regsize;
					regdelta = reginf[X86].regdelta;
					break;
				case EM_X86_64:
					regsize = reginf[X86_64].regsize;
					regdelta = reginf[X86_64].regdelta;
					break;
			}
			ut8 *buf = malloc (regsize);
			if (r_buf_read_at (bin->b, bin->phdr[i].p_offset + offset + regdelta, buf, regsize) != regsize) {
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
	r_return_val_if_fail (bin, NULL);
	char *ret;
	Elf_(Xword) val;

	if (!bin->phdr || !bin->strtab) {
		return NULL;
	}

	if (bin->dyn_info.dt_rpath != R_BIN_ELF_XWORD_MAX)  {
		val = bin->dyn_info.dt_rpath;
	} else if (bin->dyn_info.dt_runpath != R_BIN_ELF_XWORD_MAX) {
		val = bin->dyn_info.dt_runpath;
	} else {
		return NULL;
	}

	if (val > bin->strtab_size) {
		return NULL;
	}

	if (!(ret = calloc (1, ELF_STRING_LENGTH))) {
		return NULL;
	}

	r_str_ncpy (ret, bin->strtab + val, ELF_STRING_LENGTH);

	return ret;
}

static bool has_valid_section_header(ELFOBJ *bin, size_t pos) {
	return bin->g_sections[pos].info < bin->ehdr.e_shnum && bin->shdr;
}

static void fix_rva_and_offset_relocable_file(ELFOBJ *bin, RBinElfReloc *r, size_t pos) {
	if (has_valid_section_header (bin, pos)) {
		r->rva = bin->shdr[bin->g_sections[pos].info].sh_offset + r->offset;
		r->rva = Elf_(r_bin_elf_p2v) (bin, r->rva);
	} else {
		r->rva = r->offset;
	}
}

static void fix_rva_and_offset_exec_file(ELFOBJ *bin, RBinElfReloc *r) {
	r->rva = r->offset;
	r->offset = Elf_(r_bin_elf_v2p) (bin, r->offset);
}

static void fix_rva_and_offset(ELFOBJ *bin, RBinElfReloc *r, size_t pos) {
	if (is_bin_etrel (bin)) {
		fix_rva_and_offset_relocable_file (bin, r, pos);
	} else {
		fix_rva_and_offset_exec_file (bin, r);
	}
}

static bool read_reloc(ELFOBJ *bin, RBinElfReloc *r, Elf_(Xword) rel_mode, ut64 vaddr) {
	ut64 offset = Elf_(r_bin_elf_v2p_new) (bin, vaddr);
	if (offset == UT64_MAX) {
		return false;
	}

	size_t size_struct = get_size_rel_mode (rel_mode);

	ut8 buf[sizeof (Elf_(Rela))] = { 0 };
	int res = r_buf_read_at (bin->b, offset, buf, size_struct);
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

	r->rel_mode = rel_mode;
	r->last = 0;
	r->offset = reloc_info.r_offset;
	r->sym = ELF_R_SYM (reloc_info.r_info);
	r->type = ELF_R_TYPE (reloc_info.r_info);

	return true;
}

static size_t get_num_relocs_dynamic(ELFOBJ *bin) {
	size_t res = 0;

	if (bin->dyn_info.dt_relaent) {
		res += bin->dyn_info.dt_relasz / bin->dyn_info.dt_relaent;
	}

	if (bin->dyn_info.dt_relent) {
		res += bin->dyn_info.dt_relsz / bin->dyn_info.dt_relent;
	}

	return res + get_num_relocs_dynamic_plt (bin);
}

static bool sectionIsValid(ELFOBJ *bin, RBinElfSection *sect) {
	return (sect->offset + sect->size <= bin->size);
}

static Elf_(Xword) get_section_mode(ELFOBJ *bin, size_t pos) {
	if (r_str_startswith (bin->g_sections[pos].name, ".rela.")) {
		return DT_RELA;
	}
	if (r_str_startswith (bin->g_sections[pos].name, ".rel.")) {
		return DT_REL;
	}
	return 0;
}

static bool is_reloc_section(Elf_(Xword) rel_mode) {
	return rel_mode == DT_REL || rel_mode == DT_RELA;
}

static size_t get_num_relocs_sections(ELFOBJ *bin) {
	size_t i, size, ret = 0;
	Elf_(Xword) rel_mode;

	if (!bin->g_sections) {
		return 0;
	}

	for (i = 0; !bin->g_sections[i].last; i++) {
		if (!sectionIsValid (bin, &bin->g_sections[i])) {
			continue;
		}
		rel_mode = get_section_mode (bin, i);
		if (!is_reloc_section (rel_mode)) {
			continue;
		}
		size = get_size_rel_mode (rel_mode);
		ret += NUMENTRIES_ROUNDUP (bin->g_sections[i].size, size);
	}

	return ret;
}

static size_t get_num_relocs_approx(ELFOBJ *bin) {
	return get_num_relocs_dynamic (bin) + get_num_relocs_sections (bin);
}

static size_t populate_relocs_record_from_dynamic(ELFOBJ *bin, RBinElfReloc *relocs, size_t pos, size_t num_relocs) {
	size_t offset;
	size_t size = get_size_rel_mode (bin->dyn_info.dt_pltrel);

	for (offset = 0; offset < bin->dyn_info.dt_pltrelsz && pos < num_relocs; offset += size, pos++) {
		if (!read_reloc (bin, relocs + pos, bin->dyn_info.dt_pltrel, bin->dyn_info.dt_jmprel + offset)) {
			break;
		}
		fix_rva_and_offset_exec_file (bin, relocs + pos);
	}

	for (offset = 0; offset < bin->dyn_info.dt_relasz && pos < num_relocs; offset += bin->dyn_info.dt_relaent, pos++) {
		if (!read_reloc (bin, relocs + pos, DT_RELA, bin->dyn_info.dt_rela + offset)) {
			break;
		}
		fix_rva_and_offset_exec_file (bin, relocs + pos);
	}

	for (offset = 0; offset < bin->dyn_info.dt_relsz && pos < num_relocs; offset += bin->dyn_info.dt_relent, pos++) {
		if (!read_reloc (bin, relocs + pos, DT_REL, bin->dyn_info.dt_rel + offset)) {
			break;
		}
		fix_rva_and_offset_exec_file (bin, relocs + pos);
	}

	return pos;
}

static size_t get_next_not_analysed_offset(ELFOBJ *bin, size_t section_vaddr, size_t offset) {
	size_t gvaddr = section_vaddr + offset;

	if (bin->dyn_info.dt_rela != R_BIN_ELF_ADDR_MAX && bin->dyn_info.dt_rela <= gvaddr
		&& gvaddr < bin->dyn_info.dt_rela + bin->dyn_info.dt_relasz) {
		return bin->dyn_info.dt_rela + bin->dyn_info.dt_relasz - section_vaddr;
	}

	if (bin->dyn_info.dt_rel != R_BIN_ELF_ADDR_MAX && bin->dyn_info.dt_rel <= gvaddr
		&& gvaddr < bin->dyn_info.dt_rel + bin->dyn_info.dt_relsz) {
		return bin->dyn_info.dt_rel + bin->dyn_info.dt_relsz - section_vaddr;
	}

	if (bin->dyn_info.dt_jmprel != R_BIN_ELF_ADDR_MAX && bin->dyn_info.dt_jmprel <= gvaddr
		&& gvaddr < bin->dyn_info.dt_jmprel + bin->dyn_info.dt_pltrelsz) {
		return bin->dyn_info.dt_jmprel + bin->dyn_info.dt_pltrelsz - section_vaddr;
	}

	return offset;
}

static size_t populate_relocs_record_from_section(ELFOBJ *bin, RBinElfReloc *relocs, size_t pos, size_t num_relocs) {
	size_t size, i, j;
	Elf_(Xword) rel_mode;

	if (!bin->g_sections) {
		return pos;
	}

	for (i = 0; !bin->g_sections[i].last; i++) {
		rel_mode = get_section_mode (bin, i);

		if (!is_reloc_section (rel_mode) || bin->g_sections[i].size > bin->size || bin->g_sections[i].offset > bin->size) {
			continue;
		}

		size = get_size_rel_mode (rel_mode);

		for (j = get_next_not_analysed_offset (bin, bin->g_sections[i].rva, 0);
			j < bin->g_sections[i].size && pos < num_relocs;
			j = get_next_not_analysed_offset (bin, bin->g_sections[i].rva, j + size)) {

			if (!read_reloc (bin, relocs + pos, rel_mode, bin->g_sections[i].rva + j)) {
				break;
			}

			fix_rva_and_offset (bin, relocs + pos, i);
			pos++;
		}
	}

	return pos;
}

static RBinElfReloc *populate_relocs_record(ELFOBJ *bin) {
	size_t i = 0;
	size_t num_relocs = get_num_relocs_approx (bin);
	RBinElfReloc *relocs = R_NEWS0 (RBinElfReloc, num_relocs + 1);
	if (!relocs) {
		// In case we can't allocate enough memory for all the claimed
		// relocation entries, try to parse only the ones specified in
		// the dynamic segment.
		num_relocs = get_num_relocs_dynamic (bin);
		relocs = R_NEWS0 (RBinElfReloc, num_relocs + 1);
		if (!relocs) {
			return NULL;
		}
	}

	i = populate_relocs_record_from_dynamic (bin, relocs, i, num_relocs);
	i = populate_relocs_record_from_section (bin, relocs, i, num_relocs);
	relocs[i].last = 1;

	bin->g_reloc_num = i;
	return relocs;
}

RBinElfReloc* Elf_(r_bin_elf_get_relocs) (ELFOBJ *bin) {
	if (!bin) {
		return NULL;
	}

	if (!bin->g_relocs) {
		bin->g_relocs = populate_relocs_record (bin);
	}
	return bin->g_relocs;
}

RBinElfLib* Elf_(r_bin_elf_get_libs)(ELFOBJ *bin) {
	RBinElfLib *ret = NULL;
	Elf_(Off) *it = NULL;
	size_t k = 0;

	if (!bin || !bin->phdr || !bin->strtab || *(bin->strtab+1) == '0') {
		return NULL;
	}

	r_vector_foreach(&bin->dyn_info.dt_needed, it) {
		Elf_(Off) val = *it;

		RBinElfLib *r = realloc (ret, (k + 1) * sizeof (RBinElfLib));
		if (!r) {
			perror ("realloc (libs)");
			free (ret);
			return NULL;
		}
		ret = r;
		if (val > bin->strtab_size) {
			free (ret);
			return NULL;
		}
		strncpy (ret[k].name, bin->strtab + val, ELF_STRING_LENGTH);
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

static void create_section_from_phdr(ELFOBJ *bin, RBinElfSection *ret, size_t *i, const char *name, ut64 addr, ut64 sz) {
	if (!addr) {
		return;
	}

	ret[*i].offset = Elf_(r_bin_elf_v2p_new) (bin, addr);
	ret[*i].rva = addr;
	ret[*i].size = sz;
	strncpy (ret[*i].name, name, R_ARRAY_SIZE (ret[*i].name) - 1);
	ret[*i].name[R_ARRAY_SIZE (ret[*i].name) - 1] = '\0';
	ret[*i].last = 0;
	*i = *i + 1;
}

static RBinElfSection *get_sections_from_phdr(ELFOBJ *bin) {
	RBinElfSection *ret;
	size_t num_sections = 0;
	ut64 reldyn = 0, relava = 0, pltgotva = 0, relva = 0;
	ut64 reldynsz = 0, relasz = 0, pltgotsz = 0;
	r_return_val_if_fail (bin && bin->phdr, NULL);

	if (!bin->ehdr.e_phnum) {
		return NULL;
	}

	if (bin->dyn_info.dt_rel != R_BIN_ELF_ADDR_MAX) {
		reldyn = bin->dyn_info.dt_rel;
		num_sections++;
	}
	if (bin->dyn_info.dt_rela != R_BIN_ELF_ADDR_MAX) {
		relva = bin->dyn_info.dt_rela;
		num_sections++;
	}
	if (bin->dyn_info.dt_relsz) {
		reldynsz = bin->dyn_info.dt_relsz;
	}
	if (bin->dyn_info.dt_relasz) {
		relasz = bin->dyn_info.dt_relasz;
	}
	if (bin->dyn_info.dt_pltgot != R_BIN_ELF_ADDR_MAX) {
		pltgotva = bin->dyn_info.dt_pltgot;
		num_sections++;
	}
	if (bin->dyn_info.dt_pltrelsz) {
		pltgotsz = bin->dyn_info.dt_pltrelsz;
	}
	if (bin->dyn_info.dt_jmprel != R_BIN_ELF_ADDR_MAX) {
		relava = bin->dyn_info.dt_jmprel;
		num_sections++;
	}

	ret = calloc (num_sections + 1, sizeof (RBinElfSection));
	if (!ret) {
		return NULL;
	}

	size_t i = 0;
	create_section_from_phdr (bin, ret, &i, ".rel.dyn", reldyn, reldynsz);
	create_section_from_phdr (bin, ret, &i, ".rela.plt", relava, pltgotsz);
	create_section_from_phdr (bin, ret, &i, ".rel.plt", relva, relasz);
	create_section_from_phdr (bin, ret, &i, ".got.plt", pltgotva, pltgotsz);
	ret[i].last = 1;

	return ret;
}

RBinElfSection* Elf_(r_bin_elf_get_sections)(ELFOBJ *bin) {
	RBinElfSection *ret = NULL;
	char unknown_s[32], invalid_s[32];
	int i, nidx, unknown_c=0, invalid_c=0;

	r_return_val_if_fail (bin, NULL);
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
		if (is_bin_etrel (bin)) {
			ret[i].rva = bin->baddr + bin->shdr[i].sh_offset;
		} else {
			ret[i].rva = bin->shdr[i].sh_addr;
		}

		const int SHNAME = (int)bin->shdr[i].sh_name;
		const int SHSIZE = (int)bin->shstrtab_size;
		nidx = SHNAME;
		if (nidx < 0 || !bin->shstrtab_section || !bin->shstrtab_size || nidx > bin->shstrtab_size) {
			snprintf (invalid_s, sizeof (invalid_s), "invalid%d", invalid_c);
			strncpy (ret[i].name, invalid_s, sizeof (ret[i].name) - 1);
			invalid_c++;
		} else if (bin->shstrtab && (SHNAME > 0) && (SHNAME < SHSIZE)) {
			strncpy (ret[i].name, &bin->shstrtab[SHNAME], sizeof (ret[i].name) - 1);
		} else if (bin->shdr[i].sh_type == SHT_NULL) {
			//to follow the same behaviour as readelf
			ret[i].name[0] = '\0';
		} else {
			snprintf (unknown_s, sizeof (unknown_s), "unknown%d", unknown_c);
			strncpy (ret[i].name, unknown_s, sizeof (ret[i].name) - 1);
			unknown_c++;
		}
		ret[i].name[ELF_STRING_LENGTH - 1] = '\0';
		ret[i].last = 0;
	}
	ret[i].last = 1;
	return ret;
}

static bool is_special_arm_symbol(ELFOBJ *bin, Elf_(Sym) *sym, const char *name) {
	if (name[0] != '$') {
		return false;
	}
	switch (name[1]) {
	case 'a':
	case 't':
	case 'd':
	case 'x':
		return (name[2] == '\0' || name[2] == '.') &&
			ELF_ST_TYPE (sym->st_info) == STT_NOTYPE &&
			ELF_ST_BIND (sym->st_info) == STB_LOCAL &&
			ELF_ST_VISIBILITY (sym->st_info) == STV_DEFAULT;
	default:
		return false;
	}
}

static bool is_special_symbol(ELFOBJ *bin, Elf_(Sym) *sym, const char *name) {
	switch (bin->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
		return is_special_arm_symbol (bin, sym, name);
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

static const char *type2str(ELFOBJ *bin, struct r_bin_elf_symbol_t *ret, Elf_(Sym) *sym) {
	if (bin && ret && is_special_symbol (bin, sym, ret->name)) {
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

static void fill_symbol_bind_and_type(ELFOBJ *bin, struct r_bin_elf_symbol_t *ret, Elf_(Sym) *sym) {
	ret->bind = bind2str (sym);
	ret->type = type2str (bin, ret, sym);
}

static RBinElfSymbol* get_symbols_from_phdr(ELFOBJ *bin, int type) {
	Elf_(Sym) *sym = NULL;
	Elf_(Addr) addr_sym_table = 0;
	ut8 s[sizeof (Elf_(Sym))] = {0};
	RBinElfSymbol *ret = NULL;
	int i, r, tsize, nsym, ret_ctr;
	ut64 toffset = 0, tmp_offset;
	ut32 size, sym_size = 0;

	if (!bin || !bin->phdr || !bin->ehdr.e_phnum) {
		return NULL;
	}

	if (bin->dyn_info.dt_symtab == R_BIN_ELF_ADDR_MAX || !bin->dyn_info.dt_syment) {
		return NULL;
	}

	addr_sym_table = Elf_(r_bin_elf_v2p) (bin, bin->dyn_info.dt_symtab);
	sym_size = bin->dyn_info.dt_syment;
	if (!sym_size) {
		goto beach;
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
			Elf_(Sym)* temp_sym = (Elf_(Sym)*) realloc (sym, (capacity1 * GROWTH_FACTOR) * sym_size);
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
		bool is_sht_null = false;
		bool is_vaddr = false;
		// zero symbol is always empty
		// Examine entry and maybe store
		if (type == R_BIN_ELF_IMPORT_SYMBOLS && sym[i].st_shndx == SHT_NULL) {
			if (sym[i].st_value) {
				toffset = sym[i].st_value;
			} else if ((toffset = get_import_addr (bin, i)) == -1){
				toffset = 0;
			}
			tsize = 16;
		} else if (type == R_BIN_ELF_ALL_SYMBOLS) {
			tsize = sym[i].st_size;
			toffset = (ut64) sym[i].st_value;
			is_sht_null = sym[i].st_shndx == SHT_NULL;
		} else {
			continue;
		}
		// since we don't know the size of the sym table in this case,
		// let's stop at the first invalid entry
		if (!strcmp (bind2str (&sym[i]), R_BIN_BIND_UNKNOWN_STR) ||
		    !strcmp (type2str (NULL, NULL, &sym[i]), R_BIN_TYPE_UNKNOWN_STR)) {
			goto done;
		}
		tmp_offset = Elf_(r_bin_elf_v2p_new) (bin, toffset);
		if (tmp_offset == UT64_MAX) {
			tmp_offset = toffset;
			is_vaddr = true;
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
		fill_symbol_bind_and_type (bin, &ret[ret_ctr], &sym[i]);
		ret[ret_ctr].is_sht_null = is_sht_null;
		ret[ret_ctr].is_vaddr = is_vaddr;
		ret[ret_ctr].last = 0;
		ret_ctr++;
	}
done:
	// Size everything down to only what is used
	{
		nsym = i > 0? i: 1;
		Elf_(Sym) *temp_sym = (Elf_(Sym) *)realloc (sym, (nsym * GROWTH_FACTOR) * sym_size);
		if (!temp_sym) {
			goto beach;
		}
		sym = temp_sym;
	}
	{
		ret_ctr = ret_ctr > 0? ret_ctr: 1;
		RBinElfSymbol *p = (RBinElfSymbol *)realloc (ret, (ret_ctr + 1) * sizeof (RBinElfSymbol));
		if (!p) {
			goto beach;
		}
		ret = p;
	}
	ret[ret_ctr].last = 1;
	if (type == R_BIN_ELF_IMPORT_SYMBOLS && !bin->imports_by_ord_size) {
		bin->imports_by_ord_size = ret_ctr + 1;
		if (ret_ctr > 0) {
			bin->imports_by_ord = (RBinImport * *) calloc (ret_ctr + 1, sizeof (RBinImport*));
		} else {
			bin->imports_by_ord = NULL;
		}
	} else if (type == R_BIN_ELF_ALL_SYMBOLS && !bin->symbols_by_ord_size && ret_ctr) {
		bin->symbols_by_ord_size = ret_ctr + 1;
		if (ret_ctr > 0) {
			bin->symbols_by_ord = (RBinSymbol * *) calloc (ret_ctr + 1, sizeof (RBinSymbol*));
		} else {
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
	bin->phdr_symbols = get_symbols_from_phdr (bin, R_BIN_ELF_ALL_SYMBOLS);
	return bin->phdr_symbols;
}

static RBinElfSymbol *Elf_(r_bin_elf_get_phdr_imports)(ELFOBJ *bin) {
	r_return_val_if_fail (bin, NULL);
	if (!bin->phdr_imports) {
		bin->phdr_imports = get_symbols_from_phdr (bin, R_BIN_ELF_IMPORT_SYMBOLS);
	}
	return bin->phdr_imports;
}

static RBinElfSymbol *Elf_(get_phdr_symbols)(ELFOBJ *bin, int type) {
	return (type != R_BIN_ELF_IMPORT_SYMBOLS)
		? Elf_(r_bin_elf_get_phdr_symbols) (bin)
		: Elf_(r_bin_elf_get_phdr_imports) (bin);
}

static int Elf_(fix_symbols)(ELFOBJ *bin, int nsym, int type, RBinElfSymbol **sym) {
	int count = 0;
	int result = -1;
	RBinElfSymbol *ret = *sym;
	RBinElfSymbol *phdr_symbols = Elf_(get_phdr_symbols) (bin, type);
	RBinElfSymbol *tmp, *p;
	HtUP *phd_offset_map = ht_up_new0 ();
	HtUP *phd_ordinal_map = ht_up_new0 ();
	if (phdr_symbols) {
		RBinElfSymbol *d = ret;
		while (!d->last) {
			ht_up_insert (phd_offset_map, d->offset, d);
			ht_up_insert (phd_ordinal_map, d->ordinal, d);
			d++;
		}
		p = phdr_symbols;
		while (!p->last) {
			/* find match in phdr */
			d = ht_up_find (phd_offset_map, p->offset, NULL);
			if (!d) {
				d = ht_up_find (phd_ordinal_map, p->ordinal, NULL);
			}
			if (d) {
				p->in_shdr = true;
				if (*p->name && *d->name && r_str_startswith (d->name, "$")) {
					strcpy (d->name, p->name);
				}
			}
			p++;
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
				result = -1;
				goto done;
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
		result = nsym + 1;
		goto done;
	}
	result = nsym;
done:
	ht_up_free (phd_offset_map);
	ht_up_free (phd_ordinal_map);
	return result;
}

static bool is_section_local_sym(ELFOBJ *bin, Elf_(Sym) *sym) {
	if (sym->st_name != 0) {
		return false;
	}
	if (ELF_ST_TYPE (sym->st_info) != STT_SECTION) {
		return false;
	}
	if (ELF_ST_BIND (sym->st_info) != STB_LOCAL) {
		return false;
	}
	if (!is_shidx_valid (bin, sym->st_shndx)) {
		return false;
	}
	Elf_(Word) sh_name = bin->shdr[sym->st_shndx].sh_name;
	return bin->shstrtab && sh_name < bin->shstrtab_size;
}

static void setsymord(ELFOBJ* eobj, ut32 ord, RBinSymbol *ptr) {
	if (!eobj->symbols_by_ord || ord >= eobj->symbols_by_ord_size) {
		return;
	}
	r_bin_symbol_free (eobj->symbols_by_ord[ord]);
	eobj->symbols_by_ord[ord] = ptr;
}

static void _set_arm_thumb_bits(struct Elf_(r_bin_elf_obj_t) *bin, RBinSymbol **sym) {
	int bin_bits = Elf_(r_bin_elf_get_bits) (bin);
	RBinSymbol *ptr = *sym;
	int len = strlen (ptr->name);
	if (ptr->name[0] == '$' && (len >= 2 && !ptr->name[2])) {
		switch (ptr->name[1]) {
		case 'a' : //arm
			ptr->bits = 32;
			break;
		case 't': //thumb
			ptr->bits = 16;
			if (ptr->vaddr & 1) {
				ptr->vaddr--;
			}
			if (ptr->paddr & 1) {
				ptr->paddr--;
			}
			break;
		case 'd': //data
			break;
		default:
			goto arm_symbol;
		}
	} else {
arm_symbol:
		ptr->bits = bin_bits;
		if (bin_bits != 64) {
			ptr->bits = 32;
			if (ptr->paddr != UT64_MAX) {
				if (ptr->vaddr & 1) {
					ptr->vaddr--;
					ptr->bits = 16;
				}
				if (ptr->paddr & 1) {
					ptr->paddr--;
					ptr->bits = 16;
				}
			}
		}
	}
}

RBinSymbol *Elf_(_r_bin_elf_convert_symbol)(struct Elf_(r_bin_elf_obj_t) *bin,
					  struct r_bin_elf_symbol_t *symbol,
					  const char *namefmt) {
	ut64 paddr, vaddr;
	RBinSymbol *ptr = NULL;
	if (symbol->is_vaddr) {
		paddr = UT64_MAX;
		vaddr = symbol->offset;
	} else {
		paddr = symbol->offset;
		vaddr = Elf_(r_bin_elf_p2v_new) (bin, paddr);
	}

	if (!(ptr = R_NEW0 (RBinSymbol))) {
		return NULL;
	}
	ptr->name = symbol->name[0] ? r_str_newf (namefmt, &symbol->name[0]) : strdup ("");
	ptr->forwarder = "NONE";
	ptr->bind = symbol->bind;
	ptr->type = symbol->type;
	ptr->is_imported = symbol->is_imported;
	ptr->paddr = paddr;
	ptr->vaddr = vaddr;
	ptr->size = symbol->size;
	ptr->ordinal = symbol->ordinal;
	// detect thumb
	if (bin->ehdr.e_machine == EM_ARM && *ptr->name) {
		_set_arm_thumb_bits (bin, &ptr);
	}

	return ptr;
}

static ut32 hashRBinElfSymbol(const void * obj) {
	const RBinElfSymbol *symbol = (const RBinElfSymbol *)obj;
	int hash = sdb_hash (symbol->name);
	hash ^= sdb_hash (symbol->type);
	hash ^= (symbol->offset >> 32);
	hash ^= (symbol->offset & 0xffffffff);
	return hash;
}

static int cmp_RBinElfSymbol(const RBinElfSymbol *a, const RBinElfSymbol *b) {
	int result = 0;
	if (a->offset != b->offset) {
		return 1;
	}
	result = strcmp(a->name, b->name);
	if (result != 0) {
		return result;
	}
	return strcmp(a->type, b->type);
}

// TODO: return RList<RBinSymbol*> .. or run a callback with that symbol constructed, so we don't have to do it twice
static RBinElfSymbol* Elf_(_r_bin_elf_get_symbols_imports)(ELFOBJ *bin, int type) {
	ut32 shdr_size;
	int tsize, nsym, ret_ctr = 0, i, j, r, k, newsize;
	ut64 toffset;
	ut32 size = 0;
	RBinElfSymbol *ret = NULL, *import_ret = NULL;
	RBinSymbol *import_sym_ptr = NULL;
	size_t ret_size = 0, prev_ret_size = 0, import_ret_ctr = 0;
	Elf_(Shdr) *strtab_section = NULL;
	Elf_(Sym) *sym = NULL;
	ut8 s[sizeof (Elf_(Sym))] = { 0 };
	char *strtab = NULL;
	HtPP *symbol_map = NULL;
	HtPPOptions symbol_map_options = {
		.cmp = (HtPPListComparator)cmp_RBinElfSymbol,
		.hashfn = hashRBinElfSymbol,
		.dupkey = NULL,
		.calcsizeK = NULL,
		.calcsizeV = NULL,
		.freefn = NULL,
		.elem_size = sizeof (HtPPKv),
	};

	if (!bin || !bin->shdr || !bin->ehdr.e_shnum || bin->ehdr.e_shnum == 0xffff) {
		return Elf_(get_phdr_symbols) (bin, type);
	}
	if (!UT32_MUL (&shdr_size, bin->ehdr.e_shnum, sizeof (Elf_(Shdr)))) {
		return false;
	}
	if (shdr_size + 8 > bin->size) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (((type & R_BIN_ELF_SYMTAB_SYMBOLS) && bin->shdr[i].sh_type == SHT_SYMTAB) ||
			((type & R_BIN_ELF_DYNSYM_SYMBOLS) && bin->shdr[i].sh_type == SHT_DYNSYM)) {
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
					bprintf ("read (syms strtab)\n");
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
			{
				ut64 sh_begin = bin->shdr[i].sh_offset;
				ut64 sh_end = sh_begin + bin->shdr[i].sh_size;
				if (sh_begin > bin->size) {
					goto beach;
				}
				if (sh_end > bin->size) {
					st64 newshsize = bin->size - sh_begin;
					nsym = (int)(newshsize / sizeof (Elf_(Sym)));
				}
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
					bprintf ("read (sym)\n");
					goto beach;
				}
#if R_BIN_ELF64
				sym[j].st_name = READ32 (s, k);
				sym[j].st_info = READ8 (s, k);
				sym[j].st_other = READ8 (s, k);
				sym[j].st_shndx = READ16 (s, k);
				sym[j].st_value = READ64 (s, k);
				sym[j].st_size = READ64 (s, k);
#else
				sym[j].st_name = READ32 (s, k);
				sym[j].st_value = READ32 (s, k);
				sym[j].st_size = READ32 (s, k);
				sym[j].st_info = READ8 (s, k);
				sym[j].st_other = READ8 (s, k);
				sym[j].st_shndx = READ16 (s, k);
#endif
			}
			ret = realloc (ret, (ret_size + nsym) * sizeof (RBinElfSymbol));
			if (!ret) {
				bprintf ("Cannot allocate %d symbols\n", nsym);
				goto beach;
			}
			memset (ret + ret_size, 0, nsym * sizeof (RBinElfSymbol));
			prev_ret_size = ret_size;
			ret_size += nsym;
			symbol_map = ht_pp_new_opt (&symbol_map_options);
			for (k = 0; k < prev_ret_size; k++) {
				if (ret[k].name[0]) {
					ht_pp_insert (symbol_map, ret + k, ret + k);
				}
			}
			for (k = 1; k < nsym; k++) {
				bool is_sht_null = false;
				bool is_vaddr = false;
				bool is_imported = false;
				if (type == R_BIN_ELF_IMPORT_SYMBOLS) {
					if (sym[k].st_value) {
						toffset = sym[k].st_value;
					} else if ((toffset = get_import_addr (bin, k)) == -1) {
						toffset = 0;
					}
					tsize = 16;
					is_imported = sym[k].st_shndx == STN_UNDEF;
				} else {
					tsize = sym[k].st_size;
					toffset = (ut64)sym[k].st_value;
					is_sht_null = sym[k].st_shndx == SHT_NULL;
				}
				if (is_bin_etrel (bin)) {
					if (sym[k].st_shndx < bin->ehdr.e_shnum) {
						ret[ret_ctr].offset = sym[k].st_value + bin->shdr[sym[k].st_shndx].sh_offset;
					}
				} else {
					ret[ret_ctr].offset = Elf_(r_bin_elf_v2p_new) (bin, toffset);
					if (ret[ret_ctr].offset == UT64_MAX) {
						ret[ret_ctr].offset = toffset;
						is_vaddr = true;
					}
				}
				ret[ret_ctr].size = tsize;
				if (sym[k].st_name + 1 > strtab_section->sh_size) {
					bprintf ("index out of strtab range\n");
					continue;
				}
				{
					int st_name = sym[k].st_name;
					int maxsize = R_MIN (r_buf_size (bin->b), strtab_section->sh_size);
					if (is_section_local_sym (bin, &sym[k])) {
						const char *shname = &bin->shstrtab[bin->shdr[sym[k].st_shndx].sh_name];
						r_str_ncpy (ret[ret_ctr].name, shname, ELF_STRING_LENGTH);
					} else if (st_name <= 0 || st_name >= maxsize) {
						ret[ret_ctr].name[0] = 0;
					} else {
						r_str_ncpy(ret[ret_ctr].name, &strtab[st_name], ELF_STRING_LENGTH);
						ret[ret_ctr].type = type2str (bin, &ret[ret_ctr], &sym[k]);

						if (ht_pp_find (symbol_map, &ret[ret_ctr], NULL)) {
							memset (ret + ret_ctr, 0, sizeof (RBinElfSymbol));
							continue;
						}
					}
				}
				ret[ret_ctr].ordinal = k;
				ret[ret_ctr].name[ELF_STRING_LENGTH - 2] = '\0';
				fill_symbol_bind_and_type (bin, &ret[ret_ctr], &sym[k]);
				ret[ret_ctr].is_sht_null = is_sht_null;
				ret[ret_ctr].is_vaddr = is_vaddr;
				ret[ret_ctr].last = 0;
				ret[ret_ctr].is_imported = is_imported;
				ret_ctr++;
				if (type == R_BIN_ELF_IMPORT_SYMBOLS && is_imported) {
					import_ret_ctr++;
				}
			}
			R_FREE (strtab);
			R_FREE (sym);
			ht_pp_free (symbol_map);
			symbol_map = NULL;
			if (type == R_BIN_ELF_IMPORT_SYMBOLS) {
				break;
			}
		}
	}
	if (!ret) {
		return Elf_(get_phdr_symbols) (bin, type);
	}
	ret[ret_ctr].last = 1; // ugly dirty hack :D
	int max = -1;
	RBinElfSymbol *aux = NULL;
	nsym = Elf_(fix_symbols) (bin, ret_ctr, type, &ret);
	if (nsym == -1) {
		goto beach;
	}

	// Elf_(fix_symbols) may find additional symbols, some of which could be
	// imported symbols. Let's reserve additional space for them.
	r_warn_if_fail (nsym >= ret_ctr);
	import_ret_ctr += nsym - ret_ctr;

	aux = ret;
	while (!aux->last) {
		if ((int)aux->ordinal > max) {
			max = aux->ordinal;
		}
		aux++;
	}
	nsym = max;
	if (type == R_BIN_ELF_IMPORT_SYMBOLS) {
		R_FREE (bin->imports_by_ord);
		bin->imports_by_ord_size = nsym + 1;
		bin->imports_by_ord = (RBinImport**)calloc (R_MAX (1, nsym + 1), sizeof (RBinImport*));
		R_FREE (bin->symbols_by_ord);
		bin->symbols_by_ord_size = nsym + 1;
		bin->symbols_by_ord = (RBinSymbol**)calloc (R_MAX (1, nsym + 1), sizeof (RBinSymbol*));
		import_ret = calloc (import_ret_ctr + 1, sizeof (RBinElfSymbol));
		if (!import_ret) {
			bprintf ("Cannot allocate %d symbols\n", nsym);
			goto beach;
		}
		import_ret_ctr = 0;
		i = -1;
		while (!ret[++i].last) {
			if (!(import_sym_ptr = Elf_(_r_bin_elf_convert_symbol) (bin, &ret[i], "%s"))) {
				continue;
			}
			setsymord (bin, import_sym_ptr->ordinal, import_sym_ptr);
			if (ret[i].is_imported) {
				memcpy (&import_ret[import_ret_ctr], &ret[i], sizeof (RBinElfSymbol));
				++import_ret_ctr;
			}
		}
		import_ret[import_ret_ctr].last = 1;
		R_FREE (ret);
		return import_ret;
	}
	return ret;
beach:
	free (ret);
	free (sym);
	free (strtab);
	ht_pp_free (symbol_map);
	return NULL;
}

RBinElfSymbol *Elf_(r_bin_elf_get_symbols)(ELFOBJ *bin) {
	if (!bin->g_symbols) {
		bin->g_symbols = Elf_(_r_bin_elf_get_symbols_imports) (bin, R_BIN_ELF_ALL_SYMBOLS);
	}
	return bin->g_symbols;
}

RBinElfSymbol *Elf_(r_bin_elf_get_imports)(ELFOBJ *bin) {
	if (!bin->g_imports) {
		bin->g_imports = Elf_(_r_bin_elf_get_symbols_imports) (bin, R_BIN_ELF_IMPORT_SYMBOLS);
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

void Elf_(r_bin_elf_free)(ELFOBJ* bin) {
	if (!bin) {
		return;
	}
	free (bin->phdr);
	free (bin->shdr);
	free (bin->strtab);
	free (bin->shstrtab);
	free (bin->dynstr);
	r_vector_fini (&bin->dyn_info.dt_needed);
	//free (bin->strtab_section);
	size_t i;
	if (bin->imports_by_ord) {
		for (i = 0; i<bin->imports_by_ord_size; i++) {
			free (bin->imports_by_ord[i]);
		}
		free (bin->imports_by_ord);
	}
	if (bin->symbols_by_ord) {
		for (i = 0; i<bin->symbols_by_ord_size; i++) {
			r_bin_symbol_free (bin->symbols_by_ord[i]);
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
	R_FREE (bin->g_relocs);
	ht_up_free (bin->rel_cache);
	bin->rel_cache = NULL;
	free (bin);
}

ELFOBJ* Elf_(r_bin_elf_new_buf)(RBuffer *buf, bool verbose) {
	ELFOBJ *bin = R_NEW0 (ELFOBJ);
	if (bin) {
		bin->kv = sdb_new0 ();
		bin->size = r_buf_size (buf);
		bin->verbose = verbose;
		bin->b = r_buf_ref (buf);
		if (!elf_init (bin)) {
			Elf_(r_bin_elf_free) (bin);
			return NULL;
		}
	}
	return bin;
}

static int is_in_pphdr(Elf_(Phdr) * p, ut64 addr) {
	return addr >= p->p_offset && addr < p->p_offset + p->p_filesz;
}

static int is_in_vphdr(Elf_(Phdr) * p, ut64 addr) {
	return addr >= p->p_vaddr && addr < p->p_vaddr + p->p_filesz;
}

/* Deprecated temporarily. Use r_bin_elf_p2v_new in new code for now. */
ut64 Elf_(r_bin_elf_p2v) (ELFOBJ *bin, ut64 paddr) {
	size_t i;

	r_return_val_if_fail (bin, 0);
	if (!bin->phdr) {
		if (is_bin_etrel (bin)) {
			return bin->baddr + paddr;
		}
		return paddr;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &bin->phdr[i];
		if (p->p_type == PT_LOAD && is_in_pphdr (p, paddr)) {
			if (!p->p_vaddr && !p->p_offset) {
				continue;
			}
			return p->p_vaddr + paddr - p->p_offset;
		}
	}

	return paddr;
}

/* Deprecated temporarily. Use r_bin_elf_v2p_new in new code for now. */
ut64 Elf_(r_bin_elf_v2p) (ELFOBJ *bin, ut64 vaddr) {
	r_return_val_if_fail (bin, 0);
	if (!bin->phdr) {
		if (is_bin_etrel (bin)) {
			return vaddr - bin->baddr;
		}
		return vaddr;
	}

	size_t i;
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &bin->phdr[i];
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
ut64 Elf_(r_bin_elf_p2v_new) (ELFOBJ *bin, ut64 paddr) {
	size_t i;

	r_return_val_if_fail (bin, UT64_MAX);
	if (!bin->phdr) {
		if (is_bin_etrel (bin)) {
			return bin->baddr + paddr;
		}
		return UT64_MAX;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &bin->phdr[i];
		if (p->p_type == PT_LOAD && is_in_pphdr (p, paddr)) {
			return p->p_vaddr + paddr - p->p_offset;
		}
	}

	return UT64_MAX;
}

/* converts a virtual address to the relative physical address, looking
 * at the program headers in the binary bin */
ut64 Elf_(r_bin_elf_v2p_new) (ELFOBJ *bin, ut64 vaddr) {
	size_t i;

	r_return_val_if_fail (bin, UT64_MAX);
	if (!bin->phdr) {
		if (is_bin_etrel (bin)) {
			return vaddr - bin->baddr;
		}
		return UT64_MAX;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &bin->phdr[i];
		if (p->p_type == PT_LOAD && is_in_vphdr (p, vaddr)) {
			return p->p_offset + vaddr - p->p_vaddr;
		}
	}
	return UT64_MAX;
}

static bool get_nt_file_maps (ELFOBJ *bin, RList *core_maps) {
	ut16 ph, ph_num = bin->ehdr.e_phnum;

	for (ph = 0; ph < ph_num; ph++) {
		Elf_(Phdr) *p = &bin->phdr[ph];
		if (p->p_type == PT_NOTE) {
			int bits = Elf_(r_bin_elf_get_bits)(bin);
			int elf_nhdr_size = (bits == 64) ? sizeof (Elf64_Nhdr) : sizeof (Elf32_Nhdr);
			int size_of = (bits == 64) ? sizeof (ut64) : sizeof (ut32);
			void *elf_nhdr = calloc (elf_nhdr_size, 1);
			ut64 offset = 0;
			bool found = false;

			while (!found) {
				int ret;
				ut32 n_descsz, n_namesz, n_type;
				ret = r_buf_read_at (bin->b,
						bin->phdr[ph].p_offset + offset,
						elf_nhdr, elf_nhdr_size);
				if (ret != elf_nhdr_size) {
					eprintf ("Cannot read more NOTES header from CORE\n");
					free (elf_nhdr);
					goto fail;
				}
				if (bits == 64) {
					n_descsz = round_up (((Elf64_Nhdr *)elf_nhdr)->n_descsz);
					n_namesz = round_up (((Elf64_Nhdr *)elf_nhdr)->n_namesz);
					n_type = ((Elf64_Nhdr *)elf_nhdr)->n_type;
				} else {
					n_descsz = round_up (((Elf32_Nhdr *)elf_nhdr)->n_descsz);
					n_namesz = round_up (((Elf32_Nhdr *)elf_nhdr)->n_namesz);
					n_type = ((Elf32_Nhdr *)elf_nhdr)->n_type;
				}

				if (n_type == NT_FILE) {
					found = true;
					offset += elf_nhdr_size + n_namesz;
					free (elf_nhdr);
				} else {
					offset += elf_nhdr_size + n_descsz + n_namesz;
				}
			}
			ut64 i = bin->phdr[ph].p_offset + offset;
			ut64 n_maps;
			if (bits == 64) {
				n_maps = BREAD64 (bin->b, i);
				(void)BREAD64 (bin->b, i);
			} else {
				n_maps = BREAD32 (bin->b, i);
				(void)BREAD32 (bin->b, i);
			}
			ut64 jump = ((size_of * 3) * n_maps) + i;
			int len_str = 0;
			while (n_maps > 0) {
				ut64 addr;
				if (bits == 64) {
					addr = BREAD64 (bin->b, i);
				} else {
					addr = BREAD32 (bin->b, i);
				}
				if (addr == UT64_MAX) {
					break;
				}
				char str[512] = {0};
				r_buf_read_at (bin->b, jump + len_str, (ut8*)str, sizeof (str) - 1);
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
	}

	return true;
fail:
	return false;
}

static void r_bin_elf_map_free(RBinMap *map) {
	if (map) {
		free (map->file);
		free (map);
	}
}

RList *Elf_(r_bin_elf_get_maps)(ELFOBJ *bin) {
	ut16 ph, ph_num = bin->ehdr.e_phnum; //Skip PT_NOTE
	if (!bin->phdr) {
		return NULL;
	}
	RList *maps = r_list_newf ((RListFree)r_bin_elf_map_free);
	for (ph = 0; ph < ph_num; ph++) {
		Elf_(Phdr) *p = &bin->phdr[ph];
		if (p->p_type == PT_LOAD) {
			RBinMap *map = R_NEW0 (RBinMap);
			if (map) {
				map->addr = p->p_vaddr;
				map->size = p->p_memsz;
				map->perms = p->p_flags;
				map->offset = p->p_offset;
				map->file = NULL;
				r_list_append (maps, map);
			}
		}
	}

	if (!r_list_empty (maps)) {
		if (!get_nt_file_maps (bin, maps)) {
			eprintf ("Could not retrieve the names of all maps from NT_FILE\n");
		}
	}

	return maps;
}

char *Elf_(r_bin_elf_compiler)(ELFOBJ *bin) {
	RBinElfSection *section = get_section_by_name (bin, ".comment");
	if (!section) {
		return NULL;
	}
	ut64 off = section->offset;
	ut32 sz = R_MIN (section->size, 128);
	if (sz < 1) {
		return NULL;
	}
	char *buf = malloc (sz + 1);
	if (!buf) {
		return NULL;
	}
	if (r_buf_read_at (bin->b, off, (ut8*)buf, sz) < 1) {
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
	char * res = r_str_escape (buf);
	free (buf);
	return res;
}

bool Elf_(r_bin_elf_is_executable)(ELFOBJ *bin) {
	const int t = bin->ehdr.e_type;
	return t == ET_EXEC || t == ET_DYN;
}
