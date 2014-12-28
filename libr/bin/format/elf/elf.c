/* radare - LGPL - Copyright 2008-2014 - nibble, pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "elf.h"

static inline int __strnlen(const char *str, int len) {
	int l = 0;
	while (IS_PRINTABLE(*str) && --len) {
		str++;
		l++;
	}
	return l+1;
}

static int Elf_(r_bin_elf_init_ehdr)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut8 e_ident[EI_NIDENT];
	int len;
	if (r_buf_read_at (bin->b, 0, e_ident, EI_NIDENT) == -1) {
		eprintf ("Warning: read (magic)\n");
		return R_FALSE;
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
#if R_BIN_ELF64
	sdb_set (bin->kv, "elf_header.format", "[16]z[2]E[2]Exqqqxwwwwww"
		" ident (elf_type)type (elf_machine)machine version entry phoff shoff flags ehsize"
		" phentsize phnum shentsize shnum shstrndx", 0);
#else
	sdb_set (bin->kv, "elf_header.format", "[16]z[2]E[2]Exxxxxwwwwww"
		" ident (elf_type)type (elf_machine)machine version entry phoff shoff flags ehsize"
		" phentsize phnum shentsize shnum shstrndx", 0);
#endif
	bin->endian = (e_ident[EI_DATA] == ELFDATA2MSB)?
		LIL_ENDIAN: !LIL_ENDIAN;
	memset (&bin->ehdr, 0, sizeof (Elf_(Ehdr)));
	len = r_buf_fread_at (bin->b, 0, (ut8*)&bin->ehdr,
#if R_BIN_ELF64
		bin->endian?"16c2SI3LI6S":"16c2si3li6s",
#else
		bin->endian?"16c2S5I6S":"16c2s5i6s",
#endif
			1);
	if (len == -1) {
		eprintf ("Warning: read (ehdr)\n");
		return R_FALSE;
	}
	if (strncmp ((char *)bin->ehdr.e_ident, ELFMAG, SELFMAG))
		return R_FALSE;
	return R_TRUE;
}

static int Elf_(r_bin_elf_init_phdr)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut32 phdr_size;
	int len;

	if (bin->ehdr.e_phnum == 0)
		return R_FALSE;
	if (bin->phdr) return R_TRUE;

	if (!UT32_MUL (&phdr_size, bin->ehdr.e_phnum, sizeof (Elf_(Phdr))))
		return R_FALSE;

	if (!phdr_size)
		return R_FALSE;

	if ((bin->phdr = calloc (phdr_size, 1)) == NULL) {
		perror ("malloc (phdr)");
		return R_FALSE;
	}
	len = r_buf_fread_at (bin->b, bin->ehdr.e_phoff, (ut8*)bin->phdr,
		#if R_BIN_ELF64
		bin->endian? "2I6L": "2i6l",
		#else
		bin->endian? "8I": "8i",
		#endif
		bin->ehdr.e_phnum);
	if (len == -1) {
		eprintf ("Warning: read (phdr)\n");
		R_FREE (bin->phdr);
		return R_FALSE;
	}
	sdb_bool_set (bin->kv, "elf.relro", Elf_(r_bin_elf_has_relro)(bin), 0);
	sdb_num_set (bin->kv, "elf_header_size.offset", sizeof (Elf_(Ehdr)), 0);
	sdb_num_set (bin->kv, "elf_phdr_size.offset", sizeof (Elf_(Phdr)), 0);
	sdb_num_set (bin->kv, "elf_shdr_size.offset", sizeof (Elf_(Shdr)), 0);
#if R_BIN_ELF64
	sdb_num_set (bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_set (bin->kv, "elf_phdr.format", "qqqqqqqq type offset vaddr paddr filesz memsz flags align", 0);
	sdb_num_set (bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff, 0);
	sdb_set (bin->kv, "elf_shdr.format", "xxqqqqxxqq name type flags addr offset size link info addralign entsize", 0);
#else
	sdb_num_set (bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_set (bin->kv, "elf_phdr.format", "wxxxwwww type offset vaddr paddr filesz memsz flags align", 0);
	sdb_num_set (bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff, 0);
	sdb_set (bin->kv, "elf_shdr.format", "xxxxxxxxxx name type flags addr offset size link info addralign entsize", 0);
#endif
	// Usage example:
	// > pf `k bin/cur/info/elf.phdr.format` @ `k bin/cur/info/elf.phdr.offset`
	return R_TRUE;
}

static int Elf_(r_bin_elf_init_shdr)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut32 shdr_size;
	int len;

	if (!bin || bin->shdr) return R_TRUE;

	if (!UT32_MUL(&shdr_size, bin->ehdr.e_shnum, sizeof (Elf_(Shdr))))
		return R_FALSE;

	if (shdr_size<1)
		return R_FALSE;

	if ((bin->shdr = calloc (1, shdr_size+1)) == NULL) {
		perror ("malloc (shdr)");
		return R_FALSE;
	}
	len = r_buf_fread_at (bin->b, bin->ehdr.e_shoff, (ut8*)bin->shdr,
#if R_BIN_ELF64
			bin->endian?"2I4L2I2L":"2i4l2i2l",
#else
			bin->endian?"10I":"10i",
#endif
			bin->ehdr.e_shnum);
	if (len == -1) {
		eprintf ("Warning: read (shdr) at 0x%"PFMT64x"\n", (ut64) bin->ehdr.e_shoff);
		R_FREE (bin->shdr);
		return R_FALSE;
	}
	return R_TRUE;
}

static int Elf_(r_bin_elf_init_strtab)(struct Elf_(r_bin_elf_obj_t) *bin) {
	if (bin->strtab || !bin->shdr) return R_FALSE;
        if (bin->ehdr.e_shstrndx != SHN_UNDEF &&
            (bin->ehdr.e_shstrndx >= bin->ehdr.e_shnum ||
            (bin->ehdr.e_shstrndx >= SHN_LORESERVE && bin->ehdr.e_shstrndx <= SHN_HIRESERVE)))
            return R_FALSE;

	/* sh_size must be lower than UT32_MAX and not equal to zero, to avoid bugs
	   on malloc() */
	if (bin->shdr[bin->ehdr.e_shstrndx].sh_size > UT32_MAX)
		return R_FALSE;
	if (!bin->shdr[bin->ehdr.e_shstrndx].sh_size)
		return R_FALSE;

	bin->shstrtab_section =
		bin->strtab_section = &bin->shdr[bin->ehdr.e_shstrndx];

	bin->shstrtab_size =
		bin->strtab_size = bin->strtab_section->sh_size;

	if ((bin->strtab = calloc (1, bin->strtab_size+1)) == NULL) {
		perror ("malloc");
		bin->shstrtab = NULL;
		return R_FALSE;
	}
	memset (bin->strtab, 0, bin->strtab_size);
	bin->shstrtab = bin->strtab;

	sdb_num_set (bin->kv, "elf_strtab.offset", bin->strtab_section->sh_offset, 0);
	sdb_num_set (bin->kv, "elf_strtab.size", bin->strtab_section->sh_size, 0);

	if (r_buf_read_at (bin->b, bin->strtab_section->sh_offset, (ut8*)bin->strtab,
				bin->strtab_section->sh_size) == -1) {
		eprintf ("Warning: read (strtab) at 0x%"PFMT64x"\n",
				(ut64) bin->strtab_section->sh_offset);
		R_FREE (bin->strtab);
		bin->shstrtab = NULL;
		return R_FALSE;
	}
	return R_TRUE;
}

static int Elf_(r_bin_elf_init)(struct Elf_(r_bin_elf_obj_t) *bin) {
	bin->phdr = NULL;
	bin->shdr = NULL;
	bin->strtab = NULL;
	bin->strtab_size = 0;
	bin->strtab_section = NULL;

	/* bin is not an ELF */
	if (!Elf_(r_bin_elf_init_ehdr) (bin))
		return R_FALSE;

        if (!Elf_(r_bin_elf_init_phdr) (bin))
                eprintf ("Warning: Cannot initialize program headers\n");
	if (!Elf_(r_bin_elf_init_shdr) (bin))
		eprintf ("Warning: Cannot initialize section headers\n");
	if (!Elf_(r_bin_elf_init_strtab) (bin))
		eprintf ("Warning: Cannot initialize strings table\n");

	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;
	bin->symbols_by_ord_size = 0;
	bin->symbols_by_ord = NULL;

	bin->baddr = Elf_(r_bin_elf_get_baddr) (bin);
	bin->boffset = Elf_(r_bin_elf_get_boffset) (bin);

	return R_TRUE;
}

static Elf_(Shdr)* Elf_(r_bin_elf_get_section_by_name)(struct Elf_(r_bin_elf_obj_t) *bin, const char *section_name) {
	int i;
	ut32 cur_strtab_len;

	if (!bin || !bin->shdr || !bin->strtab)
		return NULL;
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if(!UT32_SUB(&cur_strtab_len, bin->shstrtab_section->sh_size, bin->shdr[i].sh_name))
			continue;
		if (!strncmp (&bin->shstrtab[bin->shdr[i].sh_name], section_name, cur_strtab_len))
			return &bin->shdr[i];
	}
	return NULL;
}

ut64 Elf_(r_bin_elf_get_section_offset)(struct Elf_(r_bin_elf_obj_t) *bin, const char *section_name) {
	Elf_(Shdr)* shdr = Elf_(r_bin_elf_get_section_by_name)(bin, section_name);
	if (!shdr) return UT64_MAX;
	return (ut64)shdr->sh_offset;
}

ut64 Elf_(r_bin_elf_get_section_addr)(struct Elf_(r_bin_elf_obj_t) *bin, const char *section_name) {
	Elf_(Shdr)* shdr = Elf_(r_bin_elf_get_section_by_name)(bin, section_name);
	if (!shdr) return UT64_MAX;
	return (ut64)shdr->sh_addr;
}

static ut64 Elf_(get_import_addr)(struct Elf_(r_bin_elf_obj_t) *bin, int sym) {
	Elf_(Rel) *rel = NULL;
	Elf_(Shdr) *rel_shdr;
	Elf_(Addr) plt_sym_addr;
	ut64 got_addr, got_offset;
	int j, k, tsize, len, nrel;

	if (!bin->shdr || !bin->strtab)
		return -1;
	if ((got_offset = Elf_(r_bin_elf_get_section_offset) (bin, ".got")) == -1 &&
		(got_offset = Elf_(r_bin_elf_get_section_offset) (bin, ".got.plt")) == -1)
		return -1;
	if ((got_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".got")) == -1 &&
		(got_addr = Elf_(r_bin_elf_get_section_addr) (bin, ".got.plt")) == -1)
		return -1;

	if((rel_shdr = Elf_(r_bin_elf_get_section_by_name)(bin, ".rel.plt")) != NULL) {
		tsize = sizeof (Elf_(Rel));
	} else if((rel_shdr = Elf_(r_bin_elf_get_section_by_name)(bin, ".rela.plt")) != NULL) {
		tsize = sizeof (Elf_(Rela));
	} else {
		return -1;
	}

	nrel = (ut32)((int)rel_shdr->sh_size / (int)tsize);
	int relsz = (int)nrel * sizeof (Elf_(Rel));
	if (relsz<1 || (rel = calloc (1, relsz)) == NULL) {
		perror ("malloc (rel)");
		return -1;
	}

	plt_sym_addr = -1;

	for (j = k = 0; j < rel_shdr->sh_size && k <nrel; j += tsize, k++) {
		len = r_buf_fread_at (bin->b, rel_shdr->sh_offset + j, 
			(ut8*)(&rel[k]),
#if R_BIN_ELF64
				      bin->endian?"2L":"2l",
#else
				      bin->endian?"2I":"2i",
#endif
				      1);
		if (len == -1) {
			eprintf ("Warning: read (rel)\n");
			break;
		}

		if (ELF_R_SYM (rel[k].r_info) == sym) {
			int of = rel[k].r_offset-got_addr+got_offset;
			if (of+sizeof(Elf_(Addr)) >= bin->b->length) {
				// do nothing
			} else {
				if (r_buf_read_at (bin->b, of,
						(ut8*)&plt_sym_addr, sizeof (Elf_(Addr))) == -1) {
					eprintf ("Warning: read (got)\n");
					break;
				}
			}
			plt_sym_addr -= 6;
			break;
		}
	}
	free (rel);
	return plt_sym_addr;
}

int Elf_(r_bin_elf_has_nx)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int i;
	if (bin && bin->phdr)
		for (i = 0; i < bin->ehdr.e_phnum; i++)
			if (bin->phdr[i].p_type == PT_GNU_STACK)
				return (!(bin->phdr[i].p_flags & 1))? 1: 0;
	return 0;
}

int Elf_(r_bin_elf_has_relro)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int i;
	if (bin && bin->phdr)
		for (i = 0; i < bin->ehdr.e_phnum; i++)
			if (bin->phdr[i].p_type == PT_GNU_RELRO)
				return 1;
	return 0;
}

ut64 Elf_(r_bin_elf_get_baddr)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int i;
	/* hopefully.. the first PT_LOAD is base */
	if (bin && bin->phdr) {
		for (i = 0; i < bin->ehdr.e_phnum; i++) {
			if (bin->phdr[i].p_type == PT_LOAD) {
				return (ut64)bin->phdr[i].p_vaddr;
			}
		}
	}
	return 0;
}

ut64 Elf_(r_bin_elf_get_boffset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int i;
	/* hopefully.. the first PT_LOAD is base */
	if (bin && bin->phdr)
		for (i = 0; i < bin->ehdr.e_phnum; i++)
			if (bin->phdr[i].p_type == PT_LOAD)
				return (ut64) bin->phdr[i].p_offset;
	return 0;
}

ut64 Elf_(r_bin_elf_get_init_offset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[512];
	if (!bin)
		return 0LL;
	if (r_buf_read_at (bin->b, entry+16, buf, sizeof (buf)) == -1) {
		eprintf ("Warning: read (init_offset)\n");
		return 0;
	}
	if (buf[0] == 0x68) { // push // x86 only
		memmove (buf, buf+1, 4);
		return (ut64)((int)(buf[0]+(buf[1]<<8)+(buf[2]<<16)+(buf[3]<<24)))-bin->baddr;
	}
	return 0;
}

ut64 Elf_(r_bin_elf_get_fini_offset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[512];
	if (!bin) return 0LL;

	if (r_buf_read_at (bin->b, entry+11, buf, sizeof (buf)) == -1) {
		eprintf ("Warning: read (get_fini)\n");
		return 0;
	}
	if (*buf == 0x68) { // push // x86/32 only
		memmove (buf, buf+1, 4);
		return (ut64)((int)(buf[0]+(buf[1]<<8)+
			(buf[2]<<16)+(buf[3]<<24)))-bin->baddr;
	}
	return 0;
}

ut64 Elf_(r_bin_elf_get_entry_offset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut64 entry;
	if (!bin)
		return 0LL;
	entry = (ut64) bin->ehdr.e_entry;
	if (entry == 0LL) {
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".init.text");
		if (entry != UT64_MAX) return entry;
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".text");
		if (entry != UT64_MAX) return entry;
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".init");
		if (entry != UT64_MAX) return entry;
	}
	if (bin->ehdr.e_entry < bin->baddr)
		return bin->ehdr.e_entry;
	return bin->ehdr.e_entry - bin->baddr;
}

ut64 Elf_(r_bin_elf_get_main_offset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[512];
	if (!bin)
		return 0LL;

	if (r_buf_read_at (bin->b, entry, buf, sizeof (buf)) == -1) {
		eprintf ("Warning: read (main)\n");
		return 0;
	}
	// TODO: Use arch to identify arch before memcmp's

	// MIPS
	/* get .got, calculate offset of main symbol */
	if (!memcmp (buf, "\x21\x00\xe0\x03\x01\x00\x11\x04\x00\x00\x00\x00", 12)) {
		ut64 got_addr = 0LL; // TODO: get .got offset
		short delta = (buf[28]+(buf[29]<<8));
		// NOTE: This is the way to resolve 'gp' register
		r_buf_read_at (bin->b, got_addr+(32734+delta), buf, 4);
		return (ut64)((int)(buf[0]+(buf[1]<<8)+(buf[2]<<16)+(buf[3]<<24)))-bin->baddr;
	}
	// ARM
	if (!memcmp (buf, "\x24\xc0\x9f\xe5\x00\xb0\xa0\xe3", 8)) {
		return (ut64)((int)(buf[48+0]+(buf[48+1]<<8)+
		(buf[48+2]<<16)+(buf[48+3]<<24)))-bin->baddr;
	}
	// X86-PIE
	if (buf[0x1d] == 0x48 && buf[0x1e] == 0x8b) {
		if (!memcmp (buf, "\x31\xed\x49\x89", 4)) {// linux
			ut64 maddr, baddr;
			ut32 n32, *num = (ut32 *)(buf+0x20);
			maddr = entry + 0x24 + *num;
			if (r_buf_read_at (bin->b, maddr, (ut8*)&n32, sizeof (n32)) == -1) {
				eprintf ("Warning: read (maddr) 2\n");
				return 0;
			}
			maddr = (ut64)n32;
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
	if (!memcmp (buf, "\x49\x89\xd9", 3) && buf[156] == 0xe8) {// openbsd
		return (ut64)((int)(buf[157+0]+(buf[157+1]<<8)+
		(buf[157+2]<<16)+(buf[157+3]<<24)))+ entry + 156 + 5;
	}
	if (!memcmp (buf+29, "\x48\xc7\xc7", 3)) // linux
		return (ut64)((int)(buf[29+3]+(buf[29+4]<<8)+
		(buf[29+5]<<16)+(buf[29+6]<<24)))-bin->baddr;
#else
	if (buf[23] == '\x68')
		return (ut64)((int)(buf[23+1]+(buf[23+2]<<8)+
		(buf[23+3]<<16)+(buf[23+4]<<24)))-bin->baddr;
#endif
	return 0;
}

int Elf_(r_bin_elf_get_stripped)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int i;
	if (!bin->shdr)
		return R_FALSE;
	for (i = 0; i < bin->ehdr.e_shnum; i++)
		if (bin->shdr[i].sh_type == SHT_SYMTAB)
			return R_FALSE;
	return R_TRUE;
}

int Elf_(r_bin_elf_get_static)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int i;
	if (!bin->phdr)
		return R_FALSE;
	for (i = 0; i < bin->ehdr.e_phnum; i++)
		if (bin->phdr[i].p_type == PT_INTERP)
			return R_FALSE;
	return R_TRUE;
}

char* Elf_(r_bin_elf_get_data_encoding)(struct Elf_(r_bin_elf_obj_t) *bin) {
	switch (bin->ehdr.e_ident[EI_DATA]) {
	case ELFDATANONE: return strdup ("none");
	case ELFDATA2LSB: return strdup ("2's complement, little endian");
	case ELFDATA2MSB: return strdup ("2's complement, big endian");
	default: return r_str_newf ("<unknown: %x>", bin->ehdr.e_ident[EI_DATA]);
	}
}

int Elf_(r_bin_elf_has_va)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut32 e_type = (ut32)bin->ehdr.e_type; // cast to avoid warn in iphone-gcc, must be ut16
	//if (bin->ehdr.e_phnum == 0)
	return (e_type == ET_REL)? 0: 1;
}

// TODO: do not strdup here
char* Elf_(r_bin_elf_get_arch)(struct Elf_(r_bin_elf_obj_t) *bin) {
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
	case EM_ARM:
	case EM_AARCH64:
		return strdup ("arm");
	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		return strdup ("sparc");
	case EM_PPC:
	case EM_PPC64:
		return strdup ("ppc");
	case EM_PROPELLER:
		return strdup ("propeller");
	case EM_SH: return strdup ("sh");
	default: return strdup ("x86");
	}
}

// TODO: do not strdup here
char* Elf_(r_bin_elf_get_machine_name)(struct Elf_(r_bin_elf_obj_t) *bin) {
	switch (bin->ehdr.e_machine) {
	case EM_NONE:        return strdup ("No machine");
	case EM_M32:         return strdup ("AT&T WE 32100");
	case EM_SPARC:       return strdup ("SUN SPARC");
	case EM_386:         return strdup ("Intel 80386");
	case EM_68K:         return strdup ("Motorola m68k family");
	case EM_88K:         return strdup ("Motorola m88k family");
	case EM_860:         return strdup ("Intel 80860");
	case EM_MIPS:        return strdup ("MIPS R3000 big-endian");
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
	default:             return r_str_newf ("<unknown>: 0x%x", bin->ehdr.e_machine);
	}
}

char* Elf_(r_bin_elf_get_file_type)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut32 e_type;
	if (!bin)
		return NULL;
	e_type = (ut32)bin->ehdr.e_type; // cast to avoid warn in iphone-gcc, must be ut16
	switch (e_type) {
	case ET_NONE: return strdup ("NONE (None)");
	case ET_REL:  return strdup ("REL (Relocatable file)");
	case ET_EXEC: return strdup ("EXEC (Executable file)");
	case ET_DYN:  return strdup ("DYN (Shared object file)");
	case ET_CORE: return strdup ("CORE (Core file)");
	}

	if ((e_type >= ET_LOPROC) && (e_type <= ET_HIPROC))
		return r_str_newf ("Processor Specific: %x", e_type);
	else if ((e_type >= ET_LOOS) && (e_type <= ET_HIOS))
		return r_str_newf ("OS Specific: %x", e_type);
	else return r_str_newf ("<unknown>: %x", e_type);
}

char* Elf_(r_bin_elf_get_elf_class)(struct Elf_(r_bin_elf_obj_t) *bin) {
	switch (bin->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASSNONE: return strdup ("none");
	case ELFCLASS32:   return strdup ("ELF32");
	case ELFCLASS64:   return strdup ("ELF64");
	default:           return r_str_newf ("<unknown: %x>", bin->ehdr.e_ident[EI_CLASS]);
	}
}

int Elf_(r_bin_elf_get_bits)(struct Elf_(r_bin_elf_obj_t) *bin) {
	/* Hack for ARCompact */
	if (bin->ehdr.e_machine == EM_ARC_A5)
		return 16;

	switch (bin->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:   return 32;
	case ELFCLASS64:   return 64;
	case ELFCLASSNONE:
	default:           return 32; // defaults
	}
}

static inline int noodle(struct Elf_(r_bin_elf_obj_t) *bin, const char *s) {
	const ut8 *p = bin->b->buf;
	if (bin->b->length>64) {
		p += bin->b->length-64;
	} else return 0;
	return r_mem_mem (p, 64, (const ut8 *)s, strlen (s)) != NULL;
}

static inline int needle(struct Elf_(r_bin_elf_obj_t) *bin, const char *s) {
	if (bin->shstrtab) {
		ut32 len = bin->shstrtab_size;
		if (len > 4096) len = 4096; // avoid slow loading .. can be buggy?
		return r_mem_mem ((const ut8*)bin->shstrtab, len,
				(const ut8*)s, strlen (s)) != NULL;
	}
	return 0;
}

// TODO: must return const char * all those strings must be const char os[LINUX] or so
char* Elf_(r_bin_elf_get_osabi_name)(struct Elf_(r_bin_elf_obj_t) *bin) {
	/* Hack to identify OS */
	if (needle (bin, "openbsd")) return strdup ("openbsd");
	if (needle (bin, "netbsd")) return strdup ("netbsd");
	if (needle (bin, "freebsd")) return strdup ("freebsd");
	if (noodle (bin, "BEOS:APP_VERSION")) return strdup ("beos");
	if (needle (bin, "GNU")) return strdup ("linux");
	return strdup ("linux");
#if 0
	// XXX: this is wrong. openbsd bins are identified as linux ones.
	switch (bin->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_ARM_AEABI:
	case ELFOSABI_ARM:        return strdup ("arm");
	case ELFOSABI_NONE:       return strdup ("linux"); // sysv
	case ELFOSABI_HPUX:       return strdup ("hpux");
	case ELFOSABI_NETBSD:     return strdup ("netbsd");
	case ELFOSABI_LINUX:      return strdup ("linux");
	case ELFOSABI_SOLARIS:    return strdup ("solaris");
	case ELFOSABI_AIX:        return strdup ("aix");
	case ELFOSABI_IRIX:       return strdup ("irix");
	case ELFOSABI_FREEBSD:    return strdup ("freebsd");
	case ELFOSABI_TRU64:      return strdup ("tru64");
	case ELFOSABI_MODESTO:    return strdup ("modesto");
	case ELFOSABI_OPENBSD:    return strdup ("openbsd");
	case ELFOSABI_STANDALONE: return strdup ("standalone");
	default:                  return r_str_newf ("<unknown: %x>", bin->ehdr.e_ident[EI_OSABI]);
	}
#endif
}

int Elf_(r_bin_elf_is_big_endian)(struct Elf_(r_bin_elf_obj_t) *bin) {
	return (bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB);
}

/* XXX Init dt_strtab? */
char *Elf_(r_bin_elf_get_rpath)(struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Dyn) *dyn = NULL;
	ut64 stroff = 0;
	char *ret = NULL;
	int ndyn, i, j, len;

	if (!bin || !bin->phdr)
		return NULL;
	for (i = 0; i < bin->ehdr.e_phnum; i++)
		if (bin->phdr[i].p_type == PT_DYNAMIC) {
			ndyn = (int)(bin->phdr[i].p_filesz / sizeof (Elf_(Dyn)));
			free (dyn); // TODO: reuse dyn allocation
			if (!(dyn = calloc (sizeof (Elf_(Dyn)), ndyn+1))) {
				perror ("malloc (dyn)");
				free (ret);
				return NULL;
			}
			len = r_buf_fread_at (bin->b, bin->phdr[i].p_offset, (ut8*)dyn,
#if R_BIN_ELF64
				bin->endian?"2L":"2l",
#else
				bin->endian?"2I":"2i",
#endif
					ndyn);
			if (len == -1) {
				eprintf ("Warning: read (dyn)\n");
				free (ret);
				free (dyn);
				return NULL;
			}
			for (j = 0; j < ndyn; j++)
				if (dyn[j].d_tag == DT_STRTAB) {
					stroff = (ut64)(dyn[j].d_un.d_ptr - bin->baddr);
					break;
				}
			for (j = 0; j < ndyn; j++)
				if (dyn[j].d_tag == DT_RPATH || dyn[j].d_tag == DT_RUNPATH) {
					free (ret);
					if ((ret = calloc (1,ELF_STRING_LENGTH)) == NULL) {
						perror ("malloc (rpath)");
						free (dyn);
						return NULL;
					}
					if (r_buf_read_at (bin->b, stroff + dyn[j].d_un.d_val,
								(ut8*)ret, ELF_STRING_LENGTH) == -1) {
						eprintf ("Warning: read (rpath)\n");
						free (ret);
						free (dyn);
						return NULL;
					}
					break;
				}
			break;
		}
	free (dyn);
	return ret;
}

static size_t Elf_(r_bin_elf_get_relocs_num)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int nidx;
	size_t i, ret = 0;
	const char *sh_name;

	if (bin->shdr == NULL) {
		return 0;
	}

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		nidx = bin->shdr[i].sh_name;

		if (nidx < 0 || !bin->shstrtab_section ||
			!bin->shstrtab_section->sh_size || nidx > bin->shstrtab_section->sh_size) {
			continue;
		} else if (!bin->shstrtab || !(bin->shdr[i].sh_name > 0) || !(bin->shdr[i].sh_name + 8 < bin->shstrtab_size)) {
			continue;
		}
		if (bin->shdr[i].sh_link >= bin->ehdr.e_shnum) {
			continue;
		}
		if (bin->shdr[i].sh_name > bin->strtab_size) {
			eprintf ("Invalid shdr index in strtab %d/%"PFMT64d"\n",
					bin->shdr[i].sh_name, (ut64) bin->strtab_size);
			continue;
		}

		sh_name = &bin->strtab[bin->shdr[i].sh_name];

		if (!sh_name)
			continue;

		if (!strncmp (sh_name, ".rela.", strlen (".rela."))) {
			ret += bin->ehdr.e_ident[EI_CLASS] == 1 ? (bin->shdr[i].sh_size) / (sizeof (ut32) * 3) :
							(bin->shdr[i].sh_size) / (sizeof (ut64) * 3);
		} else if (!strncmp (sh_name, ".rel.", strlen (".rel."))) {
			ret += bin->ehdr.e_ident[EI_CLASS] == 1 ? (bin->shdr[i].sh_size) / (sizeof (ut32) * 2) :
							(bin->shdr[i].sh_size) / (sizeof (ut64) * 2);
		}
	}

	return ret;
}

static int Elf_(r_bin_elf_read_reloc)(struct Elf_(r_bin_elf_obj_t) *bin,
		struct r_bin_elf_reloc_t *r, int is_rela, ut64 offset)
{
	char *fmt;
	st64 l1, l2, l3;
	st32 i1, i2, i3;


	if (bin->ehdr.e_ident[EI_CLASS] == 1) {
		fmt = bin->endian ? "I" : "i";
		if (r_buf_fread_at (bin->b, offset, (ut8*)&i1, fmt, 1) == -1) {
			eprintf ("Error reading r_offset\n");
			return -1;
		}
		if (r_buf_fread_at (bin->b, offset + sizeof (ut32), (ut8*)&i2, fmt, 1) == -1) {
			eprintf ("Error reading r_info\n");
			return -1;
		}
		if (is_rela && (r_buf_fread_at (bin->b, offset + sizeof (ut32) * 2, (ut8*)&i3, fmt, 1) == -1)) {
			eprintf ("Error reading r_addend\n");
			return -1;
		}

		r->is_rela = is_rela;
		r->offset = i1;
		r->type = ELF32_R_TYPE(i2);
		r->sym = ELF32_R_SYM(i2);
		r->last = 0;
		if (is_rela)
			r->addend = i3;

		return is_rela ? sizeof (ut32) * 3 : sizeof (ut32) * 2;
	} else {
		fmt = bin->endian ? "L" : "l";
		if (r_buf_fread_at (bin->b, offset, (ut8*)&l1, fmt, 1) == -1) {
			eprintf ("Error reading r_offset\n");
			return -1;
		}
		if (r_buf_fread_at (bin->b, offset + sizeof (ut64), (ut8*)&l2, fmt, 1) == -1) {
			eprintf ("Error reading r_info\n");
			return -1;
		}
		if (is_rela && (r_buf_fread_at (bin->b, offset + 2 * sizeof (ut64), (ut8*)&l3, fmt, 1) == -1)) {
			eprintf ("Error reading r_addend\n");
			return -1;
		}

		r->is_rela = is_rela;
		r->offset = l1;
		r->type = ELF64_R_TYPE(l2);
		r->sym = ELF64_R_SYM(l2);
		r->last = 0;
		if (is_rela)
			r->addend = l3;

		return is_rela ? sizeof (ut64) * 3 : sizeof (ut64) * 2;
	}
}

struct r_bin_elf_reloc_t* Elf_(r_bin_elf_get_relocs)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int nidx, res;
	const char *sh_name;
	size_t reloc_num = 0;
	size_t i, j, rel;
	struct r_bin_elf_reloc_t *ret = NULL;
	Elf_(Shdr)* section_text = NULL;
	ut64 section_text_offset = 0LL;

	if (!bin || !bin->shdr || !bin->strtab)
		return NULL;

	reloc_num = Elf_(r_bin_elf_get_relocs_num)(bin);

	if (!reloc_num)
		return NULL;

	ret = (struct r_bin_elf_reloc_t*)calloc (sizeof (struct r_bin_elf_reloc_t),
		(reloc_num + 2));

	if (!ret)
		return NULL;
	section_text = Elf_(r_bin_elf_get_section_by_name)(bin, ".text");
	if (section_text) {
		section_text_offset = section_text->sh_offset;
	}

	// TODO: check boundaries for e_shnum and filesize
	for (i = 0, rel = 0; i < bin->ehdr.e_shnum && rel < reloc_num ; i++) {
		nidx = bin->shdr[i].sh_name;

		if (nidx < 0 || !bin->shstrtab_section ||
			!bin->shstrtab_section->sh_size || nidx > bin->shstrtab_section->sh_size) {
			continue;
		} else if (!bin->shstrtab || !(bin->shdr[i].sh_name > 0) || !(bin->shdr[i].sh_name + 8 < bin->shstrtab_size)) {
			continue;
		}
		if (bin->shdr[i].sh_link >= bin->ehdr.e_shnum) {
			continue;
		}
		if (bin->shdr[i].sh_name > bin->strtab_size) {
			eprintf ("Invalid shdr index in strtab %d/%"PFMT64d"\n",
					bin->shdr[i].sh_name, (ut64) bin->strtab_size);
			continue;
		}

		sh_name = &bin->strtab[bin->shdr[i].sh_name];
		// TODO: check boundaries!!!

		if (!sh_name)
			continue;

		if (!strncmp (sh_name, ".rela.", strlen (".rela."))) {
			for (j = 0; j < bin->shdr[i].sh_size; j += res) {
				res = Elf_(r_bin_elf_read_reloc)(bin, &ret[rel],
					1, bin->shdr[i].sh_offset + j);
				ret[rel].rva = ret[rel].offset + section_text_offset;
				ret[rel].offset = ret[rel].offset - bin->baddr;
				ret[rel].last = 0;
				if (res < 0)
					break;
				rel++;
			}
		} else if (!strncmp (sh_name, ".rel.", strlen (".rel."))) {
			for (j = 0; j < bin->shdr[i].sh_size; j += res) {
				res = Elf_(r_bin_elf_read_reloc)(bin, &ret[rel],
					0, bin->shdr[i].sh_offset + j);
				ret[rel].rva = ret[rel].offset;
				ret[rel].offset = ret[rel].offset - bin->baddr;
				ret[rel].last = 0;
				if (res < 0)
					break;
				rel++;
			}
		}
	}

	ret[rel].last = 1;

	return ret;
}

struct r_bin_elf_lib_t* Elf_(r_bin_elf_get_libs)(struct Elf_(r_bin_elf_obj_t) *bin) {
	struct r_bin_elf_lib_t *ret = NULL;
	Elf_(Dyn) *dyn = NULL;
	ut64 stroff = 0;
	int ndyn, i, j, k, len, filesz;

	if (!bin || !bin->phdr)
		return NULL;
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		filesz = R_MIN (bin->size, bin->phdr[i].p_filesz);
		if (filesz < bin->phdr[i].p_filesz) {
			eprintf ("Invalid phdr.filesz value 0x%x\n",
				(int)bin->phdr[i].p_filesz);
		}
		if (bin->phdr[i].p_type == PT_DYNAMIC) {
			ndyn = (int)(filesz / sizeof (Elf_(Dyn)));
			if (!(dyn = calloc (sizeof (Elf_(Dyn)), ndyn+1))) {
				perror ("malloc (dyn)");
				return NULL;
			}
			len = r_buf_fread_at (bin->b, bin->phdr[i].p_offset,
					(ut8*)dyn,
#if R_BIN_ELF64
					bin->endian?"2L":"2l",
#else
					bin->endian?"2I":"2i",
#endif
					ndyn);
			if (len  == -1) {
				eprintf ("Warning: read (dyn)\n");
				free (dyn);
				return NULL;
			}
			for (j = 0; j < ndyn; j++)
				if (dyn[j].d_tag == DT_STRTAB) {
					stroff = (ut64)(dyn[j].d_un.d_ptr - bin->baddr);
					break;
				}
			for (j = 0, k = 0; j < ndyn; j++)
				if (dyn[j].d_tag == DT_NEEDED) {
					ret = realloc (ret, (k+1) * sizeof (struct r_bin_elf_lib_t));
					if (ret == NULL) {
						perror ("realloc (libs)");
						free (dyn);
						return NULL;
					}
					if (r_buf_read_at (bin->b, stroff + dyn[j].d_un.d_val,
							(ut8*)ret[k].name, ELF_STRING_LENGTH) == -1) {
						eprintf ("Warning: read (libs)\n");
						free (ret);
						free (dyn);
						return NULL;
					}
					ret[k].last = 0;
					if (ret[k].name[0]) {
						k++;
					}
				}
			ret = realloc (ret, (k+1) * sizeof (struct r_bin_elf_lib_t));
			if (ret == NULL) {
				perror ("realloc (libs)");
				free (dyn);
				return NULL;
			}
			ret[k].last = 1;
			free (dyn);
			break;
		}
	}
	return ret;
}

struct r_bin_elf_section_t* Elf_(r_bin_elf_get_sections)(struct Elf_(r_bin_elf_obj_t) *bin) {
	struct r_bin_elf_section_t *ret = NULL;
	char unknown_s[20], invalid_s[20];
	int i, nidx, unknown_c=0, invalid_c=0;

	if ((ret = calloc ((bin->ehdr.e_shnum + 1), sizeof (struct r_bin_elf_section_t))) == NULL)
		return NULL;
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr == NULL) {
			free (ret);
			return NULL;
		}
		ret[i].offset = bin->shdr[i].sh_offset;
		ret[i].rva = bin->shdr[i].sh_addr;//bin->shdr[i].sh_addr > bin->baddr?
		//bin->shdr[i].sh_addr-bin->baddr: bin->shdr[i].sh_addr;
		ret[i].size = bin->shdr[i].sh_size;
		ret[i].align = bin->shdr[i].sh_addralign;
		ret[i].flags = bin->shdr[i].sh_flags;
		//memset (ret[i].name, 0, sizeof (ret[i].name));
		nidx = bin->shdr[i].sh_name;
		if (nidx<0 || !bin->shstrtab_section ||
			!bin->shstrtab_section->sh_size || nidx > bin->shstrtab_section->sh_size) {
			snprintf(invalid_s, sizeof(invalid_s)-4, "invalid%d", invalid_c);
			strncpy (ret[i].name, invalid_s, sizeof (ret[i].name)-4);
			invalid_c++;
		}
		else {
#define SHNAME (int)bin->shdr[i].sh_name
#define SHNLEN sizeof (ret[i].name)-4
#define SHSIZE (int)bin->shstrtab_size
			if (bin->shstrtab && (SHNAME > 0) && (SHNAME+8 < SHSIZE)) {
				strncpy (ret[i].name, &bin->shstrtab[SHNAME], SHNLEN);
			} else {
				snprintf(unknown_s, sizeof(unknown_s)-4, "unknown%d", unknown_c);
				strncpy (ret[i].name, unknown_s, sizeof (ret[i].name)-4);
				unknown_c++;
			}
		}
		ret[i].name[sizeof (ret[i].name)-2] = 0;
		ret[i].last = 0;
		//eprintf ("%d) %s Sh_addr: 0x%04x, bin_base: 0x%04x, base_addr - bin_shdr: 0x%04x\n", i, ret[i].name, bin->shdr[i].sh_addr, bin->baddr, bin->shdr[i].sh_addr-bin->baddr);
	}
	ret[i].last = 1;
	return ret;
}

struct r_bin_elf_symbol_t* Elf_(r_bin_elf_get_symbols)(struct Elf_(r_bin_elf_obj_t) *bin, int type) {
	ut32 shdr_size;
	int tsize, nsym, ret_ctr, i, j, k, len;
	ut64 sym_offset = 0, data_offset = 0, toffset;
	struct r_bin_elf_symbol_t *ret = NULL;
	Elf_(Shdr) *strtab_section;
	Elf_(Sym) *sym;
	char *strtab;
	Elf_(Shdr)* section_text = NULL;
	ut64 section_text_offset = 0LL;

	if (!bin || !bin->shdr || bin->ehdr.e_shnum == 0 || bin->ehdr.e_shnum == 0xffff)
		return NULL;

	if (bin->ehdr.e_type== ET_REL) {
		section_text = Elf_(r_bin_elf_get_section_by_name)(bin, ".text");
		if (section_text) {
			section_text_offset = section_text->sh_offset;
		}
	}

	if (bin->ehdr.e_type == ET_REL) {
		// XXX: we must obey shndx here
		if ((sym_offset = Elf_(r_bin_elf_get_section_offset)(bin, ".text")) == -1)
			sym_offset = 0;
		if ((data_offset = Elf_(r_bin_elf_get_section_offset)(bin, ".rodata")) == -1)
			data_offset = 0;
	}
	if (!UT32_MUL (&shdr_size, bin->ehdr.e_shnum, sizeof (Elf_(Shdr))))
		return R_FALSE;
	if (shdr_size+8>bin->size)
		return R_FALSE;

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
#define BUGGY 0
#if BUGGY
/* XXX: this regression was introduced because some binary was wrongly parsed.. must be reviewed */
if (
	(
		(type == R_BIN_ELF_IMPORTS) || (type == R_BIN_ELF_SYMBOLS)
	) && (
		(bin->shdr[i].sh_type == SHT_DYNSYM) || (bin->shdr[i].sh_type == SHT_SYMTAB)
	)
) {
#else
         if ((type == R_BIN_ELF_IMPORTS && bin->shdr[i].sh_type == (bin->ehdr.e_type == ET_REL ? SHT_SYMTAB : SHT_DYNSYM)) ||
                (type == R_BIN_ELF_SYMBOLS && bin->shdr[i].sh_type == (Elf_(r_bin_elf_get_stripped) (bin) ? SHT_DYNSYM : SHT_SYMTAB))) {
#endif
			if (bin->shdr[i].sh_link < 1) {
				/* oops. fix out of range pointers */
				continue;
			}
			// hack to avoid asan cry
			if ((bin->shdr[i].sh_link*sizeof(Elf_(Shdr)))>= shdr_size) {
				/* oops. fix out of range pointers */
				continue;
			}
			strtab_section = &bin->shdr[bin->shdr[i].sh_link];
			if (!strtab_section) {
				/* oops. we have no strtab, skip */
				continue;
			}
			if ((strtab = (char *)calloc (1, 8+strtab_section->sh_size)) == NULL) {
				eprintf ("malloc (syms strtab)");
				return NULL;
			}
			if (r_buf_read_at (bin->b, strtab_section->sh_offset,
					(ut8*)strtab, strtab_section->sh_size) == -1) {
				eprintf ("Warning: read (syms strtab)\n");
				return NULL;
			}

			if ((sym = (Elf_(Sym) *)calloc (1,1+bin->shdr[i].sh_size)) == NULL) {
				eprintf ("malloc (syms)");
				free (ret);
				free (strtab);
				return NULL;
			}
			nsym = (int)(bin->shdr[i].sh_size/sizeof (Elf_(Sym)));
			if (r_buf_fread_at (bin->b, bin->shdr[i].sh_offset, (ut8*)sym,
#if R_BIN_ELF64
					bin->endian? "I2cS2L": "i2cs2l",
#else
					bin->endian? "3I2cS": "3i2cs",
#endif
					nsym) == -1) {
				eprintf ("Warning: read (sym)\n");
				free (ret);
				free (sym);
				free (strtab);
				return NULL;
			}
			for (j = k = ret_ctr = 0; j < bin->shdr[i].sh_size; j += sizeof (Elf_(Sym)), k++) {
				if (k == 0)
					continue;
				if (type == R_BIN_ELF_IMPORTS && sym[k].st_shndx == STN_UNDEF) {
					if (sym[k].st_value)
						toffset = sym[k].st_value;
					else if ((toffset = Elf_(get_import_addr) (bin, k)) == -1)
						toffset = 0;
					tsize = 16;
				} else if (type == R_BIN_ELF_SYMBOLS && sym[k].st_shndx != STN_UNDEF &&
						ELF_ST_TYPE(sym[k].st_info) != STT_SECTION && ELF_ST_TYPE(sym[k].st_info) != STT_FILE) {
					//int idx = sym[k].st_shndx;
					tsize = sym[k].st_size;
					toffset = (ut64)sym[k].st_value; //-sym_offset; // + (ELF_ST_TYPE(sym[k].st_info) == STT_FUNC?sym_offset:data_offset);
				} else continue;
				if ((ret = realloc (ret, (ret_ctr + 1) * sizeof (struct r_bin_elf_symbol_t))) == NULL) {
					perror ("realloc (symbols|imports)");
					return NULL;
				}
#if 0
				if (bin->laddr) {
					int idx = sym[k].st_shndx;
					if (idx>=0 && idx < bin->ehdr.e_shnum) {
						if (bin->baddr && toffset>bin->baddr)
							toffset -= bin->baddr;
						else
							toffset += bin->shdr[idx].sh_offset;
					} else {
						//eprintf ("orphan symbol %d %d %s\n", idx, STN_UNDEF, &strtab[sym[k].st_name] );
						continue;
					}
				}
#endif
				ret[ret_ctr].offset = (toffset >= bin->baddr ? toffset -= bin->baddr : toffset);
				if (section_text) 
					ret[ret_ctr].offset += section_text_offset;
				ret[ret_ctr].size = tsize;
				if (sym[k].st_name<0 || sym[k].st_name > strtab_section->sh_size) {
					eprintf ("Warning: index out of strtab range\n");
					free (ret);
					free (sym);
					free (strtab);
					return NULL;
				}
				//len = r_str_nlen (strtab+sym[k].st_name, ELF_STRING_LENGTH-1);
				len = __strnlen (strtab+sym[k].st_name, ELF_STRING_LENGTH-1);
				memcpy (ret[ret_ctr].name, &strtab[sym[k].st_name], len);
				ret[ret_ctr].ordinal = k;
				ret[ret_ctr].name[ELF_STRING_LENGTH-2] = '\0';
				#define s_bind(x) snprintf (ret[ret_ctr].bind, ELF_STRING_LENGTH, x);
				switch (ELF_ST_BIND(sym[k].st_info)) {
				case STB_LOCAL:  s_bind ("LOCAL"); break;
				case STB_GLOBAL: s_bind ("GLOBAL"); break;
				case STB_NUM:    s_bind ("NUM"); break;
				case STB_LOOS:   s_bind ("LOOS"); break;
				case STB_HIOS:   s_bind ("HIOS"); break;
				case STB_LOPROC: s_bind ("LOPROC"); break;
				case STB_HIPROC: s_bind ("HIPROC"); break;
				default:         s_bind ("UNKNOWN");
				}
				#define s_type(x) snprintf (ret[ret_ctr].type, ELF_STRING_LENGTH, x);
				switch (ELF_ST_TYPE (sym[k].st_info)) {
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
				ret[ret_ctr].last = 0;
				ret_ctr++;
			}
			free(sym);
			sym = NULL;
			{
			ut8 *p = (ut8*)realloc (ret, (ret_ctr+1)* sizeof (struct r_bin_elf_symbol_t));
			if (!p) {
				free (ret);
				return NULL;
			}
			ret = (struct r_bin_elf_symbol_t *) p;
			}
			ret[ret_ctr].last = 1; // ugly dirty hack :D

			if (type == R_BIN_ELF_IMPORTS && !bin->imports_by_ord_size) {
				bin->imports_by_ord_size = nsym;
				bin->imports_by_ord = (RBinImport**)calloc (nsym, sizeof (RBinImport*));
			} else if (type == R_BIN_ELF_SYMBOLS && !bin->symbols_by_ord_size) {
				bin->symbols_by_ord_size = nsym;
				bin->symbols_by_ord = (RBinSymbol**)calloc (nsym, sizeof (RBinSymbol*));
			} else break;
		}
	}
	return ret;
}

struct r_bin_elf_field_t* Elf_(r_bin_elf_get_fields)(struct Elf_(r_bin_elf_obj_t) *bin) {
	struct r_bin_elf_field_t *ret = NULL;
	int i = 0, j;
	if (!bin)
		return NULL;
	if ((ret = calloc ((bin->ehdr.e_phnum+3 + 1),
			sizeof (struct r_bin_elf_field_t))) == NULL)
		return NULL;
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

void* Elf_(r_bin_elf_free)(struct Elf_(r_bin_elf_obj_t)* bin) {
	int i;
	if (!bin) return NULL;
	free (bin->phdr);
	free (bin->shdr);
	free (bin->strtab);
	//free (bin->strtab_section);
	if (bin->imports_by_ord) {
		for (i=0; i<bin->imports_by_ord_size; i++)
			free (bin->imports_by_ord[i]);
		free (bin->imports_by_ord);
	}
	if (bin->symbols_by_ord) {
		for (i=0; i<bin->symbols_by_ord_size; i++)
			free (bin->symbols_by_ord[i]);
		free (bin->symbols_by_ord);
	}
	r_buf_free (bin->b);
	free (bin);
	return NULL;
}

struct Elf_(r_bin_elf_obj_t)* Elf_(r_bin_elf_new)(const char* file) {
	ut8 *buf;
	struct Elf_(r_bin_elf_obj_t) *bin = R_NEW0 (struct Elf_(r_bin_elf_obj_t));

	if (!bin) return NULL;
	memset (bin, 0, sizeof (struct Elf_(r_bin_elf_obj_t)));
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp (file, &bin->size)))
		return Elf_(r_bin_elf_free) (bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)){
		free (buf);
		return Elf_(r_bin_elf_free) (bin);
	}
	if (!Elf_(r_bin_elf_init) (bin)) {
		return Elf_(r_bin_elf_free) (bin);
	}
	return bin;
}

struct Elf_(r_bin_elf_obj_t)* Elf_(r_bin_elf_new_buf)(struct r_buf_t *buf) {
	struct Elf_(r_bin_elf_obj_t) *bin = R_NEW0 (struct Elf_(r_bin_elf_obj_t));
	bin->kv = sdb_new0 ();
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, buf->length))
		return Elf_(r_bin_elf_free) (bin);
	if (!Elf_(r_bin_elf_init) (bin))
		return Elf_(r_bin_elf_free) (bin);
	return bin;
}
