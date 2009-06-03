/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#if __UNIX__
#include <sys/mman.h>
#endif

#include <r_types.h>

#include "elf.h"

/* TODO: move into bin_t */
static int endian = 0;

enum {
	ENCODING_ASCII = 0,
	ENCODING_CP850 = 1
};

static void ELF_(aux_swap_endian)(u8 *value, int size)
{
	unsigned char buffer[8];

	if (!endian)
		return;

	switch(size) {
	case 2:
		memcpy(buffer, value, 2);
		value[0] = buffer[1];
		value[1] = buffer[0];
		break;
	case 4:
		memcpy(buffer, value, 4);
		value[0] = buffer[3];
		value[1] = buffer[2];
		value[2] = buffer[1];
		value[3] = buffer[0];
		break;
	case 8:
		memcpy(buffer, value, 8);
		value[0] = buffer[7];
		value[1] = buffer[6];
		value[2] = buffer[5];
		value[3] = buffer[4];
		value[4] = buffer[3];
		value[5] = buffer[2];
		value[6] = buffer[1];
		value[7] = buffer[0];
		break;
	default:
		printf("Invalid size: %d\n", size);
	}
}

static int ELF_(aux_is_encoded)(int encoding, unsigned char c)
{
	switch(encoding) {
	case ENCODING_ASCII:
		break;
	case ENCODING_CP850:
		switch(c) {
		// CP850
		case 128: // cedilla
		case 133: // a grave
		case 135: // minicedilla
		case 160: // a acute
		case 161: // i acute
		case 129: // u dieresi
		case 130: // e acute
		case 139: // i dieresi
		case 162: // o acute
		case 163: // u acute
		case 164: // enye
		case 165: // enyemay
		case 181: // A acute
		case 144: // E acute
		case 214: // I acute
		case 224: // O acute
		case 233: // U acute
			return 1;
		}
		break;
	}
	return 0;
}

static int ELF_(aux_stripstr_from_file)(const char *filename, int min, int encoding, u64 seek, u64 limit, const char *filter, int str_limit, r_bin_elf_string *strings)
{
	r_bin_elf_string *stringsp;
	unsigned char *buf;
	u64 i = seek;
	u64 len, string_len;
	int unicode = 0, matches = 0;
	static int ctr = 0;
	char str[ELF_STRING_LENGTH];

	int fd = open(filename, O_RDONLY);
	if (fd == -1) {
		ERR("Cannot open target file.\n");
		return 1;
	}

	len = lseek(fd, 0, SEEK_END);

	/* TODO: do not use mmap (is faster..but not portable) */
#if __UNIX__
	buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0); // XXX SHARED?
	if (((long)buf) == -1) {
		perror("mmap");
		return 1;
	}
	if (min <1)
		min = 5;

	if (limit && limit < len)
		len = limit;

	stringsp = strings;
	for(i = seek; i < len && ctr < str_limit; i++) { 
		if (IS_PRINTABLE(buf[i]) || (ELF_(aux_is_encoded)(encoding, buf[i]))) {
			str[matches] = buf[i];
			if (matches < sizeof(str))
				matches++;
		} else {
			/* wide char check \x??\x00\x??\x00 */
			if (matches && buf[i+2]=='\0' && buf[i]=='\0' && buf[i+1]!='\0')
				unicode = 1;
			/* check if the length fits on our request */
			if (matches >= min) {
				str[matches] = '\0';
				string_len = strlen(str);
				if (string_len>2) {
					if (!filter || strstr(str, filter)) {
						stringsp->offset = i-matches;
						stringsp->type = (unicode?'U':'A');
						stringsp->size = string_len;
						memcpy(stringsp->string, str, ELF_STRING_LENGTH);
						stringsp->string[ELF_STRING_LENGTH-1] = '\0';
						ctr++; stringsp++;
					}
				}
			}
			matches = 0;
			unicode = 0;
		}
	}

	munmap(buf, len); 
#elif __WINDOWS__
	ERR("Not yet implemented\n");
#endif
	return ctr;
}

static int ELF_(do_elf_checks)(ELF_(r_bin_elf_obj) *bin)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;

	if (strncmp((char *)ehdr->e_ident, ELFMAG, SELFMAG)) {
		ERR("File not ELF\n");
		return -1;
	}

	if (ehdr->e_version != EV_CURRENT) {
		ERR("ELF version not current\n");
		return -1;
	}

	return 0;
}

static int ELF_(load_section)(char **section, int fd, ELF_(Shdr) *shdr)
{
	if (lseek(fd, shdr->sh_offset, SEEK_SET) < 0) {
		perror("lseek");
		return -1;
	}

	*section = (char *)malloc(shdr->sh_size);
	if (*section == NULL) {
		perror("malloc");
		return -1;
	}

	if (read(fd, *section, shdr->sh_size) != shdr->sh_size) {
		perror("read");
		return -1;
	}

	return 0;
}

static int ELF_(r_bin_elf_init)(ELF_(r_bin_elf_obj) *bin)
{
	ELF_(Ehdr) *ehdr;
	ELF_(Shdr) *shdr;
	ELF_(Shdr) *strtabhdr;
	ELF_(Phdr) *phdr;
	char **sectionp;
	int i, slen;
	
	bin->base_addr = 0;
	ehdr = &bin->ehdr;

	if (lseek(bin->fd, 0, SEEK_SET) < 0) {
		perror("lseek");
		return -1;
	}
	if (read(bin->fd, ehdr, sizeof(ELF_(Ehdr))) != sizeof(ELF_(Ehdr))) {
		perror("read");
		return -1;
	}

	if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB)
		endian = LIL_ENDIAN;
	else    endian = !LIL_ENDIAN;

	ELF_(aux_swap_endian)((u8*)&(ehdr->e_type), sizeof(ELF_(Half)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_machine), sizeof(ELF_(Half)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_version), sizeof(ELF_(Word)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_entry), sizeof(ELF_(Addr)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_phoff), sizeof(ELF_(Off)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_shoff), sizeof(ELF_(Off)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_flags), sizeof(ELF_(Word)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_ehsize), sizeof(ELF_(Half)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_phentsize), sizeof(ELF_(Half)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_phnum), sizeof(ELF_(Half)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_shentsize), sizeof(ELF_(Half)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_shnum), sizeof(ELF_(Half)));
	ELF_(aux_swap_endian)((u8*)&(ehdr->e_shstrndx), sizeof(ELF_(Half)));

//printf("E_SHOFF: %x\n", ehdr->e_shoff);
	if (ELF_(do_elf_checks)(bin) == -1)
		return -1;

	bin->phdr = (ELF_(Phdr) *)malloc(bin->plen = sizeof(ELF_(Phdr))*ehdr->e_phnum);
	if (bin->phdr == NULL) {
		perror("malloc");
		return -1;
	}

	if (lseek(bin->fd, ehdr->e_phoff, SEEK_SET) < 0) {
		perror("lseek");
		return -1;
	}

	if (read(bin->fd, bin->phdr, bin->plen) != bin->plen) {
		ERR("Warning: Cannot read program headers (0x%08x->0x%08x)\n",
			(unsigned int)ehdr->e_phoff, (unsigned int)((long)&ehdr->e_phoff-(long)&ehdr->e_ident));
		perror("read");
		//return -1;
	}

	for (i = 0, phdr = bin->phdr; i < ehdr->e_phnum; i++) {
		ELF_(aux_swap_endian)((u8*)&(phdr[i].p_type), sizeof(ELF_(Word)));
		ELF_(aux_swap_endian)((u8*)&(phdr[i].p_offset), sizeof(ELF_(Off)));
		ELF_(aux_swap_endian)((u8*)&(phdr[i].p_vaddr), sizeof(ELF_(Addr)));
		ELF_(aux_swap_endian)((u8*)&(phdr[i].p_paddr), sizeof(ELF_(Addr)));
		ELF_(aux_swap_endian)((u8*)&(phdr[i].p_filesz), sizeof(ELF_Vword));
		ELF_(aux_swap_endian)((u8*)&(phdr[i].p_memsz), sizeof(ELF_Vword));
		ELF_(aux_swap_endian)((u8*)&(phdr[i].p_flags), sizeof(ELF_(Word)));
		ELF_(aux_swap_endian)((u8*)&(phdr[i].p_align), sizeof(ELF_Vword));
	}

	bin->shdr = (ELF_(Shdr) *)malloc(slen = sizeof(ELF_(Shdr))*ehdr->e_shnum);
	if (bin->shdr == NULL) {
		perror("malloc");
		return -1;
	}

	bin->section = (char **)malloc(sizeof(char **)*ehdr->e_shnum);
	if (bin->section == NULL) {
		perror("malloc");
		return -1;
	}

	//printf("shtoff = %d\n", ehdr->e_shoff);
	if (lseek(bin->fd, ehdr->e_shoff, SEEK_SET) < 0) {
		perror("lseek");
		//return -1;
	}

	//printf("shtlen = %d\n", slen);
	if (read(bin->fd, bin->shdr, slen) != slen) {
		ERR("Warning: Cannot read section headers (0x%08x->0x%08x)\n",
			(unsigned int)ehdr->e_shoff, (unsigned int)((long)&ehdr->e_shoff-(long)&ehdr->e_ident));
		perror("read");
		ERR("Warning: Cannot read %d sections.\n", ehdr->e_shnum);
		ehdr->e_shnum=0;
		//return -1;
	}

	for (i = 0, shdr = bin->shdr; i < ehdr->e_shnum; i++) {
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_name), sizeof(ELF_(Word)));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_type), sizeof(ELF_(Word)));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_flags), sizeof(ELF_Vword));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_addr), sizeof(ELF_(Addr)));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_offset), sizeof(ELF_(Off)));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_size), sizeof(ELF_Vword));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_link), sizeof(ELF_(Word)));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_info), sizeof(ELF_(Word)));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_addralign), sizeof(ELF_Vword));
		ELF_(aux_swap_endian)((u8*)&(shdr[i].sh_entsize), sizeof(ELF_Vword));
	}

	strtabhdr = &bin->shdr[ehdr->e_shstrndx];

	bin->string = (char *)malloc(strtabhdr->sh_size);
	if (bin->string == NULL) {
		perror("malloc");
		return -1;
	}

	if (lseek(bin->fd, strtabhdr->sh_offset, SEEK_SET) != strtabhdr->sh_offset) {
		perror("lseek");
		//return -1;
	}

	if (read(bin->fd, bin->string, strtabhdr->sh_size) != strtabhdr->sh_size) {
		perror("read");
		ERR("Warning: Cannot read strtabhdr.\n");
		//return -1;
	}

	bin->bss = -1;

	for (i = 0, sectionp = bin->section, shdr = bin->shdr; i < ehdr->e_shnum; i++, sectionp++) {
		if (shdr[i].sh_type == SHT_NOBITS) {
			bin->bss = i;
		} else {
			if (ELF_(load_section)(sectionp, bin->fd, &shdr[i]) == -1)
				return -1;
		}
	}

	bin->base_addr = ELF_(r_bin_elf_get_base_addr)(bin);

	return 0;
}

static u64 ELF_(get_import_addr)(ELF_(r_bin_elf_obj) *bin, int sym)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	ELF_(Addr) plt_sym_addr, got_addr = 0;
	const char *string = bin->string;
	int i, j;
	u64 got_offset;
	
	shdrp = shdr;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&string[shdrp->sh_name], ".got.plt"))
			got_addr = shdrp->sh_offset;
	}
	if (got_addr == 0) {
		/* TODO: Unknown GOT address */
	}

	shdrp = shdr;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&string[shdrp->sh_name], ".rel.plt")) {
			ELF_(Rel) *rel, *relp;
			rel = (ELF_(Rel) *)malloc(shdrp->sh_size);
			if (rel == NULL) {
				perror("malloc");
				return 0;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) != shdrp->sh_offset) {
				perror("lseek");
				return 0;
			}

			if (read(bin->fd, rel, shdrp->sh_size) != shdrp->sh_size) {
				perror("read");
				return 0;
			}

			relp = rel;
			for (j = 0; j < shdrp->sh_size; j += sizeof(ELF_(Rel)), relp++) {
				ELF_(aux_swap_endian)((u8*)&(relp->r_offset), sizeof(ELF_(Addr)));
				ELF_(aux_swap_endian)((u8*)&(relp->r_info), sizeof(ELF_Vword));
			}

			got_offset = (rel->r_offset - bin->base_addr - got_addr) & ELF_GOTOFF_MASK;
			relp = rel;
			for (j = 0; j < shdrp->sh_size; j += sizeof(ELF_(Rel)), relp++) {
				if (ELF_R_SYM(relp->r_info) == sym) {
					if (lseek(bin->fd, relp->r_offset-bin->base_addr-got_offset, SEEK_SET)
							!= relp->r_offset-bin->base_addr-got_offset) {
						perror("lseek");
						return 0;
					}

					if (read(bin->fd, &plt_sym_addr, sizeof(ELF_(Addr))) != sizeof(ELF_(Addr))) {
						perror("read");
						return 0;
					}

					return plt_sym_addr-6;
				}
			}
		} else if (!strcmp(&string[shdrp->sh_name], ".rela.plt")) {
			ELF_(Rela) *rel, *relp;
			rel = (ELF_(Rela) *)malloc(shdrp->sh_size);
			if (rel == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) != shdrp->sh_offset) {
				perror("lseek");
				return -1;
			}

			if (read(bin->fd, rel, shdrp->sh_size) != shdrp->sh_size) {
				perror("read");
				return -1;
			}

			relp = rel;
			for (j = 0; j < shdrp->sh_size; j += sizeof(ELF_(Rela)), relp++) {
				ELF_(aux_swap_endian)((u8*)&(relp->r_offset), sizeof(ELF_(Addr)));
				ELF_(aux_swap_endian)((u8*)&(relp->r_info), sizeof(ELF_Vword));
			}

			got_offset = (rel->r_offset - bin->base_addr - got_addr) & ELF_GOTOFF_MASK;
			relp = rel;
			for (j = 0; j < shdrp->sh_size; j += sizeof(ELF_(Rela)), relp++) {
				if (ELF_R_SYM(relp->r_info) == sym) {
					if (lseek(bin->fd, relp->r_offset-bin->base_addr-got_offset, SEEK_SET)
							!= relp->r_offset-bin->base_addr-got_offset) {
						perror("lseek");
						return 0;
					}

					if (read(bin->fd, &plt_sym_addr, sizeof(ELF_(Addr))) != sizeof(ELF_(Addr))) {
						perror("read");
						return 0;
					}

					return plt_sym_addr-6;
				}
			}
		}
	}

	return 0;
}

static u64 ELF_(r_bin_elf_get_section_offset)(ELF_(r_bin_elf_obj) *bin, const char *section_name)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *string = bin->string;
	int i;

	for (shdrp=shdr, i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&string[shdrp->sh_name], section_name))
			return shdrp->sh_offset;
	}

	return -1;
}

int ELF_(r_bin_elf_close)(ELF_(r_bin_elf_obj) *bin)
{
	return close(bin->fd);
}

const char* ELF_(r_bin_elf_get_arch)(ELF_(r_bin_elf_obj) *bin)
{
	u16 machine = bin->ehdr.e_machine;

	switch (machine) {
	case EM_MIPS:
	case EM_MIPS_RS3_LE:
	case EM_MIPS_X:
		return "mips";
	case EM_ARM:
		return "arm";
	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		return "sparc";
	case EM_PPC:
	case EM_PPC64:
		return "ppc"; // "powerpc" ?
	case EM_68K:
		return "m68k";
	case EM_IA_64:
	case EM_X86_64:
		return "intel64";
	default: return "intel";
	}
}

u64 ELF_(r_bin_elf_get_base_addr)(ELF_(r_bin_elf_obj) *bin)
{
	return bin->phdr->p_vaddr & ELF_ADDR_MASK;
}

u64 ELF_(r_bin_elf_get_entry_offset)(ELF_(r_bin_elf_obj) *bin)
{
	return bin->ehdr.e_entry - bin->base_addr; 
}

int ELF_(r_bin_elf_get_stripped)(ELF_(r_bin_elf_obj) *bin)
{
	int i;
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;

	shdrp = shdr;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++)
		if (shdrp->sh_type == SHT_SYMTAB)
			return 0;
	return 1;
}

int ELF_(r_bin_elf_get_static)(ELF_(r_bin_elf_obj) *bin)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Phdr) *phdr = bin->phdr, *phdrp;
	int i;

	for (phdrp=phdr, i = 0; i < ehdr->e_phnum; i++, phdrp++)
		if (phdrp->p_type == PT_INTERP)
			return 0;
	return 1;
}

const char* ELF_(r_bin_elf_get_data_encoding)(ELF_(r_bin_elf_obj) *bin)
{
	unsigned int encoding = bin->ehdr.e_ident[EI_DATA];
	static char buf[32];

	switch (encoding) {
	case ELFDATANONE: return "none";
	case ELFDATA2LSB: return "2's complement, little endian";
	case ELFDATA2MSB: return "2's complement, big endian";
	}
	snprintf (buf, sizeof (buf), "<unknown: %x>", encoding);
	return buf;
}

const char* ELF_(r_bin_elf_get_machine_name)(ELF_(r_bin_elf_obj) *bin)
{
	unsigned int e_machine = bin->ehdr.e_machine;
	static char buf[64]; 

	switch (e_machine) {
	case EM_NONE: 		return "No machine";
	case EM_M32: 		return "AT&T WE 32100";
	case EM_SPARC: 		return "SUN SPARC";
	case EM_386: 		return "Intel 80386";
	case EM_68K: 		return "Motorola m68k family";
	case EM_88K: 		return "Motorola m88k family";
	case EM_860: 		return "Intel 80860";
	case EM_MIPS: 		return "MIPS R3000 big-endian";
	case EM_S370: 		return "IBM System/370";
	case EM_MIPS_RS3_LE: 	return "MIPS R3000 little-endian";
	case EM_PARISC: 	return "HPPA";
	case EM_VPP500: 	return "Fujitsu VPP500";
	case EM_SPARC32PLUS: 	return "Sun's \"v8plus\"";
	case EM_960: 		return "Intel 80960";
	case EM_PPC: 		return "PowerPC";
	case EM_PPC64: 		return "PowerPC 64-bit";
	case EM_S390: 		return "IBM S390";
	case EM_V800: 		return "NEC V800 series";
	case EM_FR20: 		return "Fujitsu FR20";
	case EM_RH32: 		return "TRW RH-32";
	case EM_RCE: 		return "Motorola RCE";
	case EM_ARM: 		return "ARM";
	case EM_FAKE_ALPHA: 	return "Digital Alpha";
	case EM_SH: 		return "Hitachi SH";
	case EM_SPARCV9:	return "SPARC v9 64-bit";
	case EM_TRICORE:	return "Siemens Tricore";
	case EM_ARC: 		return "Argonaut RISC Core";
	case EM_H8_300: 	return "Hitachi H8/300";
	case EM_H8_300H:	return "Hitachi H8/300H";
	case EM_H8S: 		return "Hitachi H8S";
	case EM_H8_500: 	return "Hitachi H8/500";
	case EM_IA_64: 		return "Intel Merced";
	case EM_MIPS_X: 	return "Stanford MIPS-X";
	case EM_COLDFIRE:	return "Motorola Coldfire";
	case EM_68HC12: 	return "Motorola M68HC12";
	case EM_MMA: 		return "Fujitsu MMA Multimedia Accelerator";
	case EM_PCP: 		return "Siemens PCP";
	case EM_NCPU: 		return "Sony nCPU embeeded RISC";
	case EM_NDR1: 		return "Denso NDR1 microprocessor";
	case EM_STARCORE: 	return "Motorola Start*Core processor";
	case EM_ME16: 		return "Toyota ME16 processor";
	case EM_ST100: 		return "STMicroelectronic ST100 processor";
	case EM_TINYJ: 		return "Advanced Logic Corp. Tinyj emb.fam";
	case EM_X86_64: 	return "AMD x86-64 architecture";
	case EM_PDSP: 		return "Sony DSP Processor";
	case EM_FX66: 		return "Siemens FX66 microcontroller";
	case EM_ST9PLUS:	return "STMicroelectronics ST9+ 8/16 mc";
	case EM_ST7: 		return "STmicroelectronics ST7 8 bit mc";
	case EM_68HC16: 	return "Motorola MC68HC16 microcontroller";
	case EM_68HC11: 	return "Motorola MC68HC11 microcontroller";
	case EM_68HC08: 	return "Motorola MC68HC08 microcontroller";
	case EM_68HC05: 	return "Motorola MC68HC05 microcontroller";
	case EM_SVX: 		return "Silicon Graphics SVx";
	case EM_ST19: 		return "STMicroelectronics ST19 8 bit mc";
	case EM_VAX: 		return "Digital VAX";
	case EM_CRIS: 		return "Axis Communications 32-bit embedded processor";
	case EM_JAVELIN:	return "Infineon Technologies 32-bit embedded processor";
	case EM_FIREPATH:	return "Element 14 64-bit DSP Processor";
	case EM_ZSP: 		return "LSI Logic 16-bit DSP Processor";
	case EM_MMIX: 		return "Donald Knuth's educational 64-bit processor";
	case EM_HUANY: 		return "Harvard University machine-independent object files";
	case EM_PRISM: 		return "SiTera Prism";
	case EM_AVR: 		return "Atmel AVR 8-bit microcontroller";
	case EM_FR30: 		return "Fujitsu FR30";
	case EM_D10V: 		return "Mitsubishi D10V";
	case EM_D30V: 		return "Mitsubishi D30V";
	case EM_V850: 		return "NEC v850";
	case EM_M32R: 		return "Mitsubishi M32R";
	case EM_MN10300:	return "Matsushita MN10300";
	case EM_MN10200:	return "Matsushita MN10200";
	case EM_PJ: 		return "picoJava";
	case EM_OPENRISC:	return "OpenRISC 32-bit embedded processor";
	case EM_ARC_A5: 	return "ARC Cores Tangent-A5";
	case EM_XTENSA: 	return "Tensilica Xtensa Architecture";
	}
	snprintf (buf, sizeof(buf), "<unknown>: 0x%x", e_machine);
	return buf;
}

const char* ELF_(r_bin_elf_get_file_type)(ELF_(r_bin_elf_obj) *bin)
{
	unsigned int e_type = bin->ehdr.e_type;
	static char buf[32];

	switch (e_type) {
	case ET_NONE:	return "NONE (None)";
	case ET_REL:	return "REL (Relocatable file)";
	case ET_EXEC:	return "EXEC (Executable file)";
	case ET_DYN:	return "DYN (Shared object file)";
	case ET_CORE:	return "CORE (Core file)";
	}

	if ((e_type >= ET_LOPROC) && (e_type <= ET_HIPROC))
		snprintf (buf, sizeof (buf), "Processor Specific: (%x)", e_type);
	else if ((e_type >= ET_LOOS) && (e_type <= ET_HIOS))
		snprintf (buf, sizeof (buf), "OS Specific: (%x)", e_type);
	else snprintf (buf, sizeof (buf), "<unknown>: %x", e_type);

	return buf;
}

const char* ELF_(r_bin_elf_get_elf_class)(ELF_(r_bin_elf_obj) *bin)
{
	unsigned int elf_class = bin->ehdr.e_ident[EI_CLASS];
	static char buf[32];

	switch (elf_class) {
	case ELFCLASSNONE: return "none";
	case ELFCLASS32:   return "ELF32";
	case ELFCLASS64:   return "ELF64";
	}
	snprintf (buf, sizeof (buf), "<unknown: %x>", elf_class);
	return buf;
}

const char* ELF_(r_bin_elf_get_osabi_name)(ELF_(r_bin_elf_obj) *bin)
{
	unsigned int osabi = bin->ehdr.e_ident[EI_OSABI];
	static char buf[32];

	switch (osabi) {
	case ELFOSABI_NONE:		return "linux"; // sysv
	case ELFOSABI_HPUX:		return "hpux";
	case ELFOSABI_NETBSD:		return "netbsd";
	case ELFOSABI_LINUX:		return "linux";
	case ELFOSABI_SOLARIS:		return "solaris";
	case ELFOSABI_AIX:		return "aix";
	case ELFOSABI_IRIX:		return "irix";
	case ELFOSABI_FREEBSD:		return "freebsd";
	case ELFOSABI_TRU64:		return "tru64";
	case ELFOSABI_MODESTO:		return "modesto";
	case ELFOSABI_OPENBSD:		return "openbsd";
	case ELFOSABI_STANDALONE:	return "standalone";
	case ELFOSABI_ARM:		return "arm";
	}
	snprintf (buf, sizeof (buf), "<unknown: %x>", osabi);
	return buf;
}

int ELF_(r_bin_elf_is_big_endian)(ELF_(r_bin_elf_obj) *bin)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;

	return (ehdr->e_ident[EI_DATA] == ELFDATA2MSB);
}

/* TODO: Take care of endianess */
/* TODO: Real error handling */
/* TODO: Resize sections before .init */
u64 ELF_(r_bin_elf_resize_section)(ELF_(r_bin_elf_obj) *bin, const char *name, u64 size)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Phdr) *phdr = bin->phdr, *phdrp;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *string = bin->string;
	u8 *buf;
	u64 off, got_offset, got_addr = 0, rsz_offset, delta = 0;
	u64 rsz_osize = 0, rsz_fsize, rsz_size = size, rest_size = 0;
	int i, j, done = 0;

	if (size == 0) {
		printf("0 size section?\n");
		return 0;
	}
	rsz_fsize = lseek(bin->fd, 0, SEEK_END);

	/* calculate delta */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) 
		if (!strncmp(name, &string[shdrp->sh_name], ELF_NAME_LENGTH)) {
			delta =  rsz_size - shdrp->sh_size;
			rsz_offset = (u64)shdrp->sh_offset;
			rsz_osize = (u64)shdrp->sh_size;
		}

	if (delta == 0) {
		printf("Cannot find section\n");
		return 0;
	}
 
	printf("delta: %lld\n", delta);
	
	/* rewrite rel's (imports) */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&string[shdrp->sh_name], ".got.plt"))
			got_addr = (u64)shdrp->sh_offset;
	}
	if (got_addr == 0) {
		/* TODO: Unknown GOT address */
	}

	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&string[shdrp->sh_name], ".rel.plt")) {
			ELF_(Rel) *rel, *relp;
			rel = (ELF_(Rel) *)malloc(shdrp->sh_size);
			if (rel == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) < 0)
				perror("lseek");
			if (read(bin->fd, rel, shdrp->sh_size) != shdrp->sh_size)
				perror("read");

			got_offset = (rel->r_offset - bin->base_addr - got_addr) & ELF_GOTOFF_MASK;
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof(ELF_(Rel)), relp++) {
				ELF_(aux_swap_endian)((u8*)&(relp->r_offset), sizeof(ELF_(Addr)));
				/* rewrite relp->r_offset */
				if (relp->r_offset - bin->base_addr - got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset+=delta;
					off = shdrp->sh_offset + j;

					if (lseek(bin->fd, off, SEEK_SET) < 0)
						perror("lseek");
					if (write(bin->fd, &relp, sizeof(ELF_(Rel))) != sizeof(ELF_(Rel)))
						perror("write (imports)");
				}
			}
			free(rel);
			break;
		} else if (!strcmp(&string[shdrp->sh_name], ".rela.plt")) {
			ELF_(Rela) *rel, *relp;
			rel = (ELF_(Rela) *)malloc(shdrp->sh_size);
			if (rel == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) < 0)
				perror("lseek");
			if (read(bin->fd, rel, shdrp->sh_size) != shdrp->sh_size)
				perror("read");

			got_offset = (rel->r_offset - bin->base_addr - got_addr) & ELF_GOTOFF_MASK;
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof(ELF_(Rela)), relp++) {
				ELF_(aux_swap_endian)((u8*)&(relp->r_offset), sizeof(ELF_(Addr)));
				/* rewrite relp->r_offset */
				if (relp->r_offset - bin->base_addr - got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset+=delta;
					off = shdrp->sh_offset + j;

					if (lseek(bin->fd, off, SEEK_SET) < 0)
						perror("lseek");
					if (write(bin->fd, &relp, sizeof(ELF_(Rela))) != sizeof(ELF_(Rela)))
						perror("write (imports)");
				}
			}
			free(rel);
			break;
		}
	}

	/* rewrite section headers */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!done && !strncmp(name, &string[shdrp->sh_name], ELF_NAME_LENGTH)) {
			shdrp->sh_size = rsz_size;
			done = 1;
		} else if (shdrp->sh_offset >= rsz_offset + rsz_osize) {
			shdrp->sh_offset += delta;
			if (shdrp->sh_addr) shdrp->sh_addr += delta;

		}
		off = ehdr->e_shoff + i * sizeof(ELF_(Shdr));
		if (lseek(bin->fd, off, SEEK_SET) < 0)
			perror("lseek");
		if (write(bin->fd, shdrp, sizeof(ELF_(Shdr))) != sizeof(ELF_(Shdr)))
			perror("write (shdr)");
		printf("-> elf section (%s)\n", &string[shdrp->sh_name]);
	}

	/* rewrite program headers */
	for (i = 0, phdrp = phdr; i < ehdr->e_phnum; i++, phdrp++) {
#if 0 
		if (phdrp->p_offset < rsz_offset && phdrp->p_offset + phdrp->p_filesz > rsz_offset) {
			phdrp->p_filesz += delta;
			phdrp->p_memsz += delta;
		}
#endif 
		if (phdrp->p_offset >= rsz_offset + rsz_osize) {
			phdrp->p_offset += delta;
			if (phdrp->p_vaddr) phdrp->p_vaddr += delta;
			if (phdrp->p_paddr) phdrp->p_paddr += delta;
		}
		off = ehdr->e_phoff + i * sizeof(ELF_(Phdr));
		if (lseek(bin->fd, off, SEEK_SET) < 0)
			perror("lseek");
		if (write(bin->fd, phdrp, sizeof(ELF_(Phdr))) != sizeof(ELF_(Phdr)))
			perror("write (phdr)");
		printf("-> program header (%08llx)\n", (u64) phdrp->p_offset);
	}

	/* rewrite other elf pointers (entrypoint, phoff, shoff) */
	if (ehdr->e_entry - bin->base_addr >= rsz_offset + rsz_osize)
		ehdr->e_entry += delta;
	if (ehdr->e_phoff >= rsz_offset + rsz_osize)
		ehdr->e_phoff += delta;
	if (ehdr->e_shoff >= rsz_offset + rsz_osize)
		ehdr->e_shoff += delta;
	if (lseek(bin->fd, 0, SEEK_SET) < 0)
		perror("lseek");
	if (write(bin->fd, ehdr, sizeof(ELF_(Ehdr))) != sizeof(ELF_(Ehdr)))
		perror("write (ehdr)");

	/* inverse order to write bodies .. avoid overlapping here */
	/* XXX Check when delta is negative */
	rest_size = rsz_fsize - (rsz_offset + rsz_osize);
	buf = (u8 *)malloc(rest_size);
	printf("COPY FROM 0x%08llx\n", (u64) rsz_offset+rsz_osize);
	lseek(bin->fd, rsz_offset+rsz_osize, SEEK_SET);
	read(bin->fd, buf, rest_size);

	printf("COPY TO 0x%08llx\n", (u64) rsz_offset+rsz_size);
	lseek(bin->fd, rsz_offset+rsz_size, SEEK_SET);
	write(bin->fd, buf, rest_size);
	printf("Shifted %d bytes\n", (int)delta);
	free(buf);

	/* Reinit structs*/
	ELF_(r_bin_elf_init)(bin);

	return delta;
}

int ELF_(r_bin_elf_get_sections)(ELF_(r_bin_elf_obj) *bin, r_bin_elf_section *section)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	r_bin_elf_section *sectionp;
	const char *string = bin->string;
	int i;

	shdrp = shdr;
	sectionp = section;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++, sectionp++) {
		sectionp->offset = shdrp->sh_offset;
		sectionp->size = shdrp->sh_size;
		sectionp->align = shdrp->sh_addralign;
		sectionp->flags = shdrp->sh_flags;
		strncpy(sectionp->name, &string[shdrp->sh_name], ELF_NAME_LENGTH);
	}

	return i;
}

int ELF_(r_bin_elf_get_sections_count)(ELF_(r_bin_elf_obj) *bin)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	return ehdr->e_shnum;
}

int ELF_(r_bin_elf_get_imports)(ELF_(r_bin_elf_obj) *bin, r_bin_elf_import *import)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	ELF_(Sym) *sym, *symp;
	ELF_(Shdr) *strtabhdr;
	r_bin_elf_import *importp;
	char *string;
	int i, j, k;

	shdrp = shdr;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (shdrp->sh_type == (bin->ehdr.e_type == ET_REL?SHT_SYMTAB:SHT_DYNSYM)) {
			strtabhdr = &shdr[shdrp->sh_link];

			string = (char *)malloc(strtabhdr->sh_size);
			if (string == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, strtabhdr->sh_offset, SEEK_SET) != strtabhdr->sh_offset) {
				perror("lseek");
				return -1;
			}

			if (read(bin->fd, string, strtabhdr->sh_size) != strtabhdr->sh_size) {
				perror("read");
				return -1;
			}

			sym = (ELF_(Sym) *)malloc(shdrp->sh_size);
			if (sym == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) != shdrp->sh_offset) {
				perror("lseek");
				return -1;
			}

			if (read(bin->fd, sym, shdrp->sh_size) != shdrp->sh_size) {
				perror("read");
				return -1;
			}

			symp = sym;
			for (j = 0; j < shdrp->sh_size; j += sizeof(ELF_(Sym)), symp++) {
				ELF_(aux_swap_endian)((u8*)&(symp->st_name), sizeof(ELF_(Word)));
				ELF_(aux_swap_endian)((u8*)&(symp->st_value), sizeof(ELF_(Addr)));
				ELF_(aux_swap_endian)((u8*)&(symp->st_size), sizeof(ELF_Vword));
				ELF_(aux_swap_endian)((u8*)&(symp->st_shndx), sizeof(ELF_(Section)));
			}

			importp = import;
			symp = sym;
			for (j = 0, k = 0; j < shdrp->sh_size; j += sizeof(ELF_(Sym)), k++, symp++) {
				if (k == 0)
					continue;
				if (symp->st_shndx == STN_UNDEF) {
					memcpy(importp->name, &string[symp->st_name], ELF_NAME_LENGTH);
					importp->name[ELF_NAME_LENGTH-1] = '\0';
					if (symp->st_value)
						importp->offset = symp->st_value;
					else
						importp->offset = ELF_(get_import_addr)(bin, k);
					if (importp->offset >= bin->base_addr)
						importp->offset -= bin->base_addr;

					switch (ELF_ST_BIND(symp->st_info)) {
					case STB_LOCAL:  snprintf(importp->bind, ELF_NAME_LENGTH, "LOCAL"); break;
					case STB_GLOBAL: snprintf(importp->bind, ELF_NAME_LENGTH, "GLOBAL"); break;
					case STB_NUM:    snprintf(importp->bind, ELF_NAME_LENGTH, "NUM"); break;
					case STB_LOOS:   snprintf(importp->bind, ELF_NAME_LENGTH, "LOOS"); break;
					case STB_HIOS:   snprintf(importp->bind, ELF_NAME_LENGTH, "HIOS"); break;
					case STB_LOPROC: snprintf(importp->bind, ELF_NAME_LENGTH, "LOPROC"); break;
					case STB_HIPROC: snprintf(importp->bind, ELF_NAME_LENGTH, "HIPROC"); break;
					default:	 snprintf(importp->bind, ELF_NAME_LENGTH, "UNKNOWN");
					}
					switch (ELF_ST_TYPE(symp->st_info)) {
					case STT_NOTYPE:  snprintf(importp->type, ELF_NAME_LENGTH, "NOTYPE"); break;
					case STT_OBJECT:  snprintf(importp->type, ELF_NAME_LENGTH, "OBJECT"); break;
					case STT_FUNC:    snprintf(importp->type, ELF_NAME_LENGTH, "FUNC"); break;
					case STT_SECTION: snprintf(importp->type, ELF_NAME_LENGTH, "SECTION"); break;
					case STT_FILE:    snprintf(importp->type, ELF_NAME_LENGTH, "FILE"); break;
					case STT_COMMON:  snprintf(importp->type, ELF_NAME_LENGTH, "COMMON"); break;
					case STT_TLS:     snprintf(importp->type, ELF_NAME_LENGTH, "TLS"); break;
					case STT_NUM:     snprintf(importp->type, ELF_NAME_LENGTH, "NUM"); break;
					case STT_LOOS:    snprintf(importp->type, ELF_NAME_LENGTH, "LOOS"); break;
					case STT_HIOS:    snprintf(importp->type, ELF_NAME_LENGTH, "HIOS"); break;
					case STT_LOPROC:  snprintf(importp->type, ELF_NAME_LENGTH, "LOPROC"); break;
					case STT_HIPROC:  snprintf(importp->type, ELF_NAME_LENGTH, "HIPROC"); break;
					default:	  snprintf(importp->type, ELF_NAME_LENGTH, "UNKNOWN");
					}
					importp++;
				}
			}
		}
	}
	
	return 0;
}

int ELF_(r_bin_elf_get_imports_count)(ELF_(r_bin_elf_obj) *bin)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	ELF_(Sym) *sym, *symp;
	int i, j, k, ctr = 0;

	shdrp = shdr;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (shdrp->sh_type == (bin->ehdr.e_type == ET_REL?SHT_SYMTAB:SHT_DYNSYM)) {
			sym = (ELF_(Sym) *)malloc(shdrp->sh_size);
			if (sym == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) != shdrp->sh_offset) {
				perror("lseek");
				return -1;
			}

			if (read(bin->fd, sym, shdrp->sh_size) != shdrp->sh_size) {
				perror("read");
				return -1;
			}

			symp = sym;
			for (j = 0, k = 0; j < shdrp->sh_size; j += sizeof(ELF_(Sym)), k++, symp++) {
				if (k == 0)
					continue;
				if (symp->st_shndx == STN_UNDEF) {
					ctr++;
				}
			}
		}
	}

	return ctr;
}

int ELF_(r_bin_elf_get_symbols)(ELF_(r_bin_elf_obj) *bin, r_bin_elf_symbol *symbol)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	ELF_(Sym) *sym, *symp;
	ELF_(Shdr) *strtabhdr;
	r_bin_elf_symbol *symbolp;
	u64 sym_offset;
	char *string;
	int i, j, k;

	sym_offset = (bin->ehdr.e_type == ET_REL ? ELF_(r_bin_elf_get_section_offset)(bin, ".text") : 0);

	shdrp = shdr;

	/* No section headers found */
	if (ehdr->e_shnum == 0) {
	} else
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (shdrp->sh_type == (ELF_(r_bin_elf_get_stripped)(bin)?SHT_DYNSYM:SHT_SYMTAB)) {
			strtabhdr = &shdr[shdrp->sh_link];

			string = (char *)malloc(strtabhdr->sh_size);
			if (string == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, strtabhdr->sh_offset, SEEK_SET) != strtabhdr->sh_offset) {
				perror("lseek");
				return -1;
			}

			if (read(bin->fd, string, strtabhdr->sh_size) != strtabhdr->sh_size) {
				perror("read");
				return -1;
			}

			sym = (ELF_(Sym) *)malloc(shdrp->sh_size);
			if (sym == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) != shdrp->sh_offset) {
				perror("lseek");
				return -1;
			}

			if (read(bin->fd, sym, shdrp->sh_size) != shdrp->sh_size) {
				perror("read");
				return -1;
			}

			symp = sym;
			for (j = 0; j < shdrp->sh_size; j += sizeof(ELF_(Sym)), symp++) {
				ELF_(aux_swap_endian)((u8*)&(symp->st_name), sizeof(ELF_(Word)));
				ELF_(aux_swap_endian)((u8*)&(symp->st_value), sizeof(ELF_(Addr)));
				ELF_(aux_swap_endian)((u8*)&(symp->st_size), sizeof(ELF_Vword));
				ELF_(aux_swap_endian)((u8*)&(symp->st_shndx), sizeof(ELF_(Section)));
			}

			symbolp = symbol;
			symp = sym;
			for (j = 0, k = 0; j < shdrp->sh_size; j += sizeof(ELF_(Sym)), k++, symp++) {
				if (k == 0)
					continue;
				if (symp->st_shndx != STN_UNDEF && ELF_ST_TYPE(symp->st_info) != STT_SECTION && ELF_ST_TYPE(symp->st_info) != STT_FILE) {
					symbolp->size = (u64)symp->st_size; 
					memcpy(symbolp->name, &string[symp->st_name], ELF_NAME_LENGTH); 
					symbolp->name[ELF_NAME_LENGTH-1] = '\0';
					symbolp->offset = (u64)symp->st_value + sym_offset;
					if (symbolp->offset >= bin->base_addr)
						symbolp->offset -= bin->base_addr;
					switch (ELF_ST_BIND(symp->st_info)) {
					case STB_LOCAL:		snprintf(symbolp->bind, ELF_NAME_LENGTH, "LOCAL"); break;
					case STB_GLOBAL:	snprintf(symbolp->bind, ELF_NAME_LENGTH, "GLOBAL"); break;
					case STB_NUM:		snprintf(symbolp->bind, ELF_NAME_LENGTH, "NUM"); break;
					case STB_LOOS:		snprintf(symbolp->bind, ELF_NAME_LENGTH, "LOOS"); break;
					case STB_HIOS:		snprintf(symbolp->bind, ELF_NAME_LENGTH, "HIOS"); break;
					case STB_LOPROC:	snprintf(symbolp->bind, ELF_NAME_LENGTH, "LOPROC"); break;
					case STB_HIPROC:	snprintf(symbolp->bind, ELF_NAME_LENGTH, "HIPROC"); break;
					default:			snprintf(symbolp->bind, ELF_NAME_LENGTH, "UNKNOWN");
					}
					switch (ELF_ST_TYPE(symp->st_info)) {
					case STT_NOTYPE:	snprintf(symbolp->type, ELF_NAME_LENGTH, "NOTYPE"); break;
					case STT_OBJECT:	snprintf(symbolp->type, ELF_NAME_LENGTH, "OBJECT"); break;
					case STT_FUNC:		snprintf(symbolp->type, ELF_NAME_LENGTH, "FUNC"); break;
					case STT_SECTION:	snprintf(symbolp->type, ELF_NAME_LENGTH, "SECTION"); break;
					case STT_FILE:		snprintf(symbolp->type, ELF_NAME_LENGTH, "FILE"); break;
					case STT_COMMON:	snprintf(symbolp->type, ELF_NAME_LENGTH, "COMMON"); break;
					case STT_TLS:		snprintf(symbolp->type, ELF_NAME_LENGTH, "TLS"); break;
					case STT_NUM:		snprintf(symbolp->type, ELF_NAME_LENGTH, "NUM"); break;
					case STT_LOOS:		snprintf(symbolp->type, ELF_NAME_LENGTH, "LOOS"); break;
					case STT_HIOS:		snprintf(symbolp->type, ELF_NAME_LENGTH, "HIOS"); break;
					case STT_LOPROC:	snprintf(symbolp->type, ELF_NAME_LENGTH, "LOPROC"); break;
					case STT_HIPROC:	snprintf(symbolp->type, ELF_NAME_LENGTH, "HIPROC"); break;
					default:		snprintf(symbolp->type, ELF_NAME_LENGTH, "UNKNOWN");
					}

					symbolp++;
				}
			}
		}
	}

	return 0;
}

int ELF_(r_bin_elf_get_symbols_count)(ELF_(r_bin_elf_obj) *bin)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	ELF_(Sym) *sym, *symp;
	int i, j, k, ctr=0;

	shdrp = shdr;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (shdrp->sh_type == (ELF_(r_bin_elf_get_stripped)(bin)?SHT_DYNSYM:SHT_SYMTAB)) {
			sym = (ELF_(Sym) *)malloc(shdrp->sh_size);
			if (sym == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) != shdrp->sh_offset) {
				perror("lseek");
				return -1;
			}

			if (read(bin->fd, sym, shdrp->sh_size) != shdrp->sh_size) {
				perror("read");
				return -1;
			}

			symp = sym;
			for (j = 0, k = 0; j < shdrp->sh_size; j += sizeof(ELF_(Sym)), k++, symp++) {
				if (k == 0)
					continue;
				if (symp->st_shndx != STN_UNDEF && ELF_ST_TYPE(symp->st_info) != STT_SECTION && ELF_ST_TYPE(symp->st_info) != STT_FILE)
					ctr++;
			}
		}
	}

	return ctr;
}

int ELF_(r_bin_elf_get_fields)(ELF_(r_bin_elf_obj) *bin, r_bin_elf_field *field)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Phdr) *phdr = bin->phdr;
	char string[ELF_NAME_LENGTH];
	int i = 0, j = 0;

	strncpy(field[i].name, "ehdr", ELF_NAME_LENGTH); 
	field[i++].offset = 0;
	strncpy(field[i].name, "shoff", ELF_NAME_LENGTH); 
	field[i++].offset = ehdr->e_shoff;
	strncpy(field[i].name, "phoff", ELF_NAME_LENGTH); 
	field[i++].offset = ehdr->e_phoff;

	for (j = 0; j < ehdr->e_phnum; i++, j++) {
		snprintf(string, ELF_NAME_LENGTH, "phdr_%i", j);
		strncpy(field[i].name, string, ELF_NAME_LENGTH); 
		field[i].offset = phdr[i].p_offset;
	}

	return 0;
}

int ELF_(r_bin_elf_get_fields_count)(ELF_(r_bin_elf_obj) *bin)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	int ctr=0;
	
	ctr = 3;
	ctr += ehdr->e_phnum;

	return ctr;
}

int ELF_(r_bin_elf_get_strings)(ELF_(r_bin_elf_obj) *bin, int verbose, int str_limit, r_bin_elf_string *strings)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *string = bin->string;
	int i, ctr = 0;

	shdrp = shdr;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (verbose < 2 && i != 0 && !strcmp(&string[shdrp->sh_name], ".rodata"))
			ctr = ELF_(aux_stripstr_from_file)(bin->file, 3, ENCODING_ASCII,
				shdrp->sh_offset, shdrp->sh_offset+shdrp->sh_size, NULL, str_limit-ctr, strings+ctr);
		if (verbose == 2 && i != 0 && !(shdrp->sh_flags & SHF_EXECINSTR)) {
			ctr = ELF_(aux_stripstr_from_file)(bin->file, 3, ENCODING_ASCII,
				shdrp->sh_offset, shdrp->sh_offset+shdrp->sh_size, NULL, str_limit-ctr, strings+ctr);
		}
	}

	return ctr;
}

int ELF_(r_bin_elf_get_libs)(ELF_(r_bin_elf_obj) *bin, int str_limit, r_bin_elf_string *strings)
{
	ELF_(Ehdr) *ehdr = &bin->ehdr;
	ELF_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *string = bin->string;
	int i, ctr = 0;

	// TODO: use system() hack..read rabin code!
	// LD_TRACE_LOADED_OBJECTS=1 ./vim 
	shdrp = shdr;
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&string[shdrp->sh_name], ".dynstr")) {
			ctr = ELF_(aux_stripstr_from_file)(bin->file, 3, ENCODING_ASCII,
				shdrp->sh_offset, shdrp->sh_offset+shdrp->sh_size, ".so.", str_limit, strings+ctr);
		}
	}

	return ctr;
}

int ELF_(r_bin_elf_open)(ELF_(r_bin_elf_obj) *bin, const char *file, int rw)
{
	if ((bin->fd=open(file, rw?O_RDWR:O_RDONLY)) == -1) {
		ERR("Error: Cannot open \"%s\"\n", file);
		return -1;
	}

	bin->file = file;

	if (ELF_(r_bin_elf_init)(bin) == -1) {
		close(bin->fd);
		return -1;
	}

	return bin->fd;
}
