/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <r_types.h>
#include <r_util.h>

#include "elf.h"

static int Elf_(r_bin_elf_init_ehdr)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	if (lseek(bin->fd, 0, SEEK_SET) < 0) {
		perror("lseek (ehdr)");
		return R_FALSE;
	}
	if (read(bin->fd, &bin->ehdr, sizeof(Elf_(Ehdr))) != sizeof(Elf_(Ehdr))) {
		perror("read (ehdr)");
		return R_FALSE;
	}

	if (bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
		bin->endian = LIL_ENDIAN;
	else bin->endian = !LIL_ENDIAN;

	r_mem_copyendian((u8*)&(bin->ehdr.e_type), (u8*)&(bin->ehdr.e_type), sizeof(Elf_(Half)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_machine), (u8*)&(bin->ehdr.e_machine), sizeof(Elf_(Half)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_version), (u8*)&(bin->ehdr.e_version), sizeof(Elf_(Word)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_entry), (u8*)&(bin->ehdr.e_entry), sizeof(Elf_(Addr)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_phoff), (u8*)&(bin->ehdr.e_phoff), sizeof(Elf_(Off)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_shoff), (u8*)&(bin->ehdr.e_shoff), sizeof(Elf_(Off)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_flags), (u8*)&(bin->ehdr.e_flags), sizeof(Elf_(Word)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_ehsize), (u8*)&(bin->ehdr.e_ehsize), sizeof(Elf_(Half)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_phentsize), (u8*)&(bin->ehdr.e_phentsize), sizeof(Elf_(Half)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_phnum), (u8*)&(bin->ehdr.e_phnum), sizeof(Elf_(Half)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_shentsize), (u8*)&(bin->ehdr.e_shentsize), sizeof(Elf_(Half)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_shnum), (u8*)&(bin->ehdr.e_shnum), sizeof(Elf_(Half)), !bin->endian);
	r_mem_copyendian((u8*)&(bin->ehdr.e_shstrndx), (u8*)&(bin->ehdr.e_shstrndx), sizeof(Elf_(Half)), !bin->endian);

	if (strncmp((char *)bin->ehdr.e_ident, ELFMAG, SELFMAG))
		return R_FALSE;

	return R_TRUE;
}

static int Elf_(r_bin_elf_init_phdr)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	int phdr_size, i;

	phdr_size = bin->ehdr.e_phnum * sizeof(Elf_(Phdr));
	if ((bin->phdr = (Elf_(Phdr) *)malloc(phdr_size)) == NULL) {
		perror("malloc (phdr)");
		return R_FALSE;
	}
	if (lseek(bin->fd, bin->ehdr.e_phoff, SEEK_SET) < 0) {
		perror("lseek (phdr)");
		return R_FALSE;
	}
	if (read(bin->fd, bin->phdr, phdr_size) != phdr_size) {
		perror("read (phdr)");
		return R_FALSE;
	}

	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		r_mem_copyendian((u8*)&(bin->phdr[i].p_type), (u8*)&(bin->phdr[i].p_type), sizeof(Elf_(Word)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->phdr[i].p_offset), (u8*)&(bin->phdr[i].p_offset), sizeof(Elf_(Off)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->phdr[i].p_vaddr), (u8*)&(bin->phdr[i].p_vaddr), sizeof(Elf_(Addr)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->phdr[i].p_paddr), (u8*)&(bin->phdr[i].p_paddr), sizeof(Elf_(Addr)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->phdr[i].p_filesz), (u8*)&(bin->phdr[i].p_filesz), sizeof(Elf_Vword), !bin->endian);
		r_mem_copyendian((u8*)&(bin->phdr[i].p_memsz), (u8*)&(bin->phdr[i].p_memsz), sizeof(Elf_Vword), !bin->endian);
		r_mem_copyendian((u8*)&(bin->phdr[i].p_flags), (u8*)&(bin->phdr[i].p_flags), sizeof(Elf_(Word)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->phdr[i].p_align), (u8*)&(bin->phdr[i].p_align), sizeof(Elf_Vword), !bin->endian);
	}

	return R_TRUE;
}

static int Elf_(r_bin_elf_init_shdr)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	int shdr_size, i;
	
	shdr_size = bin->ehdr.e_shnum * sizeof(Elf_(Shdr));
	if ((bin->shdr = (Elf_(Shdr) *)malloc(shdr_size)) == NULL) {
		perror("malloc (shdr)");
		return R_FALSE;
	}
	if (lseek(bin->fd, bin->ehdr.e_shoff, SEEK_SET) < 0) {
		perror("lseek (shdr)");
		return R_FALSE;
	}
	if (read(bin->fd, bin->shdr, shdr_size) != shdr_size) {
		perror("read (shdr)");
		return R_FALSE;
	}

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_name), (u8*)&(bin->shdr[i].sh_name), sizeof(Elf_(Word)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_type), (u8*)&(bin->shdr[i].sh_type), sizeof(Elf_(Word)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_flags), (u8*)&(bin->shdr[i].sh_flags), sizeof(Elf_Vword), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_addr), (u8*)&(bin->shdr[i].sh_addr), sizeof(Elf_(Addr)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_offset), (u8*)&(bin->shdr[i].sh_offset), sizeof(Elf_(Off)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_size), (u8*)&(bin->shdr[i].sh_size), sizeof(Elf_Vword), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_link), (u8*)&(bin->shdr[i].sh_link), sizeof(Elf_(Word)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_info), (u8*)&(bin->shdr[i].sh_info), sizeof(Elf_(Word)), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_addralign), (u8*)&(bin->shdr[i].sh_addralign), sizeof(Elf_Vword), !bin->endian);
		r_mem_copyendian((u8*)&(bin->shdr[i].sh_entsize), (u8*)&(bin->shdr[i].sh_entsize), sizeof(Elf_Vword), !bin->endian);
	}

	return R_TRUE;
}

static int Elf_(r_bin_elf_init_strtab)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	Elf_(Shdr) *strtab_section;

	strtab_section = &bin->shdr[bin->ehdr.e_shstrndx];
	if ((bin->strtab = (char *)malloc(strtab_section->sh_size)) == NULL) {
		perror("malloc");
		return R_FALSE;
	}
	if (lseek(bin->fd, strtab_section->sh_offset, SEEK_SET) != strtab_section->sh_offset) {
		perror("lseek");
		return R_FALSE;
	}
	if (read(bin->fd, bin->strtab, strtab_section->sh_size) != strtab_section->sh_size) {
		perror("read");
		return R_FALSE;
	}

	return R_TRUE;
}

static int Elf_(r_bin_elf_init)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	if (!Elf_(r_bin_elf_init_ehdr)(bin)) {
		ERR("Warning: File is not ELF\n");
		return R_FALSE;
	}
	if (!Elf_(r_bin_elf_init_phdr)(bin))
		ERR("Warning: Cannot initialize program headers\n");
	if (!Elf_(r_bin_elf_init_shdr)(bin))
		ERR("Warning: Cannot initialize section headers\n");
	if (!Elf_(r_bin_elf_init_strtab)(bin))
		ERR("Warning: Cannot initialize strings table\n");
	bin->baddr = Elf_(r_bin_elf_get_baddr)(bin);

	return R_TRUE;
}

static u64 Elf_(r_bin_elf_get_section_offset)(struct Elf_(r_bin_elf_obj_t) *bin, const char *section_name)
{
	const char *strtab = bin->strtab;
	int i;

	for (i = 0; i < bin->ehdr.e_shnum; i++)
		if (!strcmp(&strtab[bin->shdr[i].sh_name], section_name))
			return (u64)bin->shdr[i].sh_offset;

	return -1;
}

/*XXX*/
static u64 Elf_(get_import_addr)(struct Elf_(r_bin_elf_obj_t) *bin, int sym)
{
	u64 got_addr, got_offset;
	Elf_(Addr) plt_sym_addr;
	int i, j, k;
	
	if ((got_addr = Elf_(r_bin_elf_get_section_offset)(bin, ".got")) == -1)
		return -1;

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (!strcmp(&bin->strtab[bin->shdr[i].sh_name], ".rel.plt")) {
			Elf_(Rel) *rel;
			if ((rel = (Elf_(Rel) *)malloc(bin->shdr[i].sh_size)) == NULL) {
				perror("malloc (rel)");
				return -1;
			}
			if (lseek(bin->fd, bin->shdr[i].sh_offset, SEEK_SET) != bin->shdr[i].sh_offset) {
				perror("lseek (rel)");
				return -1;
			}
			if (read(bin->fd, rel, bin->shdr[i].sh_size) != bin->shdr[i].sh_size) {
				perror("read (rel)");
				return -1;
			}

			for (j = 0; j < bin->shdr[i].sh_size; j += sizeof(Elf_(Rel))) {
				r_mem_copyendian((u8*)&(rel[j].r_offset), (u8*)&(rel[j].r_offset), sizeof(Elf_(Addr)), !bin->endian);
				r_mem_copyendian((u8*)&(rel[j].r_info), (u8*)&(rel[j].r_info), sizeof(Elf_Vword), !bin->endian);
			}

			got_offset = (rel->r_offset - bin->baddr - got_addr) & ELF_GOTOFF_MASK;

			for (j = k = 0; j < bin->shdr[i].sh_size; j += sizeof(Elf_(Rel)), k++) {
				if (ELF_R_SYM(rel[k].r_info) == sym) {
					if (lseek(bin->fd, rel[k].r_offset-bin->baddr-got_offset, SEEK_SET)
							!= rel[k].r_offset-bin->baddr-got_offset) {
						perror("lseek (got)");
						return -1;
					}
					if (read(bin->fd, &plt_sym_addr, sizeof(Elf_(Addr))) != sizeof(Elf_(Addr))) {
						perror("read (got)");
						return -1;
					}

					return (u64)(plt_sym_addr - 6);
				}
			}
			break;
		} else if (!strcmp(&bin->strtab[bin->shdr[i].sh_name], ".rela.plt")) {
			Elf_(Rela) *rel;
			if ((rel = (Elf_(Rela) *)malloc(bin->shdr[i].sh_size)) == NULL) {
				perror("malloc (rel)");
				return -1;
			}
			if (lseek(bin->fd, bin->shdr[i].sh_offset, SEEK_SET) != bin->shdr[i].sh_offset) {
				perror("lseek (rel)");
				return -1;
			}
			if (read(bin->fd, rel, bin->shdr[i].sh_size) != bin->shdr[i].sh_size) {
				perror("read (rel)");
				return -1;
			}

			for (j = 0; j < bin->shdr[i].sh_size; j += sizeof(Elf_(Rela))) {
				r_mem_copyendian((u8*)&(rel[j].r_offset), (u8*)&(rel[j].r_offset), sizeof(Elf_(Addr)), !bin->endian);
				r_mem_copyendian((u8*)&(rel[j].r_info), (u8*)&(rel[j].r_info), sizeof(Elf_Vword), !bin->endian);
			}

			got_offset = (rel->r_offset - bin->baddr - got_addr) & ELF_GOTOFF_MASK;

			for (j = k = 0; j < bin->shdr[i].sh_size; j += sizeof(Elf_(Rela)), k++) {
				if (ELF_R_SYM(rel[k].r_info) == sym) {
					if (lseek(bin->fd, rel[k].r_offset-bin->baddr-got_offset, SEEK_SET)
							!= rel[k].r_offset-bin->baddr-got_offset) {
						perror("lseek (got)");
						return -1;
					}
					if (read(bin->fd, &plt_sym_addr, sizeof(Elf_(Addr))) != sizeof(Elf_(Addr))) {
						perror("read (got)");
						return -1;
					}

					return (u64)(plt_sym_addr - 6);
				}
			}
			break;
		}
	}

	return -1;
}

u64 Elf_(r_bin_elf_get_baddr)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	return bin->phdr->p_vaddr & ELF_ADDR_MASK;
}

u64 Elf_(r_bin_elf_get_entry_offset)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	return bin->ehdr.e_entry - bin->baddr; 
}

int Elf_(r_bin_elf_get_stripped)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	int i;
	
	for (i = 0; i < bin->ehdr.e_shnum; i++)
		if (bin->shdr[i].sh_type == SHT_SYMTAB)
			return R_FALSE;
	return R_TRUE;
}

int Elf_(r_bin_elf_get_static)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	int i;

	for (i = 0; i < bin->ehdr.e_phnum; i++)
		if (bin->phdr[i].p_type == PT_INTERP)
			return R_FALSE;
	return R_TRUE;
}

char* Elf_(r_bin_elf_get_data_encoding)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	switch (bin->ehdr.e_ident[EI_DATA]) {
	case ELFDATANONE: return r_str_dup_printf("none");
	case ELFDATA2LSB: return r_str_dup_printf("2's complement, little endian");
	case ELFDATA2MSB: return r_str_dup_printf("2's complement, big endian");
	default: return r_str_dup_printf("<unknown: %x>", bin->ehdr.e_ident[EI_DATA]);
	}
}

char* Elf_(r_bin_elf_get_arch)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	switch (bin->ehdr.e_machine) {
	case EM_MIPS:
	case EM_MIPS_RS3_LE:
	case EM_MIPS_X:
		return r_str_dup_printf("mips");
	case EM_ARM:
		return r_str_dup_printf("arm");
	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		return r_str_dup_printf("sparc");
	case EM_PPC:
	case EM_PPC64:
		return r_str_dup_printf("powerpc");
	case EM_68K:
		return r_str_dup_printf("m68k");
	case EM_IA_64:
	case EM_X86_64:
		return r_str_dup_printf("intel64");
	default:
		return r_str_dup_printf("intel");
	}
}
char* Elf_(r_bin_elf_get_machine_name)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	switch (bin->ehdr.e_machine) {
	case EM_NONE:        return r_str_dup_printf("No machine");
	case EM_M32:         return r_str_dup_printf("AT&T WE 32100");
	case EM_SPARC:       return r_str_dup_printf("SUN SPARC");
	case EM_386:         return r_str_dup_printf("Intel 80386");
	case EM_68K:         return r_str_dup_printf("Motorola m68k family");
	case EM_88K:         return r_str_dup_printf("Motorola m88k family");
	case EM_860:         return r_str_dup_printf("Intel 80860");
	case EM_MIPS:        return r_str_dup_printf("MIPS R3000 big-endian");
	case EM_S370:        return r_str_dup_printf("IBM System/370");
	case EM_MIPS_RS3_LE: return r_str_dup_printf("MIPS R3000 little-endian");
	case EM_PARISC:      return r_str_dup_printf("HPPA");
	case EM_VPP500:      return r_str_dup_printf("Fujitsu VPP500");
	case EM_SPARC32PLUS: return r_str_dup_printf("Sun's \"v8plus\"");
	case EM_960:         return r_str_dup_printf("Intel 80960");
	case EM_PPC:         return r_str_dup_printf("PowerPC");
	case EM_PPC64:       return r_str_dup_printf("PowerPC 64-bit");
	case EM_S390:        return r_str_dup_printf("IBM S390");
	case EM_V800:        return r_str_dup_printf("NEC V800 series");
	case EM_FR20:        return r_str_dup_printf("Fujitsu FR20");
	case EM_RH32:        return r_str_dup_printf("TRW RH-32");
	case EM_RCE:         return r_str_dup_printf("Motorola RCE");
	case EM_ARM:         return r_str_dup_printf("ARM");
	case EM_FAKE_ALPHA:  return r_str_dup_printf("Digital Alpha");
	case EM_SH:          return r_str_dup_printf("Hitachi SH");
	case EM_SPARCV9:     return r_str_dup_printf("SPARC v9 64-bit");
	case EM_TRICORE:     return r_str_dup_printf("Siemens Tricore");
	case EM_ARC:         return r_str_dup_printf("Argonaut RISC Core");
	case EM_H8_300:      return r_str_dup_printf("Hitachi H8/300");
	case EM_H8_300H:     return r_str_dup_printf("Hitachi H8/300H");
	case EM_H8S:         return r_str_dup_printf("Hitachi H8S");
	case EM_H8_500:      return r_str_dup_printf("Hitachi H8/500");
	case EM_IA_64:       return r_str_dup_printf("Intel Merced");
	case EM_MIPS_X:      return r_str_dup_printf("Stanford MIPS-X");
	case EM_COLDFIRE:    return r_str_dup_printf("Motorola Coldfire");
	case EM_68HC12:      return r_str_dup_printf("Motorola M68HC12");
	case EM_MMA:         return r_str_dup_printf("Fujitsu MMA Multimedia Accelerator");
	case EM_PCP:         return r_str_dup_printf("Siemens PCP");
	case EM_NCPU:        return r_str_dup_printf("Sony nCPU embeeded RISC");
	case EM_NDR1:        return r_str_dup_printf("Denso NDR1 microprocessor");
	case EM_STARCORE:    return r_str_dup_printf("Motorola Start*Core processor");
	case EM_ME16:        return r_str_dup_printf("Toyota ME16 processor");
	case EM_ST100:       return r_str_dup_printf("STMicroelectronic ST100 processor");
	case EM_TINYJ:       return r_str_dup_printf("Advanced Logic Corp. Tinyj emb.fam");
	case EM_X86_64:      return r_str_dup_printf("AMD x86-64 architecture");
	case EM_PDSP:        return r_str_dup_printf("Sony DSP Processor");
	case EM_FX66:        return r_str_dup_printf("Siemens FX66 microcontroller");
	case EM_ST9PLUS:     return r_str_dup_printf("STMicroelectronics ST9+ 8/16 mc");
	case EM_ST7:         return r_str_dup_printf("STmicroelectronics ST7 8 bit mc");
	case EM_68HC16:      return r_str_dup_printf("Motorola MC68HC16 microcontroller");
	case EM_68HC11:      return r_str_dup_printf("Motorola MC68HC11 microcontroller");
	case EM_68HC08:      return r_str_dup_printf("Motorola MC68HC08 microcontroller");
	case EM_68HC05:      return r_str_dup_printf("Motorola MC68HC05 microcontroller");
	case EM_SVX:         return r_str_dup_printf("Silicon Graphics SVx");
	case EM_ST19:        return r_str_dup_printf("STMicroelectronics ST19 8 bit mc");
	case EM_VAX:         return r_str_dup_printf("Digital VAX");
	case EM_CRIS:        return r_str_dup_printf("Axis Communications 32-bit embedded processor");
	case EM_JAVELIN:     return r_str_dup_printf("Infineon Technologies 32-bit embedded processor");
	case EM_FIREPATH:    return r_str_dup_printf("Element 14 64-bit DSP Processor");
	case EM_ZSP:         return r_str_dup_printf("LSI Logic 16-bit DSP Processor");
	case EM_MMIX:        return r_str_dup_printf("Donald Knuth's educational 64-bit processor");
	case EM_HUANY:       return r_str_dup_printf("Harvard University machine-independent object files");
	case EM_PRISM:       return r_str_dup_printf("SiTera Prism");
	case EM_AVR:         return r_str_dup_printf("Atmel AVR 8-bit microcontroller");
	case EM_FR30:        return r_str_dup_printf("Fujitsu FR30");
	case EM_D10V:        return r_str_dup_printf("Mitsubishi D10V");
	case EM_D30V:        return r_str_dup_printf("Mitsubishi D30V");
	case EM_V850:        return r_str_dup_printf("NEC v850");
	case EM_M32R:        return r_str_dup_printf("Mitsubishi M32R");
	case EM_MN10300:     return r_str_dup_printf("Matsushita MN10300");
	case EM_MN10200:     return r_str_dup_printf("Matsushita MN10200");
	case EM_PJ:          return r_str_dup_printf("picoJava");
	case EM_OPENRISC:    return r_str_dup_printf("OpenRISC 32-bit embedded processor");
	case EM_ARC_A5:      return r_str_dup_printf("ARC Cores Tangent-A5");
	case EM_XTENSA:      return r_str_dup_printf("Tensilica Xtensa Architecture");
	default:             return r_str_dup_printf("<unknown>: 0x%x", bin->ehdr.e_machine);
	}
}

char* Elf_(r_bin_elf_get_file_type)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	switch (bin->ehdr.e_type) {
	case ET_NONE: return r_str_dup_printf("NONE (None)");
	case ET_REL:  return r_str_dup_printf("REL (Relocatable file)");
	case ET_EXEC: return r_str_dup_printf("EXEC (Executable file)");
	case ET_DYN:  return r_str_dup_printf("DYN (Shared object file)");
	case ET_CORE: return r_str_dup_printf("CORE (Core file)");
	}

	if ((bin->ehdr.e_type >= ET_LOPROC) && (bin->ehdr.e_type <= ET_HIPROC))
		return r_str_dup_printf("Processor Specific: %x", bin->ehdr.e_type);
	else if ((bin->ehdr.e_type >= ET_LOOS) && (bin->ehdr.e_type <= ET_HIOS))
		return r_str_dup_printf("OS Specific: %x", bin->ehdr.e_type);
	else return r_str_dup_printf("<unknown>: %x", bin->ehdr.e_type);
}

char* Elf_(r_bin_elf_get_elf_class)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	switch (bin->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASSNONE: return r_str_dup_printf("none");
	case ELFCLASS32:   return r_str_dup_printf("ELF32");
	case ELFCLASS64:   return r_str_dup_printf("ELF64");
	default:           return r_str_dup_printf("<unknown: %x>", bin->ehdr.e_ident[EI_CLASS]);
	}
}

char* Elf_(r_bin_elf_get_osabi_name)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	switch (bin->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_NONE:       return r_str_dup_printf("linux"); // sysv
	case ELFOSABI_HPUX:       return r_str_dup_printf("hpux");
	case ELFOSABI_NETBSD:     return r_str_dup_printf("netbsd");
	case ELFOSABI_LINUX:      return r_str_dup_printf("linux");
	case ELFOSABI_SOLARIS:    return r_str_dup_printf("solaris");
	case ELFOSABI_AIX:        return r_str_dup_printf("aix");
	case ELFOSABI_IRIX:       return r_str_dup_printf("irix");
	case ELFOSABI_FREEBSD:    return r_str_dup_printf("freebsd");
	case ELFOSABI_TRU64:      return r_str_dup_printf("tru64");
	case ELFOSABI_MODESTO:    return r_str_dup_printf("modesto");
	case ELFOSABI_OPENBSD:    return r_str_dup_printf("openbsd");
	case ELFOSABI_STANDALONE: return r_str_dup_printf("standalone");
	case ELFOSABI_ARM:        return r_str_dup_printf("arm");
	default:                  return r_str_dup_printf("<unknown: %x>", bin->ehdr.e_ident[EI_OSABI]);
	}
}

int Elf_(r_bin_elf_is_big_endian)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	return (bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB);
}

struct r_bin_elf_section_t* Elf_(r_bin_elf_get_sections)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	struct r_bin_elf_section_t *ret = NULL;
	const char *strtab = bin->strtab;
	int i;
	
	if ((ret = malloc((bin->ehdr.e_shnum + 1) * sizeof(struct r_bin_elf_section_t))) == NULL)
		return NULL;

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		ret[i].offset = bin->shdr[i].sh_offset;
		ret[i].size = bin->shdr[i].sh_size;
		ret[i].align = bin->shdr[i].sh_addralign;
		ret[i].flags = bin->shdr[i].sh_flags;
		strncpy(ret[i].name, &strtab[bin->shdr[i].sh_name], ELF_STRING_LENGTH);
		ret[i].last = 0;
	}
	ret[i].last = 1;

	return ret;
}

struct r_bin_elf_symbol_t* Elf_(r_bin_elf_get_symbols)(struct Elf_(r_bin_elf_obj_t) *bin, int type)
{
	Elf_(Shdr) *strtab_section;
	Elf_(Sym) *sym;
	struct r_bin_elf_symbol_t *ret = NULL;
	char *strtab;
	u64 sym_offset, toffset;
	int tsize, ret_ctr, i, j, k;

	sym_offset = (bin->ehdr.e_type == ET_REL ? Elf_(r_bin_elf_get_section_offset)(bin, ".text") : 0);

	if (bin->ehdr.e_shnum == 0)
		return NULL;

	for (i = 0; i < bin->ehdr.e_shnum; i++)
		if (bin->shdr[i].sh_type == (Elf_(r_bin_elf_get_stripped)(bin)?SHT_DYNSYM:SHT_SYMTAB)) {
			strtab_section = &bin->shdr[bin->shdr[i].sh_link];
			if ((strtab = (char *)malloc(strtab_section->sh_size)) == NULL) {
				perror("malloc (syms strtab)");
				return NULL;
			}
			if (lseek(bin->fd, strtab_section->sh_offset, SEEK_SET) != strtab_section->sh_offset) {
				perror("lseek (syms strtab)");
				return NULL;
			}
			if (read(bin->fd, strtab, strtab_section->sh_size) != strtab_section->sh_size) {
				perror("read (syms strtab)");
				return NULL;
			}

			if ((sym = (Elf_(Sym) *)malloc(bin->shdr[i].sh_size)) == NULL) {
				perror("malloc (syms)");
				return NULL;
			}
			if (lseek(bin->fd, bin->shdr[i].sh_offset, SEEK_SET) != bin->shdr[i].sh_offset) {
				perror("lseek (syms)");
				return NULL;
			}
			if (read(bin->fd, sym, bin->shdr[i].sh_size) != bin->shdr[i].sh_size) {
				perror("read (syms)");
				return NULL;
			}

			for (j = 0; j < bin->shdr[i].sh_size; j += sizeof(Elf_(Sym))) {
				r_mem_copyendian((u8*)&(sym[i].st_name), (u8*)&(sym[i].st_name), sizeof(Elf_(Word)), !bin->endian);
				r_mem_copyendian((u8*)&(sym[i].st_value), (u8*)&(sym[i].st_value), sizeof(Elf_(Addr)), !bin->endian);
				r_mem_copyendian((u8*)&(sym[i].st_size), (u8*)&(sym[i].st_size), sizeof(Elf_Vword), !bin->endian);
				r_mem_copyendian((u8*)&(sym[i].st_shndx), (u8*)&(sym[i].st_shndx), sizeof(Elf_(Section)), !bin->endian);
			}

			for (j = k = ret_ctr = 0; j < bin->shdr[i].sh_size; j += sizeof(Elf_(Sym)), k++) {
				if (k == 0)
					continue;
				if (type == R_BIN_ELF_IMPORTS && sym[k].st_shndx == STN_UNDEF) {
					if (sym[k].st_value)
						toffset = sym[k].st_value;
					else if ((toffset = Elf_(get_import_addr)(bin, k)) == -1)
						toffset = 0;
					tsize = 0;
				} else if (type == R_BIN_ELF_SYMBOLS && sym[k].st_shndx != STN_UNDEF &&
						ELF_ST_TYPE(sym[k].st_info) != STT_SECTION && ELF_ST_TYPE(sym[k].st_info) != STT_FILE) {
					toffset = (u64)sym[k].st_value + sym_offset;
					tsize = sym[k].st_size;
				} else continue;
				if ((ret = realloc(ret, (ret_ctr + 1) * sizeof(struct r_bin_elf_symbol_t))) == NULL) {
					perror("realloc (symbols|imports)");
					return NULL;
				}
				ret[ret_ctr].offset = (toffset >= bin->baddr ? toffset -= bin->baddr : toffset);
				ret[ret_ctr].size = tsize;
				memcpy(ret[ret_ctr].name, &strtab[sym[k].st_name], ELF_STRING_LENGTH); 
				ret[ret_ctr].name[ELF_STRING_LENGTH-1] = '\0';
				switch (ELF_ST_BIND(sym[k].st_info)) {
				case STB_LOCAL:  snprintf(ret[ret_ctr].bind, ELF_STRING_LENGTH, "LOCAL"); break;
				case STB_GLOBAL: snprintf(ret[ret_ctr].bind, ELF_STRING_LENGTH, "GLOBAL"); break;
				case STB_NUM:    snprintf(ret[ret_ctr].bind, ELF_STRING_LENGTH, "NUM"); break;
				case STB_LOOS:   snprintf(ret[ret_ctr].bind, ELF_STRING_LENGTH, "LOOS"); break;
				case STB_HIOS:   snprintf(ret[ret_ctr].bind, ELF_STRING_LENGTH, "HIOS"); break;
				case STB_LOPROC: snprintf(ret[ret_ctr].bind, ELF_STRING_LENGTH, "LOPROC"); break;
				case STB_HIPROC: snprintf(ret[ret_ctr].bind, ELF_STRING_LENGTH, "HIPROC"); break;
				default:         snprintf(ret[ret_ctr].bind, ELF_STRING_LENGTH, "UNKNOWN");
				}
				switch (ELF_ST_TYPE(sym[k].st_info)) {
				case STT_NOTYPE:  snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "NOTYPE"); break;
				case STT_OBJECT:  snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "OBJECT"); break;
				case STT_FUNC:    snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "FUNC"); break;
				case STT_SECTION: snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "SECTION"); break;
				case STT_FILE:    snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "FILE"); break;
				case STT_COMMON:  snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "COMMON"); break;
				case STT_TLS:     snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "TLS"); break;
				case STT_NUM:     snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "NUM"); break;
				case STT_LOOS:    snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "LOOS"); break;
				case STT_HIOS:    snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "HIOS"); break;
				case STT_LOPROC:  snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "LOPROC"); break;
				case STT_HIPROC:  snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "HIPROC"); break;
				default:          snprintf(ret[ret_ctr].type, ELF_STRING_LENGTH, "UNKNOWN");
				}
				ret[ret_ctr].last = 0;
				ret_ctr++;
			}
			if ((ret = realloc(ret, (ret_ctr + 1) * sizeof(struct r_bin_elf_symbol_t))) == NULL)
				return NULL;
			ret[ret_ctr].last = 1;
			break;
		}
	return ret;
}

struct r_bin_elf_field_t* Elf_(r_bin_elf_get_fields)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	struct r_bin_elf_field_t *ret = NULL;
	int i = 0, j;

	if ((ret = malloc((bin->ehdr.e_phnum+3 + 1) * sizeof(struct r_bin_elf_field_t))) == NULL)
		return NULL;

	strncpy(ret[i].name, "ehdr", ELF_STRING_LENGTH); 
	ret[i++].offset = 0;
	strncpy(ret[i].name, "shoff", ELF_STRING_LENGTH); 
	ret[i++].offset = bin->ehdr.e_shoff;
	strncpy(ret[i].name, "phoff", ELF_STRING_LENGTH); 
	ret[i++].offset = bin->ehdr.e_phoff;
	for (j = 0; j < bin->ehdr.e_phnum; i++, j++) {
		snprintf(ret[i].name, ELF_STRING_LENGTH, "phdr_%i", j);
		ret[i].offset = bin->phdr[j].p_offset;
		ret[i].last = 0;
	}
	ret[i].last = 1;

	return ret;
}

int Elf_(r_bin_elf_open)(struct Elf_(r_bin_elf_obj_t) *bin, const char *file, int rw)
{
	if ((bin->fd=open(file, rw?O_RDWR:O_RDONLY)) == -1) {
		ERR("Error: Cannot open \"%s\"\n", file);
		return -1;
	}

	bin->file = file;

	if (!Elf_(r_bin_elf_init)(bin)) {
		close(bin->fd);
		return -1;
	}

	return bin->fd;
}

int Elf_(r_bin_elf_close)(struct Elf_(r_bin_elf_obj_t) *bin)
{
	return close(bin->fd);
}
