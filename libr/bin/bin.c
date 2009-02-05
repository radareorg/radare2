/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

/* TODO:
 * Linked libraries
 * dlopen library and show address
 * Strings
 * XRefs
 * Generic resize
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "r_types.h"
#include "r_bin.h"

#define ELF_CALL(func, bin, args...)\
	bin->format==R_BIN_FMT_ELF64?\
	Elf64_##func(&bin->object.elf.e64,##args):\
	Elf32_##func(&bin->object.elf.e32,##args)

enum {
	R_BIN_FMT_ELF32,
	R_BIN_FMT_ELF64,
	R_BIN_FMT_PE
};

static int r_bin_identify(r_bin_obj *bin)
{
	int fd;
	unsigned char buf[1024];

	if ((fd = open(bin->file, 0)) == -1) {
		return -1;
	}

	lseek(fd, 0, SEEK_SET);
	read(fd, buf, 1024);

	close(fd);

	if (!memcmp(buf, "\x7F\x45\x4c\x46", 4)) {
		if (buf[EI_CLASS] == ELFCLASS64)
			bin->format = R_BIN_FMT_ELF64;
		else bin->format = R_BIN_FMT_ELF32;
		return 0;
	} else if (!memcmp(buf, "\x4d\x5a", 2)) {
		bin->format = R_BIN_FMT_PE;
		return 0;
	} 

	return -1;
}

r_bin_obj *r_bin_new(char *file, int rw)
{
	r_bin_obj *bin = MALLOC_STRUCT(r_bin_obj);
	r_bin_init(bin, file, rw);
	return bin;
}

void r_bin_free(r_bin_obj *bin)
{
	free(bin);
}

int r_bin_init(r_bin_obj *bin, const char *file, int rw)
{
	int fd;

	bin->file = file;

	if (r_bin_identify(bin) == -1)
		return -1;

	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		if ((fd = ELF_CALL(r_bin_elf_open,bin,file,rw)) != -1) {
			bin->fd = fd;
			return fd;
		}
		break;
	case R_BIN_FMT_PE:
		if ((fd = r_bin_pe_open(&bin->object.pe, file)) != -1) {
			bin->fd = fd;
			return fd;
		}
		break;
	}

	return -1;
}

int r_bin_close(r_bin_obj *bin)
{
	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		return ELF_CALL(r_bin_elf_close, bin);
	case R_BIN_FMT_PE:
		return r_bin_pe_close(&bin->object.pe);
	}

	return -1;
}

u64 r_bin_get_baddr(r_bin_obj *bin)
{
	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		return ELF_CALL(r_bin_elf_get_base_addr, bin);
	case R_BIN_FMT_PE:
		return r_bin_pe_get_image_base(&bin->object.pe);
	}

	return -1;
}

r_bin_entry* r_bin_get_entry(r_bin_obj *bin)
{
	r_bin_entry *ret;
	r_bin_pe_entrypoint entry;

	if((ret = malloc(sizeof(r_bin_entry))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(r_bin_entry));

	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		ret->offset = ret->rva = ELF_CALL(r_bin_elf_get_entry_offset, bin);
		return ret;
	case R_BIN_FMT_PE:
		r_bin_pe_get_entrypoint(&bin->object.pe, &entry);
		ret->offset = entry.offset;
		ret->rva = entry.rva;
		return ret;
	}

	return NULL;
}

r_bin_section* r_bin_get_sections(r_bin_obj *bin)
{
	int sections_count, i;
	r_bin_section *ret, *retp;
	union {
		r_bin_elf_section* elf;
		r_bin_pe_section*  pe;
	} section, sectionp;
	ret = retp = NULL;
	section.elf = sectionp.elf =  NULL;
	section.pe = section.pe = NULL;

	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		sections_count = ELF_CALL(r_bin_elf_get_sections_count,bin);

		if((section.elf = malloc(sections_count * sizeof(r_bin_elf_section))) == NULL)
			return NULL;
		if((ret = malloc((sections_count + 1) * sizeof(r_bin_section))) == NULL)
			return NULL;
		memset(ret, '\0', (sections_count + 1) * sizeof(r_bin_section));

		ELF_CALL(r_bin_elf_get_sections,bin,section.elf);

		retp = ret;
		sectionp.elf = section.elf;
		for (i = 0; i < sections_count; i++, sectionp.elf++, retp++) {
			strncpy(retp->name, (char*)sectionp.elf->name, R_BIN_SIZEOF_NAMES);
			retp->size = sectionp.elf->size;
			retp->vsize = sectionp.elf->size;
			retp->offset = sectionp.elf->offset;
			retp->rva = sectionp.elf->offset;
			retp->characteristics = 0;
			if (R_BIN_ELF_SCN_IS_EXECUTABLE(sectionp.elf->flags))
				retp->characteristics |= 0x1;
			if (R_BIN_ELF_SCN_IS_WRITABLE(sectionp.elf->flags))
				retp->characteristics |= 0x2;
			if (R_BIN_ELF_SCN_IS_READABLE(sectionp.elf->flags))
				retp->characteristics |= 0x4;
			retp->last = 0;
		}
		retp->last = 1;
		
		free(section.elf);

		return ret;
	case R_BIN_FMT_PE:
		sections_count = r_bin_pe_get_sections_count(&bin->object.pe);
		
		if ((section.pe = malloc(sections_count * sizeof(r_bin_pe_section))) == NULL)
			return NULL;
		if ((ret = malloc((sections_count + 1) * sizeof(r_bin_section))) == NULL)
			return NULL;
		memset(ret, '\0', (sections_count + 1) * sizeof(r_bin_section));
		
		r_bin_pe_get_sections(&bin->object.pe, section.pe);
		
		retp = ret;
		sectionp.pe = section.pe;
		for (i = 0; i < sections_count; i++, sectionp.pe++, retp++) {
			strncpy(retp->name, (char*)sectionp.pe->name, R_BIN_SIZEOF_NAMES);
			retp->size = sectionp.pe->size;
			retp->vsize = section.pe->vsize;
			retp->offset = sectionp.pe->offset;
			retp->rva = sectionp.pe->rva;
			retp->characteristics = 0;
			if (R_BIN_PE_SCN_IS_EXECUTABLE(sectionp.pe->characteristics))
				retp->characteristics |= 0x1;
			if (R_BIN_PE_SCN_IS_WRITABLE(sectionp.pe->characteristics))
				retp->characteristics |= 0x2;
			if (R_BIN_PE_SCN_IS_READABLE(sectionp.pe->characteristics))
				retp->characteristics |= 0x4;
			if (R_BIN_PE_SCN_IS_SHAREABLE(sectionp.pe->characteristics))
				retp->characteristics |= 0x8;
			retp->last = 0;
		}
		retp->last = 1;
		
		free(section.pe);
		return ret;
	}

	return NULL;
}

r_bin_symbol* r_bin_get_symbols(r_bin_obj *bin)
{
	int symbols_count, i;
	r_bin_symbol *ret, *retp;
	union {
		r_bin_elf_symbol* elf;
		r_bin_pe_export*  pe;
	} symbol, symbolp;
	ret = retp = NULL;
	symbol.elf = symbolp.elf =  NULL;
	symbol.pe = symbolp.pe = NULL;

	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		symbols_count = ELF_CALL(r_bin_elf_get_symbols_count,bin);

		if ((symbol.elf = malloc(symbols_count * sizeof(r_bin_elf_symbol))) == NULL)
			return NULL;
		if ((ret = malloc((symbols_count + 1) * sizeof(r_bin_symbol))) == NULL)
			return NULL;
		memset(ret, '\0', (symbols_count + 1) * sizeof(r_bin_symbol));
		
		ELF_CALL(r_bin_elf_get_symbols,bin,symbol.elf);

		retp = ret;
		symbolp.elf = symbol.elf;
		for (i = 0; i < symbols_count; i++, symbolp.elf++, retp++) {
			strncpy(retp->name, symbolp.elf->name, R_BIN_SIZEOF_NAMES);
			strncpy(retp->forwarder, "NONE", R_BIN_SIZEOF_NAMES);
			strncpy(retp->bind, symbolp.elf->bind, R_BIN_SIZEOF_NAMES);
			strncpy(retp->type, symbolp.elf->type, R_BIN_SIZEOF_NAMES);
			retp->rva = symbolp.elf->offset;
			retp->offset = symbolp.elf->offset;
			retp->size = symbolp.elf->size;
			retp->ordinal = 0;
			retp->last = 0;
		}
		retp->last = 1;

		free(symbol.elf);

		return ret;
	case R_BIN_FMT_PE:
		symbols_count = r_bin_pe_get_exports_count(&bin->object.pe);

		if ((symbol.pe = malloc(symbols_count * sizeof(r_bin_pe_export))) == NULL)
			return NULL;
		if ((ret = malloc((symbols_count + 1) * sizeof(r_bin_symbol))) == NULL)
			return NULL;
		memset(ret, '\0', (symbols_count + 1) * sizeof(r_bin_symbol));
		
		r_bin_pe_get_exports(&bin->object.pe, symbol.pe);

		retp = ret;
		symbolp.pe = symbol.pe;
		for (i = 0; i < symbols_count; i++, symbolp.pe++, retp++) {
			strncpy(retp->name, (char*)symbolp.pe->name, R_BIN_SIZEOF_NAMES);
			strncpy(retp->forwarder, (char*)symbolp.pe->forwarder, R_BIN_SIZEOF_NAMES);
			strncpy(retp->bind, "NONE", R_BIN_SIZEOF_NAMES);
			strncpy(retp->type, "NONE", R_BIN_SIZEOF_NAMES);
			retp->rva = symbolp.pe->rva;
			retp->offset = symbolp.pe->offset;
			retp->size = 0;
			retp->ordinal = symbolp.pe->ordinal;
			retp->last = 0;
		}
		retp->last = 1;

		free(symbol.pe);

		return ret;
	}

	return NULL;
}

r_bin_import* r_bin_get_imports(r_bin_obj *bin)
{
	int imports_count, i;
	r_bin_import *ret, *retp;
	union {
		r_bin_elf_import* elf;
		r_bin_pe_import*  pe;
	} import, importp;
	ret = retp = NULL;
	import.elf = importp.elf =  NULL;
	import.pe = importp.pe = NULL;

	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		imports_count = ELF_CALL(r_bin_elf_get_imports_count,bin);

		if ((import.elf = malloc(imports_count * sizeof(r_bin_elf_import))) == NULL)
			return NULL;
		if ((ret = malloc((imports_count + 1) * sizeof(r_bin_import))) == NULL)
			return NULL;
		memset(ret, '\0', (imports_count + 1) * sizeof(r_bin_import));
		
		ELF_CALL(r_bin_elf_get_imports,bin,import.elf);

		retp = ret;
		importp.elf = import.elf;
		for (i = 0; i < imports_count; i++, importp.elf++, retp++) {
			strncpy(retp->name, importp.elf->name, R_BIN_SIZEOF_NAMES);
			strncpy(retp->bind, importp.elf->bind, R_BIN_SIZEOF_NAMES);
			strncpy(retp->type, importp.elf->type, R_BIN_SIZEOF_NAMES);
			retp->rva = importp.elf->offset;
			retp->offset = importp.elf->offset;
			retp->ordinal = 0;
			retp->hint = 0;
			retp->last = 0;
		}
		retp->last = 1;
		free(import.elf);
		return ret;
	case R_BIN_FMT_PE:
		imports_count = r_bin_pe_get_imports_count(&bin->object.pe);

		if ((import.pe = malloc(imports_count * sizeof(r_bin_pe_import))) == NULL)
			return NULL;
		if ((ret = malloc((imports_count + 1) * sizeof(r_bin_import))) == NULL)
			return NULL;
		memset(ret, '\0', (imports_count + 1) * sizeof(r_bin_import));
		
		r_bin_pe_get_imports(&bin->object.pe, import.pe);

		retp = ret;
		importp.pe = import.pe;
		for (i = 0; i < imports_count; i++, importp.pe++, retp++) {
			strncpy(retp->name, (char*)importp.pe->name, R_BIN_SIZEOF_NAMES);
			strncpy(retp->bind, "NONE", R_BIN_SIZEOF_NAMES);
			strncpy(retp->type, "NONE", R_BIN_SIZEOF_NAMES);
			retp->rva = importp.pe->rva;
			retp->offset = importp.pe->offset;
			retp->ordinal = importp.pe->ordinal;
			retp->hint = importp.pe->hint;
			retp->last = 0;
		}
		retp->last = 1;
		free(import.pe);
		return ret;
	}

	return NULL;
}

r_bin_info* r_bin_get_info(r_bin_obj *bin)
{
	char pe_class_str[PE_NAME_LENGTH], pe_os_str[PE_NAME_LENGTH], pe_machine_str[PE_NAME_LENGTH];
	char pe_arch_str[PE_NAME_LENGTH], pe_subsystem_str[PE_NAME_LENGTH];
	r_bin_info *ret = NULL;

	if((ret = malloc(sizeof(r_bin_info))) == NULL)
		return NULL;
	memset(ret, '\0', sizeof(r_bin_info));

	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		strncpy(ret->type, ELF_CALL(r_bin_elf_get_file_type,bin), R_BIN_SIZEOF_NAMES);
		strncpy(ret->class, ELF_CALL(r_bin_elf_get_elf_class,bin), R_BIN_SIZEOF_NAMES);
		strncpy(ret->rclass, "elf", R_BIN_SIZEOF_NAMES);
		strncpy(ret->os, ELF_CALL(r_bin_elf_get_osabi_name,bin), R_BIN_SIZEOF_NAMES);
		strncpy(ret->subsystem, ELF_CALL(r_bin_elf_get_osabi_name,bin), R_BIN_SIZEOF_NAMES);
		strncpy(ret->machine, ELF_CALL(r_bin_elf_get_machine_name,bin), R_BIN_SIZEOF_NAMES);
		strncpy(ret->arch, ELF_CALL(r_bin_elf_get_arch,bin), R_BIN_SIZEOF_NAMES);
		ret->big_endian=ELF_CALL(r_bin_elf_is_big_endian,bin);
		ret->dbg_info = 0;
		if (ELF_CALL(r_bin_elf_get_stripped,bin)) {
			ret->dbg_info |= 0x01;
		} else {
			ret->dbg_info |= 0x04;
			ret->dbg_info |= 0x08;
			ret->dbg_info |= 0x10;
		}
		if (ELF_CALL(r_bin_elf_get_static,bin))
			ret->dbg_info |= 0x02;
		return ret;
	case R_BIN_FMT_PE:
		if (r_bin_pe_get_class(&bin->object.pe, pe_class_str))
			strncpy(ret->class, pe_class_str, R_BIN_SIZEOF_NAMES);
		strncpy(ret->rclass, "pe", R_BIN_SIZEOF_NAMES);
		if (r_bin_pe_get_os(&bin->object.pe, pe_os_str))
			strncpy(ret->os, pe_os_str, R_BIN_SIZEOF_NAMES);
		if (r_bin_pe_get_arch(&bin->object.pe, pe_arch_str))
			strncpy(ret->arch, pe_arch_str, R_BIN_SIZEOF_NAMES);
		if (r_bin_pe_get_machine(&bin->object.pe, pe_machine_str))
			strncpy(ret->machine, pe_machine_str, R_BIN_SIZEOF_NAMES);
		if (r_bin_pe_get_subsystem(&bin->object.pe, pe_subsystem_str))
			strncpy(ret->subsystem, pe_subsystem_str, R_BIN_SIZEOF_NAMES);
		if (r_bin_pe_is_dll(&bin->object.pe))
			strncpy(ret->type, "DLL (Dynamic Link Library)", R_BIN_SIZEOF_NAMES);
		else
			strncpy(ret->type, "EXEC (Executable file)", R_BIN_SIZEOF_NAMES);
		ret->big_endian = r_bin_pe_is_big_endian(&bin->object.pe);

		ret->dbg_info = 0;
		if (!r_bin_pe_is_stripped_debug(&bin->object.pe))
			ret->dbg_info |= 0x01;
		if (r_bin_pe_is_stripped_line_nums(&bin->object.pe))
			ret->dbg_info |= 0x04;
		if (r_bin_pe_is_stripped_local_syms(&bin->object.pe))
			ret->dbg_info |= 0x08;
		if (r_bin_pe_is_stripped_relocs(&bin->object.pe))
			ret->dbg_info |= 0x10;
		return ret;
	}
	return NULL;
}

u64 r_bin_get_section_offset(r_bin_obj *bin, char *name)
{
	r_bin_section *sections, *sectionsp;
	u64 ret = -1;

	sections = r_bin_get_sections(bin);

	sectionsp = sections;
	while (!sectionsp->last) {
		if (!strcmp(sectionsp->name, name)) {
			ret = sectionsp->offset;
			break;
		}

		sectionsp++;
	}

	free(sections);

	return ret;
}

u64 r_bin_get_section_rva(r_bin_obj *bin, char *name)
{
	r_bin_section *sections, *sectionsp;
	u64 ret = -1;

	sections = r_bin_get_sections(bin);

	sectionsp = sections;
	while (!sectionsp->last) {
		if (!strcmp(sectionsp->name, name)) {
			ret = sectionsp->rva;
			break;
		}

		sectionsp++;
	}

	free(sections);

	return ret;
}

u32 r_bin_get_section_size(r_bin_obj *bin, char *name)
{
	r_bin_section *sections, *sectionsp;
	u64 ret = -1;

	sections = r_bin_get_sections(bin);

	sectionsp = sections;
	while (!sectionsp->last) {
		if (!strcmp(sectionsp->name, name)) {
			ret = sectionsp->size;
			break;
		}
		sectionsp++;
	}

	free(sections);

	return ret;
}

u64 r_bin_resize_section(r_bin_obj *bin, char *name, u64 size)
{
	switch (bin->format) {
	case R_BIN_FMT_ELF32:
	case R_BIN_FMT_ELF64:
		return ELF_CALL(r_bin_elf_resize_section, bin, name, size);
	case R_BIN_FMT_PE:
		return 0;
	}

	return 0;
}

#if 0
int r_bin_get_libs()
{

}

int r_bin_get_strings()
{

}
#endif
