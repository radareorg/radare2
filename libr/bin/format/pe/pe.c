/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <r_types.h>

#if __UNIX__
#include <sys/mman.h>
#endif

#include "pe.h"

enum {
	ENCODING_ASCII = 0,
	ENCODING_CP850 = 1
};

static PE_DWord r_bin_pe_aux_rva_to_offset(r_bin_pe_obj *bin, PE_DWord rva)
{
	pe_image_section_header *shdrp;
	PE_DWord section_base;
	int i, section_size;

	shdrp = bin->section_header;
	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++, shdrp++) {
		section_base = shdrp->VirtualAddress;
		section_size = shdrp->Misc.VirtualSize;
		if (rva >= section_base && rva < section_base + section_size)
			return shdrp->PointerToRawData + (rva - section_base);
	}
		
	return 0;
}

static PE_DWord r_bin_pe_aux_offset_to_rva(r_bin_pe_obj *bin, PE_DWord offset)
{
	pe_image_section_header *shdrp;
	PE_DWord section_base;
	int i, section_size;

	shdrp = bin->section_header;
	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++, shdrp++) {
		section_base = shdrp->PointerToRawData;
		section_size = shdrp->SizeOfRawData;
		if (offset >= section_base && offset < section_base + section_size)
			return shdrp->VirtualAddress + (offset - section_base);
	}
		
	return 0;
}

// XXX dupped code in elf.c...we really need cp850 support? =) where's utf? use iconv?
static int r_bin_pe_aux_is_encoded(int encoding, unsigned char c)
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

static int r_bin_pe_aux_stripstr_from_file(r_bin_pe_obj *bin, int min, int encoding, PE_DWord seek, PE_DWord limit, const char *filter, int str_limit, r_bin_pe_string *strings)
{
	int fd = open(bin->file, O_RDONLY);
	r_bin_pe_string *stringsp;
	unsigned char *buf;
	PE_DWord i = seek;
	PE_DWord len, string_len;
	int unicode = 0, matches = 0;
	static int ctr = 0;
	char str[PE_STRING_LENGTH];

	if (fd == -1) {
		ERR("Cannot open target file.\n")    ;
		return 1;
	}

	len = lseek(fd, 0, SEEK_END);

	// TODO: use read here ?!?
	/* TODO: do not use mmap */
#if __UNIX__
	buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (((int)buf) == -1 ) {
		perror("mmap");
		return 1;
	}
	if (min <1)
		min = 5;

	if (limit && limit < len)
		len = limit;

	stringsp = strings;
	for(i = seek; i < len && ctr < str_limit; i++) { 
		if ((IS_PRINTABLE(buf[i]) || (r_bin_pe_aux_is_encoded(encoding, buf[i])))) {
			str[matches] = buf[i];
			if (matches < sizeof(str))
				matches++;
		} else {
			/* wide char check \x??\x00\x??\x00 */
			if (matches && buf[i+2]=='\0' && buf[i]=='\0' && buf[i+1]!='\0') {
				unicode = 1;
			}
			/* check if the length fits on our request */
			if (matches >= min) {
				str[matches] = '\0';
				string_len = strlen(str);
				if (string_len>2) {
					if (!filter || strstr(str, filter)) {
						stringsp->offset = i-matches;
						stringsp->rva = r_bin_pe_aux_offset_to_rva(bin, i-matches);
						stringsp->type = (unicode?'U':'A');
						stringsp->size = string_len;
						memcpy(stringsp->string, str, PE_STRING_LENGTH);
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

static int r_bin_pe_do_checks(r_bin_pe_obj *bin)
{
	if (strncmp((char*)&bin->dos_header->e_magic, "MZ", 2)) {
		ERR("File not PE\n");
		return -1;
	}

	if (strncmp((char*)&bin->nt_headers->Signature, "PE", 2)) {
		ERR("File not PE\n");
		return -1;
	}

	if (bin->nt_headers->file_header.SizeOfOptionalHeader != 224)
		return -1;

	return 0;
}

static int r_bin_pe_init(r_bin_pe_obj *bin)
{
	int sections_size;

	lseek(bin->fd, 0, SEEK_SET);
	bin->dos_header = malloc(sizeof(pe_image_dos_header));
	read(bin->fd, bin->dos_header, sizeof(pe_image_dos_header));

	lseek(bin->fd, bin->dos_header->e_lfanew, SEEK_SET);
	bin->nt_headers = malloc(sizeof(pe_image_nt_headers));
	read(bin->fd, bin->nt_headers, sizeof(pe_image_nt_headers));

	if (r_bin_pe_do_checks(bin) == -1)
		return -1;

	sections_size = sizeof(pe_image_section_header) * bin->nt_headers->file_header.NumberOfSections;
	lseek(bin->fd, bin->dos_header->e_lfanew + sizeof(pe_image_nt_headers), SEEK_SET);
	bin->section_header = malloc(sections_size);
	read(bin->fd, bin->section_header, sections_size);

	return 0;
}

static int r_bin_pe_init_exports(r_bin_pe_obj *bin)
{
	pe_image_data_directory *data_dir_export = &bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	PE_DWord export_dir_offset = r_bin_pe_aux_rva_to_offset(bin, data_dir_export->VirtualAddress);

	if (export_dir_offset == 0)
		return -1;

	lseek(bin->fd, export_dir_offset, SEEK_SET);
	bin->export_directory = malloc(sizeof(pe_image_export_directory));
	read(bin->fd, bin->export_directory, sizeof(pe_image_export_directory));

	return 0;
}

static int r_bin_pe_init_imports(r_bin_pe_obj *bin)
{
	pe_image_data_directory *data_dir_import = &bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_IMPORT];
	pe_image_data_directory *data_dir_delay_import = &bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	PE_DWord import_dir_offset = r_bin_pe_aux_rva_to_offset(bin, data_dir_import->VirtualAddress);
	PE_DWord delay_import_dir_offset = r_bin_pe_aux_rva_to_offset(bin, data_dir_delay_import->VirtualAddress);
	int import_dir_size = data_dir_import->Size;
	int delay_import_dir_size = data_dir_delay_import->Size;
	
	if (import_dir_offset == 0 && delay_import_dir_offset == 0)
		return -1;

	if (import_dir_offset != 0) {
		lseek(bin->fd, import_dir_offset, SEEK_SET);
		bin->import_directory = malloc(import_dir_size);
		read(bin->fd, bin->import_directory, import_dir_size);
	}

	if (delay_import_dir_offset != 0) {
		lseek(bin->fd, delay_import_dir_offset, SEEK_SET);
		bin->delay_import_directory = malloc(delay_import_dir_size);
		read(bin->fd, bin->delay_import_directory, delay_import_dir_size);
	}

	return 0;
}

static int r_bin_pe_get_import_dirs_count(r_bin_pe_obj *bin)
{
	pe_image_data_directory *data_dir_import = &bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_IMPORT];

	return (int) (data_dir_import->Size / sizeof(pe_image_import_directory) - 1);
}

static int r_bin_pe_get_delay_import_dirs_count(r_bin_pe_obj *bin)
{
	pe_image_data_directory *data_dir_delay_import = \
		&bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

	return (int) (data_dir_delay_import->Size / sizeof(pe_image_delay_import_directory) - 1);
}

static int r_bin_pe_parse_imports(r_bin_pe_obj *bin, r_bin_pe_import **importp, char *dll_name, PE_DWord OriginalFirstThunk, PE_DWord FirstThunk)
{
	char import_name[PE_NAME_LENGTH], name[PE_NAME_LENGTH];
	PE_Word import_hint, import_ordinal;
	PE_DWord import_table = 0;
	int i = 0;

	do {
		lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, OriginalFirstThunk) + i * sizeof(PE_DWord), SEEK_SET);
		read(bin->fd, &import_table, sizeof(PE_DWord));

		if (import_table & 0x80000000) {
			import_ordinal = import_table & 0x7fffffff;
			import_hint = 0;
			snprintf(import_name, PE_NAME_LENGTH, "%s_Ordinal_%i", dll_name, import_ordinal);
		} else if (import_table) {
			import_ordinal = 0;
			lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, import_table), SEEK_SET);
			read(bin->fd, &import_hint, sizeof(PE_Word));
			read(bin->fd, name, PE_NAME_LENGTH);
			snprintf(import_name, PE_NAME_LENGTH, "%s_%s", dll_name, name);
		}
		
		if (import_table) {
			memcpy((*importp)->name, import_name, PE_NAME_LENGTH);
			(*importp)->rva = FirstThunk + i * sizeof(PE_DWord);
			(*importp)->offset = r_bin_pe_aux_rva_to_offset(bin, FirstThunk) + i * sizeof(PE_DWord);
			(*importp)->hint = import_hint;
			(*importp)->ordinal = import_ordinal;
			(*importp)++; i++;
		}
	} while (import_table);

	return 0;
}

int r_bin_pe_close(r_bin_pe_obj *bin)
{
	if (bin->dos_header != NULL)
		free(bin->dos_header);
	if (bin->nt_headers != NULL)
		free(bin->nt_headers);
	if (bin->section_header != NULL)
		free(bin->section_header);
	if (bin->export_directory != NULL)
		free(bin->export_directory);
	if (bin->import_directory != NULL)
		free(bin->import_directory);
	if (bin->delay_import_directory != NULL)
		free(bin->delay_import_directory);

	return close(bin->fd);
}

int r_bin_pe_get_arch(r_bin_pe_obj *bin, char *str)
{
	if (str)
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ALPHA:
	case PE_IMAGE_FILE_MACHINE_ALPHA64:
		snprintf(str, PE_NAME_LENGTH, "alpha");
		break;
	case PE_IMAGE_FILE_MACHINE_ARM:
	case PE_IMAGE_FILE_MACHINE_THUMB:
		snprintf(str, PE_NAME_LENGTH, "arm");
		break;
	case PE_IMAGE_FILE_MACHINE_M68K:
		snprintf(str, PE_NAME_LENGTH, "m68k");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPS16:
	case PE_IMAGE_FILE_MACHINE_MIPSFPU:
	case PE_IMAGE_FILE_MACHINE_MIPSFPU16:
	case PE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		snprintf(str, PE_NAME_LENGTH, "mips");
		break;
	case PE_IMAGE_FILE_MACHINE_POWERPC:
	case PE_IMAGE_FILE_MACHINE_POWERPCFP:
		snprintf(str, PE_NAME_LENGTH, "ppc");
		break;
	case PE_IMAGE_FILE_MACHINE_AMD64:
	case PE_IMAGE_FILE_MACHINE_IA64:
		snprintf(str, PE_NAME_LENGTH, "intel64");
		break;
	default:
		snprintf(str, PE_NAME_LENGTH, "intel");
	}
	return bin->nt_headers->file_header.Machine;
}

// XXX: why not return entrypoint address in u64 form here?
// XXX: do we really need int?
int r_bin_pe_get_entrypoint(r_bin_pe_obj *bin, r_bin_pe_entrypoint *entrypoint)
{
	entrypoint->rva = bin->nt_headers->optional_header.AddressOfEntryPoint;
	entrypoint->offset = r_bin_pe_aux_rva_to_offset(bin, bin->nt_headers->optional_header.AddressOfEntryPoint);
	return 0;
}

int r_bin_pe_get_exports(r_bin_pe_obj *bin, r_bin_pe_export *export)
{
	PE_DWord functions_offset, names_offset, ordinals_offset, function_rva, name_rva, name_offset;
	PE_Word function_ordinal;
	r_bin_pe_export *exportp;
	char function_name[PE_NAME_LENGTH], forwarder_name[PE_NAME_LENGTH];
	char dll_name[PE_NAME_LENGTH], export_name[PE_NAME_LENGTH];
	int i;
	pe_image_data_directory *data_dir_export =
		&bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	PE_DWord export_dir_rva = data_dir_export->VirtualAddress;
	int export_dir_size = data_dir_export->Size;
	
	if (r_bin_pe_init_exports(bin) == -1)
		return -1;
	
	lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, bin->export_directory->Name), SEEK_SET);
    	read(bin->fd, dll_name, PE_NAME_LENGTH);

	functions_offset = r_bin_pe_aux_rva_to_offset(bin, bin->export_directory->AddressOfFunctions);
	names_offset = r_bin_pe_aux_rva_to_offset(bin, bin->export_directory->AddressOfNames);
	ordinals_offset = r_bin_pe_aux_rva_to_offset(bin, bin->export_directory->AddressOfOrdinals);

	exportp = export;
	for (i = 0; i < bin->export_directory->NumberOfNames; i++, exportp++) {
		lseek(bin->fd, functions_offset + i * sizeof(PE_DWord), SEEK_SET);
		read(bin->fd, &function_rva, sizeof(PE_DWord));
		lseek(bin->fd, ordinals_offset + i * sizeof(PE_Word), SEEK_SET);
		read(bin->fd, &function_ordinal, sizeof(PE_Word));
		lseek(bin->fd, names_offset + i * sizeof(PE_DWord), SEEK_SET);
		read(bin->fd, &name_rva, sizeof(PE_DWord));
		name_offset = r_bin_pe_aux_rva_to_offset(bin, name_rva);

		if (name_offset) {
			lseek(bin->fd, name_offset, SEEK_SET);
			read(bin->fd, function_name, PE_NAME_LENGTH);
		} else {
			snprintf(function_name, PE_NAME_LENGTH, "Ordinal_%i", function_ordinal);
		}
		
		snprintf(export_name, PE_NAME_LENGTH, "%s_%s", dll_name, function_name);

		if (function_rva >= export_dir_rva && function_rva < (export_dir_rva + export_dir_size)) {
			lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, function_rva), SEEK_SET);
			read(bin->fd, forwarder_name, PE_NAME_LENGTH);
		} else {
			snprintf(forwarder_name, PE_NAME_LENGTH, "NONE");
		}

		exportp->rva = function_rva;
		exportp->offset = r_bin_pe_aux_rva_to_offset(bin, function_rva);
		exportp->ordinal = function_ordinal;
		memcpy(exportp->forwarder, forwarder_name, PE_NAME_LENGTH);
		memcpy(exportp->name, export_name, PE_NAME_LENGTH);
	}

	return 0;
}

int r_bin_pe_get_exports_count(r_bin_pe_obj *bin)
{
	if (r_bin_pe_init_exports(bin) == -1)
		return 0;
	
	return bin->export_directory->NumberOfNames;
}

int r_bin_pe_get_file_alignment(r_bin_pe_obj *bin)
{
	return bin->nt_headers->optional_header.FileAlignment;
}

PE_DWord r_bin_pe_get_image_base(r_bin_pe_obj *bin)
{
	return bin->nt_headers->optional_header.ImageBase;
}

int r_bin_pe_get_imports(r_bin_pe_obj *bin, r_bin_pe_import *import)
{
	pe_image_import_directory *import_dirp;
	pe_image_delay_import_directory *delay_import_dirp;
	r_bin_pe_import *importp;
	char dll_name[PE_NAME_LENGTH];
	int import_dirs_count = r_bin_pe_get_import_dirs_count(bin);
	int delay_import_dirs_count = r_bin_pe_get_delay_import_dirs_count(bin);
	int i;
	
	if (r_bin_pe_init_imports(bin) == -1)
		return -1;

	importp = import;

	import_dirp = bin->import_directory;
	for (i = 0; i < import_dirs_count; i++, import_dirp++) {
		lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, import_dirp->Name), SEEK_SET);
		read(bin->fd, dll_name, PE_NAME_LENGTH);
		r_bin_pe_parse_imports(bin, &importp, dll_name,
			import_dirp->Characteristics, import_dirp->FirstThunk);
	}

	delay_import_dirp = bin->delay_import_directory;
	for (i = 0; i < delay_import_dirs_count; i++, delay_import_dirp++) {
		lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, delay_import_dirp->Name), SEEK_SET);
		read(bin->fd, dll_name, PE_NAME_LENGTH);
		r_bin_pe_parse_imports(bin, &importp, dll_name, delay_import_dirp->DelayImportNameTable,
			delay_import_dirp->DelayImportAddressTable);
	}

	return 0;
}

int r_bin_pe_get_imports_count(r_bin_pe_obj *bin)
{
	pe_image_import_directory *import_dirp;
	pe_image_delay_import_directory *delay_import_dirp;
	PE_DWord import_table;
	int import_dirs_count = r_bin_pe_get_import_dirs_count(bin);
	int delay_import_dirs_count = r_bin_pe_get_delay_import_dirs_count(bin);
	int imports_count = 0, i, j;

	if (r_bin_pe_init_imports(bin) == -1)
		return 0;

	import_dirp = bin->import_directory;
	import_table = 0;
	for (i = 0; i < import_dirs_count; i++, import_dirp++) {
		j = 0;
		do {
			lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, import_dirp->Characteristics) + j * sizeof(PE_DWord), SEEK_SET);
    			read(bin->fd, &import_table, sizeof(PE_DWord));
			
			if (import_table) {
				imports_count++;
				j++;
			}
		} while (import_table);
	}

	delay_import_dirp = bin->delay_import_directory;
	import_table = 0;
	for (i = 0; i < delay_import_dirs_count; i++, delay_import_dirp++) {
		j = 0;
		do {
			lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, delay_import_dirp->DelayImportNameTable) + j * sizeof(PE_DWord), SEEK_SET);
    			read(bin->fd, &import_table, sizeof(PE_DWord));
			
			if (import_table) {
				imports_count++;
				j++;
			}
		} while (import_table);
	}

	return imports_count;
}

int r_bin_pe_get_libs(r_bin_pe_obj *bin, int limit, r_bin_pe_string *strings)
{
	pe_image_import_directory *import_dirp;
	pe_image_delay_import_directory *delay_import_dirp;
	r_bin_pe_string *stringsp;
	char dll_name[PE_STRING_LENGTH];
	int import_dirs_count = r_bin_pe_get_import_dirs_count(bin), delay_import_dirs_count = r_bin_pe_get_delay_import_dirs_count(bin);
	int i, ctr=0;
	
	if (r_bin_pe_init_imports(bin) == -1)
		return -1;

	import_dirp = bin->import_directory;
	stringsp = strings;
	for (i = 0; i < import_dirs_count && ctr < limit; i++, import_dirp++, stringsp++) {
		lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, import_dirp->Name), SEEK_SET);
		read(bin->fd, dll_name, PE_STRING_LENGTH);
		memcpy(stringsp->string, dll_name, PE_STRING_LENGTH);
		stringsp->type = 'A';
		stringsp->offset = 0;
		stringsp->size = 0;
		ctr++;
	}
	
	delay_import_dirp = bin->delay_import_directory;
	for (i = 0; i < delay_import_dirs_count && ctr < limit; i++, delay_import_dirp++, stringsp++) {
		lseek(bin->fd, r_bin_pe_aux_rva_to_offset(bin, delay_import_dirp->Name), SEEK_SET);
		read(bin->fd, dll_name, PE_STRING_LENGTH);
		memcpy(stringsp->string, dll_name, PE_STRING_LENGTH);
		stringsp->type = 'A';
		stringsp->offset = 0;
		stringsp->size = 0;
		ctr++;
	}
	
	return ctr;
}

int r_bin_pe_get_image_size(r_bin_pe_obj *bin)
{
	return bin->nt_headers->optional_header.SizeOfImage;
}

int r_bin_pe_get_machine(r_bin_pe_obj *bin, char *str)
{
	if (str)
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ALPHA:
		snprintf(str, PE_NAME_LENGTH, "Alpha");
		break;
	case PE_IMAGE_FILE_MACHINE_ALPHA64:
		snprintf(str, PE_NAME_LENGTH, "Alpha 64");
		break;
	case PE_IMAGE_FILE_MACHINE_AM33:
		snprintf(str, PE_NAME_LENGTH, "AM33");
		break;
	case PE_IMAGE_FILE_MACHINE_AMD64:
		snprintf(str, PE_NAME_LENGTH, "AMD 64");
		break;
	case PE_IMAGE_FILE_MACHINE_ARM:
		snprintf(str, PE_NAME_LENGTH, "ARM");
		break;
	case PE_IMAGE_FILE_MACHINE_CEE:
		snprintf(str, PE_NAME_LENGTH, "CEE");
		break;
	case PE_IMAGE_FILE_MACHINE_CEF:
		snprintf(str, PE_NAME_LENGTH, "CEF");
		break;
	case PE_IMAGE_FILE_MACHINE_EBC:
		snprintf(str, PE_NAME_LENGTH, "EBC");
		break;
	case PE_IMAGE_FILE_MACHINE_I386:
		snprintf(str, PE_NAME_LENGTH, "i386");
		break;
	case PE_IMAGE_FILE_MACHINE_IA64:
		snprintf(str, PE_NAME_LENGTH, "ia64");
		break;
	case PE_IMAGE_FILE_MACHINE_M32R:
		snprintf(str, PE_NAME_LENGTH, "M32R");
		break;
	case PE_IMAGE_FILE_MACHINE_M68K:
		snprintf(str, PE_NAME_LENGTH, "M68K");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPS16:
		snprintf(str, PE_NAME_LENGTH, "Mips 16");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPSFPU:
		snprintf(str, PE_NAME_LENGTH, "Mips FPU");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPSFPU16:
		snprintf(str, PE_NAME_LENGTH, "Mips FPU 16");
		break;
	case PE_IMAGE_FILE_MACHINE_POWERPC:
		snprintf(str, PE_NAME_LENGTH, "PowerPC");
		break;
	case PE_IMAGE_FILE_MACHINE_POWERPCFP:
		snprintf(str, PE_NAME_LENGTH, "PowerPC FP");
		break;
	case PE_IMAGE_FILE_MACHINE_R10000:
		snprintf(str, PE_NAME_LENGTH, "R10000");
		break;
	case PE_IMAGE_FILE_MACHINE_R3000:
		snprintf(str, PE_NAME_LENGTH, "R3000");
		break;
	case PE_IMAGE_FILE_MACHINE_R4000:
		snprintf(str, PE_NAME_LENGTH, "R4000");
		break;
	case PE_IMAGE_FILE_MACHINE_SH3:
		snprintf(str, PE_NAME_LENGTH, "SH3");
		break;
	case PE_IMAGE_FILE_MACHINE_SH3DSP:
		snprintf(str, PE_NAME_LENGTH, "SH3DSP");
		break;
	case PE_IMAGE_FILE_MACHINE_SH3E:
		snprintf(str, PE_NAME_LENGTH, "SH3E");
		break;
	case PE_IMAGE_FILE_MACHINE_SH4:
		snprintf(str, PE_NAME_LENGTH, "SH4");
		break;
	case PE_IMAGE_FILE_MACHINE_SH5:
		snprintf(str, PE_NAME_LENGTH, "SH5");
		break;
	case PE_IMAGE_FILE_MACHINE_THUMB:
		snprintf(str, PE_NAME_LENGTH, "Thumb");
		break;
	case PE_IMAGE_FILE_MACHINE_TRICORE:
		snprintf(str, PE_NAME_LENGTH, "Tricore");
		break;
	case PE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		snprintf(str, PE_NAME_LENGTH, "WCE Mips V2");
		break;
	default:
		snprintf(str, PE_NAME_LENGTH, "unknown");
	}

	return bin->nt_headers->file_header.Machine;
}

int r_bin_pe_get_os(r_bin_pe_obj *bin, char *str)
{
	if (str)
	switch (bin->nt_headers->optional_header.Subsystem) {
	case PE_IMAGE_SUBSYSTEM_NATIVE:
		snprintf(str, PE_NAME_LENGTH, "native");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		snprintf(str, PE_NAME_LENGTH, "windows");
		break;
	case PE_IMAGE_SUBSYSTEM_POSIX_CUI:
		snprintf(str, PE_NAME_LENGTH, "posix");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
	case PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
	case PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
	case PE_IMAGE_SUBSYSTEM_EFI_ROM:
		snprintf(str, PE_NAME_LENGTH, "efi");
		break;
	case PE_IMAGE_SUBSYSTEM_XBOX:
		snprintf(str, PE_NAME_LENGTH, "xbox");
		break;
	default:
		snprintf(str, PE_NAME_LENGTH, "unknown");
	}

	return bin->nt_headers->optional_header.Subsystem;
}

int r_bin_pe_get_class(r_bin_pe_obj *bin, char *str)
{
	if (str)
	switch (bin->nt_headers->optional_header.Magic) {
	case PE_IMAGE_FILE_TYPE_PE32:
		snprintf(str, PE_NAME_LENGTH, "PE32");
		break;
	case PE_IMAGE_FILE_TYPE_PE32PLUS:
		snprintf(str, PE_NAME_LENGTH, "PE32+");
		break;
	}
	return bin->nt_headers->optional_header.Magic;
}

int r_bin_pe_get_section_alignment(r_bin_pe_obj *bin)
{
	return bin->nt_headers->optional_header.SectionAlignment;
}

int r_bin_pe_get_sections(r_bin_pe_obj *bin, r_bin_pe_section *section)
{
	pe_image_section_header *shdrp;
	r_bin_pe_section *sectionp;
	int i, sections_count = r_bin_pe_get_sections_count(bin);

	shdrp = bin->section_header;
	sectionp = section;
	for (i = 0; i < sections_count; i++, shdrp++, sectionp++) {
		memcpy(sectionp->name, shdrp->Name, PE_IMAGE_SIZEOF_SHORT_NAME);
		sectionp->rva = shdrp->VirtualAddress;
		sectionp->size = shdrp->SizeOfRawData;
		sectionp->vsize = shdrp->Misc.VirtualSize;
		sectionp->offset = shdrp->PointerToRawData;
		sectionp->characteristics = shdrp->Characteristics;
	}

	return 0;
}

int r_bin_pe_get_sections_count(r_bin_pe_obj *bin)
{
	return bin->nt_headers->file_header.NumberOfSections;
}

int r_bin_pe_get_strings(r_bin_pe_obj *bin, int verbose, int str_limit, r_bin_pe_string *strings)
{
	pe_image_section_header *shdrp;
	int i, ctr = 0, sections_count = r_bin_pe_get_sections_count(bin);

	shdrp = bin->section_header;
	for (i = 0; i < sections_count; i++, shdrp++) {
		ctr = r_bin_pe_aux_stripstr_from_file(
			bin, 5, ENCODING_ASCII, shdrp->PointerToRawData,
			shdrp->PointerToRawData+shdrp->SizeOfRawData, NULL,
			str_limit, strings+ctr);
	}

	return ctr;
}

int r_bin_pe_get_subsystem(r_bin_pe_obj *bin, char *str)
{
	if (str)
	switch (bin->nt_headers->optional_header.Subsystem) {
	case PE_IMAGE_SUBSYSTEM_UNKNOWN:
		snprintf(str, PE_NAME_LENGTH, "Unknown");
		break;
	case PE_IMAGE_SUBSYSTEM_NATIVE:
		snprintf(str, PE_NAME_LENGTH, "Native");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
		snprintf(str, PE_NAME_LENGTH, "Windows GUI");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
		snprintf(str, PE_NAME_LENGTH, "Windows CUI");
		break;
	case PE_IMAGE_SUBSYSTEM_POSIX_CUI:
		snprintf(str, PE_NAME_LENGTH, "POSIX CUI");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		snprintf(str, PE_NAME_LENGTH, "Windows CE GUI");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
		snprintf(str, PE_NAME_LENGTH, "EFI Application");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		snprintf(str, PE_NAME_LENGTH, "EFI Boot Service Driver");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		snprintf(str, PE_NAME_LENGTH, "EFI Runtime Driver");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_ROM:
		snprintf(str, PE_NAME_LENGTH, "EFI ROM");
		break;
	case PE_IMAGE_SUBSYSTEM_XBOX:
		snprintf(str, PE_NAME_LENGTH, "XBOX");
		break;
	}

	return bin->nt_headers->optional_header.Subsystem;
}

int r_bin_pe_is_dll(r_bin_pe_obj *bin)
{
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_DLL;
}

int r_bin_pe_is_big_endian(r_bin_pe_obj *bin)
{
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_BYTES_REVERSED_HI;
}

int r_bin_pe_is_stripped_relocs(r_bin_pe_obj *bin)
{
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_RELOCS_STRIPPED;
}

int r_bin_pe_is_stripped_line_nums(r_bin_pe_obj *bin)
{
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_LINE_NUMS_STRIPPED;
}

int r_bin_pe_is_stripped_local_syms(r_bin_pe_obj *bin) {
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED;
}

int r_bin_pe_is_stripped_debug(r_bin_pe_obj *bin)
{
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_DEBUG_STRIPPED;
}

int r_bin_pe_open(r_bin_pe_obj *bin, const char *file)
{
	bin->dos_header = NULL;
	bin->nt_headers = NULL;
	bin->section_header = NULL;
	bin->export_directory = NULL;
	bin->import_directory = NULL;
	bin->delay_import_directory = NULL;

	if ((bin->fd = open(file, O_RDONLY)) == -1)
		return -1;

	bin->file = file;

	if (r_bin_pe_init(bin) == -1) {
		close(bin->fd);
		return -1;
	}

	return bin->fd;
}
