/* radare - LGPL - Copyright 2008-2013 nibble, pancake, xvilka */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "te_specs.h"
#include "te.h"

ut64 r_bin_te_get_stripped_delta(struct r_bin_te_obj_t *bin) {
	return bin->header->StrippedSize - sizeof(TE_image_file_header);
}

ut64 r_bin_te_get_main_paddr(struct r_bin_te_obj_t *bin) {
	RBinAddr *entry = r_bin_te_get_entrypoint (bin);
	ut64 addr = 0LL;
	ut8 buf[512];

	if (r_buf_read_at (bin->b, entry->paddr, buf, sizeof (buf)) == -1) {
		eprintf ("Error: read (entry)\n");
	} else {
		if (buf[367] == 0xe8) {
			int delta = (buf[368] | buf[369]<<8 | buf[370]<<16 | buf[371]<<24);
			addr = entry->vaddr + 367 + 5 + delta;
		}
	}
	free (entry);

	return addr;
}

static TE_DWord r_bin_te_vaddr_to_paddr(struct r_bin_te_obj_t* bin, TE_DWord vaddr) {
	TE_DWord section_base;
	int i, section_size;

	for (i = 0; i < bin->header->NumberOfSections; i++) {
		section_base = bin->section_header[i].VirtualAddress;
		section_size = bin->section_header[i].VirtualSize;
		if (vaddr >= section_base && vaddr < section_base + section_size)
			return bin->section_header[i].PointerToRawData + (vaddr - section_base);
	}
	return 0;
}

static int r_bin_te_init_hdr(struct r_bin_te_obj_t* bin) {
	if (!(bin->header = malloc(sizeof(TE_image_file_header)))) {
		perror ("malloc (header)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, 0, (ut8*)bin->header, sizeof(TE_image_file_header)) == -1) {
		eprintf("Error: read (header)\n");
		return R_FALSE;
	}
	if (strncmp ((char*)&bin->header->Signature, "VZ", 2))
		return R_FALSE;
	return R_TRUE;
}

static int r_bin_te_init_sections(struct r_bin_te_obj_t* bin) {
	int sections_size = sizeof(TE_image_section_header) * bin->header->NumberOfSections;
	if (sections_size > bin->size) {
		eprintf ("Invalid NumberOfSections value\n");
		return R_FALSE;
	}
	if (!(bin->section_header = malloc (sections_size))) {
		perror ("malloc (sections headers)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, sizeof(TE_image_file_header),
				(ut8*)bin->section_header, sections_size) == -1) {
		eprintf ("Error: read (sections headers)\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int r_bin_te_init(struct r_bin_te_obj_t* bin) {
	bin->header = NULL;
	bin->section_header = NULL;
	bin->endian = 0;
	if (!r_bin_te_init_hdr(bin)) {
		eprintf("Warning: File is not TE\n");
		return R_FALSE;
	}
	if (!r_bin_te_init_sections(bin)) {
		eprintf("Warning: Cannot initialize sections\n");
		return R_FALSE;
	}
	return R_TRUE;
}

char* r_bin_te_get_arch(struct r_bin_te_obj_t* bin) {
	char *arch;
	switch (bin->header->Machine) {
	case TE_IMAGE_FILE_MACHINE_ALPHA:
	case TE_IMAGE_FILE_MACHINE_ALPHA64:
		arch = strdup("alpha");
		break;
	case TE_IMAGE_FILE_MACHINE_ARM:
	case TE_IMAGE_FILE_MACHINE_THUMB:
		arch = strdup("arm");
		break;
	case TE_IMAGE_FILE_MACHINE_M68K:
		arch = strdup("m68k");
		break;
	case TE_IMAGE_FILE_MACHINE_MIPS16:
	case TE_IMAGE_FILE_MACHINE_MIPSFPU:
	case TE_IMAGE_FILE_MACHINE_MIPSFPU16:
	case TE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		arch = strdup("mips");
		break;
	case TE_IMAGE_FILE_MACHINE_POWERPC:
	case TE_IMAGE_FILE_MACHINE_POWERPCFP:
		arch = strdup("ppc");
		break;
	default:
		arch = strdup("x86");
	}
	return arch;
}

int r_bin_te_get_bits(struct r_bin_te_obj_t* bin) {
	return 32; // It is always 32 bit by now
}


RBinAddr* r_bin_te_get_entrypoint(struct r_bin_te_obj_t* bin) {
	RBinAddr *entry = NULL;

	if ((entry = malloc(sizeof(RBinAddr))) == NULL) {
		perror("malloc (entrypoint)");
		return NULL;
	}
	entry->vaddr = bin->header->AddressOfEntryPoint - r_bin_te_get_stripped_delta(bin);
	if (entry->vaddr == 0) // in TE if EP = 0 then EP = baddr
		entry->vaddr = bin->header->ImageBase;
	entry->paddr = r_bin_te_vaddr_to_paddr(bin, entry->vaddr);
	return entry;
}

ut64 r_bin_te_get_image_base(struct r_bin_te_obj_t* bin)
{
	return (ut64)bin->header->ImageBase;
}

char* r_bin_te_get_machine(struct r_bin_te_obj_t* bin) {
	char *machine;

	switch (bin->header->Machine) {
	case TE_IMAGE_FILE_MACHINE_ALPHA:
		machine = strdup("Alpha");
		break;
	case TE_IMAGE_FILE_MACHINE_ALPHA64:
		machine = strdup("Alpha 64");
		break;
	case TE_IMAGE_FILE_MACHINE_AM33:
		machine = strdup("AM33");
		break;
	case TE_IMAGE_FILE_MACHINE_AMD64:
		machine = strdup("AMD 64");
		break;
	case TE_IMAGE_FILE_MACHINE_ARM:
		machine = strdup("ARM");
		break;
	case TE_IMAGE_FILE_MACHINE_CEE:
		machine = strdup("CEE");
		break;
	case TE_IMAGE_FILE_MACHINE_CEF:
		machine = strdup("CEF");
		break;
	case TE_IMAGE_FILE_MACHINE_EBC:
		machine = strdup("EBC");
		break;
	case TE_IMAGE_FILE_MACHINE_I386:
		machine = strdup("i386");
		break;
	case TE_IMAGE_FILE_MACHINE_IA64:
		machine = strdup("ia64");
		break;
	case TE_IMAGE_FILE_MACHINE_M32R:
		machine = strdup("M32R");
		break;
	case TE_IMAGE_FILE_MACHINE_M68K:
		machine = strdup("M68K");
		break;
	case TE_IMAGE_FILE_MACHINE_MIPS16:
		machine = strdup("Mips 16");
		break;
	case TE_IMAGE_FILE_MACHINE_MIPSFPU:
		machine = strdup("Mips FPU");
		break;
	case TE_IMAGE_FILE_MACHINE_MIPSFPU16:
		machine = strdup("Mips FPU 16");
		break;
	case TE_IMAGE_FILE_MACHINE_POWERPC:
		machine = strdup("PowerPC");
		break;
	case TE_IMAGE_FILE_MACHINE_POWERPCFP:
		machine = strdup("PowerPC FP");
		break;
	case TE_IMAGE_FILE_MACHINE_R10000:
		machine = strdup("R10000");
		break;
	case TE_IMAGE_FILE_MACHINE_R3000:
		machine = strdup("R3000");
		break;
	case TE_IMAGE_FILE_MACHINE_R4000:
		machine = strdup("R4000");
		break;
	case TE_IMAGE_FILE_MACHINE_SH3:
		machine = strdup("SH3");
		break;
	case TE_IMAGE_FILE_MACHINE_SH3DSP:
		machine = strdup("SH3DSP");
		break;
	case TE_IMAGE_FILE_MACHINE_SH3E:
		machine = strdup("SH3E");
		break;
	case TE_IMAGE_FILE_MACHINE_SH4:
		machine = strdup("SH4");
		break;
	case TE_IMAGE_FILE_MACHINE_SH5:
		machine = strdup("SH5");
		break;
	case TE_IMAGE_FILE_MACHINE_THUMB:
		machine = strdup("Thumb");
		break;
	case TE_IMAGE_FILE_MACHINE_TRICORE:
		machine = strdup("Tricore");
		break;
	case TE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		machine = strdup("WCE Mips V2");
		break;
	default:
		machine = strdup("unknown");
	}
	return machine;
}

char* r_bin_te_get_os(struct r_bin_te_obj_t* bin) {
	char *os;

	switch (bin->header->Subsystem) {
	case TE_IMAGE_SUBSYSTEM_NATIVE:
		os = strdup("native");
		break;
	case TE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
	case TE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
	case TE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		os = strdup ("windows");
		break;
	case TE_IMAGE_SUBSYSTEM_POSIX_CUI:
		os = strdup ("posix");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
	case TE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
	case TE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
	case TE_IMAGE_SUBSYSTEM_EFI_ROM:
		os = strdup ("efi");
		break;
	case TE_IMAGE_SUBSYSTEM_XBOX:
		os = strdup ("xbox");
		break;
	default:
		// XXX: this is unknown
		os = strdup ("windows");
	}
	return os;
}

struct r_bin_te_section_t* r_bin_te_get_sections(struct r_bin_te_obj_t* bin) {
	struct r_bin_te_section_t *sections = NULL;
	TE_image_section_header *shdr = bin->section_header;
	int i, sections_count = bin->header->NumberOfSections;

	if ((sections = malloc((sections_count + 1) * sizeof(struct r_bin_te_section_t))) == NULL) {
		perror ("malloc (sections)");
		return NULL;
	}
	for (i = 0; i < sections_count; i++) {
		memcpy (sections[i].name, shdr[i].Name, TE_IMAGE_SIZEOF_NAME);
		// not a null terminated string if len==buflen
		//sections[i].name[TE_IMAGE_SIZEOF_NAME] = '\0';
		sections[i].vaddr = shdr[i].VirtualAddress - r_bin_te_get_stripped_delta(bin);
		sections[i].size = shdr[i].SizeOfRawData;
		sections[i].vsize = shdr[i].VirtualSize;
		sections[i].paddr = shdr[i].PointerToRawData - r_bin_te_get_stripped_delta(bin);
		sections[i].flags = shdr[i].Characteristics;
		sections[i].last = 0;
	}
	sections[i].last = 1;
	return sections;
}

char* r_bin_te_get_subsystem(struct r_bin_te_obj_t* bin) {
	char *subsystem;

	switch (bin->header->Subsystem) {
	case TE_IMAGE_SUBSYSTEM_NATIVE:
		subsystem = strdup("Native");
		break;
	case TE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
		subsystem = strdup("Windows GUI");
		break;
	case TE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
		subsystem = strdup("Windows CUI");
		break;
	case TE_IMAGE_SUBSYSTEM_POSIX_CUI:
		subsystem = strdup("POSIX CUI");
		break;
	case TE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		subsystem = strdup("Windows CE GUI");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
		subsystem = strdup("EFI Application");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		subsystem = strdup("EFI Boot Service Driver");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		subsystem = strdup("EFI Runtime Driver");
		break;
	case TE_IMAGE_SUBSYSTEM_EFI_ROM:
		subsystem = strdup("EFI ROM");
		break;
	case TE_IMAGE_SUBSYSTEM_XBOX:
		subsystem = strdup("XBOX");
		break;
	default:
		subsystem = strdup("Unknown");
	}
	return subsystem;
}

void* r_bin_te_free(struct r_bin_te_obj_t* bin) {
	if (!bin) return NULL;
	free (bin->header);
	free (bin->section_header);
	r_buf_free (bin->b);
	free (bin);
	return NULL;
}

struct r_bin_te_obj_t* r_bin_te_new(const char* file) {
	ut8 *buf;
	struct r_bin_te_obj_t *bin = R_NEW0 (struct r_bin_te_obj_t);
	if (!bin) return NULL;
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size)))
		return r_bin_te_free(bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return r_bin_te_free(bin);
	}
	free (buf);
	if (!r_bin_te_init(bin))
		return r_bin_te_free(bin);
	return bin;
}

struct r_bin_te_obj_t* r_bin_te_new_buf(struct r_buf_t *buf) {
	struct r_bin_te_obj_t *bin = R_NEW0 (struct r_bin_te_obj_t);
	if (!bin) return NULL;
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		return r_bin_te_free(bin);
	}
	if (!r_bin_te_init(bin))
		return r_bin_te_free(bin);
	return bin;
}
