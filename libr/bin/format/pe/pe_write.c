/* radare - LGPL - Copyright 2008-2016 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "pe.h"

bool PE_(r_bin_pe_section_perms)(struct PE_(r_bin_pe_obj_t) *bin, const char *name, int perms) {
	PE_(image_section_header) *section_header = bin->section_header;
	PE_(image_section_header) *target_section = 0;
	int i; ut32 charac; ut32 p_offset;

	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++) {
		if (!strncmp(section_header[i].Name, name, PE_IMAGE_SIZEOF_SHORT_NAME)) {
			target_section = &section_header[i];
			charac = target_section->Characteristics;
			break;
		}
	}
	
	if (!target_section)
	{
		eprintf("Cannot find section named %s\n", name);
		return false;
	}
	
	charac = charac & 0x0FFFFFFF;
	if (perms & 1)
		charac |= PE_IMAGE_SCN_MEM_EXECUTE;
	if (perms & 2)
		charac |= PE_IMAGE_SCN_MEM_WRITE;
	if (perms & 4)
		charac |= PE_IMAGE_SCN_MEM_READ;
	if (perms & 16)
		charac |= PE_IMAGE_SCN_MEM_SHARED;

	p_offset = bin->nt_header_offset + sizeof(PE_(image_nt_headers)) + sizeof(PE_(image_section_header)) * i;
	p_offset += r_offsetof(PE_(image_section_header), Characteristics);
	r_buf_write_at (bin->b, p_offset, &charac, sizeof(charac));
	return true;
}