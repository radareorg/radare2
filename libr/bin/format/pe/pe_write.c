/* radare - LGPL - Copyright 2010-2018 pancake, nibble */

#include <r_types.h>
#include <r_util.h>
#include "pe.h"

bool PE_(r_bin_pe_section_perms)(struct PE_(r_bin_pe_obj_t) *bin, const char *name, int perms) {
	PE_(image_section_header) *shdr = bin->section_header;
	int i;

	if (!shdr) {
		return false;
	}

	for (i = 0; i < bin->num_sections; i++) {
		const char *sname = (const char*) shdr[i].Name;
		if (!strncmp (name, sname, PE_IMAGE_SIZEOF_SHORT_NAME)) {
			int patchoff;
			ut32 newperms = shdr[i].Characteristics;
			ut32 newperms_le;

			/* Apply permission flags */
			if (perms & R_PERM_X) {
				newperms |=  PE_IMAGE_SCN_MEM_EXECUTE;
			} else {
				newperms &= ~PE_IMAGE_SCN_MEM_EXECUTE;
			}
			if (perms & R_PERM_W) {
				newperms |=  PE_IMAGE_SCN_MEM_WRITE;
			} else {
				newperms &= ~PE_IMAGE_SCN_MEM_WRITE;
			}
			if (perms & R_PERM_R) {
				newperms |=  PE_IMAGE_SCN_MEM_READ;
			} else {
				newperms &= ~PE_IMAGE_SCN_MEM_READ;
			}
			if (perms & R_PERM_SHAR) {
				newperms |=  PE_IMAGE_SCN_MEM_SHARED;
			} else {
				newperms &= ~PE_IMAGE_SCN_MEM_SHARED;
			}

			patchoff = bin->section_header_offset;
			patchoff += i * sizeof (PE_(image_section_header));
			patchoff += r_offsetof (PE_(image_section_header), Characteristics);
			r_write_le32 (&newperms_le, newperms);
			printf ("wx %02x @ 0x%x\n", newperms_le, patchoff);
			r_buf_write_at (bin->b, patchoff, (ut8*)&newperms_le, sizeof (newperms_le));
			return true;
		}
	}
	return false;
}
