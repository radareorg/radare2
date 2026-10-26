/* radare - LGPL - Copyright 2019-2022 - pancake, nibble */

#include "mach0_defines.h"

static bool section_name_is(const ut8 *raw, const char *name) {
	char segname[17], sectname[17], full[40];
	r_str_ncpy (sectname, (const char *)raw, sizeof (sectname));
	r_str_filter (sectname, -1);
	r_str_ncpy (segname, (const char *)raw + 16, sizeof (segname));
	r_str_filter (segname, -1);
	snprintf (full, sizeof (full), "%s.%s", segname, sectname);
	return strstr (full, name) != NULL;
}

static bool has_prelink_sections(RBuffer *b, ut64 cursor, ut64 end, ut32 ncmds) {
	enum { PRELINK_INFO = 1, PRELINK_TEXT = 2, PRELINK_DATA = 4 };
	ut32 found = 0;
	bool has_data_segment = false;
	ut64 total = 0;
	ut32 i;
	for (i = 0; i < ncmds && cursor < end; i++) {
		ut32 cmdtype = r_buf_read_le32_at (b, cursor);
		ut32 cmdsize = r_buf_read_le32_at (b, cursor + 4);
		if (cmdtype == LC_SEGMENT_64) {
			if (cmdsize < sizeof (struct MACH0_(segment_command))) {
				return false;
			}
			ut8 segname[16];
			if (r_buf_read_at (b, cursor + 8, segname, sizeof (segname)) != sizeof (segname)) {
				return false;
			}
			if (!strncmp ((const char *)segname, "__DATA", sizeof (segname))) {
				has_data_segment = true;
			}
			ut32 nsects = r_buf_read_le32_at (b, cursor + 64);
			if (nsects > MACHO_MAX_SECTIONS - total ||
				cmdsize - sizeof (struct MACH0_(segment_command)) != (ut64)nsects * sizeof (struct MACH0_(section))) {
				return false;
			}
			total += nsects;
			ut64 sect = cursor + sizeof (struct MACH0_(segment_command));
			ut32 j;
			for (j = 0; j < nsects; j++, sect += sizeof (struct MACH0_(section))) {
				ut8 names[32];
				if (r_buf_read_at (b, sect, names, sizeof (names)) != sizeof (names)) {
					return false;
				}
				if (section_name_is (names, "__PRELINK_INFO.__info")) {
					found |= PRELINK_INFO;
				}
				if (section_name_is (names, "__PRELINK_TEXT.__text")) {
					found |= PRELINK_TEXT;
				}
				if (section_name_is (names, "__PRELINK_DATA.__data")) {
					found |= PRELINK_DATA;
				}
			}
		}
		cursor += cmdsize;
	}
	if (!(found & PRELINK_DATA) && has_data_segment) {
		found |= PRELINK_DATA;
	}
	return found == (PRELINK_INFO | PRELINK_TEXT | PRELINK_DATA);
}

static bool is_kernelcache_buffer(RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length < sizeof (struct MACH0_(mach_header))) {
		return false;
	}
	ut32 cputype = r_buf_read_le32_at (b, 4);
	if (cputype != CPU_TYPE_ARM64) {
		return false;
	}
	ut32 filetype = r_buf_read_le32_at (b, 12);
	if (filetype == MH_FILESET) {
		return true;
	}
	ut32 flags = r_buf_read_le32_at (b, 24);
	if (!(flags & MH_PIE)) {
		return false;
	}

	ut32 ncmds = r_buf_read_le32_at (b, 16);
	ut32 sizeofcmds = r_buf_read_le32_at (b, 20);
	ut64 header_size = sizeof (struct MACH0_(mach_header));
	if (sizeofcmds > length - header_size) {
		return false;
	}
	if (ncmds > sizeofcmds / sizeof (struct load_command)) {
		return false;
	}
	bool has_unixthread = false;
	bool has_negative_vaddr = false;
	bool has_kext = false;

	ut64 cursor = header_size;
	ut64 end = cursor + sizeofcmds;
	ut32 i;
	for (i = 0; i < ncmds; i++) {
		if (end - cursor < sizeof (struct load_command)) {
			return false;
		}
		ut32 cmdtype = r_buf_read_le32_at (b, cursor);
		ut32 cmdsize = r_buf_read_le32_at (b, cursor + 4);
		if (cmdsize < sizeof (struct load_command) || cmdsize > end - cursor) {
			return false;
		}

		switch (cmdtype) {
		case LC_KEXT:
			has_kext = true;
			break;
		case LC_UNIXTHREAD:
			has_unixthread = true;
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
		case LC_LAZY_LOAD_DYLIB:
			return false;
		case LC_SEGMENT_64:
			{
				if (has_negative_vaddr) {
					break;
				}
				if (cmdsize < sizeof (struct MACH0_(segment_command))) {
					return false;
				}
				st64 vmaddr = r_buf_read_le64_at (b, cursor + 24);
				if (vmaddr < 0) {
					has_negative_vaddr = true;
				}
			}
			break;
		}
		cursor += cmdsize;
	}

	if (has_kext || !has_unixthread || !has_negative_vaddr) {
		return has_kext;
	}
	return has_prelink_sections (b, header_size, header_size + sizeofcmds, ncmds);
}
