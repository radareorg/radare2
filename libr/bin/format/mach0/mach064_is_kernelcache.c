static bool is_kernelcache(const ut8 *buf, ut64 length) {
	if (length < sizeof (struct MACH0_(mach_header))) {
		return false;
	}
	ut32 cputype = r_read_le32 (buf + 4);
	if (cputype != CPU_TYPE_ARM64) {
		return false;
	}

	const ut8 *end = buf + length;
	const ut8 *cursor = buf + sizeof (struct MACH0_(mach_header));
	int i, ncmds = r_read_le32 (buf + 16);
	bool has_unixthread = false;
	bool has_negative_vaddr = false;

	for (i = 0; i < ncmds; i++) {
		if (cursor >= end) {
			return false;
		}

		ut32 cmdtype = r_read_le32 (cursor);
		ut32 cmdsize = r_read_le32 (cursor + 4);

		switch (cmdtype) {
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
				st64 vmaddr = r_read_le64 (cursor + 24);
				if (vmaddr < 0) {
					has_negative_vaddr = true;
				}
			}
			break;
		}

		cursor += cmdsize;
	}

	return has_unixthread && has_negative_vaddr;
}
