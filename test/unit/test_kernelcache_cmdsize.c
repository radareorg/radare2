#include <r_util.h>
#include <r_bin.h>
#include "minunit.h"
#include "../../libr/bin/format/mach0/mach0_defines.h"

static void write_le32(RBuffer *buf, ut64 off, ut32 value) {
	ut8 tmp[4];
	r_write_le32 (tmp, value);
	r_buf_write_at (buf, off, tmp, sizeof (tmp));
}

static void write_le64(RBuffer *buf, ut64 off, ut64 value) {
	ut8 tmp[8];
	r_write_le64 (tmp, value);
	r_buf_write_at (buf, off, tmp, sizeof (tmp));
}

static void write_padded(RBuffer *buf, ut64 off, const char *str, size_t len) {
	ut8 tmp[16];
	memset (tmp, 0, sizeof (tmp));
	r_str_ncpy ((char *)tmp, str, len);
	r_buf_write_at (buf, off, tmp, len);
}

static void write_mach0_header(RBuffer *buf, ut64 off, ut32 filetype, ut32 ncmds, ut32 sizeofcmds) {
	write_le32 (buf, off + offsetof (struct mach_header_64, magic), MH_MAGIC_64);
	write_le32 (buf, off + offsetof (struct mach_header_64, cputype), CPU_TYPE_ARM64);
	write_le32 (buf, off + offsetof (struct mach_header_64, cpusubtype), 0);
	write_le32 (buf, off + offsetof (struct mach_header_64, filetype), filetype);
	write_le32 (buf, off + offsetof (struct mach_header_64, ncmds), ncmds);
	write_le32 (buf, off + offsetof (struct mach_header_64, sizeofcmds), sizeofcmds);
	write_le32 (buf, off + offsetof (struct mach_header_64, flags), MH_PIE);
	write_le32 (buf, off + offsetof (struct mach_header_64, reserved), 0);
}

static void write_segsect64(RBuffer *buf, ut64 off, const char *segname, const char *sectname, ut64 vaddr, ut64 paddr) {
	const ut32 cmdsize = sizeof (struct segment_command_64) + sizeof (struct section_64);
	ut64 sec_off = off + sizeof (struct segment_command_64);

	write_le32 (buf, off + offsetof (struct segment_command_64, cmd), LC_SEGMENT_64);
	write_le32 (buf, off + offsetof (struct segment_command_64, cmdsize), cmdsize);
	write_padded (buf, off + offsetof (struct segment_command_64, segname), segname, 16);
	write_le64 (buf, off + offsetof (struct segment_command_64, vmaddr), vaddr);
	write_le64 (buf, off + offsetof (struct segment_command_64, vmsize), 0x1000);
	write_le64 (buf, off + offsetof (struct segment_command_64, fileoff), paddr);
	write_le64 (buf, off + offsetof (struct segment_command_64, filesize), 0x1000);
	write_le32 (buf, off + offsetof (struct segment_command_64, maxprot), 5);
	write_le32 (buf, off + offsetof (struct segment_command_64, initprot), 5);
	write_le32 (buf, off + offsetof (struct segment_command_64, nsects), 1);
	write_le32 (buf, off + offsetof (struct segment_command_64, flags), 0);

	write_padded (buf, sec_off + offsetof (struct section_64, sectname), sectname, 16);
	write_padded (buf, sec_off + offsetof (struct section_64, segname), segname, 16);
	write_le64 (buf, sec_off + offsetof (struct section_64, addr), vaddr);
	write_le64 (buf, sec_off + offsetof (struct section_64, size), 0x10);
	write_le32 (buf, sec_off + offsetof (struct section_64, offset), (ut32)paddr);
	write_le32 (buf, sec_off + offsetof (struct section_64, align), 2);
	write_le32 (buf, sec_off + offsetof (struct section_64, reloff), 0);
	write_le32 (buf, sec_off + offsetof (struct section_64, nreloc), 0);
	write_le32 (buf, sec_off + offsetof (struct section_64, flags), 0);
	write_le32 (buf, sec_off + offsetof (struct section_64, reserved1), 0);
	write_le32 (buf, sec_off + offsetof (struct section_64, reserved2), 0);
	write_le32 (buf, sec_off + offsetof (struct section_64, reserved3), 0);
}

static bool has_kext_section(RList *sections) {
	RListIter *it;
	RBinSection *section;
	r_list_foreach (sections, it, section) {
		if (section && section->name && strstr (section->name, "testkext.")) {
			return true;
		}
	}
	return false;
}

bool test_kernelcache_cmdsize(void) {
	RBuffer *buf = r_buf_new_sparse (0);
	const ut64 big_size = 0x100000400ULL;
	const ut64 header_size = sizeof (struct mach_header_64);
	const ut64 cmd1_off = header_size;
	const ut32 cmd1_size = 0xfffffff0U;
	const ut64 cmd2_off = cmd1_off + (ut64)cmd1_size;
	const ut32 cmd2_size = 48;
	const ut64 seg_cmd_size = sizeof (struct segment_command_64) + sizeof (struct section_64);
	const ut64 cmd3_off = cmd2_off + cmd2_size;
	const ut64 cmd4_off = cmd3_off + seg_cmd_size;
	const ut64 cmd5_off = cmd4_off + seg_cmd_size;
	const ut64 kext_off = 0x2000;
	const ut64 kext_cmd_off = kext_off + header_size;

	r_buf_resize (buf, big_size);

	write_mach0_header (buf, 0, MH_FILESET, 5, 0);
	write_le32 (buf, cmd1_off + offsetof (struct load_command, cmd), LC_SEGMENT_64);
	write_le32 (buf, cmd1_off + offsetof (struct load_command, cmdsize), cmd1_size);

	write_le32 (buf, cmd2_off + offsetof (struct load_command, cmd), LC_KEXT);
	write_le32 (buf, cmd2_off + offsetof (struct load_command, cmdsize), cmd2_size);
	write_le64 (buf, cmd2_off + 8, kext_off);
	write_le64 (buf, cmd2_off + 16, kext_off);
	write_padded (buf, cmd2_off + 32, "testkext", 16);

	write_segsect64 (buf, cmd3_off, "__PRELINK_INFO", "__info", 0x3000, 0x3000);
	write_segsect64 (buf, cmd4_off, "__PRELINK_TEXT", "__text", 0x4000, 0x4000);
	write_segsect64 (buf, cmd5_off, "__PRELINK_DATA", "__data", 0x5000, 0x5000);

	write_mach0_header (buf, kext_off, MH_EXECUTE, 1, seg_cmd_size);
	write_segsect64 (buf, kext_cmd_off, "__TEXT_EXEC", "__text", 0x1000, 0x1000);

	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.pluginname = "kernelcache";
	bool res = r_bin_open_buf (bin, buf, &opt);
	mu_assert ("kernelcache buffer could not be opened", res);

	RList *sections = r_bin_get_sections (bin);
	mu_assert ("kernelcache sections missing kext data", sections && has_kext_section (sections));

	r_bin_free (bin);
	r_io_free (io);
	r_buf_free (buf);
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_kernelcache_cmdsize);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
