/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>
#include "minunit.h"

static RBuffer *gameboy_rom(ut8 bank_id, ut8 color, size_t size) {
	static const ut8 logo[] = {
		0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00, 0x83,
		0x00, 0x0c, 0x00, 0x0d, 0x00, 0x08, 0x11, 0x1f, 0x88, 0x89, 0x00, 0x0e,
		0xdc, 0xcc, 0x6e, 0xe6, 0xdd, 0xdd, 0xd9, 0x99, 0xbb, 0xbb, 0x67, 0x63,
		0x6e, 0x0e, 0xec, 0xcc, 0xdd, 0xdc, 0x99, 0x9f, 0xbb, 0xb9, 0x33, 0x3e
	};
	ut8 *bytes = calloc (1, size);
	if (!bytes) {
		return NULL;
	}
	memcpy (bytes + 0x104, logo, sizeof (logo));
	if (size >= 0x150) {
		bytes[0x143] = color;
		bytes[0x148] = bank_id;
	}
	RBuffer *buf = r_buf_new_with_bytes (bytes, size);
	free (bytes);
	return buf;
}

static bool test_gameboy_banks(void) {
	static const struct {
		ut8 id;
		int count;
	} cases[] = { { 0, 2 }, { 6, 128 }, { 7, 256 }, { 8, 512 }, { 0x52, 72 }, { 0x53, 80 }, { 0x54, 96 } };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RBuffer *buf = gameboy_rom (cases[i].id, 0, cases[i].count * 0x4000);
		mu_assert_notnull (buf, "cartridge buffer");
		RBin *bin = r_bin_new ();
		RIO *io = r_io_new ();
		r_io_bind (io, &bin->iob);
		RBinFileOptions opt = {0};
		r_bin_file_options_init (&opt, -1, 0, 0, 0);
		opt.filename = "synthetic.gb";
		opt.pluginname = "ningb";
		mu_assert_true (r_bin_open_buf (bin, buf, &opt), "load Game Boy ROM");
		RVecRBinSection *sections = r_bin_get_sections_vec (bin);
		mu_assert_eq (RVecRBinSection_length (sections), cases[i].count, "ROM bank count");
		RBinSection *last = RVecRBinSection_at (sections, cases[i].count - 1);
		mu_assert_eq (last->paddr, (cases[i].count - 1) * 0x4000, "last ROM bank physical address");
		mu_assert_eq (last->vaddr, (cases[i].count - 1) * 0x10000 - 0xc000, "last ROM bank analysis address");
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

static bool test_gameboy_memory(void) {
	RBuffer *buf = gameboy_rom (8, 0xc0, 0x5000);
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);
	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "partial.gbc";
	opt.pluginname = "ningb";
	mu_assert_true (r_bin_open_buf (bin, buf, &opt), "load partial ROM for analysis");
	RVecRBinSection *sections = r_bin_get_sections_vec (bin);
	mu_assert_eq (RVecRBinSection_length (sections), 2, "no sections beyond end of ROM");
	RBinSection *last = RVecRBinSection_at (sections, 1);
	mu_assert_eq (last->size, 0x1000, "partial bank physical size");
	mu_assert_eq (last->vsize, 0x4000, "partial bank virtual size");
	mu_assert_true (strstr (r_bin_get_info (bin)->type, "GameboyColor"), "CGB-only header flag");
	RList *memory = r_bin_get_mem (bin);
	RBinMem *region;
	RListIter *iter;
	bool ports = false, echo = false;
	r_list_foreach (memory, iter, region) {
		if (!strcmp (region->name, "ioports")) {
			ports = region->addr == 0xff00 && region->size == 0x80;
		}
		if (region->mirrors) {
			RBinMem *mirror = r_list_first (region->mirrors);
			echo = mirror && mirror->addr == 0xe000 && (mirror->perms & R_PERM_W);
		}
	}
	mu_assert_true (ports, "complete IO register range");
	mu_assert_true (echo, "writable echo RAM");
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_gameboy_banks);
	mu_run_test (test_gameboy_memory);
	return tests_passed != tests_run;
}
