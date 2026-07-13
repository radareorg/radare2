#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>

//TODO test r_str_chop_path

bool test_r_bin(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinFileOptions opt = {0};
	bool res = r_bin_open (bin, "bins/elf/ioli/crackme0x00", &opt);
	mu_assert ("crackme0x00 binary could not be opened", res);

	RVecRBinSection *sections = r_bin_get_sections_vec (bin);
	// XXX this is wrong, because its returning the sections and the segments, we need another api here
	mu_assert_eq (RVecRBinSection_length (sections), 39, "r_bin_get_sections_vec");

	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

static RBuffer *pebble_resource_pack(ut32 table_size) {
	size_t content_start = 12 + table_size * 16;
	const ut8 content[] = "ICONfont-data";
	size_t size = content_start + sizeof (content) - 1;
	ut8 *bytes = calloc (1, size);
	if (!bytes) {
		return NULL;
	}
	r_write_le32 (bytes, 2);
	r_write_le32 (bytes + 4, 0x11223344);
	r_write_le32 (bytes + 8, 0);
	r_write_le32 (bytes + 12, 1);
	r_write_le32 (bytes + 16, 0);
	r_write_le32 (bytes + 20, 4);
	r_write_le32 (bytes + 24, 0xaabbccdd);
	r_write_le32 (bytes + 28, 2);
	r_write_le32 (bytes + 32, 4);
	r_write_le32 (bytes + 36, sizeof (content) - 5);
	r_write_le32 (bytes + 40, 0x55667788);
	memcpy (bytes + content_start, content, sizeof (content) - 1);
	RBuffer *buf = r_buf_new_with_bytes (bytes, size);
	free (bytes);
	return buf;
}

bool test_r_bin_pebble_resources(void) {
	RBuffer *buf = pebble_resource_pack (256);
	mu_assert_notnull (buf, "Pebble resource pack allocation");
	RBin *bin = r_bin_new ();
	RBinFile probe = {0};
	probe.file = "app_resources.pbpack";
	RBinPlugin *plugin = r_bin_get_binplugin_by_buffer (bin, &probe, buf);
	mu_assert_true (plugin && !strcmp (plugin->meta.name, "pebble"), "Pebble application resource pack detection");
	RBuffer *system_buf = pebble_resource_pack (512);
	mu_assert_notnull (system_buf, "Pebble system resource pack allocation");
	probe.file = "system_resources.pbpack";
	plugin = r_bin_get_binplugin_by_buffer (bin, &probe, system_buf);
	mu_assert_true (plugin && !strcmp (plugin->meta.name, "pebble"), "Pebble system resource pack detection");
	r_unref (system_buf);
	RBuffer *invalid_buf = pebble_resource_pack (256);
	mu_assert_notnull (invalid_buf, "Invalid Pebble resource pack allocation");
	ut8 invalid_offset[4];
	r_write_le32 (invalid_offset, UT32_MAX);
	r_buf_write_at (invalid_buf, 16, invalid_offset, sizeof (invalid_offset));
	probe.file = "invalid.pbpack";
	plugin = r_bin_get_binplugin_by_buffer (bin, &probe, invalid_buf);
	mu_assert_false (plugin && !strcmp (plugin->meta.name, "pebble"), "Reject out-of-bounds Pebble resource");
	r_unref (invalid_buf);
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "app_resources.pbpack";
	bool opened = r_bin_open_buf (bin, buf, &opt);
	mu_assert_true (opened, "Pebble resource pack could not be opened");

	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Pebble resource pack binfile");
	RVecRBinResource *resources = r_bin_file_get_resources (bf);
	mu_assert_notnull (resources, "Pebble resources");
	mu_assert_eq (RVecRBinResource_length (resources), 2, "Pebble resource count");
	RBinResource *resource = RVecRBinResource_at (resources, 0);
	mu_assert_streq (resource->name, "1", "Pebble resource id name");
	mu_assert_streq (resource->type, "RESOURCE", "Pebble resource type");
	mu_assert_eq (resource->paddr, 4108, "Pebble resource physical address");
	mu_assert_eq (resource->size, 4, "Pebble resource size");

	RBuffer *data = r_bin_file_get_resource_data (bf, resource);
	mu_assert_notnull (data, "Pebble resource data");
	ut8 bytes[4];
	mu_assert_eq (r_buf_read_at (data, 0, bytes, sizeof (bytes)), sizeof (bytes), "Read Pebble resource data");
	mu_assert_memeq (bytes, (const ut8 *)"ICON", sizeof (bytes), "Pebble resource contents");
	r_unref (data);

	RVecRBinSection *sections = r_bin_get_sections_vec (bin);
	mu_assert_eq (RVecRBinSection_length (sections), 3, "Pebble resource pack sections");
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	mu_end;
}


bool all_tests(void) {
	mu_run_test(test_r_bin);
	mu_run_test(test_r_bin_pebble_resources);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
