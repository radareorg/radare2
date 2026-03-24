#include <r_magic.h>
#include <r_util.h>
#include "minunit.h"

static bool check_magic_output(const char *magic_source, const ut8 *probe, size_t probe_len, const char *expected) {
	RMagic *ms = r_magic_new (0);
	const char *type;

	mu_assert_notnull (ms, "r_magic_new () failed");
	mu_assert_true (r_magic_load_buffer (ms, (const ut8 *)magic_source, strlen (magic_source)), "text buffer load failed");
	type = r_magic_buffer (ms, probe, probe_len);
	mu_assert_notnull (type, "magic probe failed");
	mu_assert_streq (type, expected, "magic match");

	r_magic_free (ms);
	mu_end;
}

static bool test_r_magic_load_text_buffer(void) {
	const char magic_source[] =
		"0\tstring\tABCD\ttext magic\n"
		"!:mime\ttext/x-r2-magic\n";
	const ut8 probe[] = "ABCD";
	RMagic *ms = r_magic_new (0);
	const char *type;

	mu_assert_notnull (ms, "r_magic_new () failed");
	mu_assert_true (r_magic_load_buffer (ms, (const ut8 *)magic_source, sizeof (magic_source) - 1), "text buffer load failed");
	r_magic_setflags (ms, R_MAGIC_MIME_TYPE);
	type = r_magic_buffer (ms, probe, sizeof (probe) - 1);
	mu_assert_notnull (type, "text magic probe failed");
	mu_assert_streq (type, "text/x-r2-magic", "text magic match");

	r_magic_free (ms);
	mu_end;
}

static bool test_r_magic_load_compiled_buffer(void) {
	struct {
		struct r_magic header;
		struct r_magic entry;
	} db;
	const ut8 probe[] = "ABCD";
	const ut32 hdr[] = { MAGICNO, VERSIONNO };
	RMagic *ms;
	const char *type;

	memset (&db, 0, sizeof (db));
	memcpy (&db.header, hdr, sizeof (hdr));
	db.entry.flag = BINTEST;
	db.entry.reln = '=';
	db.entry.vallen = 4;
	db.entry.type = FILE_STRING;
	db.entry.lineno = 1;
	memcpy (db.entry.value.s, probe, sizeof (probe) - 1);
	memcpy (db.entry.desc, "compiled magic", sizeof ("compiled magic"));

	ms = r_magic_new (0);
	mu_assert_notnull (ms, "r_magic_new () failed");
	mu_assert_true (r_magic_load_buffer (ms, (const ut8 *)&db, sizeof (db)), "compiled buffer load failed");
	type = r_magic_buffer (ms, probe, sizeof (probe) - 1);
	mu_assert_notnull (type, "compiled magic probe failed");
	mu_assert_streq (type, "compiled magic", "compiled magic match");

	r_magic_free (ms);
	mu_end;
}

static bool test_r_magic_load_buffer_accepts_printf_suffixes(void) {
	const char magic_source[] =
		"0\tbyte\t0x41\tversion %c,\n"
		"0\tbyte\t0x42\tvalue %d,\n"
		"0\tstring\tABCD\tfrom '%s'\n"
		"0\tstring\tWXYZ\t%.3s\n";
	RMagic *ms = r_magic_new (0);

	mu_assert_notnull (ms, "r_magic_new () failed");
	mu_assert_true (r_magic_load_buffer (ms, (const ut8 *)magic_source, sizeof (magic_source) - 1), "printf descriptions should load");

	r_magic_free (ms);
	mu_end;
}

static bool test_r_magic_buffer_formats_byte_char_descriptions(void) {
	const char magic_source[] = "0\tbyte\t0x41\tversion %c,\n";
	const ut8 probe[] = "ABCD";

	return check_magic_output (magic_source, probe, sizeof (probe) - 1, "version A,");
}

static bool test_r_magic_buffer_formats_string_precision_descriptions(void) {
	const char magic_source[] = "0\tstring\tABCD\t%.3s\n";
	const ut8 probe[] = "ABCD";

	return check_magic_output (magic_source, probe, sizeof (probe) - 1, "ABC");
}

static bool test_r_magic_file_uses_slurp_and_buffer(void) {
	const char magic_source[] = "0\tstring\tABCD\tfile magic\n";
	char *filename = NULL;
	const ut8 probe[] = "ABCD";
	RMagic *ms = r_magic_new (0);
	const char *type;
	int fd;

	mu_assert_notnull (ms, "r_magic_new () failed");
	mu_assert_true (r_magic_load_buffer (ms, (const ut8 *)magic_source, sizeof (magic_source) - 1), "text buffer load failed");
	fd = r_file_mkstemp ("", &filename);
	mu_assert_neq ((ut64)fd, (ut64)-1, "mkstemp failed");
	mu_assert_eq ((int)write (fd, probe, sizeof (probe) - 1), (int)(sizeof (probe) - 1), "probe write failed");
	close (fd);
	type = r_magic_file (ms, filename);
	mu_assert_notnull (type, "magic file probe failed");
	mu_assert_streq (type, "file magic", "magic file match");

	r_file_rm (filename);
	free (filename);
	r_magic_free (ms);
	mu_end;
}

static bool test_r_magic_load_buffers_merges_multiple_databases(void) {
	const char magic_a[] = "0\tstring\tABCD\tmagic A\n";
	const char magic_b[] = "0\tstring\tWXYZ\tmagic B\n";
	const void *buffers[] = { magic_a, magic_b };
	const size_t sizes[] = { sizeof (magic_a) - 1, sizeof (magic_b) - 1 };
	const ut8 probe[] = "WXYZ";
	RMagic *ms = r_magic_new (0);
	const char *type;

	mu_assert_notnull (ms, "r_magic_new () failed");
	mu_assert_true (r_magic_load_buffers (ms, buffers, sizes, 2), "buffer list load failed");
	type = r_magic_buffer (ms, probe, sizeof (probe) - 1);
	mu_assert_notnull (type, "merged magic probe failed");
	mu_assert_streq (type, "magic B", "merged magic match");

	r_magic_free (ms);
	mu_end;
}

static bool test_r_magic_getflags_returns_current_flags(void) {
	RMagic *ms = r_magic_new (0);

	mu_assert_notnull (ms, "r_magic_new () failed");
	r_magic_setflags (ms, R_MAGIC_MIME_TYPE | R_MAGIC_RAW);
	mu_assert_eq (r_magic_getflags (ms), R_MAGIC_MIME_TYPE | R_MAGIC_RAW, "flag roundtrip");

	r_magic_free (ms);
	mu_end;
}

static bool test_r_magic_load_accepts_null_magic_path(void) {
	const char magic_source[] = "0\tstring\tABCD\tenv magic\n";
	const ut8 probe[] = "ABCD";
	char *filename = NULL;
	char *old_magic = r_sys_getenv ("MAGIC");
	RMagic *ms = r_magic_new (0);
	const char *type;
	int fd;

	mu_assert_notnull (ms, "r_magic_new () failed");
	fd = r_file_mkstemp ("", &filename);
	mu_assert_neq ((ut64)fd, (ut64)-1, "mkstemp failed");
	mu_assert_eq ((int)write (fd, magic_source, sizeof (magic_source) - 1), (int)(sizeof (magic_source) - 1), "magic write failed");
	close (fd);
	mu_assert_eq (r_sys_setenv ("MAGIC", filename), 0, "setenv failed");
	mu_assert_true (r_magic_load (ms, NULL), "null path load failed");
	type = r_magic_buffer (ms, probe, sizeof (probe) - 1);
	mu_assert_notnull (type, "env-backed magic probe failed");
	mu_assert_streq (type, "env magic", "env-backed magic match");

	if (old_magic) {
		r_sys_setenv ("MAGIC", old_magic);
	} else {
		r_sys_setenv ("MAGIC", "");
	}
	free (old_magic);
	r_file_rm (filename);
	free (filename);
	r_magic_free (ms);
	mu_end;
}

static bool test_r_magic_api_version_matches_header_constant(void) {
	mu_assert_eq (r_magic_api_version (), R_MAGIC_VERSION, "version mismatch");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_magic_load_text_buffer);
	mu_run_test (test_r_magic_load_compiled_buffer);
	mu_run_test (test_r_magic_load_buffer_accepts_printf_suffixes);
	mu_run_test (test_r_magic_buffer_formats_byte_char_descriptions);
	mu_run_test (test_r_magic_buffer_formats_string_precision_descriptions);
	mu_run_test (test_r_magic_file_uses_slurp_and_buffer);
	mu_run_test (test_r_magic_load_buffers_merges_multiple_databases);
	mu_run_test (test_r_magic_getflags_returns_current_flags);
	mu_run_test (test_r_magic_load_accepts_null_magic_path);
	mu_run_test (test_r_magic_api_version_matches_header_constant);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	return all_tests ();
}
