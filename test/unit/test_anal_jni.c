#include <r_core.h>
#include "minunit.h"

#define DATA_ADDR 0x1000
#define STRINGS_ADDR 0x2000
#define CODE_ADDR 0x3000
#define RECORD_SIZE64 24
#define REBASE 0x10000

static void write_record(ut8 *buf, int index, int ps, bool be, ut64 name, ut64 desc, ut64 fcn) {
	ut8 *record = buf + index * ps * 3;
	if (ps == 8) {
		r_write_ble64 (record, name, be);
		r_write_ble64 (record + 8, desc, be);
		r_write_ble64 (record + 16, fcn, be);
	} else {
		r_write_ble32 (record, name, be);
		r_write_ble32 (record + 4, desc, be);
		r_write_ble32 (record + 8, fcn, be);
	}
}

static RCore *jni_test_core_new(int bits, bool big_endian, ut64 shift) {
	RCore *core = r_core_new ();
	core->io->va = true;
	r_io_open_at (core->io, "malloc://128", R_PERM_RW, 0644, DATA_ADDR + shift);
	r_io_open_at (core->io, "malloc://256", R_PERM_RW, 0644, STRINGS_ADDR + shift);
	r_io_open_at (core->io, "malloc://128", R_PERM_RWX, 0644, CODE_ADDR + shift);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", bits);
	core->anal->config->endian = big_endian? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;

	RBinFile *bf = R_NEW0 (RBinFile);
	RBinObject *bo = R_NEW0 (RBinObject);
	bf->bo = bo;
	bf->rbin = core->bin;
	core->bin->cur = bf;
	RVecRBinSection_init (&bo->sections_vec);
	RBinSection *section = RVecRBinSection_emplace_back (&bo->sections_vec);
	section->name = strdup (".data");
	section->vaddr = DATA_ADDR;
	section->paddr = DATA_ADDR;
	section->size = (bits / 8) * 3 * 3;
	section->vsize = section->size;
	section->perm = R_PERM_RW;
	bo->baddr_shift = shift;
	bo->langs = r_vpack_add (bo->langs, R_BIN_LANG_JNI);
	return core;
}

static void jni_test_core_free(RCore *core) {
	RBinFile *bf = core->bin->cur;
	core->bin->cur = NULL;
	RVecRBinSection_fini (&bf->bo->sections_vec);
	free (bf->bo);
	free (bf);
	r_core_free (core);
}

static RAnalPlugin *jni_test_plugin(RAnal *anal) {
	RListIter *iter;
	RAnalPlugin *plugin;
	r_list_foreach (anal->libstore->plugins, iter, plugin) {
		if (!strcmp (plugin->meta.name, "jni")) {
			return plugin;
		}
	}
	return NULL;
}

static bool test_jni_native_method_table_scan(void) {
	RCore *core = jni_test_core_new (64, false, 0);
	mu_assert_notnull (core, "create test core");
	ut8 strings[0x90] = { 0 };
	memcpy (strings, "first", sizeof ("first"));
	memcpy (strings + 0x10, "(I)V", sizeof ("(I)V"));
	memcpy (strings + 0x20, "second", sizeof ("second"));
	memcpy (strings + 0x30, "()I", sizeof ("()I"));
	memcpy (strings + 0x40, "onlyOne", sizeof ("onlyOne"));
	memcpy (strings + 0x50, "not-a-descriptor", sizeof ("not-a-descriptor"));
	memcpy (strings + 0x70, "looksValid", sizeof ("looksValid"));
	memcpy (strings + 0x80, "(V)V", sizeof ("(V)V"));
	mu_assert_true (r_io_write_at (core->io, STRINGS_ADDR, strings, sizeof (strings)),
		"write JNI strings");

	ut8 data[RECORD_SIZE64 * 3] = { 0 };
	write_record (data, 0, 8, false, STRINGS_ADDR, STRINGS_ADDR + 0x10, CODE_ADDR);
	write_record (data, 1, 8, false, STRINGS_ADDR + 0x20, STRINGS_ADDR + 0x30,
		CODE_ADDR + 0x10);
	write_record (data, 2, 8, false, STRINGS_ADDR + 0x40, STRINGS_ADDR + 0x50,
		CODE_ADDR + 0x20);
	mu_assert_true (r_io_write_at (core->io, DATA_ADDR, data, sizeof (data)),
		"write valid JNI table");
	RAnalPlugin *plugin = jni_test_plugin (core->anal);
	mu_assert_notnull (plugin, "find JNI analysis plugin");
	mu_assert_eq (plugin->eligible (core->anal), 0, "JNI plugin eligibility");
	mu_assert_true (plugin->pre_analysis (core->anal), "discover JNI table");
	Sdb *db = sdb_ns (core->anal->sdb, "jni", 0);
	mu_assert_notnull (db, "JNI analysis database");
	mu_assert_eq (sdb_num_get (db, "tables", 0), 1, "one JNI table");
	mu_assert_eq (sdb_num_get (db, "table.0.addr", 0), DATA_ADDR, "table address");
	mu_assert_eq (sdb_num_get (db, "table.0.count", 0), 2, "method count");
	mu_assert_streq (sdb_const_get (db, "table.0.method.0.name", 0), "first",
		"first method name");
	mu_assert_streq (sdb_const_get (db, "table.0.method.0.descriptor", 0), "(I)V",
		"first method descriptor");
	mu_assert_eq (sdb_num_get (db, "table.0.method.1.function", 0), CODE_ADDR + 0x10,
		"second method function");

	memset (data, 0, sizeof (data));
	write_record (data, 0, 8, false, STRINGS_ADDR, STRINGS_ADDR + 0x10, CODE_ADDR);
	mu_assert_true (r_io_write_at (core->io, DATA_ADDR, data, sizeof (data)),
		"write one-record JNI candidate");
	mu_assert_false (plugin->pre_analysis (core->anal),
		"reject a single JNI record");
	mu_assert_eq (sdb_num_get (db, "tables", 0), 0, "single record is not a table");

	memset (data, 0, sizeof (data));
	write_record (data, 0, 8, false, STRINGS_ADDR + 0x40, STRINGS_ADDR + 0x50,
		CODE_ADDR);
	write_record (data, 1, 8, false, STRINGS_ADDR + 0x70, STRINGS_ADDR + 0x80,
		CODE_ADDR + 0x10);
	mu_assert_true (r_io_write_at (core->io, DATA_ADDR, data, sizeof (data)),
		"write non-JNI pointer triples");
	mu_assert_false (plugin->pre_analysis (core->anal),
		"reject malformed JNI descriptors");
	mu_assert_eq (sdb_num_get (db, "tables", 0), 0, "invalid triples are not a table");

	jni_test_core_free (core);
	mu_end;
}

static bool test_jni_big_endian_32bit_table(void) {
	RCore *core = jni_test_core_new (32, true, REBASE);
	mu_assert_notnull (core, "create 32-bit test core");
	ut8 strings[0x40] = { 0 };
	memcpy (strings, "first", sizeof ("first"));
	memcpy (strings + 0x10, "(I)V", sizeof ("(I)V"));
	memcpy (strings + 0x20, "second", sizeof ("second"));
	memcpy (strings + 0x30, "()I", sizeof ("()I"));
	mu_assert_true (r_io_write_at (core->io, STRINGS_ADDR + REBASE, strings, sizeof (strings)),
		"write 32-bit JNI strings");
	ut8 data[36] = { 0 };
	write_record (data, 0, 4, true, STRINGS_ADDR, STRINGS_ADDR + 0x10, CODE_ADDR);
	write_record (data, 1, 4, true, STRINGS_ADDR + 0x20, STRINGS_ADDR + 0x30,
		CODE_ADDR + 0x10);
	mu_assert_true (r_io_write_at (core->io, DATA_ADDR + REBASE, data, sizeof (data)),
		"write big-endian JNI table");
	RAnalPlugin *plugin = jni_test_plugin (core->anal);
	mu_assert_notnull (plugin, "find JNI analysis plugin");
	mu_assert_true (plugin->pre_analysis (core->anal), "discover big-endian table");
	Sdb *db = sdb_ns (core->anal->sdb, "jni", 0);
	mu_assert_eq (sdb_num_get (db, "table.0.addr", 0), DATA_ADDR + REBASE,
		"rebased table address");
	mu_assert_eq (sdb_num_get (db, "table.0.count", 0), 2, "32-bit method count");
	mu_assert_eq (sdb_num_get (db, "table.0.method.1.function", 0),
		CODE_ADDR + REBASE + 0x10,
		"32-bit function pointer");
	jni_test_core_free (core);
	mu_end;
}

static bool all_tests(void) {
	mu_run_test (test_jni_native_method_table_scan);
	mu_run_test (test_jni_big_endian_32bit_table);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	return all_tests ();
}
