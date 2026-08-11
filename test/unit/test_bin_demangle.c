#include <r_bin.h>
#include "minunit.h"

static char *unit_demangle(RBinFile *bf, const char *symbol, ut64 vaddr) {
	(void)bf;
	(void)vaddr;
	return strdup (symbol);
}

static bool test_demangle_registry(void) {
	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "RBin allocation");
	mu_assert_true (r_libstore_load (bin->libstore), "load static RBin plugins");

	RBinDemanglePlugin *cxx = r_bin_demangle_plugin_find (bin, "cxx");
	if (cxx) {
		mu_assert_ptreq (cxx, r_bin_demangle_plugin_find (bin, "c++"), "C++ alias lookup");
		mu_assert_ptreq (cxx, bin->demangle_by_type[r_bits_ctz32 (R_BIN_LANG_CXX)], "C++ direct table lookup");
	}

	RBinDemanglePlugin plugin = {
		.meta = {
			.name = "unit",
			.desc = "unit test demangler",
		},
		.type = R_BIN_LANG_NONE,
		.aliases = "test,testalias",
		.demangle = unit_demangle,
	};
	mu_assert_true (r_bin_demangle_plugin_add (bin, &plugin), "add named demangler");
	mu_assert_ptreq (r_bin_demangle_plugin_find (bin, "unit"), r_bin_demangle_plugin_find (bin, "testalias"), "custom alias lookup");

	RBinFile bf = { 0 };
	bf.rbin = bin;
	char *res = r_bin_demangle (&bf, "test", "symbol", 0, false);
	mu_assert_streq (res, "symbol", "dispatch an explicitly named demangler");
	free (res);

	RBinDemanglePlugin duplicate_alias = {
		.meta.name = "duplicate",
		.type = R_BIN_LANG_NONE,
		.aliases = "testalias",
		.demangle = unit_demangle,
	};
	mu_assert_false (r_bin_demangle_plugin_add (bin, &duplicate_alias), "reject duplicate aliases");

	RBinDemanglePlugin typed = {
		.meta.name = "typed",
		.type = R_BIN_LANG_CIL,
		.demangle = unit_demangle,
	};
	mu_assert_true (r_bin_demangle_plugin_add (bin, &typed), "add typed demangler");
	RBinDemanglePlugin duplicate_type = {
		.meta.name = "duplicate_type",
		.type = R_BIN_LANG_CIL,
		.demangle = unit_demangle,
	};
	mu_assert_false (r_bin_demangle_plugin_add (bin, &duplicate_type), "reject duplicate language providers");
	res = r_bin_demangle (&bf, "cil", "typed-symbol", 0, false);
	mu_assert_streq (res, "typed-symbol", "direct language table dispatch");
	free (res);

	RBinDemanglePlugin invalid_type = {
		.meta.name = "invalid_type",
		.type = R_BIN_LANG_CXX | R_BIN_LANG_RUST,
		.demangle = unit_demangle,
	};
	mu_assert_false (r_bin_demangle_plugin_add (bin, &invalid_type), "reject non-unique language types");
	mu_assert_true (r_bin_demangle_plugin_remove (bin, &typed), "remove typed demangler");
	mu_assert_true (r_bin_demangle_plugin_remove (bin, &plugin), "remove named demangler");
	mu_assert_null (r_bin_demangle_plugin_find (bin, "testalias"), "remove alias index");
	mu_assert_null (r_bin_demangle_plugin (bin, "missing", "symbol"), "missing demangler");

	r_bin_free (bin);
	mu_end;
}

static bool all_tests(void) {
	mu_run_test (test_demangle_registry);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	return all_tests ();
}
