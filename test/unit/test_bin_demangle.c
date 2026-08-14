#include <r_bin.h>
#include "minunit.h"

static char *unit_demangle(RBinFile *bf, const char *symbol, ut64 vaddr) {
	(void)bf;
	(void)vaddr;
	return strdup (symbol);
}

static bool test_demangle_registry(void) {
	mu_assert_eq (r_bin_demangle_type ("java"), R_BIN_LANG_JAVA, "Java selects the Java demangler");
	mu_assert_eq (r_bin_demangle_type ("dalvik"), R_BIN_LANG_NONE, "Dalvik is a runtime, not a demangler");
	char *invalid_msvc = r_bin_demangle_msvc ("?metadata");
	mu_assert_null (invalid_msvc, "reject invalid MSVC decoration");

	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "RBin allocation");
	mu_assert_true (r_libstore_load (bin->libstore), "load static RBin plugins");

	RBinDemanglePlugin *cxx = r_bin_demangle_plugin_find (bin, "cxx");
	if (cxx) {
		mu_assert_ptreq (cxx, r_bin_demangle_plugin_find (bin, "c++"), "C++ alias lookup");
		mu_assert_ptreq (cxx, bin->demangle_by_type[R_BIN_LANG_CXX], "C++ direct table lookup");
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
	RBinObject bo = { 0 };
	bf.rbin = bin;
	bf.bo = &bo;
	char *res = r_bin_demangle (&bf, "test", "symbol", 0, false);
	mu_assert_streq (res, "symbol", "dispatch an explicitly named demangler");
	free (res);
	res = r_bin_demangle (&bf, "__mh_execute_header", "__mh_execute_header", 0, false);
	mu_assert_null (res, "reject a C symbol that only resembles C++ mangling");
	mu_assert_false (R_VPACK_HAS (bo.langs, R_BIN_LANG_CXX), "failed demangling does not register a language");

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
	mu_assert_true (R_VPACK_HAS (bo.langs, R_BIN_LANG_CIL), "demangling registers the binary language");
	free (res);

	RBinDemanglePlugin invalid_type = {
		.meta.name = "invalid_type",
		.type = R_BIN_LANG_LAST,
		.demangle = unit_demangle,
	};
	mu_assert_false (r_bin_demangle_plugin_add (bin, &invalid_type), "reject invalid language type");
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
