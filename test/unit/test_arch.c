#include <r_arch.h>
#include "minunit.h"

static RArchPlugin test_plugin = {
	.name = "test_plugin",
	.arch = "test",
	.author = "radare2",
	.desc = "Example RArch plugin",
};

bool test_register_plugin(void) {
	RArch *a = r_arch_new ();
	bool res = r_arch_add (a, &test_plugin);
	mu_assert ("test_plugin should be registered the first time", res);
	res = r_arch_add (a, &test_plugin);
	mu_assert ("test_plugin was already registered", !res);

	RArchPlugin *ap = r_arch_get_plugin (a, "test_plugin");
	mu_assert_notnull (ap, "test_plugin should be found");
	mu_assert_ptreq (ap, &test_plugin, "test_plugin and ap should be the same");

	res = r_arch_del (a, ap);
	mu_assert ("test_plugin should be deleted", res);
	res = r_arch_del (a, ap);
	mu_assert ("test_plugin was already deleted", !res);

	ap = r_arch_get_plugin (a, "test_plugin");
	mu_assert_null (ap, "test_plugin should NOT be found, because deleted");

	r_arch_free (a);
	mu_end;
}

int all_tests() {
	mu_run_test (test_register_plugin);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
