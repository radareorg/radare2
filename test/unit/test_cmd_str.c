#include <r_core.h>
#include "minunit.h"

bool test_cmd_str_issue_18799(void) {
	RCore *core = r_core_new ();
	char *output = r_core_cmd_str (core, "pd 1 @e:asm.hints=false");
	mu_assert ("command output leaked to stdout", strlen (output) > 0);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_cmd_str_issue_18799);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
