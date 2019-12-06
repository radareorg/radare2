#include <r_flag.h>
#include "minunit.h"

bool test_r_flag_get_set(void) {
	RFlag *flags;
	RFlagItem *fi;

	flags = r_flag_new ();
	mu_assert_notnull (flags, "r_flag_new () failed");

	r_flag_set (flags, "foo", 1024, 50);
	fi = r_flag_get_i (flags, 1024);
	mu_assert_notnull (fi, "cannot find 'foo' flag at 1024");

	r_flag_set (flags, "foo", 300LL, 0);
	fi = r_flag_get_i (flags, 0);
	mu_assert_null (fi, "found a flag at 0 while there is none");
	fi = r_flag_get_i (flags, 300LL);
	mu_assert_notnull (fi, "cannot find 'foo' flag at 300LL");

	fi = r_flag_get (flags, "foo");
	mu_assert_notnull (fi, "cannot find 'foo' flag");

	r_flag_free (flags);
	mu_end;
}

bool test_r_flag_by_spaces(void) {
	RFlag *flags;
	RFlagItem *fi;

	flags = r_flag_new ();
	r_flag_space_set (flags, "sp1");
	r_flag_set (flags, "foo1", 1024, 50);
	r_flag_set (flags, "foo2", 1024, 0);
	r_flag_space_set (flags, "sp2");
	r_flag_set (flags, "foo3", 1024, 50);
	r_flag_set (flags, "foo4", 1024, 0);
	r_flag_space_set (flags, "sp3");
	r_flag_set (flags, "foo5", 1024, 50);
	r_flag_set (flags, "foo6", 1024, 0);
	r_flag_space_set (flags, "sp4");
	r_flag_set (flags, "foo7", 1024, 50);

	fi = r_flag_get_by_spaces (flags, 1024, "sp2", "sp4", NULL);
	mu_assert_notnull (fi, "should be retrieved");
	mu_assert_streq (fi->name, "foo3", "first defined in sp2 should be get");

	fi = r_flag_get_by_spaces (flags, 1024, NULL);
	mu_assert_notnull (fi, "something should be retrieved");
	mu_assert_streq (fi->name, "foo1", "a random one should be get (the first)");

	fi = r_flag_get_by_spaces (flags, 1024, "sp5", "sp8", "sp1", "sp3", "sp10", NULL);
	mu_assert_notnull (fi, "something should be retrieved");
	mu_assert_streq (fi->name, "foo1", "first defined in sp1 should be get");

	r_flag_free (flags);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_flag_get_set);
	mu_run_test (test_r_flag_by_spaces);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
