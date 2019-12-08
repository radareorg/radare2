#include <r_util.h>
#include "minunit.h"

static Sdb *setup_sdb(void) {
	Sdb *res = sdb_new0 ();
	sdb_set (res, "ExitProcess", "func", 0);
	sdb_set (res, "ReadFile", "func", 0);
	sdb_set (res, "memcpy", "func", 0);
	sdb_set (res, "strchr", "func", 0);
	sdb_set (res, "__stack_chk_fail", "func", 0);
	sdb_set (res, "WSAStartup", "func", 0);
	return res;
}

bool test_dll_names(void) {
	Sdb *TDB = setup_sdb ();
	char *s;

	s = r_type_func_guess (TDB, "sub.KERNEL32.dll_ExitProcess");
	mu_assert_notnull (s, "dll_ should be ignored");
	mu_assert_streq (s, "ExitProcess", "dll_ should be ignored");
	free (s);

	s = r_type_func_guess (TDB, "sub.dll_ExitProcess_32");
	mu_assert_notnull (s, "number should be ignored");
	mu_assert_streq (s, "ExitProcess", "number should be ignored");
	free (s);

	s = r_type_func_guess (TDB, "sym.imp.KERNEL32.dll_ReadFile");
	mu_assert_notnull (s, "dll_ and number should be ignored case 1");
	mu_assert_streq (s, "ReadFile", "dll_ and number should be ignored case 1");
	free (s);

	s = r_type_func_guess (TDB, "sub.VCRUNTIME14.dll_memcpy");
	mu_assert_notnull (s, "dll_ and number should be ignored case 2");
	mu_assert_streq (s, "memcpy", "dll_ and number should be ignored case 2");
	free (s);

	s = r_type_func_guess (TDB, "sub.KERNEL32.dll_ExitProcess_32");
	mu_assert_notnull (s, "dll_ and number should be ignored case 3");
	mu_assert_streq (s, "ExitProcess", "dll_ and number should be ignored case 3");
	free (s);

	s = r_type_func_guess (TDB, "WS2_32.dll_WSAStartup");
	mu_assert_notnull (s, "dll_ and number should be ignored case 4");
	mu_assert_streq (s, "WSAStartup", "dll_ and number should be ignored case 4");
	free (s);

	sdb_free (TDB);
	mu_end;
}

bool test_ignore_prefixes(void) {
	Sdb *TDB = setup_sdb ();
	char *s;

	s = r_type_func_guess (TDB, "fcn.KERNEL32.dll_ExitProcess_32");
	mu_assert_null (s, "fcn. names should be ignored");
	free (s);

	s = r_type_func_guess (TDB, "loc.KERNEL32.dll_ExitProcess_32");
	mu_assert_null (s, "loc. names should be ignored");
	free (s);

	sdb_free (TDB);
	mu_end;
}

bool test_remove_r2_prefixes(void) {
	Sdb *TDB = setup_sdb ();
	char *s;

	s = r_type_func_guess (TDB, "sym.imp.ExitProcess");
	mu_assert_notnull (s, "sym.imp should be ignored");
	mu_assert_streq (s, "ExitProcess", "sym.imp should be ignored");
	free (s);

	s = r_type_func_guess (TDB, "sym.imp.fcn.ExitProcess");
	mu_assert_notnull (s, "sym.imp.fcn should be ignored");
	mu_assert_streq (s, "ExitProcess", "sym.imp.fcn should be ignored");
	free (s);

	s = r_type_func_guess (TDB, "longprefix.ExitProcess");
	mu_assert_null (s, "prefixes longer than 3 should not be ignored");
	free (s);

	sdb_free (TDB);
	mu_end;
}

bool test_autonames(void) {
	Sdb *TDB = setup_sdb ();
	char *s;

	s = r_type_func_guess (TDB, "sub.strchr_123");
	mu_assert_null (s, "function that calls common fcns shouldn't be identified as such");
	free (s);

	s = r_type_func_guess (TDB, "sub.__strchr_123");
	mu_assert_null (s, "initial _ should not confuse the api");
	free (s);

	s = r_type_func_guess (TDB, "sub.__stack_chk_fail_740");
	mu_assert_null (s, "initial _ should not confuse the api");
	free (s);

	s = r_type_func_guess (TDB, "sym.imp.strchr");
	mu_assert_notnull (s, "sym.imp. should be ignored");
	mu_assert_streq (s, "strchr", "strchr should be identified");
	free (s);

	sdb_free (TDB);
	mu_end;
}

bool test_initial_underscore(void) {
	Sdb *TDB = setup_sdb ();
	char *s;

	s = r_type_func_guess (TDB, "sym._strchr");
	mu_assert_notnull (s, "sym._ should be ignored");
	mu_assert_streq (s, "strchr", "strchr should be identified");
	free (s);

	sdb_free (TDB);
	mu_end;
}

int all_tests() {
	mu_run_test (test_ignore_prefixes);
	mu_run_test (test_remove_r2_prefixes);
	mu_run_test (test_dll_names);
	mu_run_test (test_autonames);
	mu_run_test (test_initial_underscore);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
