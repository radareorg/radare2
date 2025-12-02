#include <r_util.h>
#include <r_util/r_ref.h>
#include <r_core.h>
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

bool test_file_slurp(void) {

#ifdef R2__WINDOWS__
#define S_IRWXU _S_IREAD | _S_IWRITE
#endif

	const char* test_file =  "./empty_file";
	size_t s;
	const char* some_words = "some words";

	int f = open (test_file, O_CREAT, S_IRWXU);
	mu_assert_neq (f, -1, "cannot create empty file");
	close (f);

	char* content = r_file_slurp (test_file, &s);
	mu_assert_eq (s, 0, "size should be zero");
	mu_assert_eq (strlen (content), 0, "returned buffer should be empty");
	free (content);

	f = open (test_file, O_WRONLY, S_IRWXU);
	mu_assert_neq (f, -1, "cannot reopen empty file");
	size_t len = strlen (some_words);
	size_t res = write (f, some_words, len);
	mu_assert_eq (res, len, "size and length must be the same");
	close (f);

	content = r_file_slurp (test_file, &s);
	mu_assert_eq (s, strlen (some_words), "size should be correct");
	mu_assert_eq (strlen (content), strlen (some_words), "size for the buffer should be correct");
	mu_assert_streq (content, some_words, "content should match");
	free (content);

	unlink (test_file);

	mu_end;
}

R_ALIGNED(4) static const char msg[] = "Hello World"; // const strings can have the lowerbit set
R_TAGGED void *tagged(bool owned) {
	if (owned) {
		void *res = strdup ("hello world");
		return R_TAG_NOP (res);
	}
	return R_TAG (msg);
}

bool test_tagged_pointers(void) {
	void *a = tagged (false);
	void *b = tagged (true);
	// eprintf ("%p %p\n", a, b);
	// eprintf ("%d %d\n", (size_t)a&1, (size_t)b&1);
	mu_assert_eq (R_IS_TAGGED (a), 1, "tagged");
	char *msg = R_UNTAG (a);
	mu_assert_streq (msg, "Hello World", "faileq");
	mu_assert_eq (R_IS_TAGGED (b), 0, "not tagged");
	char *msg2 = R_UNTAG (b);
	mu_assert_streq (msg2, "hello world", "faileq");
	R_TAG_FREE (a);
	R_TAG_FREE (b);
	mu_end;
}

bool test_initial_underscore(void) {
	Sdb *TDB = setup_sdb ();
	char *s = r_type_func_guess (TDB, "sym._strchr");
	mu_assert_notnull (s, "sym._ should be ignored");
	mu_assert_streq (s, "strchr", "strchr should be identified");
	free (s);

	sdb_free (TDB);
	mu_end;
}

/* references */
typedef struct {
	const char *name;
	R_REF_TYPE;
} TypeTest;

static void r_type_test_free(TypeTest *tt) {
	tt->name = "";
}

static TypeTest *r_type_test_new(const char *name) {
	TypeTest *tt = R_NEW0 (TypeTest);
	if (tt) {
		r_ref_init (tt, r_type_test_free);
		tt->name = name;
	}
	return tt;
}

// DEPRECATE R_REF_FUNCTIONS
// R_REF_FUNCTIONS(TypeTest, r_type_test);

bool test_references(void) {
	TypeTest *tt = r_type_test_new ("foo");
	mu_assert_eq (r_ref_count (tt), 1, "reference count issue");
	r_ref (tt);
	mu_assert_eq (r_ref_count (tt), 2, "reference count issue");
	r_unref (tt);
	mu_assert_streq (tt->name, "foo", "typetest name should be foo");
	mu_assert_eq (r_ref_count (tt), 1, "reference count issue");
	r_unref (tt); // tt becomes invalid
	if (tt) {
		mu_assert_eq (0, 1, "reference count invalidation is failing");
		// mu_assert_eq (r_ref_count (tt), 0, "reference count issue");
		// mu_assert_streq (tt->name, "", "typetest name should be foo");
		free (tt);
	}
	mu_end;
}

bool test_log(void) {
	// Stand up a semi-realistic log environment with an RCore
	RCore *core = r_core_new ();
	r_log_set_quiet (true);

	// https://github.com/radareorg/radare2/issues/22468
	R_LOG_INFO ("%s", "");

	r_core_free (core);
	mu_end;
}

bool test_endian_tostring(void) {
	// Test basic endian values
	mu_assert_streq (r_sys_endian_tostring (R_SYS_ENDIAN_NONE), "none", "NONE should return 'none'");
	mu_assert_streq (r_sys_endian_tostring (R_SYS_ENDIAN_LITTLE), "little", "LITTLE should return 'little'");
	mu_assert_streq (r_sys_endian_tostring (R_SYS_ENDIAN_BIG), "big", "BIG should return 'big'");
	mu_assert_streq (r_sys_endian_tostring (R_SYS_ENDIAN_MIDDLE), "middle", "MIDDLE should return 'middle'");
	mu_assert_streq (r_sys_endian_tostring (R_SYS_ENDIAN_BI), "bi", "BI should return 'bi'");

	// Test aliases
	mu_assert_streq (r_sys_endian_tostring (R_SYS_ENDIAN_4321), "little", "4321 should return 'little'");
	mu_assert_streq (r_sys_endian_tostring (R_SYS_ENDIAN_1234), "big", "1234 should return 'big'");
	mu_assert_streq (r_sys_endian_tostring (R_SYS_ENDIAN_2134), "middle", "2134 should return 'middle'");

	// Test unknown value
	mu_assert_streq (r_sys_endian_tostring (999), "unknown", "unknown value should return 'unknown'");

	// Test bitmask combinations
	int bi_endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG;
	mu_assert_streq (r_sys_endian_tostring (bi_endian), "bi", "bitmask LITTLE|BIG should return 'bi'");

	mu_end;
}

bool test_endian_fromstring(void) {
	// Test basic endian strings
	mu_assert_eq (r_sys_endian_fromstring ("none"), R_SYS_ENDIAN_NONE, "'none' should return NONE");
	mu_assert_eq (r_sys_endian_fromstring ("little"), R_SYS_ENDIAN_LITTLE, "'little' should return LITTLE");
	mu_assert_eq (r_sys_endian_fromstring ("big"), R_SYS_ENDIAN_BIG, "'big' should return BIG");
	mu_assert_eq (r_sys_endian_fromstring ("middle"), R_SYS_ENDIAN_MIDDLE, "'middle' should return MIDDLE");
	mu_assert_eq (r_sys_endian_fromstring ("bi"), R_SYS_ENDIAN_BI, "'bi' should return BI");

	// Test numeric aliases
	mu_assert_eq (r_sys_endian_fromstring ("4321"), R_SYS_ENDIAN_LITTLE, "'4321' should return LITTLE");
	mu_assert_eq (r_sys_endian_fromstring ("1234"), R_SYS_ENDIAN_BIG, "'1234' should return BIG");
	mu_assert_eq (r_sys_endian_fromstring ("2134"), R_SYS_ENDIAN_MIDDLE, "'2134' should return MIDDLE");

	// Test case sensitivity (should be case sensitive)
	mu_assert_eq (r_sys_endian_fromstring ("Little"), R_SYS_ENDIAN_NONE, "Case sensitive test - 'Little' should fail");
	mu_assert_eq (r_sys_endian_fromstring ("BIG"), R_SYS_ENDIAN_NONE, "Case sensitive test - 'BIG' should fail");

	// Test invalid strings
	mu_assert_eq (r_sys_endian_fromstring ("invalid"), R_SYS_ENDIAN_NONE, "invalid string should return NONE");
	mu_assert_eq (r_sys_endian_fromstring (""), R_SYS_ENDIAN_NONE, "empty string should return NONE");

	// Test NULL input
	mu_assert_eq (r_sys_endian_fromstring (NULL), R_SYS_ENDIAN_NONE, "NULL should return NONE");

	mu_end;
}

bool test_endian_is(void) {
	// Test basic endian checking
	mu_assert_true (r_sys_endian_is (R_SYS_ENDIAN_LITTLE, R_SYS_ENDIAN_LITTLE), "LITTLE should match LITTLE");
	mu_assert_true (r_sys_endian_is (R_SYS_ENDIAN_BIG, R_SYS_ENDIAN_BIG), "BIG should match BIG");
	mu_assert_true (r_sys_endian_is (R_SYS_ENDIAN_MIDDLE, R_SYS_ENDIAN_MIDDLE), "MIDDLE should match MIDDLE");
	mu_assert_false (r_sys_endian_is (R_SYS_ENDIAN_LITTLE, R_SYS_ENDIAN_BIG), "LITTLE should not match BIG");

	// Test BI endian (bitmask)
	int bi_endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG;
	mu_assert_true (r_sys_endian_is (bi_endian, R_SYS_ENDIAN_LITTLE), "BI should match LITTLE");
	mu_assert_true (r_sys_endian_is (bi_endian, R_SYS_ENDIAN_BIG), "BI should match BIG");
	mu_assert_false (r_sys_endian_is (bi_endian, R_SYS_ENDIAN_MIDDLE), "BI should not match MIDDLE");

	// Test with aliases
	mu_assert_true (r_sys_endian_is (R_SYS_ENDIAN_4321, R_SYS_ENDIAN_LITTLE), "4321 should match LITTLE");
	mu_assert_true (r_sys_endian_is (R_SYS_ENDIAN_1234, R_SYS_ENDIAN_BIG), "1234 should match BIG");
	mu_assert_true (r_sys_endian_is (R_SYS_ENDIAN_2134, R_SYS_ENDIAN_MIDDLE), "2134 should match MIDDLE");

	// Test exact match vs partial match
	int complex_endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_MIDDLE;
	mu_assert_true (r_sys_endian_is (complex_endian, R_SYS_ENDIAN_LITTLE), "complex should match LITTLE");
	mu_assert_true (r_sys_endian_is (complex_endian, R_SYS_ENDIAN_MIDDLE), "complex should match MIDDLE");
	mu_assert_false (r_sys_endian_is (complex_endian, R_SYS_ENDIAN_BIG), "complex should not match BIG");

	mu_end;
}

bool test_endian_roundtrip(void) {
	// Test that tostring/fromstring are consistent for all valid values
	const char *test_strings[] = {"none", "little", "big", "middle", "bi", "4321", "1234", "2134"};
	int expected_values[] = {
		R_SYS_ENDIAN_NONE,
		R_SYS_ENDIAN_LITTLE,
		R_SYS_ENDIAN_BIG,
		R_SYS_ENDIAN_MIDDLE,
		R_SYS_ENDIAN_BI,
		R_SYS_ENDIAN_LITTLE,
		R_SYS_ENDIAN_BIG,
		R_SYS_ENDIAN_MIDDLE
	};

	for (int i = 0; i < sizeof (test_strings) / sizeof (test_strings[0]); i++) {
		int from_string = r_sys_endian_fromstring (test_strings[i]);
		const char *to_string = r_sys_endian_tostring (from_string);
		
		// For BI, we need special handling since tostring might return "bi" for both "bi" and bitmask combinations
		if (from_string == R_SYS_ENDIAN_BI) {
			mu_assert_streq (to_string, "bi", "BI should roundtrip correctly");
		} else {
			mu_assert_eq (from_string, expected_values[i], "fromstring should return expected value");
			// For non-BI values, tostring should return the canonical name
			if (from_string == R_SYS_ENDIAN_LITTLE) {
				mu_assert_streq (to_string, "little", "LITTLE should tostring to 'little'");
			} else if (from_string == R_SYS_ENDIAN_BIG) {
				mu_assert_streq (to_string, "big", "BIG should tostring to 'big'");
			} else if (from_string == R_SYS_ENDIAN_MIDDLE) {
				mu_assert_streq (to_string, "middle", "MIDDLE should tostring to 'middle'");
			} else if (from_string == R_SYS_ENDIAN_NONE) {
				mu_assert_streq (to_string, "none", "NONE should tostring to 'none'");
			}
		}
	}

	mu_end;
}

int all_tests(void) {
	mu_run_test (test_ignore_prefixes);
	mu_run_test (test_remove_r2_prefixes);
	mu_run_test (test_dll_names);
	mu_run_test (test_references);
	mu_run_test (test_autonames);
	mu_run_test (test_file_slurp);
	mu_run_test (test_initial_underscore);
	mu_run_test (test_tagged_pointers);
	mu_run_test (test_log);
	mu_run_test (test_endian_tostring);
	mu_run_test (test_endian_fromstring);
	mu_run_test (test_endian_is);
	mu_run_test (test_endian_roundtrip);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
