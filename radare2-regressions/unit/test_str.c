#include <r_util.h>
#include "minunit.h"

//TODO test r_str_chop_path

bool test_r_str_replace_char_once(void) {
	char* str = strdup ("hello world");
	(void) r_str_replace_char_once (str, 'l', 'x');
	mu_assert_streq (str, "hexlo world", "error, replace char once failed");
	free (str);
	mu_end;
}

bool test_r_str_replace_char(void) {
	char* str = strdup ("hello world");
	(void) r_str_replace_char (str, 'l', 'x');
	mu_assert_streq (str, "hexxo worxd", "error, replace char multi failed");
	free (str);
	mu_end;
}

//TODO test r_str_bits

bool test_r_str_bits64(void) {
	char buf[65];
	(void)r_str_bits64 (buf, 0);
	mu_assert_streq (buf, "00000000", "binary of 0");
	(void)r_str_bits64 (buf, 1);
	mu_assert_streq (buf, "00000001", "binary of 1");
	(void)r_str_bits64 (buf, 2);
	mu_assert_streq (buf, "00000010", "binary of 2");
	mu_end;
}

//TODO test r_str_bits_from_string

bool test_r_str_rwx(void) {
	int rwx = r_str_rwx ("-rwx");
	int rw =  r_str_rwx ("-rw-");
	int rx = r_str_rwx ("rx");
	int mx = r_str_rwx ("m--x");
	int none = r_str_rwx ("----");
	int number = r_str_rwx ("9999");
	int rx_number = r_str_rwx ("5");
	int rwx_number = r_str_rwx ("7");
	mu_assert_eq (rwx, 7, "rwx");
	mu_assert_eq (rw, 6, "rw");
	mu_assert_eq (rx, 5, "rx");
	mu_assert_eq (mx, 17, "mx");
	mu_assert_eq (none, 0, "no permissions");
	mu_assert_eq (number, 0, "large input number string");
	mu_assert_eq (rx_number, 5, "rx number");
	mu_assert_eq (rwx_number, 7, "rwx number");
	mu_end;
}

//TODO test r_str_binstr2bin

bool test_r_str_rwx_i(void) {
	const char* rwx = r_str_rwx_i (7);
	const char* rw = r_str_rwx_i (6);
	const char* rx = r_str_rwx_i (5);
	const char* mx = r_str_rwx_i (17);
	const char* invalid_mode = r_str_rwx_i (898);
	const char* invalid_mode_neg = r_str_rwx_i (-10);
	mu_assert_streq (rwx, "-rwx", "rwx = 7 mode");
	mu_assert_streq (rw, "-rw-", "rw = 6 mode");
	mu_assert_streq (rx, "-r-x", "rx = 5 mode");
	mu_assert_streq (mx, "m--x", "mx = 17 mode");
	mu_assert_streq (invalid_mode, "----", "invalid permissions mode");
	mu_assert_streq (invalid_mode_neg, "----", "invalid permissions mode (negative value)");
	mu_end;
}

//TODO find a way to test r_str_home.

bool test_r_str_bool(void) {
	const char* one = r_str_bool(1);
	const char* zero = r_str_bool(0);
	const char* fifty = r_str_bool(50);
	const char* negative = r_str_bool(-1);
	mu_assert_streq (one, "true", "one");
	mu_assert_streq (zero, "false", "zero");
	mu_assert_streq (fifty, "true", "large positive value");
	mu_assert_streq (negative, "true", "negative number");
	mu_end;
}

bool test_r_str_case(void) {
	char* str1_mixedcase = strdup ("mIxEdCaSe");
	char* str2_mixedcase = strdup ("mIxEdCaSe");
	r_str_case (str1_mixedcase, true /*upcase*/);
	r_str_case (str2_mixedcase, false /*downcase*/);
	mu_assert_streq (str1_mixedcase, "MIXEDCASE", "upcase");
	mu_assert_streq (str2_mixedcase, "mixedcase", "downcase");
	char* non_alphanum_1 = strdup ("c00lstring!");
	char* non_alphanum_2 = strdup ("c00lstrinG!");
	r_str_case (non_alphanum_1, true /*upcase*/);
	r_str_case (non_alphanum_2, false /*downcase*/);
	mu_assert_streq (non_alphanum_1, "C00LSTRING!", "upcase, nonalpanum");
	mu_assert_streq (non_alphanum_2, "c00lstring!", "downcase, nonalpanum");
	free (str1_mixedcase);
	free (str2_mixedcase);
	free (non_alphanum_1);
	free (non_alphanum_2);
	mu_end;
}

//TODO test r_str_hash64, r_str_hash
//TODO test r_str_delta (WTF!)

bool test_r_str_split(void) {
	char* hi = strdup ("hello world");
	mu_assert_eq (r_str_split (hi, ' '), 1, "split on space");
	char* hello = hi;
	char* world = hi + 6;
	mu_assert_streq (hello, "hello", "first string in split");
	mu_assert_streq (world, "world", "second string in split");
	free (hi);
	mu_end;
}

bool test_r_str_tokenize(void) {
	//XXX r_str_word0 doesn't work on "hello      world" to
	// tokenize into ["hello", "world"]
	char* hi = strdup ("hello world");
	mu_assert_eq (r_str_word_set0 (hi), 1, "tokenize hello world");
	const char* hello = r_str_word_get0 (hi, 0);
	const char* world = r_str_word_get0 (hi, 1);
	mu_assert_streq (hello, "hello", "first string in split");
	mu_assert_streq (world, "world", "second string in split");
	free (hi);
	mu_end;
}

bool test_r_str_char_count(void) {
	mu_assert_eq (r_str_char_count ("poop", 'p'), 2, "number of p in poop");
	mu_end;
}

bool test_r_str_word_count(void) {
	mu_assert_eq (r_str_word_count ("let's test\nradare2 \t libraries!"), 4,
				"words in a string");
	mu_end;
}

bool test_r_str_ichr(void) {
	char* test = "rrrrrradare2";
	char* out = r_str_ichr (test, 'r');
	mu_assert_streq (out, "adare2",
			"string after the first non-r character in rrrrrradare2");
	mu_end;
}

bool test_r_str_lchr(void) {
	const char* test = "radare2";
	const char* out = r_str_lchr (test, 'r');
	mu_assert_streq (out, "re2", "pointer to last r in radare2");
	mu_end;
}

bool test_r_sub_str_lchr(void) {
	const char* test = "raddddare2d";
	const char* out = r_sub_str_lchr (test, 1, 8, 'd');
	mu_assert_streq (out, "dare2d", "pointer to last d in range in radddddare2d");
	mu_end;
}

bool test_r_sub_str_rchr(void) {
	const char* test = "raddddare2d";
	const char* out = r_sub_str_rchr (test, 1, 8, 'd');
	mu_assert_streq (out, "ddddare2d", "pointer to first d in range in radddddare2d");
	mu_end;
	mu_end;
}

bool test_r_str_rchr(void) {
	const char* test = "raddddare2d";
	const char* out = r_str_rchr (test, NULL, '2');
	mu_assert_streq (out, "2d", "pointer to last p in range in raddddare2d");
	out = r_str_rchr (test, NULL, 'p');
	if (out) {
		mu_assert ("non NULL value returned", 0);
	}
	out = test + 9;
	out = r_str_rchr (test, out, 'd');
	mu_assert_streq (out, "dare2d", "pointer to last d in range in raddddare2d");
	out = test + strlen (test);
	out = r_str_rchr (test, out, 'p');
	if (out) {
		mu_assert ("non NULL value of out", 0);
	}
	mu_end;
}

bool all_tests() {
	mu_run_test(test_r_str_replace_char_once);
	mu_run_test(test_r_str_replace_char);
	mu_run_test(test_r_str_bits64);
	mu_run_test(test_r_str_rwx);
	mu_run_test(test_r_str_rwx_i);
	mu_run_test(test_r_str_bool);
	mu_run_test(test_r_str_case);
	mu_run_test(test_r_str_split);
	mu_run_test(test_r_str_tokenize);
	mu_run_test(test_r_str_char_count);
	mu_run_test(test_r_str_word_count);
	mu_run_test(test_r_str_ichr);
	mu_run_test(test_r_str_lchr);
	mu_run_test(test_r_sub_str_lchr);
	mu_run_test(test_r_sub_str_rchr);
	mu_run_test(test_r_str_rchr);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
