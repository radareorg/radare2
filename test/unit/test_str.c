#include <r_util.h>
#include "minunit.h"

//TODO test r_str_chop_path

bool test_r_str_wrap(void) {
	char *s = r_str_wrap ("hello world\nhow are you\n", 5);
	char *res = strdup ("hello \nworld\nhow ar\ne you\n");
	mu_assert_streq (s, res, "error, invalid string wrapping");
	free (s);
	free (res);
	mu_end;
}

bool test_r_str_replace_char_once(void) {
	char* str = strdup ("hello world");
	(void) r_str_replace_char_once (str, 'l', 'x');
	mu_assert_streq (str, "hexlo world", "error, replace char once failed");
	free (str);
	mu_end;
}

bool test_r_str_replace(void) {
	// infinite loop test
	char *str = r_str_replace (strdup ("hello world"), "hell", "ihell", 0);
	mu_assert_streq (str, "ihello world", "error, replace char multi failed");
	free (str);

	str = r_str_replace (strdup ("hello world"), "hell", "ihell", 1);
	mu_assert_streq (str, "ihello world", "error, replace char multi failed");
	free (str);

	str = r_str_replace (strdup ("hello world"), "hello", "", 1);
	mu_assert_streq (str, " world", "error, replace char multi failed");
	free (str);

	str = r_str_replace (strdup ("hello world"), "h", "hello", 0);
	mu_assert_streq (str, "helloello world", "error, replace char multi failed");
	free (str);

	str = r_str_replace (strdup ("hello horld"), "h", "hello", 1);
	mu_assert_streq (str, "helloello helloorld", "error, replace char multi failed");
	free (str);
	str = r_str_replace (strdup ("hello horld"), "h", "hello", 0);
	mu_assert_streq (str, "helloello horld", "error, replace char multi failed");
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
	int rwx = r_str_rwx ("rwx");
	int rw =  r_str_rwx ("rw-");
	int rx = r_str_rwx ("rx");
	int none = r_str_rwx ("---");
	int number = r_str_rwx ("999");
	int rx_number = r_str_rwx ("5");
	int rwx_number = r_str_rwx ("7");
	mu_assert_eq (rwx, 7, "rwx");
	mu_assert_eq (rw, 6, "rw");
	mu_assert_eq (rx, 5, "rx");
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
	const char* invalid_mode = r_str_rwx_i (898);
	const char* invalid_mode_neg = r_str_rwx_i (-10);
	mu_assert_streq (rwx, "rwx", "rwx = 7 mode");
	mu_assert_streq (rw, "rw-", "rw = 6 mode");
	mu_assert_streq (rx, "r-x", "rx = 5 mode");
	mu_assert_streq (invalid_mode, "---", "invalid permissions mode");
	mu_assert_streq (invalid_mode_neg, "---", "invalid permissions mode (negative value)");
	mu_end;
}

bool test_r_str_trim(void) {
	//  1
	const char* one = r_str_trim_head_ro ("  hello  ");
	mu_assert_streq (one, "hello  ", "one");
	//  2
	char* two = strdup ("  hello  ");
	r_str_trim_head (two);
	mu_assert_streq (two, "hello  ", "two");
	r_str_trim (two);
	//  2
	mu_assert_streq (two, "hello", "three");
	free (two);
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
	int r = r_str_split (hi, ' ');
	mu_assert_eq (r, 2, "split on space");
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
	int r = r_str_word_set0 (hi);
	mu_assert_eq (r, 2, "tokenize hello world");
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

bool test_r_str_ansi_len(void) {
	int len;

	len = r_str_ansi_len ("radare2");
	mu_assert_eq (len, 7, "len(ascii only)");

	len = r_str_ansi_len ("r\x1b[38;2;208;80;0madare2");
	mu_assert_eq (len, 7, "len(ascii + ansi ending with m)");

	len = r_str_ansi_len ("r\x1b[0Jadare2");
	mu_assert_eq (len, 7, "len(ascii + ansi ending with J)");

	len = r_str_ansi_len ("r\x1b[42;42Hadare2");
	mu_assert_eq (len, 7, "len(ascii + ansi ending with H)");

	len = r_str_ansi_len ("r\xc3\xa4""dare2");
	mu_assert_eq (len, 8, "len(ascii + 2 byte utf-8 counted as 2 chars)");

	len = r_str_ansi_len ("radar\xe2\x82\xac""2");
	mu_assert_eq (len, 9, "len(ascii + 3 byte utf-8 counted as 3 chars)");

	len = r_str_ansi_len ("radar\xf0\x9d\x84\x9e""2");
	mu_assert_eq (len, 10, "len(ascii + 4 byte utf-8 counted as 4 chars)");

	mu_end;
}

bool test_r_str_len_utf8_ansi(void) {
	int len;

	len = r_str_len_utf8_ansi ("radare2");
	mu_assert_eq (len, 7, "len(ascii only)");

	len = r_str_len_utf8_ansi ("r\x1b[38;2;208;80;0madare2");
	mu_assert_eq (len, 7, "len(ascii + ansi ending with m)");

	len = r_str_len_utf8_ansi ("r\x1b[0Jadare2");
	mu_assert_eq (len, 7, "len(ascii + ansi ending with J)");

	len = r_str_len_utf8_ansi ("r\x1b[42;42Hadare2");
	mu_assert_eq (len, 7, "len(ascii + ansi ending with H)");

	len = r_str_len_utf8_ansi ("r\xc3\xa4""dare2");
	mu_assert_eq (len, 7, "len(ascii + 2 byte utf-8 counted as 1 char)");

	len = r_str_len_utf8_ansi ("radar\xe2\x82\xac""2");
	mu_assert_eq (len, 7, "len(ascii + 3 byte utf-8 counted as 1 char)");

	len = r_str_len_utf8_ansi ("radar\xf0\x9d\x84\x9e""2");
	mu_assert_eq (len, 7, "len(ascii + 4 byte utf-8 counted as 1 char)");

	mu_end;
}

bool test_r_str_utf8_charsize(void) {
	char s[16] = "\x61\xc3\xa1\xe6\x97\xa5\xf0\x9f\x91\x8c\xf0\x9f\x91\x8c\x8c"; // aá日👌
	int sz;

	sz = r_str_utf8_charsize (s);
	mu_assert_eq (sz, 1, "1 byte UTF-8");

	sz = r_str_utf8_charsize (s + 1);
	mu_assert_eq (sz, 2, "2 byte UTF-8");

	sz = r_str_utf8_charsize (s + 3);
	mu_assert_eq (sz, 3, "3 byte UTF-8");

	sz = r_str_utf8_charsize (s + 6);
	mu_assert_eq (sz, 4, "4 byte UTF-8");

	sz = r_str_utf8_charsize (s + 10);
	mu_assert_eq (sz, 0, "Malformed UTF-8");

	mu_end;
}

bool test_r_str_utf8_charsize_prev(void) {
	char s[16] = "\x61\xc3\xa1\xe6\x97\xa5\xf0\x9f\x91\x8c\xf0\x9f\x91\x8c\x8c"; // aá日👌
	int sz;

	sz = r_str_utf8_charsize_last (s);
	mu_assert_eq (sz, 0, "Malformed UTF-8");

	sz = r_str_utf8_charsize_prev (s + 10, 10);
	mu_assert_eq (sz, 4, "4 byte UTF-8");

	sz = r_str_utf8_charsize_prev (s + 6, 6);
	mu_assert_eq (sz, 3, "3 byte UTF-8");

	sz = r_str_utf8_charsize_prev (s + 3, 3);
	mu_assert_eq (sz, 2, "2 byte UTF-8");

	sz = r_str_utf8_charsize_prev (s + 1, 1);
	mu_assert_eq (sz, 1, "1 byte UTF-8");

	mu_end;
}

bool test_r_str_sanitize_sdb_key(void) {
	char *s = r_str_sanitize_sdb_key("rada.re2<is>::Cool");
	mu_assert_streq (s, "rada_re2_is_::Cool", "sanitize");
	free (s);
	mu_end;
}

bool test_r_str_escape_sh(void) {
	char *escaped = r_str_escape_sh ("Hello, \"World\"");
	mu_assert_streq (escaped, "Hello, \\\"World\\\"", "escaped \"double quotes\"");
	free (escaped);
	escaped = r_str_escape_sh ("Hello, \\World\\");
	mu_assert_streq (escaped, "Hello, \\\\World\\\\", "escaped backspace");
	free (escaped);
#if __UNIX__
	escaped = r_str_escape_sh ("Hello, $(World)");
	mu_assert_streq (escaped, "Hello, \\$(World)", "escaped $(command)");
	free (escaped);
	escaped = r_str_escape_sh ("Hello, `World`");
	mu_assert_streq (escaped, "Hello, \\`World\\`", "escaped `command`");
	free (escaped);
#endif
	mu_end;
}

bool test_r_str_unescape(void) {
	char buf[] = "Hello\\x31World\\n";
	r_str_unescape (buf);
	mu_assert_streq (buf, "Hello1World\n", "unescaped");
	mu_end;
}

bool test_r_str_newf(void) {
	char *a = r_str_newf ("hello");
	mu_assert_streq (a, "hello", "oops");
	free (a);

	a = r_str_newf ("%s/%s", "hello", "world");
	mu_assert_streq (a, "hello/world", "oops");
	free (a);

	a = r_str_newf ("%s/%s", "hello", "world");
	a = r_str_appendf (a, "..%s/%s", "cow", "low");
	a = r_str_appendf (a, "PWN");
	mu_assert_streq (a, "hello/world..cow/lowPWN", "oops");
	free (a);
	mu_end;
}

bool test_r_str_constpool(void) {
	RStrConstPool pool;
	bool s = r_str_constpool_init (&pool);
	mu_assert ("pool init success", s);

	const char *a_ref = "deliverance";
	const char *a_pooled = r_str_constpool_get (&pool, a_ref);
	mu_assert_ptrneq (a_pooled, a_ref, "pooled != ref");
	mu_assert_streq (a_pooled, a_ref, "pooled == ref (strcmp)");
	const char *a_pooled2 = r_str_constpool_get (&pool, a_ref);
	mu_assert_ptreq (a_pooled2, a_pooled, "same on re-get");
	char *a_ref_cpy = strdup (a_ref);
	a_pooled2 = r_str_constpool_get (&pool, a_ref_cpy);
	free (a_ref_cpy);
	mu_assert_ptreq (a_pooled2, a_pooled, "same on re-get with different ptr");

	const char *b_ref = "damnation";
	const char *b_pooled = r_str_constpool_get (&pool, b_ref);
	mu_assert_ptrneq (b_pooled, b_ref, "pooled != ref (second)");
	mu_assert_streq (b_pooled, b_ref, "pooled == ref (strcmp, second)");

	r_str_constpool_fini (&pool);
	mu_end;
}

bool test_r_str_format_msvc_argv() {
	// Examples from http://daviddeley.com/autohotkey/parameters/parameters.htm#WINCRULES
	const char *a = "CallMePancake";
	char *str = r_str_format_msvc_argv (1, &a);
	mu_assert_streq (str, "CallMePancake", "no escaping");
	free (str);

	a = "Call Me Pancake";
	str = r_str_format_msvc_argv (1, &a);
	mu_assert_streq (str, "\"Call Me Pancake\"", "just quoting");
	free (str);

	a = "CallMe\"Pancake";
	str = r_str_format_msvc_argv (1, &a);
	mu_assert_streq (str, "CallMe\\\"Pancake", "just escaping");
	free (str);

	a = "CallMePancake\\";
	str = r_str_format_msvc_argv (1, &a);
	mu_assert_streq (str, "CallMePancake\\", "no escaping of backslashes");
	free (str);

	a = "Call Me Pancake\\";
	str = r_str_format_msvc_argv (1, &a);
	mu_assert_streq (str, "\"Call Me Pancake\\\\\"", "escaping of backslashes before closing quote");
	free (str);

	a = "CallMe\\\"Pancake";
	str = r_str_format_msvc_argv (1, &a);
	mu_assert_streq (str, "CallMe\\\\\\\"Pancake", "escaping of backslashes before literal quote");
	free (str);

	a = "Call Me\\\"Pancake";
	str = r_str_format_msvc_argv (1, &a);
	mu_assert_streq (str, "\"Call Me\\\\\\\"Pancake\"", "escaping of backslashes before literal quote in quote");
	free (str);

	const char *args[] = { "rm", "-rf", "\\"};
	str = r_str_format_msvc_argv (3, args);
	mu_assert_streq (str, "rm -rf \\", "multiple args");
	free (str);

	mu_end;
}

bool test_r_str_str_xy(void) {
	char *canvas = "Hello World\n"
		"This World is World\n"
		"World is Hello\n";
	int x = 0, y = 0;
	const char *next = r_str_str_xy (canvas, "World", NULL, &x, &y);
	mu_assert_eq (x, 6, "x of first occurrence");
	mu_assert_eq (y, 0, "y of first occurrence");
	next = r_str_str_xy (canvas, "World", next, &x, &y);
	mu_assert_eq (x, 5, "x of second occurrence");
	mu_assert_eq (y, 1, "y of second occurrence");
	next = r_str_str_xy (canvas, "World", next, &x, &y);
	mu_assert_eq (x, 14, "x of third occurrence");
	mu_assert_eq (y, 1, "y of third occurrence");
	next = r_str_str_xy (canvas, "World", next, &x, &y);
	mu_assert_eq (x, 0, "x of fourth occurrence");
	mu_assert_eq (y, 2, "y of fourth occurrence");
	next = r_str_str_xy (canvas, "World", next, &x, &y);
	mu_assert_null (next, "no more occurences");
	mu_end;
}

bool test_r_str_encoded_json(void) {
	char *invalidJsonString = "This is my \xe2 sample © string\n";
	size_t len = strlen (invalidJsonString);

	const char *array = r_str_encoded_json (invalidJsonString, len, PJ_ENCODING_STR_ARRAY);
	mu_assert_streq (array, "084,104,105,115,032,105,115,032,109,121,032,226,032,115,097,109,112,108,101,032,194,169,032,115,116,114,105,110,103,010", "string as array of uchar");
	free ((void *)array);

	const char *hex = r_str_encoded_json (invalidJsonString, len, PJ_ENCODING_STR_HEX);
	mu_assert_streq (hex, "54686973206973206D7920E22073616D706C6520C2A920737472696E670A", "string as hexpairs");
	free ((void *)hex);

	const char *b64 = r_str_encoded_json (invalidJsonString, len, PJ_ENCODING_STR_BASE64);
	mu_assert_streq (b64, "VGhpcyBpcyBteSDiIHNhbXBsZSDCqSBzdHJpbmcK", "string as base64 encoded");
	free ((void *)b64);

	const char *stripped = r_str_encoded_json (invalidJsonString, len, PJ_ENCODING_STR_STRIP);
	mu_assert_streq (stripped, "This is my  sample © string\\n", "string with bad chars stripped");
	free ((void *)stripped);

	const char *none = r_str_encoded_json (invalidJsonString, len, PJ_ENCODING_STR_DEFAULT);
	mu_assert_streq (none, "This is my \\xe2 sample © string\\n", "default encoding");
	free ((void *)none);

	mu_end;
}

bool all_tests () {
	mu_run_test (test_r_str_wrap);
	mu_run_test (test_r_str_newf);
	mu_run_test (test_r_str_replace_char_once);
	mu_run_test (test_r_str_replace_char);
	mu_run_test (test_r_str_replace);
	mu_run_test (test_r_str_bits64);
	mu_run_test (test_r_str_rwx);
	mu_run_test (test_r_str_rwx_i);
	mu_run_test (test_r_str_bool);
	mu_run_test (test_r_str_trim);
	mu_run_test (test_r_str_case);
	mu_run_test (test_r_str_split);
	mu_run_test (test_r_str_tokenize);
	mu_run_test (test_r_str_char_count);
	mu_run_test (test_r_str_word_count);
	mu_run_test (test_r_str_ichr);
	mu_run_test (test_r_str_lchr);
	mu_run_test (test_r_sub_str_lchr);
	mu_run_test (test_r_sub_str_rchr);
	mu_run_test (test_r_str_rchr);
	mu_run_test (test_r_str_ansi_len);
	mu_run_test (test_r_str_len_utf8_ansi);
	mu_run_test (test_r_str_utf8_charsize);
	mu_run_test (test_r_str_utf8_charsize_prev);
	mu_run_test (test_r_str_sanitize_sdb_key);
	mu_run_test (test_r_str_escape_sh);
	mu_run_test (test_r_str_unescape);
	mu_run_test (test_r_str_constpool);
	mu_run_test (test_r_str_format_msvc_argv);
	mu_run_test (test_r_str_str_xy);
	mu_run_test (test_r_str_encoded_json);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
