#include <r_util.h>
#include "minunit.h"

bool test_r_strbuf_slice(void) {
	RStrBuf *sa = r_strbuf_new ("foo,bar,cow");
	r_strbuf_slice (sa, 2, 4); // should be from/to instead of from/len ?
	char *a = r_strbuf_drain (sa);
	mu_assert_streq (a, "o,ba", "slicing fails");
	free (a);

	mu_end;
}

bool test_r_strbuf_append(void) {
	RStrBuf *sa = r_strbuf_new ("foo");
	r_strbuf_append (sa, "bar");
	r_strbuf_prepend (sa, "pre");
	char *a = r_strbuf_drain (sa);
	mu_assert_streq (a, "prefoobar", "append+prepend");
	free (a);

	mu_end;
}

bool test_r_strbuf_strong_string(void) {
	// small string
	RStrBuf *sa = r_strbuf_new ("");
	r_strbuf_set (sa, "food");
	mu_assert_eq (r_strbuf_length (sa), 4, "r_strbuf_set:food");
	mu_assert_eq (sa->len, 4, "len of string");
	// ptrlen not used here
	r_strbuf_free (sa);

	// long string
	sa = r_strbuf_new ("");
	r_strbuf_set (sa, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER");
	mu_assert_eq (r_strbuf_length (sa), 46, "length from api");
	mu_assert_eq (sa->len, 46, "len of string");
	mu_assert_eq (sa->ptrlen, 47, "ptrlen of string");
	r_strbuf_free (sa);

	mu_end;
}

bool test_r_strbuf_strong_binary(void) {
	RStrBuf *sa = r_strbuf_new ("");
	bool res = r_strbuf_setbin (sa, (const ut8 *)"food", 4);
	mu_assert ("setbin success", res);
	mu_assert_memeq ((const ut8 *)r_strbuf_get (sa), (const ut8 *)"food", 4, "small binary data");
	mu_assert_eq (sa->len, 4, "len of binary data");
	mu_assert_eq (sa->ptrlen, 4, "ptrlen of binary data");
	r_strbuf_free (sa);

	sa = r_strbuf_new ("");
	res = r_strbuf_setbin (sa, (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46);
	mu_assert ("setbin success", res);
	mu_assert_memeq ((const ut8 *)r_strbuf_get (sa), (const ut8 *)"VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER", 46, "big binary data");
	mu_assert_eq (sa->len, 46, "len of binary data");
	mu_assert_eq (sa->ptrlen, 46, "ptrlen of binary data");
	r_strbuf_free (sa);

	mu_end;
}

bool test_r_strbuf(void) {
	RStrBuf *sa = r_strbuf_new ("");
	RStrBuf *sb = r_strbuf_new (NULL);

	char *as = r_strbuf_drain (sa);
	char *bs = r_strbuf_drain (sb);
	mu_assert_streq (as, "", "'' == null");
	mu_assert_streq (as, bs, "'' == null");
	free (as);
	free (bs);

	mu_end;
}

bool all_tests() {
	mu_run_test (test_r_strbuf);
	mu_run_test (test_r_strbuf_append);
	mu_run_test (test_r_strbuf_strong_string);
	mu_run_test (test_r_strbuf_strong_binary);
	mu_run_test (test_r_strbuf_slice);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
