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

bool test_r_strbuf_ptr(void) {
	RStrBuf *sa = r_strbuf_new ("");
	RStrBuf *sb = r_strbuf_new (NULL);

	r_strbuf_set (sa, "food");
	mu_assert_eq (r_strbuf_length (sa), 5, "r_strbuf_set:food");
	r_strbuf_set (sa, "VERYLONGTEXTTHATDOESNTFITINSIDETHESTRUCTBUFFER");
	char *a = sa->ptr;
	mu_assert_eq (r_strbuf_length (sa), 47, "r_strbuf_set:food");
	char *b = sa->ptr;
	mu_assert_eq (a, b, "sa->ptr after setbin");
	bool res = r_strbuf_setbin (sa, (const ut8*)"food", -1);
	mu_assert_eq (res, true, "setbin-1");
	r_strbuf_set (sa, "food");
	mu_assert_eq (r_strbuf_length (sa), 5, "r_srtbuf_setbin-1");
	r_strbuf_setbin (sa, (const ut8*)"food", 4);
	mu_assert_eq (r_strbuf_length (sa), 4, "r_srtbuf_setbin");
	r_strbuf_setbin (sa, (const ut8*)"food", 5);
	mu_assert_eq (r_strbuf_length (sa), 5, "r_srtbuf_setbin5");
	r_strbuf_setptr (sa, "food", 5);
	mu_assert_eq (r_strbuf_length (sa), 5, "r_srtbuf_setbin5");

	r_strbuf_fini (sa);
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
	mu_run_test(test_r_strbuf);
	mu_run_test(test_r_strbuf_ptr);
	mu_run_test(test_r_strbuf_slice);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
