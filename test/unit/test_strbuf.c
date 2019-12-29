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
	mu_run_test(test_r_strbuf_slice);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
