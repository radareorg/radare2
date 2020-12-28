#include <r_util.h>
#include "minunit.h"

static RNum *num;

bool test_r_num_units(void) {
	char humansz[8];
	const struct {
		const char *expected_res;
		const char *message;
		ut64 num;
	} test_cases[] = {
		{ "0",        "B", 0ULL },
		{ "512",      "B", 512ULL },
		{ "1K",       "K", 1ULL << 10 },
		{ "1M",       "M", 1ULL << 20 },
		{ "1G",       "G", 1ULL << 30 },
		{ "1T",       "T", 1ULL << 40 },
		{ "1P",       "P", 1ULL << 50 },
		{ "1E",       "E", 1ULL << 60 },
		/* Decimal test */
		{ "1.0K",     "K", 1025 },
		{ "994K",     "K", 994 * (1ULL << 10) },
		{ "999K",     "K", 999 * (1ULL << 10) },
		{ "1.0M",     "M", 1025 * (1ULL << 10) },
		{ "1.5M",     "M", 1536 * (1ULL << 10) },
		{ "1.9M",     "M", 1996 * (1ULL << 10) },
		{ "2.0M",     "M", 1997 * (1ULL << 10) },
		{ "2.0M",     "M", 2047 * (1ULL << 10) },
		{ "2M",       "M", 2048 * (1ULL << 10) },
		{ "2.0M",     "M", 2099 * (1ULL << 10) },
		{ "2.1M",     "M", 2100 * (1ULL << 10) },
		{ "9.9G",     "G", 10188 * (1ULL << 20) },
		/* Biggest units */
		{ "82P",      "P", 82 * (1ULL << 50) },
		{ "16E",    "E", UT64_MAX }
	};
	size_t nitems = sizeof (test_cases) / sizeof (test_cases[0]);
	size_t i;
	for (i = 0; i < nitems; i++) {
		r_num_units (humansz, sizeof (humansz), test_cases[i].num);
		mu_assert_streq (humansz, test_cases[i].expected_res, test_cases[i].message);
	}
	mu_end;
}

bool test_r_num_minmax_swap_i(void) {
	int a = -1, b = 2;
	r_num_minmax_swap_i (&a, &b);
	mu_assert_eq (a == -1 && b == 2, 1, "a < b -> a < b");
	a = 2, b = -1;
	r_num_minmax_swap_i (&a, &b);
	mu_assert_eq (a == -1 && b == 2, 1, "b < a -> a < b");
	mu_end;
}

bool test_r_num_minmax_swap(void) {
	ut64 a = 1, b = 2;
	r_num_minmax_swap (&a, &b);
	mu_assert_eq (a == 1 && b == 2, 1, "a < b -> a < b");
	a = 2, b = 1;
	r_num_minmax_swap (&a, &b);
	mu_assert_eq (a == 1 && b == 2, 1, "b < a -> a < b");
	mu_end;
}

bool test_r_num_between(void) {
	mu_assert_eq (r_num_between (num, "1 2 3"), 1, "1 <= 2 <= 3");
	mu_assert_eq (r_num_between (num, "3 2 1"), 0, "3 <= 2 <= 1");
	mu_assert_eq (r_num_between (num, "1 1 1"), 1, "1 <= 1 <= 1");
	mu_assert_eq (r_num_between (num, "2 1 3"), 0, "2 <= 1 <= 3");
	mu_assert_eq (r_num_between (num, "1 2 1+2"), 1, "1 <= 2 <= 1+2");
	mu_assert_eq (r_num_between (num, "2 3 1+2+3"), 1, "2 <= 3 <= 1+2+3");
	mu_assert_eq (r_num_between (num, "1+2 2 1+1"), 0, "1+2 <= 2 <= 1+1");
	mu_assert_eq (r_num_between (num, "1 + 2 2 1 + 1"), 0, "1 + 2 <= 2 <= 1 + 1");
	mu_end;
}

bool test_r_num_str_len(void) {
	mu_assert_eq (r_num_str_len ("1"), 1, "\"1\"");
	mu_assert_eq (r_num_str_len ("1+1"), 3, "\"1+1\"");
	mu_assert_eq (r_num_str_len ("1 + 1"), 5, "\"1 + 1\"");
	mu_assert_eq (r_num_str_len ("1 + 1 "), 5, "\"1 + 1 \"");
	mu_assert_eq (r_num_str_len ("1 + 1  "), 5, "\"1 + 1  \"");
	mu_assert_eq (r_num_str_len ("1 + 1 1"), 5, "\"1 + 1 1\"");
	mu_assert_eq (r_num_str_len ("1 + 1 1 + 1"), 5, "\"1 + 1 1 + 1\"");
	mu_assert_eq (r_num_str_len ("1 + (1 + 1) 1"), 11, "\"1 + (1 + 1) 1\"");
	mu_assert_eq (r_num_str_len ("1 + (1 + (1 + 1)) 1"), 17, "\"1 + (1 + (1 + 1)) 1\"");
	mu_assert_eq (r_num_str_len ("1+(1+(1+1)) 1"), 11, "\"1+(1+(1+1)) 1\"");
	mu_assert_eq (r_num_str_len ("(1 + 1) + (1 + 1) 1"), 17, "\"(1 + 1) + (1 + 1) 1\"");
	mu_assert_eq (r_num_str_len ("(1+1)+(1+1) 1"), 11, "\"(1+1)+(1+1) 1\"");
    mu_end;
}

bool test_r_num_str_split(void) {
	char *str = malloc (0x20);
	strcpy (str, "1 1 + 2 1 + (2 + 3) 4 ");
	//expected "1\01 + 2\01 + (2 + 3)\04\0"
	int count = r_num_str_split (str);
	mu_assert_eq (count, 4, "r_num_str_split (str) == 4");
	mu_assert_streq (str+0, "1", "1");
	mu_assert_streq (str+2, "1 + 2", "1 + 2");
	mu_assert_streq (str+8, "1 + (2 + 3)", "1 + (2 + 3)");
	mu_assert_streq (str+20, "4", "4");
	free (str);
    mu_end;
}

bool test_r_num_str_split_list(void) {
	char *s;
	char *str = malloc (0x20);
	strcpy (str, "1 1 + 2 1 + (2 + 3) 4 ");
	//expected {"1", "1 + 2", "1 + (2 + 3)", "4"} as list
	RList *list = r_num_str_split_list (str);
	mu_assert_eq (r_list_length (list), 4, "r_list_length (list) == 4");
	s = (char *)r_list_pop_head (list);
	mu_assert_streq (s, "1", "1");
	s = (char *)r_list_pop_head (list);
	mu_assert_streq (s, "1 + 2", "1 + 2");
	s = (char *)r_list_pop_head (list);
	mu_assert_streq (s, "1 + (2 + 3)", "1 + (2 + 3)");
	s = (char *)r_list_pop_head (list);
	mu_assert_streq (s, "4", "4");
	free (str);
	r_list_free (list);
    mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_num_units);
	mu_run_test (test_r_num_minmax_swap_i);
	mu_run_test (test_r_num_minmax_swap);
	mu_run_test (test_r_num_between);
	mu_run_test (test_r_num_str_len);
	mu_run_test (test_r_num_str_split);
	mu_run_test (test_r_num_str_split_list);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	num = r_num_new (NULL, NULL, NULL);
	return all_tests ();
}
