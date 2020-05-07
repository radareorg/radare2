#include <r_big.h>
#include "minunit.h"

bool test_r_list_clone(void) {

    char *test[] = { "aa", "bb", "cc", "dd", "ee", "ff" };

    RList *list1 = r_list_new ();
    RList *list2 = r_list_new ();

    int i;
    for (i = 0; i < R_ARRAY_SIZE (test); ++i) {
        r_list_prepend (list1, test[i]);
    }

    list2 = r_list_clone (list1);

    char buf[BUF_LENGTH];
    RListIter *iter1 = list1->head;
    RListIter *iter2 = list2->head;
    for (i = 0; i < R_ARRAY_SIZE (test); ++i) {
        snprintf (buf, BUF_LENGTH, "%d-th value after clone", i);
        mu_assert_streq ((char *)iter2->data, (char *)iter1->data, buf);
        iter1 = iter1->n;
        iter2 = iter2->n;
    }

    r_list_free (list1);
    r_list_free (list2);
    mu_end;
}

int all_tests() {
    mu_run_test(test_r_big_from_to_int);
    mu_run_test(test_r_big_from_to_hexstr);
    mu_run_test(test_r_big_assign);
    mu_run_test(test_r_big_add);
    mu_run_test(test_r_big_sub);
    mu_run_test(test_r_big_mul);
    mu_run_test(test_r_big_div);
    mu_run_test(test_r_big_mod);
    mu_run_test(test_r_big_divmod);
    mu_run_test(test_r_big_and);
    mu_run_test(test_r_big_or);
    mu_run_test(test_r_big_xor);
    mu_run_test(test_r_big_lshift);
    mu_run_test(test_r_big_rshift);
    mu_run_test(test_r_big_inc);
    mu_run_test(test_r_big_dec);
    mu_run_test(test_r_big_cmp);
    mu_run_test(test_r_big_is_zero);
    mu_run_test(test_r_big_pow);
    mu_run_test(test_r_big_isqrt);

    mu_run_test(test_r_list_clone);
    return tests_passed != tests_run;
}

int main(int argc, char **argv) {
    return all_tests();
}