#include <r_util.h>
#include "minunit.h"

static bool range_has(RRange *rgs, ut64 fr, ut64 to) {
	RListIter *iter;
	RRangeItem *r;
	r_list_foreach (rgs->ranges, iter, r) {
		if (r->fr == fr && r->to == to) {
			return true;
		}
	}
	return false;
}

bool test_r_str_range_in(void) {
	mu_assert_true (r_str_range_in ("0x100", 0x100), "single value");
	mu_assert_false (r_str_range_in ("0x100", 0x101), "single value is not a range");
	mu_assert_true (r_str_range_in ("0x100..0x1ff", 0x100), "range start");
	mu_assert_true (r_str_range_in ("0x100..0x1ff", 0x1ff), "range end is inclusive");
	mu_assert_false (r_str_range_in ("0x100..0x1ff", 0x200), "past range end");
	mu_assert_false (r_str_range_in ("0x100..0x1ff", 0xff), "before range start");
	mu_assert_true (r_str_range_in ("1,10..20,30", 15), "mixed list range");
	mu_assert_true (r_str_range_in ("1,10..20,30", 30), "mixed list last value");
	mu_assert_true (r_str_range_in ("1,10..20,30", 1), "mixed list first value");
	mu_assert_false (r_str_range_in ("1,10..20,30", 25), "mixed list gap");
	mu_assert_true (r_str_range_in (" 1 , 10 .. 20 ", 20), "whitespace");
	mu_assert_false (r_str_range_in ("", 0), "empty string");
	mu_assert_false (r_str_range_in (NULL, 0), "null string");
	mu_assert_true (r_str_range_in ("0..0xffffffffffffffff", UT64_MAX), "full range");
	mu_assert_true (r_str_range_in ("0x100..0x100+0x20", 0x120), "expression in range end");
	mu_assert_true (r_str_range_in ("0x110-0x10", 0x100), "dash is subtraction");
	mu_end;
}

bool test_r_str_range_in_invalid(void) {
	mu_assert_false (r_str_range_in ("..", 0), "bare dots");
	mu_assert_false (r_str_range_in ("10..", 10), "missing end");
	mu_assert_false (r_str_range_in ("..10", 0), "missing start");
	mu_assert_false (r_str_range_in ("20..10", 15), "reversed range");
	mu_assert_false (r_str_range_in ("0x100-0x1ff", 0x150), "dash is not a separator");
	mu_assert_false (r_str_range_in ("1,,2", 2), "empty item");
	mu_assert_false (r_str_range_in ("foo", 0), "not a number");
	mu_end;
}

bool test_r_range_new_from_string(void) {
	RRange *rgs = r_range_new_from_string ("0x10..0x1f,0x40,0x80..0x8f");
	mu_assert_eq (r_list_length (rgs->ranges), 3, "three items");
	mu_assert_true (range_has (rgs, 0x10, 0x20), "inclusive end maps to to + 1");
	mu_assert_true (range_has (rgs, 0x40, 0x41), "single address");
	mu_assert_true (range_has (rgs, 0x80, 0x90), "last range");
	mu_assert_eq (r_range_size (rgs), 0x10 + 1 + 0x10, "total size");
	r_range_free (rgs);

	rgs = r_range_new_from_string ("..");
	mu_assert_eq (r_list_length (rgs->ranges), 0, "bare dots adds nothing");
	r_range_free (rgs);

	rgs = r_range_new_from_string ("6-5");
	mu_assert_true (range_has (rgs, 1, 2), "dash is subtraction");
	r_range_free (rgs);
	mu_end;
}

bool all_tests(void) {
	mu_run_test (test_r_str_range_in);
	mu_run_test (test_r_str_range_in_invalid);
	mu_run_test (test_r_range_new_from_string);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
