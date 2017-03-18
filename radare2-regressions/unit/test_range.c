#include <r_util.h>
#include "minunit.h"
#define BUF_LENGTH 100

bool test_r_tinyrange_in(void) {
	RRangeTiny *bbr = r_tinyrange_new ();
	r_tinyrange_add (bbr, 100, 200);
	r_tinyrange_add (bbr, 300, 400);
	r_tinyrange_add (bbr, 400, 500);
	r_tinyrange_add (bbr, 600, 800);
	r_tinyrange_add (bbr, 750, 900);
	mu_assert_eq (true, r_tinyrange_in (bbr, 100), "Failed first");
	mu_assert_eq (false, r_tinyrange_in (bbr, 250), "Failed second");
	mu_assert_eq (true, r_tinyrange_in (bbr, 450), "Failed thirst");
	mu_assert_eq (true, r_tinyrange_in (bbr, 750), "Failed fourth");
	mu_assert_eq (true, r_tinyrange_in (bbr, 880), "Failed fifth");
	mu_assert_eq (false, r_tinyrange_in (bbr, 50), "Failed sixth");
	r_tinyrange_fini (bbr);
	free (bbr);
	mu_end;
}

bool test_r_tinyrange_in_two(void) {
	RRangeTiny *bbr = r_tinyrange_new ();
	r_tinyrange_add (bbr, 4199920, 4200121);
	r_tinyrange_add (bbr, 4200128, 4200215);
	r_tinyrange_add (bbr, 4200262, 4200298); //4,5
	r_tinyrange_add (bbr, 4200304, 4200575);
	r_tinyrange_add (bbr, 4200576, 4200654);
	r_tinyrange_add (bbr, 4200656, 4200812);
	mu_assert_eq (true, r_tinyrange_in (bbr, 4200288), "Failed two");
	r_tinyrange_fini (bbr);
	free (bbr);
	mu_end;

}

bool test_r_tinyrange_in_r2(void) {
	RRangeTiny *bbr = r_tinyrange_new ();
	r_tinyrange_add (bbr, 0x50e0, 0x50fb);
	r_tinyrange_add (bbr, 0x5110, 0x5112);
	r_tinyrange_add (bbr, 0x50e0, 0x50fb);
	r_tinyrange_add (bbr, 0x50fb, 0x5107);
	r_tinyrange_add (bbr, 0x5110, 0x5112);
	r_tinyrange_add (bbr, 0x50e0, 0x50fb);
	r_tinyrange_add (bbr, 0x50fb, 0x5107);
	r_tinyrange_add (bbr, 0x5107, 0x510a);
	r_tinyrange_add (bbr, 0x5110, 0x5112);
	r_tinyrange_add (bbr, 0x50e0, 0x50fb);
	r_tinyrange_add (bbr, 0x50fb, 0x5107);
	r_tinyrange_add (bbr, 0x5107, 0x510a);
	r_tinyrange_add (bbr, 0x5110, 0x5112);
	r_tinyrange_add (bbr, 0x50e0, 0x50fb);
	r_tinyrange_add (bbr, 0x50fb, 0x5107);
	r_tinyrange_add (bbr, 0x5107, 0x510a);
	r_tinyrange_add (bbr, 0x5110, 0x5112);
	r_tinyrange_add (bbr, 0x50e0, 0x50fb);
	r_tinyrange_add (bbr, 0x50fb, 0x5107);
	r_tinyrange_add (bbr, 0x5107, 0x510a);
	r_tinyrange_add (bbr, 0x5110, 0x5112);
	mu_assert_eq (true, r_tinyrange_in (bbr, 0x5110), "Failed inr2");
	r_tinyrange_fini (bbr);
	free (bbr);
	mu_end;

}

bool test_r_tinyrange_in_three(void) {
	RRangeTiny *bbr = r_tinyrange_new ();
	r_tinyrange_add (bbr, 4294981054, 4294981108);
	r_tinyrange_add (bbr, 4294982988, 4294983738); //2,3 
	r_tinyrange_add (bbr, 4294984100, 4294984477); 
	r_tinyrange_add (bbr, 4294984485, 4294984703);
	mu_assert_eq (false, r_tinyrange_in (bbr, 4294983738), "Failed three");
	r_tinyrange_fini (bbr);
	free (bbr);
	mu_end;

}

bool test_r_tinyrange_in_four(void) {
	RRangeTiny *bbr = r_tinyrange_new ();
	r_tinyrange_add (bbr, 20704, 20746);
	r_tinyrange_add (bbr, 20752, 20754); //2,3 
	mu_assert_eq (true, r_tinyrange_in (bbr, 20752), "Failed four");
	r_tinyrange_fini (bbr);
	free (bbr);
	mu_end;
}



int all_tests() {
	mu_run_test (test_r_tinyrange_in);
	mu_run_test (test_r_tinyrange_in_r2);
	mu_run_test (test_r_tinyrange_in_two);
	mu_run_test (test_r_tinyrange_in_three);
	mu_run_test (test_r_tinyrange_in_four);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
