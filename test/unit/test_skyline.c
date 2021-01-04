#include <r_util.h>
#include <r_skyline.h>
#include "minunit.h"

bool test_r_skyline(void) {
	RSkyline sky;
	r_skyline_init (&sky);
	r_skyline_add (&sky, (RInterval){ 0, 1 }, (void *)1);
	mu_assert_true (r_skyline_contains (&sky, 0), "Skyline should contain 0");
	mu_assert_false (r_skyline_contains (&sky, 1), "Skyline shouldn't contain 1");
	r_skyline_add (&sky, (RInterval){ 2, 4 }, (void *)2);
	mu_assert_true (r_skyline_contains (&sky, 2), "Skyline should contain 2");
	mu_assert_eq ((size_t)r_skyline_get (&sky, 0), 1, "r_skyline_get should get first map");
	mu_assert_eq ((size_t)r_skyline_get (&sky, 2), 2, "r_skyline_get should get second map");
	mu_assert_eq ((size_t)r_skyline_get_intersect (&sky, 1, 2), 2, "r_skyline_get_intersect should get second map");
	r_skyline_add (&sky, (RInterval){ 0, 3 }, (void *)3);
	mu_assert_true (r_skyline_contains (&sky, 0) && r_skyline_contains (&sky, 3),
		"Skyline should still contain 0 to 3 after overlap");
	mu_assert_eq ((size_t)r_skyline_get (&sky, 0), 3, "r_skyline_get should get third map");
	r_skyline_fini (&sky);
	mu_end;
}

bool test_r_skyline_overlaps(void) {
	RSkyline sky;
	r_skyline_init (&sky);

	r_skyline_add (&sky, (RInterval){ 10, 10 }, (void *)1);
	const RSkylineItem *item = r_skyline_get_item (&sky, 10);
	mu_assert_eq ((size_t)item->user, 1, "r_skyline_get should get 1st map");
	
	r_skyline_add (&sky, (RInterval){ 9, 2 }, (void *)2);
	item = r_skyline_get_item (&sky, 10);
	mu_assert_eq ((size_t)item->user, 2, "r_skyline_get should get 2nd map");
	
	r_skyline_add (&sky, (RInterval){ 19, 2 }, (void *)3);
	item = r_skyline_get_item (&sky, 19);
	mu_assert_eq ((size_t)item->user, 3, "r_skyline_get should get 3rd map");
	
	r_skyline_add (&sky, (RInterval){ 14, 3 }, (void *)4);
	item = r_skyline_get_item (&sky, 14);
	mu_assert_eq ((size_t)item->user, 4, "r_skyline_get should get 4th map");
	
	item = r_skyline_get_item (&sky, 12);
	mu_assert_eq ((size_t)item->user, 1, "r_skyline_get should get 1st map head after it was overlapped");
	mu_assert_eq (r_itv_begin (item->itv), 11, "1st map head should start at 11");
	mu_assert_eq (r_itv_end (item->itv), 14, "1st map head should end at 14");
	
	item = r_skyline_get_item (&sky, 17);
	mu_assert_eq ((size_t)item->user, 1, "r_skyline_get should get 1st map tail after it was overlapped");
	mu_assert_eq (r_itv_begin (item->itv), 17, "1st map tail should start at 17");
	mu_assert_eq (r_itv_end (item->itv), 19, "1st map tail should end at 19");
	
	r_skyline_add (&sky, (RInterval){ 0, 30 }, (void *)5);
	mu_assert_eq (r_vector_len (&sky.v), 1, "5th map should cover entire skyline");
	item = r_skyline_get_item (&sky, 10);
	mu_assert_eq ((size_t)item->user, 5, "r_skyline_get should get 5th map");
	mu_assert_eq (r_itv_size (item->itv), 30, "5th map should have size of 30");

	r_skyline_add (&sky, (RInterval){ 0, 10 }, (void *)6);
	r_skyline_add (&sky, (RInterval){ 10, 10 }, (void *)7);
	r_skyline_add (&sky, (RInterval){ 20, 10 }, (void *)8);
	r_skyline_add (&sky, (RInterval){ 30, 10 }, (void *)9);
	mu_assert_eq (r_vector_len (&sky.v), 4, "maps 5 through 9 should be the only ones existing");

	r_skyline_add (&sky, (RInterval){ 5, 30 }, (void *)10);
	mu_assert_eq (r_vector_len (&sky.v), 3, "10th map should remove all maps it covered, leaving a head and a tail");

	item = r_skyline_get_item (&sky, 35);
	mu_assert_eq (r_itv_begin (item->itv), 35, "9th map should begin at 35 after 10th covered its beginning");
	
	r_skyline_add (&sky, (RInterval){ 3, 5 }, (void *)11);
	item = r_skyline_get_item (&sky, 0);
	mu_assert_eq (r_itv_size (item->itv), 3, "6th map should have size of 3 after 11th covered its end");

	item = r_skyline_get_item (&sky, 20);
	mu_assert_eq (r_itv_begin (item->itv), 8, "10th map should begin at 8 after 11th covered its beginning");

	r_skyline_add (&sky, (RInterval){ 3, 5 }, (void *)12);
	item = r_skyline_get_item (&sky, 3);
	bool cond = r_vector_len (&sky.v) == 4 && r_itv_begin (item->itv) == 3
		&& r_itv_end (item->itv) == 8 && (size_t)item->user == 12;
	mu_assert_true (cond, "12th map should completely cover 11th");

	r_skyline_fini (&sky);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_skyline);
	mu_run_test (test_r_skyline_overlaps);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}