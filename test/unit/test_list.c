#include <r_list.h>
#include "minunit.h"
#define BUF_LENGTH 100

bool test_r_list_size(void) {
	// Test that r_list adding and deleting works correctly.
	int i;
	RList* list = r_list_new ();
	intptr_t test = 0x101010;
	// Add 100 items.
	for (i = 0; i < 100; i++) {
		r_list_append (list, (void*)test);
		mu_assert_eq (r_list_length (list), i + 1, "r_list_length failed on append");
	}
	// Delete 50 of them.
	for (i = 0; i < 50; i++) {
		(void)r_list_pop (list);
		mu_assert_eq(99 - i, r_list_length (list), "r_list_length failed on pop");
	}
	// Purge the list.
	r_list_purge (list);
	mu_assert_eq(0, r_list_length (list), "r_list_length failed on purged list");
	r_list_free (list);
	mu_end;
}

bool test_r_list_values(void) {
	RList* list = r_list_new ();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	r_list_append (list, (void*)test1);
	r_list_append (list, (void*)test2);
	int top1 = (intptr_t)r_list_pop (list);
	int top2 = (intptr_t)r_list_pop (list);
	mu_assert_eq(top1, 0x88888, "first value not 0x88888");
	mu_assert_eq(top2, 0x12345, "first value not 0x12345");
	r_list_free (list);
	mu_end;
}

bool test_r_list_join(void) {
	RList* list1 = r_list_new ();
	RList* list2 = r_list_new ();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	r_list_append (list1, (void*)test1);
	r_list_append (list2, (void*)test2);
	int joined = r_list_join (list1, list2);
	mu_assert_eq(joined, 1, "r_list_join of two lists");
	mu_assert_eq(r_list_length (list1), 2, "r_list_join two single element lists result length is 1");
	r_list_free (list1);
	r_list_free (list2);
	mu_end;
}


bool test_r_list_free(void) {
	RList* list = r_list_newf ((void*)0x9999);
	mu_assert_eq((int)(intptr_t)list->free, 0x9999, "r_list_newf function gets set properly");
	r_list_free (list);
	mu_end;
}

bool test_r_list_del_n(void) {
	RList* list = r_list_new ();
	intptr_t test1 = 0x12345;
	intptr_t test2 = 0x88888;
	r_list_append (list, (void*)test1);
	r_list_append (list, (void*)test2);
	mu_assert_eq (r_list_length (list), 2,
			"list is of length 2 when adding 2 values");
	r_list_del_n (list, 0);
	int top1 = (intptr_t)r_list_pop (list);
	mu_assert_eq(top1, 0x88888,
			"error, first value not 0x88888");
	r_list_free (list);
	mu_end;
}

bool test_r_list_sort(void) {
	RList* list = r_list_new ();
	char* test1 = "AAAA";
	char* test2 = "BBBB";
	char* test3 = "CCCC";
	// Put in not sorted order.
	r_list_append (list, (void*)test1);
	r_list_append (list, (void*)test3);
	r_list_append (list, (void*)test2);
	// Sort.
	r_list_sort (list, (RListComparator)strcmp);
	// Check that the list is actually sorted.
	mu_assert_streq ((char*)list->head->data, "AAAA", "first value in sorted list");
	mu_assert_streq ((char*)list->head->n->data, "BBBB", "second value in sorted list");
	mu_assert_streq ((char*)list->head->n->n->data, "CCCC", "third value in sorted list");
	r_list_free (list);
	mu_end;
}


bool test_r_list_sort2(void) {
	RList* list = r_list_new ();
	char* test1 = "AAAA";
	char* test2 = "BBBB";
	char* test3 = "CCCC";
	// Put in not sorted order.
	r_list_append (list, (void*)test3);
	r_list_append (list, (void*)test2);
	r_list_append (list, (void*)test1);
	// Sort.
	r_list_merge_sort (list, (RListComparator)strcmp);
	// Check that the list is actually sorted.
	mu_assert_streq ((char*)list->head->data, "AAAA", "first value in sorted list");
	mu_assert_streq ((char*)list->head->n->data, "BBBB", "second value in sorted list");
	mu_assert_streq ((char*)list->head->n->n->data, "CCCC", "third value in sorted list");
	r_list_free (list);
	mu_end;
}


static int cmp_range(const void *a, const void *b) {
	int ra = *(int *)a;
	int rb = *(int *)b;
	return ra - rb;
}

bool test_r_list_sort3(void) {
	RList* list = r_list_new ();
	int test1 = 33508;
	int test2 = 33480;
	int test3 = 33964;
	// Put in not sorted order.
	r_list_append (list, (void*)&test1);
	r_list_append (list, (void*)&test3);
	r_list_append (list, (void*)&test2);
	// Sort.
	r_list_merge_sort (list, (RListComparator)cmp_range);
	// Check that the list is actually sorted.
	mu_assert_eq (*(int*)list->head->data, 33480, "first value in sorted list");
	mu_assert_eq (*(int*)list->head->n->data, 33508, "second value in sorted list");
	mu_assert_eq (*(int*)list->head->n->n->data, 33964, "third value in sorted list");
	r_list_free (list);
	mu_end;
}


bool test_r_list_length(void) {
	RList* list = r_list_new ();
	RList* list2 = r_list_new ();
	RListIter *iter;
	int count = 0;
	int test1 = 33508;
	int test2 = 33480;
	int test3 = 33964;
	// Put in not sorted order.
	r_list_append (list, (void*)&test1);
	r_list_append (list, (void*)&test3);
	r_list_append (list, (void*)&test2);
	iter = list->head;
	while (iter) {
		count++;
		iter = iter->n;
	}
	mu_assert_eq (list->length, 3, "First length check");

	r_list_delete_data (list, (void*)&test1);
	mu_assert_eq (list->length, 2, "Second length check");

	r_list_append (list, (void*)&test1);
	mu_assert_eq (list->length, 3, "Third length check");

	r_list_pop (list);
	mu_assert_eq (list->length, 2, "Fourth length check");

	r_list_pop_head (list);
	mu_assert_eq (list->length, 1, "Fifth length check");

	r_list_insert (list, 2, (void*)&test2);
	mu_assert_eq (list->length, 2, "Sixth length check");

	r_list_prepend (list, (void*)&test3);
	mu_assert_eq (list->length, 3, "Seventh length check");

	r_list_del_n (list, 2);
	mu_assert_eq (list->length, 2, "Eighth length check");

	r_list_append (list2, (void*)&test1);
	r_list_append (list2, (void*)&test3);
	r_list_append (list2, (void*)&test2);
	r_list_join (list, list2);
	mu_assert_eq (list->length, 5, "Ninth length check");
	iter = list->head;
	count = 0;
	while (iter) {
		count++;
		iter = iter->n;
	}
	mu_assert_eq (list->length, count, "Tenth length check");
	r_list_free (list);
	r_list_free (list2);
	mu_end;
}


bool test_r_list_sort5(void) {
	RList* list = r_list_new ();
	int i = 0;
	char *upper[] = {"A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"};
	char *lower[] = {"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"};
	for (i = 0; i < 26; i++) {
		r_list_append (list, (void *)lower[i]);
	}
	for (i = 0; i < 26; i++) {
		r_list_append (list, (void *)upper[i]);
	}
	//add more than 43 elements to trigger merge sort
	r_list_sort (list, (RListComparator)strcmp);
	mu_assert_streq ((char *)list->head->data, upper[0], "First element");
	mu_assert_streq ((char *)list->tail->data, lower[25], "Last element");
	r_list_free (list);
	mu_end;
}

// 3-valued comparator -> {LT,EQ,GT}.
static int pintcmp(int* a, int* b) {
	return (int)(*a > *b) - (int)(*b > *a);
}

bool test_r_list_mergesort_pint() {
	// 47 items
	int data[] = {-440, -468, -444, -80, -568, -564, -396, -404, -436, -420,
		-428, -388, -356, -324, -292, -464, -260, -252, -204, -196, -212, -76,
		-160, -540, -216, -536, -532, -148, -116, -560, -556, -244, -460, -448,
		-236, -156, -228, -456, -552, -548, -544, -220, -180, -188, -84, -172,
		-164};
	int expected[] = {-568, -564, -560, -556, -552, -548, -544, -540, -536,
		-532, -468, -464, -460, -456, -448, -444, -440, -436, -428, -420, -404,
		-396, -388, -356, -324, -292, -260, -252, -244, -236, -228, -220, -216,
		-212, -204, -196, -188, -180, -172, -164, -160, -156, -148, -116, -84,
		-80, -76};

	RList* list = r_list_new();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (data); i++) {
		r_list_append (list, (void *)&data[i]);
	}

	// invoke sorting
	r_list_sort (list, (RListComparator)pintcmp);

	// assert the list is sorted as expected
	RListIter* iter;
	for (i = 0, iter = list->head; i < R_ARRAY_SIZE (expected); i++, iter = iter->n) {
		mu_assert_eq (*(int *)iter->data, expected[i], "array content mismatch");
	}

	r_list_free(list);
	mu_end;
}


bool test_r_list_sort4(void) {
	RList* list = r_list_new ();
	char* test1 = "AAAA";
	char* test2 = "BBBB";
	char* test3 = "CCCC";
	char* test4 = "DDDD";
	char* test5 = "EEEE";
	char* test6_later = "FFFF";
	char* test7 = "GGGG";
	char* test8 = "HHHH";
	char* test9 = "IIII";
	char* test10 = "JJJJ";
	char* ins_tests_odd[] = {test10, test1, test3, test7, test5, test9, test2,
		test4, test8};
	char* exp_tests_odd[] = {test1, test2, test3, test4, test5, test7,
		test8, test9, test10};
	int i;

	// Put in not sorted order.
	for (i = 0; i < R_ARRAY_SIZE (ins_tests_odd); ++i) {
		r_list_append (list, (void*)ins_tests_odd[i]);
	}
	// Sort.
	r_list_merge_sort (list, (RListComparator)strcmp);

	// Check that the list (odd-length) is actually sorted.
	RListIter *next = list->head;
	for (i = 0; i < R_ARRAY_SIZE (exp_tests_odd); ++i) {
		char buf[BUF_LENGTH];
		snprintf(buf, BUF_LENGTH, "%d-th value in sorted list", i);
		mu_assert_streq ((char*)next->data, exp_tests_odd[i], buf);
		next = next->n;
	}

#if 0 // Debug Print
	char *data;

	printf("after sorted 1 \n");
	r_list_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}
#endif

	char* exp_tests_even[] = {test1, test2, test3, test4, test5,
		test6_later, test7, test8, test9, test10};
	// Add test6 to make the length even
	r_list_append (list, (void*)test6_later);

#if 0 // Debug Printing
	printf("after adding FFFF \n");
	r_list_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}
#endif

	// Sort
	r_list_merge_sort (list, (RListComparator)strcmp);

#if 0 // Debug Printing
	printf("after sorting 2 \n");
	r_list_foreach (list, next, data) {
		printf("l -> %s\n", data);
	}
#endif

	// Check that the list (even-length) is actually sorted.
	next = list->head;
	for (i = 0; i < R_ARRAY_SIZE (exp_tests_even); ++i) {
		char buf[BUF_LENGTH];
		snprintf(buf, BUF_LENGTH, "%d-th value in sorted list", i);
		mu_assert_streq ((char*)next->data, exp_tests_even[i], buf);
		next = next->n;
	}
	r_list_free (list);
	mu_end;
}

bool test_r_list_append_prepend(void) {

	char *test[] = {
		"HEAD 00",
		"HEAD",
		"foo",
		"bar",
		"cow",
		"LAST"
	};

	RList *list = r_list_new ();
	RListIter *iter;

	r_list_append (list, test[2]);
	r_list_append (list, test[3]);
	r_list_append (list, test[4]);
	r_list_prepend (list, test[1]);
	r_list_prepend (list, test[0]);
	r_list_append (list, test[5]);

	char buf[BUF_LENGTH];
	int i;
	//Check that the next sequence is correct
	iter = list->head;
	for (i = 0; i < R_ARRAY_SIZE (test); ++i) {
		snprintf (buf, BUF_LENGTH, "%d-th value in list from head", i);
		mu_assert_streq ((char *)iter->data, test[i], buf);
		iter = iter->n;
	}

	//Check that the previous sequence is correct
	iter = list->tail;
	for (i = (R_ARRAY_SIZE (test)) - 1; i > 0; --i) {
		snprintf (buf, BUF_LENGTH, "%d-th value in list from tail", i);
		mu_assert_streq ((char *)iter->data, test[i], buf);
		iter = iter->p;
	}

	r_list_free (list);
	mu_end;
}

bool test_r_list_set_get(void) {

	char *test[] = { "aa", "bb", "cc", "dd", "ee", "ff" };

	RList *list = r_list_new ();

	int i;
	for (i = 0; i < R_ARRAY_SIZE (test); ++i) {
		r_list_append (list, test[i]);
	}

	char *str;
	r_list_set_n (list, 2, "CC");
	str = (char *)r_list_get_n (list, 2);
	mu_assert_streq (str, "CC", "value after set");

	r_list_prepend (list, "AA0");
	str = (char *)r_list_get_n (list, 3);
	mu_assert_streq (str, "CC", "value after prepend");

	bool s;
	s = r_list_set_n (list, 100, "ZZZZ");
	mu_assert_eq (s, false, "set out of bound");
	s = r_list_get_n (list, 100);
	mu_assert_eq (s, false, "get out of bound");

	r_list_free (list);
	mu_end;
}

bool test_r_list_reverse(void) {

	char *test[] = { "aa", "bb", "cc", "dd", "ee", "ff" };

	RList *list = r_list_new ();

	int i;
	for (i = 0; i < R_ARRAY_SIZE (test); ++i) {
		r_list_prepend (list, test[i]);
	}

	r_list_reverse (list);

	char buf[BUF_LENGTH];
	//Check that the sequence is correct
	RListIter *iter = list->head;
	for (i = 0; i < R_ARRAY_SIZE (test); ++i) {
		snprintf (buf, BUF_LENGTH, "%d-th value in list after reverse", i);
		mu_assert_streq ((char *)iter->data, test[i], buf);
		iter = iter->n;
	}

	r_list_free (list);
	mu_end;
}

bool test_r_list_clone(void) {

	char *test[] = { "aa", "bb", "cc", "dd", "ee", "ff" };

	RList *list1 = r_list_new ();
	RList *list2;

	int i;
	for (i = 0; i < R_ARRAY_SIZE (test); ++i) {
		r_list_prepend (list1, test[i]);
	}

	list2 = r_list_clone (list1, NULL);

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
	mu_run_test(test_r_list_size);
	mu_run_test(test_r_list_values);
	mu_run_test(test_r_list_join);
	mu_run_test(test_r_list_free);
	mu_run_test(test_r_list_del_n);
	mu_run_test(test_r_list_sort);
	mu_run_test(test_r_list_sort2);
	mu_run_test(test_r_list_sort3);
	mu_run_test(test_r_list_sort4);
	mu_run_test(test_r_list_sort5);
	mu_run_test(test_r_list_mergesort_pint);
	mu_run_test(test_r_list_length);
	mu_run_test(test_r_list_append_prepend);
	mu_run_test(test_r_list_set_get);
	mu_run_test(test_r_list_reverse);
	mu_run_test(test_r_list_clone);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
