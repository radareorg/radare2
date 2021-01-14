#include <r_util.h>
#include "minunit.h"
#define BUF_LENGTH 100

//TODO test r_str_chop_path

bool test_r_table(void) {
	RTable *t = r_table_new ("test1");

	// r_table_fromcsv (t, csv);
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");

	r_table_add_column (t, typeString, "name", 0);
	r_table_add_column (t, typeNumber, "address", 0);

	r_table_add_row (t, "hello", "100", NULL);
	r_table_add_row (t, "namings", "20000", NULL);

	// r_table_filter (t, 1, '>', "200");
	// r_table_filter (t, 1, '=', "100");
	// r_table_query (t, "[1]/q/100");
	r_table_sort (t, 1, true);
	{
		char *j = r_table_tojson (t);
		const char *jOK = "[{\"name\":\"namings\",\"address\":20000},{\"name\":\"hello\",\"address\":100}]";
		mu_assert_streq (j, jOK, "r_table_get_sections");
		free (j);
	}
	r_table_free (t);
	mu_end;
}

RTable *__table_test_data1() {
	RTable *t = r_table_new ("test2");

	r_table_add_column (t, r_table_type ("string"), "ascii", 0);
	r_table_add_column (t, r_table_type ("number"), "code", 0);

	r_table_add_row (t, "a", "97", NULL);
	r_table_add_row (t, "b", "98", NULL);
	r_table_add_row (t, "c", "99", NULL);

	return t;
}

bool test_r_table_column_type(void) {
	RTable *t = __table_test_data1 ();
	RTableColumn *c = r_list_get_n (t->cols, 1);
	c->type = r_table_type ("NUMBER");
	r_table_sort (t, 1, true);
	char *s = r_table_tostring (t);
	mu_assert_streq (s,
		"ascii code\n"
		"----------\n"
		"a     97\n"
		"b     98\n"
		"c     99\n", "not sorted by second column due to undefined type");
	free (s);
	r_table_free (t);
	mu_end;
}

bool test_r_table_tostring(void) {
	RTable *t = __table_test_data1 ();
	char buf[BUF_LENGTH];

	int i;
	for (i = 0; i < 4; i++) {
		char *s = r_table_tostring (t);
		snprintf (buf, BUF_LENGTH, "%d-th call to r_table_tostring", i);
		mu_assert_streq (s,
			"ascii code\n"
			"----------\n"
			"a     97\n"
			"b     98\n"
			"c     99\n", buf);
		free (s);
	}
	r_table_free (t);
	mu_end;
}

bool test_r_table_sort1(void) {
	RTable *t = __table_test_data1 ();

	r_table_sort (t, 1, true);
	char *strd = r_table_tostring (t);
	mu_assert_streq (strd,
		"ascii code\n"
		"----------\n"
		"c     99\n"
		"b     98\n"
		"a     97\n", "sort decreasing second column using number type");
	free (strd);

	r_table_sort (t, 1, false);
	char *stri = r_table_tostring (t);
	mu_assert_streq (stri,
		"ascii code\n"
		"----------\n"
		"a     97\n"
		"b     98\n"
		"c     99\n", "sort increasing second column using number type");
	free (stri);
	r_table_free (t);
	mu_end;
}

bool test_r_table_uniq(void) {
	RTable *t = __table_test_data1 ();

	r_table_uniq (t);
	char *strd = r_table_tostring (t);
	mu_assert_streq (strd,
		"ascii code\n"
		"----------\n"
		"a     97\n"
		"b     98\n"
		"c     99\n",
		"uniq delete nothing");
	free (strd);

	r_table_add_row (t, "a", "97", NULL);
	r_table_add_row (t, "a", "97", NULL);
	r_table_add_row (t, "a", "97", NULL);
	r_table_add_row (t, "b", "98", NULL);
	r_table_add_row (t, "c", "99", NULL);
	r_table_add_row (t, "b", "98", NULL);
	r_table_add_row (t, "c", "99", NULL);
	r_table_add_row (t, "d", "99", NULL);
	r_table_add_row (t, "b", "98", NULL);
	r_table_add_row (t, "d", "99", NULL);
	r_table_add_row (t, "c", "99", NULL);
	r_table_add_row (t, "c", "100", NULL);

	r_table_uniq (t);
	char *stri = r_table_tostring (t);
	mu_assert_streq (stri,
		"ascii code\n"
		"----------\n"
		"a     97\n"
		"b     98\n"
		"c     99\n"
		"d     99\n"
		"c     100\n",
		"uniq delete some rows");
	free (stri);
	r_table_free (t);
	mu_end;
}

static void simple_merge(RTableRow *acc, RTableRow *new_row, int nth) {
	RList *lhs = acc->items;
	RList *rhs = new_row->items;
	RListIter *iter_lhs;
	RListIter *iter_rhs;

	char *item_lhs;

	int i = 0;

	for (iter_lhs = lhs->head, iter_rhs = rhs->head;
		iter_lhs && iter_rhs;
		iter_lhs = iter_lhs->n, iter_rhs = iter_rhs->n) {

		item_lhs = iter_lhs->data;

		if (i != nth) {
			if (!strcmp (item_lhs, "a")) {
				free (iter_lhs->data);
				iter_lhs->data = r_str_new ("a | e");
			} else if (!strcmp (item_lhs, "b")) {
				free (iter_lhs->data);
				iter_lhs->data = r_str_new ("b | f");
			} else if (!strcmp (item_lhs, "c")) {
				free (iter_lhs->data);
				iter_lhs->data = r_str_new ("c | h");
			} else if (!strcmp (item_lhs, "d")) {
				free (iter_lhs->data);
				iter_lhs->data = r_str_new ("d | g");
			}
		}

		++i;
	}
}

bool test_r_table_group (void) {
	RTable *t = __table_test_data1 ();

	r_table_group (t, -1, NULL);
	char *str = r_table_tostring (t);
	mu_assert_streq (str,
		"ascii code\n"
		"----------\n"
		"a     97\n"
		"b     98\n"
		"c     99\n",
		"group delete nothing");
	free (str);

	r_table_add_row (t, "a", "97", NULL);
	r_table_add_row (t, "a", "97", NULL);
	r_table_add_row (t, "a", "97", NULL);
	r_table_add_row (t, "b", "98", NULL);
	r_table_add_row (t, "c", "99", NULL);
	r_table_add_row (t, "b", "98", NULL);
	r_table_add_row (t, "c", "99", NULL);
	r_table_add_row (t, "d", "1", NULL);
	r_table_add_row (t, "b", "98", NULL);
	r_table_add_row (t, "d", "99", NULL);
	r_table_add_row (t, "c", "99", NULL);
	r_table_add_row (t, "c", "100", NULL);

	r_table_group (t, 0, NULL);
	str = r_table_tostring (t);
	mu_assert_streq (str,
		"ascii code\n"
		"----------\n"
		"a     97\n"
		"b     98\n"
		"c     99\n"
		"d     1\n",
		"group delete some rows");
	free (str);

	r_table_add_row (t, "e", "97", NULL);
	r_table_add_row (t, "f", "98", NULL);
	r_table_add_row (t, "g", "99", NULL);
	r_table_add_row (t, "h", "1", NULL);

	r_table_group (t, 1, simple_merge);
	str = r_table_tostring (t);
	mu_assert_streq (str,
		"ascii code\n"
		"----------\n"
		"a | e 97\n"
		"b | f 98\n"
		"c | h 99\n"
		"d | g 1\n",
		"group delete some rows");
	free (str);

	r_table_free (t);
	mu_end;
}

bool test_r_table_columns () {
	RTable *t = NULL;
#define CREATE_TABLE                                                   \
	r_table_free (t);                                              \
	t = r_table_new ("test");                                      \
	r_table_add_column (t, r_table_type ("number"), "name", 0);    \
	r_table_add_column (t, r_table_type ("number"), "address", 0); \
	r_table_add_row (t, "hello", "100", NULL);                     \
	r_table_add_row (t, "namings", "20000", NULL);

	CREATE_TABLE
	char *s = r_table_tocsv (t);
	mu_assert_streq (s,
		"name,address\n"
		"hello,100\n"
		"namings,20000\n", "original");
	free (s);

	RList *newcols = r_list_new ();
	r_table_columns (t, newcols);
	s = r_table_tocsv (t);
	mu_assert_streq (s,
		"\n"
		"\n"
		"\n", "no cols");
	free (s);

	CREATE_TABLE
	r_list_push (newcols, "address");
	r_table_columns (t, newcols);
	s = r_table_tocsv (t);
	mu_assert_streq (s,
		"address\n"
		"100\n"
		"20000\n", "select");
	free (s);

	CREATE_TABLE
	r_list_push (newcols, "name");
	r_table_columns (t, newcols);
	s = r_table_tocsv (t);
	mu_assert_streq (s,
		"address,name\n"
		"100,hello\n"
		"20000,namings\n", "reorder");
	free (s);

	CREATE_TABLE
	r_list_push (newcols, "name");
	r_list_push (newcols, "address");
	r_table_columns (t, newcols);
	s = r_table_tocsv (t);
	mu_assert_streq (s,
		"address,name,name,address\n"
		"100,hello,hello,100\n"
		"20000,namings,namings,20000\n", "replicate");
	free (s);

	r_list_free (newcols);
	r_table_free (t);
	mu_end;
#undef CREATE_TABLE
}

bool all_tests() {
	mu_run_test(test_r_table);
	mu_run_test(test_r_table_column_type);
	mu_run_test(test_r_table_tostring);
	mu_run_test(test_r_table_sort1);
	mu_run_test(test_r_table_uniq);
	mu_run_test(test_r_table_group);
	mu_run_test (test_r_table_columns);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
