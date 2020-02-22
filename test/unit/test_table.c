#include <r_util.h>
#include "minunit.h"

//TODO test r_str_chop_path

bool test_r_table(void) {
	RTable *t = r_table_new ();

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

bool test_r_table_columns() {
	RTable *t = NULL;
#define CREATE_TABLE \
	r_table_free (t); \
	t = r_table_new (); \
	r_table_add_column (t, r_table_type ("number"), "name", 0); \
	r_table_add_column (t, r_table_type ("number"), "address", 0); \
	r_table_add_row (t, "hello", "100", NULL); \
	r_table_add_row (t, "namings", "20000", NULL); \

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
	mu_run_test(test_r_table_columns);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
