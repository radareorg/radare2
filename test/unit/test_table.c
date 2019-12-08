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


bool all_tests() {
	mu_run_test(test_r_table);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
