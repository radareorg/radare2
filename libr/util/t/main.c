#include "../table.c"

const char *csv = "action,target\n"
	"hello,world\n";

int main() {
	RTable *t = r_table_new ();

	// r_table_fromcsv (t, csv);

	r_table_add_column (t, &r_table_type_string, "name", 0);
	r_table_add_column (t, &r_table_type_number, "address", 0);

	r_table_add_row (t, "hello", "100", NULL);
	r_table_add_row (t, "namings", "20000", NULL);
	{
		char *s = r_table_tostring (t);
		eprintf ("%s\n", s);
		free (s);
	}
	{
		char *j = r_table_tojson (t);
		eprintf ("%s\n", j);
		free (j);
	}
	{
		char *c = r_table_tocsv (t);
		eprintf ("%s\n", c);
		free (c);
	}
	r_table_free (t);
	return 0;
}
