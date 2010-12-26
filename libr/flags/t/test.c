#include <r_cons.h>
#include <r_flags.h>

int main()
{
	RFlag *flags;
	RFlagItem *fi;

	r_cons_new ();
	flags = r_flag_new();
	r_flag_set(flags, "foo", 1024, 50, 0);

	fi = r_flag_get_i(flags, 1024);
	if (fi) printf("FLAG FOUND '%s'\n", fi->name);
	else printf("FLAG NOT FOUND\n");

	r_flag_set(flags, "foo", 300LL, 0, 0);
	fi = r_flag_get_i(flags, 0);
	if (fi) printf("FLAG FOUND '%s'\n", fi->name);
	else printf("FLAG NOT FOUND\n");

	fi = r_flag_get(flags, "foo");
	if (fi) printf("FLAG FOUND '%s'\n", fi->name);
	else printf("FLAG NOT FOUND\n");

	r_cons_printf ("--- pre ---\n");
	r_flag_list (flags, 0);
	r_cons_flush ();

	r_cons_printf ("--- sort ---\n");
	r_cons_flush ();
	r_flag_sort (flags, 0);

	r_cons_printf ("--- list ---\n");
	r_cons_flush ();
	r_flag_list (flags, 1);
	r_cons_flush ();
	r_flag_free (flags);
	r_cons_free ();

	return 0;
}
