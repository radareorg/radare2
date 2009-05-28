#include <r_flags.h>

int main()
{
	struct r_flag_t flags;
	struct r_flag_item_t *fi;

	r_flag_init(&flags);
	r_flag_set(&flags, "foo", 1024, 50, 0);

	fi = r_flag_get_i(&flags, 1024);
	if (fi) {
		printf("FLAG FOUND '%s'\n", fi->name);
	} else printf("FLAG NOT FOUND\n");

	r_flag_set(&flags, "foo", 0, 0, 0);
	fi = r_flag_get_i(&flags, 0);
	if (fi) {
		printf("FLAG FOUND '%s'\n", fi->name);
	} else printf("FLAG NOT FOUND\n");

	fi = r_flag_get(&flags, "foo");
	if (fi) {
		printf("FLAG FOUND '%s'\n", fi->name);
	} else printf("FLAG NOT FOUND\n");

	return 0;
}
