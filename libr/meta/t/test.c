#include <r_meta.h>

int main()
{
	struct r_meta_t *m = r_meta_new();
	r_meta_add(m, R_META_FUNCTION, 0x8048300, 128, "main");
	r_meta_add(m, R_META_COMMENT, 0x8048300, 1, "Everything starts here");
	r_meta_add(m, R_META_FUNCTION, 0x8048200, 54, "entrypoint");

	r_meta_list(m, R_META_ANY);
	{
		char *str = r_meta_get_string(m, R_META_ANY, 0x8048300);
		printf("COMMENT:\n%s\n", str);
		free(str);
	}
	return 0;
}
