#include "r_parse.h"

int main()
{
	struct r_parse_t *p;
	p = r_parse_new();
	printf("List: \n");
	r_parse_list(p);
	printf("Using plugin: \n");
	r_parse_set(p, "parse_x86_pseudo");
	return 0;
}
