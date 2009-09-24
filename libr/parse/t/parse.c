#include "r_parse.h"

int main()
{
	char str[128];
	struct r_parse_t *p;
	p = r_parse_new();
	printf("List: \n");
	r_parse_list(p);
	printf("Using plugin: \n");
	r_parse_use(p, "x86.pseudo");
	str[0]='\0';
	r_parse_assemble(p, str, strdup("eax=1;int 0x80"));
	printf("--output--\n");
	printf("%s\n", str);
	return 0;
}
