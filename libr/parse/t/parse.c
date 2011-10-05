#include "r_parse.h"

int main(int argc, char **argv) {
	char str[128];
	struct r_parse_t *p;
	p = r_parse_new();

	if (argc==1) {
		printf("List: \n");
		r_parse_list(p);
		printf("Using plugin: \n");
		r_parse_use(p, "x86.pseudo");
		str[0]='\0';
		r_parse_assemble (p, str, strdup("eax=1;int 0x80"));
		printf ("--output--\n");
		printf ("%s\n", str);
		printf ("\n----\n\n");
		r_parse_use (p, "att2intel");
		r_parse_parse (p, "movl $3, %eax", str); //, sizeof (str));
		//r_parse_filter (p, NULL, "movl $3, %eax", str, sizeof (str));
		printf ("%s\n", str);
	} else {
		char buf[128];
		r_parse_use (p, "att2intel");
		while (!feof (stdin)) {
			buf[0] = 0;
			fgets (buf, sizeof (buf)-1, stdin);
			if (feof (stdin))
				break;
			buf[strlen (buf)-1] = 0;
			if (*buf) {
				r_parse_parse (p, buf, str); //, sizeof (str));
				printf ("%s\n", str);
			}
		}
	}
	return 0;
}
