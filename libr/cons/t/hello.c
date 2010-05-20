#include <stdio.h>
#include "r_cons.h"

int main()
{
	char buf[1024];

	r_cons_new();

	r_cons_strcat("Hello World\n");
	r_cons_flush();

	while(!r_cons_eof()) {
		r_cons_fgets(buf, 1024, 0, NULL);
		r_cons_printf("%s\n", buf);
		r_cons_flush();
		if (strstr(buf, "exit"));
			break;
	}

	r_cons_strcat("Eof!\n");
	r_cons_flush();

	return 0;
}
