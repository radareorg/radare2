#include "r_line.h"

int main()
{
	const char *str;

	r_cons_init();

	if (! r_line_init() ) {
		printf("Cannot initizalize r_line\n");
		return 0;
	}
	
	while(1) {
		str = r_line_readline(0, NULL);
		if (str == NULL) // catch eof
			break;
		printf("%s\n", str);
		r_line_hist_add(str);
	}
}
