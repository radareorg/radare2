#include "r_cons.h"
#include "r_print.h"

int main()
{
	struct r_print_t *p;
	const ut8 buf[] = "1234578901234567890";

	p = r_print_new();
	p->printf = r_cons_printf;
	r_cons_init();
	r_print_format(p, 0LL, buf, 10, "xxd foo bar cow");
	r_print_format(p, 0LL, buf, 10, "xxd");
	r_cons_flush();
	r_print_free(p);

	return 0;
}
