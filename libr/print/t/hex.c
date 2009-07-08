#include "r_cons.h"
#include "r_print.h"

int main()
{
	struct r_print_t *p;
	ut8 *buf = (ut8*)main;

	r_cons_init();
	p = r_print_new();
	r_print_hexdump(p, (ut64)(ut32)(main), buf, 128, 16, 1);
	r_cons_flush();

	return 0;
}
