#include "r_cons.h"
#include "r_print.h"

int main()
{
	struct r_print_t *p;
	u8 *buf = (u8*)main;

	r_cons_init();
	p = r_print_new();
	r_print_hexdump(p, (u64)(u32)(main), buf, 128, 1);
	r_cons_flush();

	return 0;
}
