#include <stdio.h>
#include "r_syscall.h"

int main() {
	struct r_syscall_t *ctx;

	ctx = r_syscall_new ();
	r_syscall_setup (ctx, "x86", "linux");

	printf("4 = %s\n", r_syscall_get_i(ctx, 4, -1));
	printf("write = %d\n", r_syscall_get_num(ctx, "write"));

	r_syscall_free (ctx);

	return 0;
}
