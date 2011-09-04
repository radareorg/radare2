#include <stdio.h>
#include "r_syscall.h"

int main() {
	int i, num = 3;
	RSyscall *ctx = r_syscall_new ();
	r_syscall_setup (ctx, "x86", "linux", 32);

	printf("4 = %s\n", r_syscall_get_i(ctx, 4, -1));
	printf("write = %d\n", r_syscall_get_num(ctx, "write"));

	// if args = 0 { no args }
	for (i=1; i<=num; i++) {
		const char *arg = r_syscall_reg (ctx, i, num);
		printf ("%d %d: %s\n", i, num, arg);
	}

	r_syscall_free (ctx);

	return 0;
}
