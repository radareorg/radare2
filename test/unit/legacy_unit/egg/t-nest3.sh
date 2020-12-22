#!/bin/sh
EXIT=0
OUTPUT="zero
zero
one
zero
zero
one
two
zero
zero
one
zero
zero
one
two"
cat > t.r <<EOF
exit@syscall(1);
write@syscall(4);

main@global(128,128) {
	.var0 = 2;
	while (.var0) {
		.var4 = 2;
		while (.var4) {
			.var8 = 2;
			while (.var8) {
				write (1, "zero\n", 5);
				.var8 -= 1;
			}
			write (1, "one\n", 4);
			.var4 -= 1;
		}
		write (1, "two\n", 4);
		.var0 -= 1;
	}
	exit (0);
}
EOF
. ./t.sh

