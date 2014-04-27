#!/bin/sh
EXIT=0
OUTPUT="one
one
two
one
one
two"
cat > t.r <<EOF
exit@syscall(1);
write@syscall(4);

main@global(128,128) {
	.var0 = 2;
	: polla:
	.var4 = 2;
	while (.var4) {
		write (1, "one\n", 4);
		.var4 -= 1;
	}
	write (1, "two\n", 4);
	.var0 -= 1;
	if (.var0) {
		goto(polla);
	}
	exit (0);
}
EOF
. ./t.sh

