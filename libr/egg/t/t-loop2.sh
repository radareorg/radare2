#!/bin/sh
EXIT=0
OUTPUT="loop
loop
loop"
cat > t.r <<EOF
exit@syscall(1);
write@syscall(4);
main@global(128,128) {
	.var0 = 0;
	while (.var0<2) {
		write (1, "loop\n", 5);
		.var0 += 1;
	}
	exit (0);
}
EOF
. ./t.sh
