#!/bin/sh
EXIT=0
OUTPUT="loop
loop
loop"
cat > t.r <<EOF
exit@syscall(1);
write@syscall(4);
main();
main@global(128,128) {
	.var0 = 0;
	.var4 = &.var8;
	.var8 = "helloworld";
	while (*.var4:1) {
		.var4 += 1;
		.var0 += 1;
	}
	exit (.var0);
}
EOF
. ./t.sh
