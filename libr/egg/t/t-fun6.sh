#!/bin/sh
EXIT=0
OUTPUT="loop
loop
loop"
cat > t.r <<EOF
exit@syscall(1);
write@syscall(4);

main();

fun2@(,8) {
// XXX: we cant access args in naked functions
//	write (.arg0, .arg4, .arg8);
	write (1, "pop\n", 4);
}

fun@(16) {
	fun2 (1, .arg0, .arg4);
}

main@global(128,128) {
	.var0 = 0;
	while (.var0<2) {
		fun ("loop\n", 5);
		.var0 += 1;
	}
	exit (0);
}
EOF
. ./t.sh
