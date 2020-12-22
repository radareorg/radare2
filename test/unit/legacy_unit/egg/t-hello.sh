#!/bin/sh
EXIT=0
OUTPUT="hello world"
cat > t.r <<EOF
exit@syscall(1);
write@syscall(4);
main@global(128,128) {
	write (1, "hello world\n", 12);
	exit (0);
}
EOF
. ./t.sh

