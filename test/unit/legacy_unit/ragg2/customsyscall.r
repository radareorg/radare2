/* Hello World */

exit@syscall(1);

@syscall() {
	: int3
}

main@global() {
	exit(2);
}
