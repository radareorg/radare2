exit@syscall(1);
@syscall() {
	: int 0x88
}
main@global() {
	exit(0);
}
