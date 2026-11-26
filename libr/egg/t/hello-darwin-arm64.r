/* macOS arm64 hello world using Darwin syscall numbers */

write@syscall(4);
exit@syscall(1);

main@global(64) {
	: nop
	.var0 = "Hello from Darwin arm64!\n";
	write (1, .var0, 25);
	exit (0);
}
