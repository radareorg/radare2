/* classic hello world with a while-loop counter */

write@syscall(4);
exit@syscall(1);

main@global(128) {
	.var0 = 4;
	.var4 = "Hello World\n";
	while (.var0 > 0) {
		write (1, .var4, 12);
		.var0 -= 2;
	}
	exit (0);
}
