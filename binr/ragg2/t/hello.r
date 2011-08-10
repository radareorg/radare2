/* hello world in r_egg */
write@syscall(4);
exit@syscall(1);

main@global(128) {
	.var0 = 4;
	.var4 = "Hello World\n";
	while (.var0) {
		write (1, .var4, 12);
		.var0 -= 1;
	}
	exit (0);
}
