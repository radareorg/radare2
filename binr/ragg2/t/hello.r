/* hello world in r_egg */
write@syscall(4);
exit@syscall(1);

main@global(128) {
	.var0 = 4;
	.var4 = "Hello World\n";
	.var40 = "LOL\n";
	while (.var0 > 0) {
		write (1, .var4, 12);
//		if (.var0 == 2) { write (1, .var20, 4); }
		.var0 -= 2;
	}
	exit (0);
}
