io.r@include("io/libc64");

main@global(128) {
	/* Keep locals above the native emitter's syscall argument slots. */
	.var48 = 0;
	.var56 = 1;
	.var64 = 7;
	.var72 = "0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n";
	while (.var64 > 0) {
		/* Each of the first seven terms selects a digit and its newline. */
		.var80 = .var72 + .var48 + .var48;
		write (1, .var80, 2);
		.var88 = .var48 + .var56;
		.var48 = .var56;
		.var56 = .var88;
		.var64 -= 1;
	}
	exit (0);
}
