puts@global() {
	/* do nothing */
}
main@global(128)
{
	.var0 = 3;
	.var4 = "counter";
	{
		puts(.var4);
		.var0 -= 1;
	} while(.var0);
	/* comment */
	.var0 = 3;
	.var4 = "coconut";
	while(.var0) {
		puts(.var4);
		.var0 -= 1;
	}
	0;
}

