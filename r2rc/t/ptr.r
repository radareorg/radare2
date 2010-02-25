
main@global(128)
{
	.var0 = system;
	.var4 = "/bin/sh";
	.var0(.var4);

	/* segfault 1 */
	.var0 = 0;
	.var0();

	.var0 += 10;

	/* segfault 2 */
	*0x8048018();

	/* segfault 3 */
	0x8048000();
}
