main@global(128)
{
	.var0 = &.var20;
	memset(.var0, $0, $10);
	read($0, .var0, $10);
	puts(.var0);

	memset(&.var20, $0, $10);
	read($0, &.var20, $10);
	puts(&.var20);

	#exit($0);
	0;
}
