__main@global(16)
{
  	.var0 = "/bin/sh";
  	system(.var0);
}

main@global(128)
{
	.var0 = "/bin/sh";
	.var20 = "%s:%d\n";
	#.var50 = $33;
	#printf(.var20, .var0, .var50);
	printf(.var20, .var0, $33);
	puts(.var0);
	system(.var0);
}
