# This is a test program in rlang
#
#<{;include i/sys.r}>

puts(4)
{
	.var0 = strlen(.arg0);
	write(1, .arg0, .var0);
#	write(1, str, strlen(str));
}

main@global(128)
{
	.var0 = "Hello World"
	printf("Result %d\n", 3+2);
	puts("Hello World\n");
	3;
}
