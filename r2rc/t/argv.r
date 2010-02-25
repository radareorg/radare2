# Test program checking for arguments

main@global(128)
{
	# arguments
	.var80 = "argc = %d\n";
	printf(.var80, .arg0);

	.var80 = "0x%08x : argv[%02d] = %s\n";
	.var0 = 0;
	.var4 = *.arg1;
	while(.var0 <= .arg0) {
		printf(.var80, .var4, .var0, .var4);
		.var0 += 1;     # increment counter
		.arg1 += 4;     # increment pointer
		.var4 = *.arg1; # get next argument
	}

	# environment
	.var80 = "0x%08x : envp[%02d] = %s\n";
	.var0 = 0;
	.var4 = *.arg2;
	{
		printf(.var80, .var4, .var0, .var4);
		.var0 += 1;     # increment counter
		.arg2 += 4;     # increment pointer
		.var4 = *.arg2; # get next environ
	} while(.var4);
: mov $1, %eax
: int $0x80
	
	0;
}
