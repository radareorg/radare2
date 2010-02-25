addr_start@alias(0x8048000);
addr_end@alias(0x8048032);
# printf@alias(0xb7edd780); 

main@global(512)
{
	.var4 = addr_start;
	.var20 = "0x%08x %.08x\n";

	while(.var4<$addr_end) {
		.var0 = *.var4;
		printf(.var20, .var4, .var0);
		.var4 += 4;
	}
	0;
}
