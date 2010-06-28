addr_start@alias(0x8048000);
addr_end@alias(0x8048016);
# printf@alias(0xb7edd780); 

main@global(512)
{
	.var8 = addr_start;
	.var20 = "0x%08x 0x%02x xor 0x18 = 0x%02x\n";

	while(.var8<$addr_end) {
		.var0 = 0;
		.var4 = 0;
		.var0:1 = *.var8;
		.var4:1 = .var0;
		.var4:1 ^= 24;
		printf(.var20, .var8, .var0, .var4);
		# xor ciphah!
		.var8 += 1;
	}
	0;
}
