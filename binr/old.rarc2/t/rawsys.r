#
# syscall implementation example
#

goto(main);

# 32 bits
write@syscall(4);
exit@syscall(1);
@syscall() {
	: movl $`.arg`, %eax
	: int $0x80
}

main@global(64,64)
{
	# raw syscall access for fun
	write($1, "Hello World\n", $12);
	exit($0);
}
