#
# Hello World featuring libc call with quoted
#

msg@data(3){"Hello World"}
arg@data(){"Hello Argument"}
num@data(10){0}

AF_INET@alias(2);

#puts@alias(printf);

hello2(128)
{
	: movl $0x6c6c6548, -8(%ebp) /* hell */
	: movl $0x7453206f, -4(%ebp) /* o st */
	: movl $0x006b6361, -0(%ebp) /* ack  */
	: mov %ebp, %eax
	: sub $8, %eax
	: push %eax
	: call puts
	: add $4, %esp
}

hello_stack(128)
{
	.var0="Hello Stack";
	puts(.var0);
	#hello_arg(.var0);
}

hello_arg(32)
{
	puts(.arg0);
}

# Argument passing with 0 framesize is different
hello_arg0()
{
	puts(.arg0);
}

hello(32)
{
	.var0 = "Local hello";
	puts($msg);
# hello2 segfaults
#	hello2();
	hello_stack();
	puts(.var0);
	hello_arg($arg);
	puts(.var0);
	hello_arg0(.var0);
	hello_arg($msg);
	puts(.var0);
}

oops(32)
{
	.var0 = "AF_INET is %d\n";
	printf(.var0, $AF_INET);
}

main@global()
{
	oops();
	puts($msg);
	hello();
	0;
}
