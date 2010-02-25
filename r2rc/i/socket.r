# i/socket.r
AF_INET@alias(2);
AF_INET6@alias(10);
SOCK_STREAM@alias(1);
SOCK_DGRAM@alias(2);

close@inline()
{
	: mov `.arg2`, %edx
	: mov `.arg1`, %ecx
	: mov `.arg0`, %ebx
	: mov $3, %eax
}

read@inline()
{
}
