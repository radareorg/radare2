# sys.r
#
# This file describes syscall accessing rules for syscalls on Linux
#

write@inline()
{
	: mov `.arg2`, %edx
	: mov `.arg1`, %ecx
	: mov `.arg0`, %ebx
	: mov $4, %eax
	: int $0x80
}

exit@inline()
{
	: mov `.arg0`, %ebx
	: mov $1, %eax
	: int $0x80
}

: .data
: str: .string "ftw\n"
: .text

main@global(128)
{
	#.var0 = 4;
	.var0 = strlen($str);
	write($1, $str, .var0);
	exit($0);
}
