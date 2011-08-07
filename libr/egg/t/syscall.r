# sys.r
#
# This file describes syscall accessing rules for syscalls on Linux
#

write@inline()
{
	: mov edx, `.arg2`
	: mov ecx, `.arg1`
	: mov ebx, `.arg0`
	: mov eax, 4
	: int 0x80
}

exit@inline()
{
	: mov ebx, `.arg0`
	: mov eax, 1
	: int 0x80
}

: .data
: str:
: .string "ftw\n"
: .text

strlen@alias(0);
/*
strlen@inline() {
	# nothing
}
*/

main@global(128)
{
	.var0 = 4;
	#.var0 = strlen($str);
	write($1, $str, .var0);
	exit($0);
}
