.global getsock
.code32

getsock:
	xorl %edx, %edx
	pushl %esp
	pushl %esp
	pushl %edx
	movl %esp, %ecx
	movl $6, %ebx

search_sock:
	movl $0x66, %eax
	inc %edx
	movl %edx, (%ecx)
#getsockname
	int $0x80
	test %eax, %eax
	jnz search_sock

sock_found:
	movl %edx, %ebx
