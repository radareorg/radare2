#if 0
r_anal_vm
=========

call0_enter
	push ebp
	mov ebp, esp
call0_exit
	
call0_signature:
	stack

r32=eax,ebx,ecx,edx,esp,ebp,esi,edi
byte.0x6a=
byte.0xc9=leave

regs:
	rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi
	
opcode
	0x6a, BYTE ; esp+=4;[esp-4]32=$0 # = push byte
	0x50:rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi push
	0x58:rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi pop
	0xc9 = leave
	0xb8:$regs$u32 # mov $0, $1

stack
	keep backtrace

stackframes

#endif
