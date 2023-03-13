.os linux
.arch x86
.bits 64

mov rax, $sys.getpid
syscall
mov rdi, $sys.kill
xor rax, rdi
xor rdi, rax
xor rax, rdi
syscall
