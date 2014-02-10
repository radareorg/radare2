.os linux
.arch x86
.bits 64

mov rax, $sys.getpid
syscall
mov rdi, $sys.kill
xchg rax, rdi
syscall
