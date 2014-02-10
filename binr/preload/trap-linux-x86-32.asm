.os linux
.arch x86
.bits 32

mov eax, $sys.getpid
int 0x80
mov ebx, $sys.kill
xchg eax, ebx
int 0x80
