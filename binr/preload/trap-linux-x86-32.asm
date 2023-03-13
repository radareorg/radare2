.os linux
.arch x86
.bits 32

mov eax, $sys.getpid
int 0x80
mov ebx, $sys.kill
xor eax, ebx
xor ebx, eax
xor eax, ebx
int 0x80
