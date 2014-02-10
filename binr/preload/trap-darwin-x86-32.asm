.os darwin
.arch x86
.bits 32

mov eax, $sys.getpid
sub esp, 4
int 0x80
mov ebx, $sys.kill
xchg eax, ebx
sub esp, 8
int 0x80
