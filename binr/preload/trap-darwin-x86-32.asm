.os darwin
.arch x86
.bits 32

mov eax, $sys.getpid
add esp, -0x4
int 0x80
mov ebx, $sys.kill
xor eax, ebx
xor rbx, eax
xor eax, ebx
add esp, -0x8
int 0x80
