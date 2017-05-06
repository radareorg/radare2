.arch x86
.bits 32
.include ../../files/rasm2/inc_test.asm

mov ebx, 0
int 0x80
ret
