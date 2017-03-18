; e803000000c39090cc
.arch x86
.bits 32
.align 8

call test
ret
test:
int3
