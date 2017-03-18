; e801000000c3cc
.arch x86
.bits 32

call test
ret
test:
int3
