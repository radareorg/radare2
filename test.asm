#include "foo.asm"
_start:
mov rax, 10
jmp second
third:
add rax, 2
ret
second:
sub rax, 5
jmp third
