.org 0

push ebp

sopa:
#jeje

  mov ebp, esp
end_loop:
  sub esp, 192
 call sopa
jz end_loop

nop
mov eax,44
