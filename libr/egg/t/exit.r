/* Inline assembly using the Linux i386 exit syscall. */

main@global(128) {
	: nop
	: mov eax, 1
	: xor ebx, ebx
	: int 0x80
}
