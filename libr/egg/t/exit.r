/* inline asm only: invoke exit() via raw Linux i386 syscall
 * any line starting with ":" is copied verbatim into the
 * assembler stream, no high-level translation happens. */

main@global(128) {
	: nop
	: mov eax, 1
	: push eax
	: int 0x80
}
