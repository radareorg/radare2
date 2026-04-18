/* override the syscall body with inline asm
 *
 * the `@syscall() { ... }` definition replaces the default
 * syscall prologue that the backend generates. In this example
 * every syscall traps into int3 instead of actually issuing one.
 */

exit@syscall(1);

@syscall() {
	: int3
}

main@global() {
	exit (2);
}
