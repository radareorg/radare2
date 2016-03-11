/* hello world

 */

// oneliner

: nop

write@syscall(4);

main@global(128) {
	write(1, "Hello World\n", 12);
	exit(2);
}
