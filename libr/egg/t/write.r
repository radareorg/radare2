/* declare the write syscall and push a short string to it */

write@syscall(4);

main@global(128) {
	.var1 = "sup";
	write (1, .var1, 3);
}
