/* hello world in r_egg */
write@syscall(4);
exit@syscall(1);

main@global(128) {
	.var0 = "hi!\n";
	write(1,.var0, 4);
	exit(0);
}
