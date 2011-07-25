# This is a rlang test for osx x86-32
# --pancake

main@global(128) {
# puts("Hello World");
	exit(42);
}

# XXX: this function without inline doesnt works
exit@global(4) {
	: mov eax, 1
	: push `.arg0`
	: sub esp, 4
	: int 0x80
}

/*
puts(4) {
	.var0 = strlen(.arg0);
	write(1, .arg0, .var0);
}
*/
