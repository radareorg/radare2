main@global(128) {
#//	printf ("Hello World\n");
	: nop
	: mov eax, 1
	: push eax
	: int 0x80
}
