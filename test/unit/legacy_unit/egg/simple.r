#!/usr/bin/ragg2 -X
main();

// OSX syscall definitions
write@syscall(4);
exit@syscall(1);
@syscall() {
	: mov eax, `.arg`
	: push eax
	: int 0x80
}

// code

main@global(128, 128) {
	.var0 = 0;
	.var1 = 4;
	.var2 = 8;

	// prolematic sizes: 1 2 5 6 9
	write (1, "hello.\n", 7);
	write (1, "hello world\n", 12);
	.ret = 3;
	exit(0);

	// line comment
	if (.var0 == 0) {
		goto(PENE);
		break();
		break;
	}
	:PENE:
}
