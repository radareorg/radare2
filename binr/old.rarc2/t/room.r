# example using static stackframe area

test1(1,32) {
	puts("Hello World");
}

test2(20) {
	.var0 = "Hello World";
	puts(.var0);
}

test3(20,32) {
	.var0 = "ByebyeWorld";
	puts("Hello World");
	puts(.var0);
}

test4(32,32) {
	printf("Hello %s %d\n", "World", $33);
}

main@global(,32) {
	test1();
	test2();
	test3();
	test4();
	printf("That's awesome!\n");
}
