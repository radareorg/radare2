/* TODO: all bins must contain a jmp main */
/* entrypoint */
//main();
goto(main);
//:jmp main


puts@global() {
	//write(1,.arg0);
	/* do nothing */
	: mov edx, 3
	/* : mov ecx, 0x10000002a */
	: mov ecx, `.arg0`
	: mov ebx, 1
	: mov eax, 4
	: push eax
	: int 0x80
	: pop eax
}

exit@global() {
	: mov ebx, `.arg0`
	: mov eax, 1
	: push eax
	: int 0x80
}

main@global(128) {
	.var0 = 3;
	.var4 = "counter";
	exit(0);
	{
		puts(.var4);
		.var0 -= 1;
	} while(.var0);

	/* comment */
	.var0 = 3;
	.var4 = "coconut";
	while(.var0) {
		puts(.var4);
		.var0 -= 1;
	}
	0;
}

