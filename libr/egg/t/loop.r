/* TODO: all bins must contain a jmp main */
/* entrypoint */
:jmp main

puts@global() {
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
	: mov eax, 1
	: push eax
	: int 0x80
}

main@global(128)
{
	.var0 = 3;
	.var4 = "counter";
	{
		puts(.var4);
		.var0 -= 1;
	} while(.var0);
	exit()
	/* comment */
	.var0 = 3;
	.var4 = "coconut";
	while(.var0) {
		puts(.var4);
		.var0 -= 1;
	}
	0;
}

