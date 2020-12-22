#!/usr/bin/ragg2 -FO
goto(main);

exit@syscall(1);
write@syscall(4);
@syscall() {
        : mov eax, `.arg`
        : push eax
        : int 0x80
	// restore stack
	: add esp, 4
}

dowrite@() {
	write (1, .arg0, .arg4);
}

/* this call is failing as long as .arg access is wrong */
dowritefail@(128) {
	write (1, .arg0, .arg4);
}

main@global(128,128) {
//	dowrite ("foo\nbla\n", 8);
	dowritefail ("foo\nbla\n", 8);
	write (1, "hiz\n", 4);
	write (1, "Hello World\n", 12);
	write (1, "Hello rld\n", 10);
	exit (0);
}
