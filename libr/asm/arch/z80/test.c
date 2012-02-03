
main() {
	int i;
	char buf[32], str[1024];
	for (i=0; i<255; i++) {
		buf[0] = i;
		Disassemble (buf, str);
		printf ("%s\n", str);
	}
}
