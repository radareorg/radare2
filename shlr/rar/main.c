#include "main.c"

int main(int argc, char **argv) {
	int i, bits;
	unsigned char buf[1024] = {0};
	Bitbuf b = {.out = buf, .bits = 0};

	bits = b.bits;
	printf ("assemble:\n");
	if (argc>1) {
		bits = rarvm_assemble (&b, argv[1]);
	} else  {
		//bits = rarvm_assemble (&b, "mov r2, #33");
		//bits = rarvm_assemble (&b, "add r4, r5");
		bits = rarvm_assemble (&b, "xor r2, r3");
		//      0 000 0 1 001 01 101111100000000000000000000000000000000
		//bitadd (&b, 1, 2);
		//bits = rarvm_assemble (&b, "mov r1, [r2+#3]");
	}

	for (i=0; i<bits; i++) {
		printf ("%d", bitget (&b, i)); //b.bits+i));
		//buf[b] & (1<<bit))?1:0);
	}
	printf ("\n");


	printf ("disassemble:\n");
	{
		char str[64];
		rarvm_disassemble (&b, str);
		printf ("disasm: %s\n", str);
	}
	printf ("\n-----\n");
#if 0
	bits = rarvm_assemble (buf, "    cmp     r0, #6765");
#endif
	printf ("%d = %02x %02x %02x %02x %02x %02x %02x .. %02x\n",
			bits, buf[0], buf[1], buf[2], buf[3],
			buf[4], buf[5], buf[6], buf[7]);
	printf ("--\n");
	for (i=0; i<bits; i++) {
		printf ("%d", bitget (&b, i));
	}
	printf ("\n--> ");

	bits=16;
	for (i=0; i<bits; i++) {
		printf ("%d", bitget (&b, i)); //b.bits+i));
		//buf[b] & (1<<bit))?1:0);
	}
	printf ("\n");
	return 0;
}
