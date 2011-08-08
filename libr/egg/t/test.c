/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>
#include <getopt.h>

static int usage () {
	eprintf ("./test [-a x86|arm] [-b 32|64] foo.r\n");
	return 1;
}

int main(int argc, char **argv) {
	const char *arch = "x86";
	int bits = 32;
	int c, i;
	RBuffer *b;
	REgg *egg = r_egg_new ();

        while ((c = getopt (argc, argv, "ha:b:")) != -1) {
                switch (c) {
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = atoi (optarg);
			break;
		case 'h':
			return usage ();
		}
	}

	if (optind == argc)
		return usage ();

	r_egg_setup (egg, arch, bits, 0, 0);
	r_egg_include (egg, argv[optind], 0);
	r_egg_compile (egg);
	r_egg_assemble (egg);
	//r_egg_setup (egg, "x86", 32, 0, 0);
	//r_egg_setup (egg, "x86", 64, 0, 0);

	//printf ("src (%s)\n", r_egg_get_source (egg));
	printf ("asm (%s)\n", r_egg_get_assembly (egg));
	b = r_egg_get_bin (egg);
	if (b == NULL) {
		eprintf ("Cannot assemble egg :(\n");
	} else {
		printf ("BUFFER : %d\n", b->length);
		for (i=0;i<b->length;i++) {
			printf ("%02x", b->buf[i]);
		}
		printf ("\n");
	}
#if VALA
	var egg = new REgg ();
	egg.include ("test.r", 'r');
	egg.compile ();
#endif
	r_egg_free (egg);
	return 0;
}
/*
	r_egg_syscall (egg, "close", 0);
r_egg_compile (egg);
*/
/*
	printf ("src (%s)\n", r_egg_get_source (egg));
	printf ("ass (%s)\n", r_egg_get_assembly (egg));
	b = r_egg_get_bin (egg);
	if (b == NULL) {
		eprintf ("Cannot assemble egg :(\n");
	} else {
		printf ("BUFFER : %d\n", b->length);
		for (i=0;i<b->length;i++) {
			printf ("%02x", b->buf[i]);
		}
		printf ("\n");
	}
*/
