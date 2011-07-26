#include <r_egg.h>

int main() {
	int i;
	RBuffer *b;
	REgg *egg = r_egg_new ();
	r_egg_include (egg, "test.r", 0);
	r_egg_compile (egg);

	printf ("src (%s)\n", r_egg_get_source (egg));
	printf ("asm (%s)\n", r_egg_get_assembly (egg));
	b = r_egg_get_bin (egg);

	printf ("BUFFER : %d\n", b->length);
	for (i=0;i<b->length;i++) {
		printf ("%02x", b->buf[i]);
	}
	printf ("\n");
#if VALA
	var egg = new REgg ();
	egg.include ("test.r", 'r');
	egg.compile ();
#endif

	r_egg_syscall (egg, "close", 0);
	r_egg_free (egg);
	return 0;
}
