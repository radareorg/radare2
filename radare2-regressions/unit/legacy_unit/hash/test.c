#include <r_hash.h>

void printmd5(const char *str, RHash *h) {
	int i;
	printf ("(%d) %s: ", h->rst, str);
	for (i=0; i<R_HASH_SIZE_MD5; i++) {
		printf ("%02x", h->digest[i]);
	}
	printf ("\n");
}

main () {
	int HASH = R_HASH_MD5;
	RHash *h = r_hash_new (1, HASH);

	r_hash_do_begin (h, HASH);

	r_hash_do_md5 (h, "hello", 5);
	printmd5("hello", h);
	r_hash_do_md5 (h, "world", 5);
	printmd5("world", h);

	r_hash_do_end (h, HASH);
	printmd5("FINISH", h);

	r_hash_do_md5 (h, "helloworld", 10);
	printmd5("helloworld", h);
}
