#include <r_util.h>

static void test(const char *str) {
	int i, argc;
	char **argv = r_str_argv (str, &argc);
	printf ("[%s]\n", str);
	for(i=0; i<argc; i++)
		printf (" - %s\n", argv[i]);
	r_str_argv_free (argv);
}

main () {
	test ("  hello world  ");
	test ("hello world");
	test ("hello   \"world\"");
	test ("'hello world'");
	test ("/bin/ls -l 'food is pure bar' \"barra cow is low\"");
	test ("'hello'   \"world\"");
}
