#include <stdio.h>
#include <r_regex.h>

int _main() {
	RRegex rx;
	int rc = r_regex_comp (&rx, "^hi", R_REGEX_NOSUB);	
	if (rc) {
		printf ("error\n");

	} else {
		rc = r_regex_exec (&rx, "patata", 0, 0, 0);
		printf ("out = %d\n", rc);

		rc = r_regex_exec (&rx, "hillow", 0, 0, 0);
		printf ("out = %d\n", rc);
	}
	r_regex_free (&rx);
	return 0;
}

static void test_or() {
	RRegex *rx = r_regex_new ("(eax|ebx)", "e");
	printf ("result (%s) = %d\n", "mov eax", r_regex_match("(eax|ebx)", "e", "mov eax"));
	printf ("result (%s) = %d\n", "mov ebx", r_regex_match("(eax|ebx)", "e", "mov ebx"));
	printf ("result (%s) = %d\n", "mov eax", r_regex_match("(eax|ebx)", "e", "mov ecx"));
	printf ("result (%s) = %d\n", "mov ebx", r_regex_match("(eax|ecx)", "e", "mov ebx"));
	printf ("result (%s) = %d\n", "mov eax", r_regex_check(rx, "mov eax"));
	printf ("result (%s) = %d\n", "mov ebx", r_regex_check(rx, "mov ebx"));
	printf ("result (%s) = %d\n", "mov eax", r_regex_exec(rx, "mov eax", 0, 0, 1));
	printf ("result (%s) = %d\n", "mov ebx", r_regex_exec(rx, "mov ebx", 0, 0, 1));
	r_regex_free (rx);
}

int main(int argc, char **argv) {
	const char *needle = "^hi";
	const char *haystack_1 = "patata";
	const char *haystack_2 = "hillow";
	if (argc>3) {
		needle = argv[1];
		haystack_1 = argv[2];
		haystack_2 = argv[3];
	} else printf ("Using default values\n");
	RRegex *rx = r_regex_new (needle, "");
	if (rx) {
		int res = r_regex_exec (rx, haystack_1, 0, 0, 0);
		printf ("result (%s) = %d\n", haystack_1, res);
		res = r_regex_exec (rx, haystack_2, 0, 0, 0);
		printf ("result (%s) = %d\n", haystack_2, res);
		r_regex_free (rx);
	} else printf ("oops, cannot compile regexp\n");
	test_or();
	return 0;
}
