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

int main() {
	RRegex *rx = r_regex_new ("^hi", "");
	if (rx) {
		int res = r_regex_exec (rx, "patata", 0, 0, 0);
		printf ("result (patata) = %d\n", res);
		res = r_regex_exec (rx, "hillow", 0, 0, 0);
		printf ("result (hillow) = %d\n", res);
		r_regex_free (rx);
	} else printf ("oops, cannot compile regexp\n");
	return 0;
}
