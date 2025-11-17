#include <stdio.h>
#include <r_util/r_json.h>
#include <stdlib.h>

int main(void) {
	const char *s = "[{\"cnum\":0,\"data\":1094861636},{\"cnum\":1,\"data\":3735928559}]";
	char *dup = strdup (s);
	RJson *j = r_json_parse (dup);
	if (!j) {
		printf ("parse failed\n");
		return 1;
	}
	printf ("parse ok, type=%d\n", j->type);
	r_json_free (j);
	free (dup);
	return 0;
}
