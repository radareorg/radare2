// SPDX-License-Identifier: MIT
// Standalone tester: reads symbols from argv or stdin, prints demangled form.
// Not part of the radare2 build.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cxx2.h"

int main(int argc, char **argv) {
	if (argc > 1) {
		int i;
		for (i = 1; i < argc; i++) {
			char *s = r_demangle_cxx2 (argv[i]);
			printf ("%s\n", s ? s : argv[i]);
			free (s);
		}
		return 0;
	}
	char line[1 << 16];
	while (fgets (line, sizeof (line), stdin)) {
		size_t n = strlen (line);
		while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
			line[--n] = 0;
		}
		char *s = r_demangle_cxx2 (line);
		printf ("%s\n", s ? s : line);
		free (s);
	}
	return 0;
}
