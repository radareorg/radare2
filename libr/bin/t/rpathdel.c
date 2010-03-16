/* rpathdel.c - rooted 2010 - nibble<develsec.org> */

#include <stdio.h>
#include <r_bin.h>

int main(int argc, char **argv) {
	RBin *bin;
	char *input, *output;

	if (argc != 3) {
		fprintf (stderr, "Usage: %s <input file> <output file>\n", argv[0]);
		return 1;
	}
	input = argv[1];
	output = argv[2];

	bin = r_bin_new ();
	if (!r_bin_load (bin, input, NULL)) {
		fprintf (stderr, "Error: Cannot open file '%s'\n", input);
		return 1;
	}

	if (!r_bin_wr_rpath_del (bin)) {
		fprintf (stderr, "Error: Cannot remove rpath\n");
		return 1;
	}
	r_bin_wr_output (bin, output);

	r_bin_free (bin);

	return 0;
}
