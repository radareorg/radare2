#include <r_bin.h>
#include <getopt.h>

///////////////////////////////////////////////////////////////////////////////
static void print_usage(void) {
	printf ("pdb_parser -f pdb_file [option]\n");
	printf (" -f, --pdb_file : set pdb file to parse\n");
	printf ("[option]:\n");
	printf (" -t, --print_types : print all types parsed in pdb file\n");
	printf (" -g, --print_globals : print all globals functions/variables parsed in pdb file\n");
}

///////////////////////////////////////////////////////////////////////////////
static const struct option long_options[] = {
	{ "pdb_file", required_argument, 0, 'f'},
	{ "print_types", no_argument, 0, 't'},
	{ "print_globals", required_argument, 0, 'g'},
	{ "help", no_argument, 0, 'h'},
	{NULL, 0, 0, 0}
};

int main(int argc, char **argv) {
	RBinPdb pdb;

	int option_index = 0;
	char *pdb_file = 0;

	while (1) {
		int c = getopt_long (argc, argv, ":f:tg:h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			pdb_file = optarg;
			strcpy (&pdb.file_name, optarg);
			if (!r_bin_pdb_parser (&pdb)) {
				R_LOG_ERROR ("Cannot initialize the pdb parser");
				return 0;
			}
			pdb.pdb_parse (&pdb);
			break;
		case 't':
			pdb.print_types (&pdb, 0);
			break;
		case 'g':
			pdb.print_gvars (&pdb, 0, 'r');
			break;
		default:
			print_usage ();
			return 0;
		}
	}

	return 0;
}
