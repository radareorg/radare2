#include <stdio.h>
#include <r_pdb.h>

#include <string.h>
#include <getopt.h>

///////////////////////////////////////////////////////////////////////////////
static void print_usage() {
	printf("pdb_parser -f pdb_file [option]\n");
	printf("\t -f, --pdb_file : set pdb file to parse\n");
	printf("[option]:\n");
	printf("\t -t, --print_types : print all types parsed in pdb file\n");
	printf("\t -g, --print_globals : print all globals functions/variables parsed in pdb file\n");
}

///////////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv) {
	R_PDB pdb;

	static struct option long_options[] =
	{
		{"pdb_file", required_argument, 0, 'f'},
		{"print_types", no_argument, 0, 't'},
		{"print_globals", required_argument, 0, 'g'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	int option_index = 0;
	int c = 0;
	char *pdb_file = 0;

	while(1) {
		c = getopt_long (argc, argv, ":f:tg:h",
						 long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'f':
			pdb_file = optarg;
			strcpy (&pdb.file_name, optarg);
			if (!init_pdb_parser(&pdb)) {
				printf("initialization error of pdb parser\n");
				return 0;
			}
			pdb.pdb_parse(&pdb);
			break;
		case 't':
			pdb.print_types(&pdb, 0);
			break;
		case 'g':
			pdb.print_gvars(&pdb, 0, 'r'); //*(int *)optarg);
			break;
		default:
			print_usage();
			return 0;
		}
	}

	return 0;
}
