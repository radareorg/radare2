#include <r_pdb.h>

int init_pdb_parser(R_PDB *pdb)
{
	if (!pdb) {
		printf("struct R_PDB is null\n");
		return 0;
	}

	printf("init_pdb_parser()\n");
	return 1;
}
