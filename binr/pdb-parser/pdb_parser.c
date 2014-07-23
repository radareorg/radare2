#include <stdio.h>
#include <r_pdb.h>

int main() {
	printf("main()\n");

	R_PDB pdb = 0;
	init_pdb_parser(&pdb);

	return 0;
}
