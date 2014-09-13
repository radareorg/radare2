#include <stdio.h>
#include <r_pdb.h>

#include <string.h>

int main() {
	printf("main()\n");

	R_PDB pdb;
	strcpy(&pdb.file_name, "/root/test.pdb");
	init_pdb_parser(&pdb);
	pdb.pdb_parse(&pdb);
	pdb.finish_pdb_parse(&pdb);

	return 0;
}
