#include <stdio.h>
#include <r_pdb.h>

#include <string.h>

int main() {
	printf("main()\n");

	R_PDB pdb;
	strcpy(&pdb.file_name, "/root/wkernel32.pdb");
	if (init_pdb_parser(&pdb)) {
		pdb.pdb_parse(&pdb);
//		pdb.print_types(&pdb);
		pdb.print_gvars(&pdb, 0x40100);
		pdb.finish_pdb_parse(&pdb);
	}

	return 0;
}
