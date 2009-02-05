#include <stdio.h>
#include <stdlib.h>

#include "r_types.h"
#include "r_bin.h"


int main(int argc, char *argv[])
{
	int ctr = 0;
	r_bin_obj bin;
	u64 baddr;
	r_bin_import *imports, *importsp;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", argv[0]);
		return 1;
	}

	if (r_bin_init(&bin, argv[1], 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	baddr = r_bin_get_baddr(&bin);

	imports = r_bin_get_imports(&bin);

	printf("[imports]\n");

	importsp = imports;
	while (!importsp->last) {
		printf("address=0x%08llx offset=0x%08llx ordinal=%03i hint=%03i "
				"bind=%s type=%s name=%s\n",
				baddr + importsp->rva, importsp->offset,
				importsp->ordinal, importsp->hint,  importsp->bind,
				importsp->type, importsp->name);
		importsp++; ctr++;
	}

	printf("\n%i imports\n", ctr);

	r_bin_close(&bin);
	free(imports);

	return 0;
}

