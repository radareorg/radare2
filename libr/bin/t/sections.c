#include <stdio.h>
#include <stdlib.h>

#include "r_types.h"
#include "r_bin.h"


int main(int argc, char *argv[])
{
	int ctr = 0;
	r_bin_obj bin;
	u64 baddr;
	r_bin_section *sections, *sectionsp;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", argv[0]);
		return 1;
	}

	if (r_bin_init(&bin, argv[1], 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	baddr = r_bin_get_baddr(&bin);

	sections = r_bin_get_sections(&bin);

	printf("[Sections]\n");

	sectionsp = sections;
	while (!sectionsp->last) {
		printf("idx=%02i address=0x%08llx offset=0x%08llx size=%08lli privileges=%c%c%c%c name=%s\n",
				ctr, (u64) (baddr + sectionsp->rva),
				(u64) (sectionsp->offset), (u64) (sectionsp->size),
				R_BIN_SCN_SHAREABLE(sectionsp->characteristics)?'s':'-',
				R_BIN_SCN_READABLE(sectionsp->characteristics)?'r':'-',
				R_BIN_SCN_WRITABLE(sectionsp->characteristics)?'w':'-',
				R_BIN_SCN_EXECUTABLE(sectionsp->characteristics)?'x':'-',
				sectionsp->name);
		sectionsp++; ctr++;
	}

	printf("\n%i sections\n", ctr);

	r_bin_close(&bin);
	free(sections);

	return 0;
}

