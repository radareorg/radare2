#include <stdio.h>
#include <stdlib.h>

#include "r_types.h"
#include "r_bin.h"


int main(int argc, char *argv[])
{
	r_bin_obj bin;
	u64 baddr;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", argv[0]);
		return 1;
	}

	if (r_bin_init(&bin, argv[1], 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	baddr = r_bin_get_baddr(&bin);
	printf("Base addr: 0x%08x\n", baddr);

	r_bin_close(&bin);

	return 0;
}

