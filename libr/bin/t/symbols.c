#include <stdio.h>
#include <stdlib.h>

#include "r_types.h"
#include "r_bin.h"

int main(int argc, char *argv[])
{
	int ctr = 0;
	r_bin_obj bin;
	u64 baddr;
	r_bin_symbol *symbols, *symbolsp;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", argv[0]);
		return 1;
	}

	if (r_bin_init(&bin, argv[1], 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	baddr = r_bin_get_baddr(&bin);

	symbols = r_bin_get_symbols(&bin);

	printf("[Symbols]\n");

	symbolsp = symbols;
	while (!symbolsp->last) {
		printf("address=0x%08llx offset=0x%08llx ordinal=%03i forwarder=%s "
				"size=%08i bind=%s type=%s name=%s\n",
				baddr + symbolsp->rva, symbolsp->offset,
				symbolsp->ordinal, symbolsp->forwarder,
				symbolsp->size, symbolsp->bind, symbolsp->type, 
				symbolsp->name);
		symbolsp++; ctr++;
	}

	printf("\n%i symbols\n", ctr);

	r_bin_close(&bin);
	free(symbols);

	return 0;
}

