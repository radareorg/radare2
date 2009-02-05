#include <stdio.h>

#include "r_types.h"
#include "r_bin_elf.h"

int main(int argc, char *argv[])
{
	Elf32_r_bin_elf_obj bin;

	if (argc != 4) {
		printf("Usage: %s <ELF32 file> <section> <size>\n", argv[0]);
		return 1;
	}

	if (Elf32_r_bin_elf_open(&bin, argv[1], 1) == -1) {
		fprintf(stderr, "cannot open file\n");
		return 1;
	}

	Elf32_r_bin_elf_resize_section(&bin, argv[2], atoi(argv[3]));

	Elf32_r_bin_elf_close(&bin);

	return 0;
}

