#include <stdio.h>
#include <stdlib.h>

#include "r_types.h"
#include "r_bin.h"


int main(int argc, char *argv[])
{
	r_bin_obj bin;
	r_bin_info *info;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", argv[0]);
		return 1;
	}

	if (r_bin_init(&bin, argv[1], 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	info = r_bin_get_info(&bin);

	printf("[File info]\n");

	printf("Type: %s\n"
			"Class: %s\n"
			"Arch: %s\n"
			"Machine: %s\n"
			"OS: %s\n"
			"Subsystem: %s\n"
			"Big endian: %s\n"
			"Stripped: %s\n"
			"Static: %s\n"
			"Line_nums: %s\n"
			"Local_syms: %s\n"
			"Relocs: %s\n",
			info->type, info->class, info->arch, info->machine, info->os, 
			info->subsystem, info->big_endian?"True":"False",
			R_BIN_DBG_STRIPPED(info->dbg_info)?"True":"False",
			R_BIN_DBG_STATIC(info->dbg_info)?"True":"False",
			R_BIN_DBG_LINENUMS(info->dbg_info)?"True":"False",
			R_BIN_DBG_SYMS(info->dbg_info)?"True":"False",
			R_BIN_DBG_RELOCS(info->dbg_info)?"True":"False"
			);

	r_bin_close(&bin);
	free(info);

	return 0;
}

