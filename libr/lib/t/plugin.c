#include <r_lib.h>

int mystuff = 31337;

struct r_lib_struct_t radare_plugin = {
	.type = 1,
	.data = &mystuff
};
