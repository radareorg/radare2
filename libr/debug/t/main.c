#include <r_debug.h>

int main(int argc, char **argv)
{
	struct r_dbg_t *dbg = r_debug_new();
	//r_debug_bp_add(dbg, 0x8048018);
	r_debug_continue(dbg);
	return 0;
}
