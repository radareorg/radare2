#include <r_util.h>
#include <r_debug.h>

int main(int argc, char **argv)
{
	int ret;
	struct r_io_t *io = r_io_new();
	struct r_dbg_t *dbg;

	dbg = r_debug_new();

	printf("Supported debugger backends:\n");
	r_debug_handle_list (dbg);

	ret = r_debug_handle_set (dbg, "dbg_ptrace");
	printf("Using 'dbg_ptrace' = %s\n", r_str_bool(ret));
	//r_debug_bp_add(dbg, 0x8048018);
	//r_debug_set_io
	ret = r_debug_start (dbg, "/bin/ls");
	if (!ret) {
		printf("Cannot create process\n");
		goto beach;
	}

	r_debug_continue (dbg);

beach:
	return 0;
}
