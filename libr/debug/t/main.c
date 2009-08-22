#include <r_util.h>
#include <r_debug.h>
#include <r_io.h>

int main(int argc, char **argv)
{
	int ret;
	struct r_io_t *io = r_io_new();
	struct r_dbg_t *dbg;

	io = r_io_new();
	printf("Supported IO pluggins:\n");
	r_io_handle_list(io);

	ret = r_io_open(io, "dbg:///bin/ls", 0, 0);
	printf("r_io_open dbg:///bin/ls' = %s\n", r_str_bool(ret));
	if (!ret) {
		printf("Cannot open dbg:///bin/ls\n");
		goto beach;
	}

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
	r_io_free(io);
	r_debug_free(dbg);
	return 0;
}
