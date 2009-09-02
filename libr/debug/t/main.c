/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_util.h>
#include <r_debug.h>
#include <r_io.h>

int main(int argc, char **argv)
{
	int ret;
	int tid, pid;
	struct r_io_t *io;
	struct r_dbg_t *dbg;

	io = r_io_new();
	printf("Supported IO pluggins:\n");
	r_io_handle_list(io);

	ret = r_io_open(io, "dbg:///bin/ls", 0, 0);
	r_io_set_fd(io, ret);
	printf("r_io_open dbg:///bin/ls' = %s\n", r_str_bool(ret));
	if (!ret) {
		printf("Cannot open dbg:///bin/ls\n");
		goto beach;
	}

	{
		/* dump process memory */
		char buf[128];
		int ret = r_io_read_at(io, buf, 128);
		printf("%02x\n", buf[0]);
	}

	dbg = r_debug_new();
	printf("Supported debugger backends:\n");

	ret = r_debug_handle_set (dbg, "dbg_ptrace");
	printf("Using 'dbg_ptrace' = %s\n", r_str_bool(ret));
	
	tid = pid = r_io_system(io, "pid");
	r_debug_select(dbg, pid, tid);

	printf("--> regs pre step\n");
	r_io_system(io, "reg");

	printf("--> perform 2 steps (only 1 probably?)\n");
	r_debug_step(dbg, 2);

	printf("--> regs post step\n");
	r_io_system(io, "reg");

	printf("---\n");
	r_debug_continue (dbg);
	printf("---\n");

beach:
	r_io_free(io);
	r_debug_free(dbg);
	return 0;
}
