/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_util.h>
#include <r_debug.h>
#include <r_io.h>

int main(int argc, char **argv) {
	int ret, i;
	RIODesc *fd;
	int tid, pid;
	struct r_io_t *io;
	struct r_debug_t *dbg = NULL;

	io = r_io_new ();
	printf ("Supported IO pluggins:\n");
	r_io_plugin_list (io);

	fd = r_io_open_nomap (io, "dbg:///bin/ls", 0, 0);
	if (!fd) {
		printf("Cannot open dbg:///bin/ls\n");
		goto beach;
	}
//	r_io_set_fd(io, ret);
	printf ("r_io_open_nomap dbg:///bin/ls' = %d\n", io->fd->fd);

	{
		/* dump process memory */
		ut8 buf[128];
#if __arm__
		int ret = r_io_read_at(io, 0x8000, buf, 128);
#else
		int ret = r_io_read_at(io, 0x8048000, buf, 128);
#endif
		if (ret != 128)
			eprintf ("OOps cannot read 128 bytes\n");
		else
		for (i=0;i<128;i++) {
			printf ("%02x ", buf[i]);
			if (!((i+1)%16)) printf ("\n");
		}
	}

	dbg = r_debug_new (R_TRUE);
	printf("Supported debugger backends:\n");

	ret = r_debug_use (dbg, "native");
	printf ("Using native debugger = %s\n", r_str_bool(ret));
	
	tid = pid = r_io_system (io, "pid");
	eprintf (" My pid is : %d\n", pid);
	r_debug_select (dbg, pid, tid);

	//printf("--> regs pre step\n");
	//r_io_system(io, "reg");

	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, 0);
	r_debug_reg_list (dbg, R_REG_TYPE_GPR, 32, NULL);

	printf ("--> perform 2 steps (only 1 probably?)\n");
	r_debug_step (dbg, 2);

	r_debug_reg_sync(dbg, R_REG_TYPE_GPR, 0);
	r_debug_reg_list(dbg, R_REG_TYPE_GPR, 32, NULL);

	//printf("--> regs post step\n");
	//r_io_system(io, "reg");

	printf("---\n");
	r_debug_continue (dbg);
	printf("---\n");

beach:
	r_io_free (io);
	r_debug_free (dbg);
	return 0;
}
