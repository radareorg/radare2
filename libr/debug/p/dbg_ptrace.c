/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>
#include <r_lib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>


static int r_debug_ptrace_step(int pid)
{
	//u32 addr = 0; /* should be eip */
	//u32 data = 0;
	printf("NATIVE STEP over PID=%d\n", pid);
	ptrace(PTRACE_SINGLESTEP, pid, 0, 0); //addr, data);
	perror("ptrace-singlestep");
	return R_TRUE;
}

static int r_debug_ptrace_attach(int pid)
{
	u32 addr;
	u32 data;
	int ret = ptrace(PTRACE_ATTACH, pid, addr, data);
	return (ret != -1)?R_TRUE:R_FALSE;
}

static int r_debug_ptrace_detach(int pid)
{
	u32 addr;
	u32 data;
	return ptrace(PTRACE_DETACH, pid, addr, data);
}

static int r_debug_ptrace_continue(int pid)
{
	u32 addr;
	u32 data;
	return ptrace(PTRACE_CONT, pid, addr, data);
}

static int r_debug_ptrace_wait(int pid)
{
	int ret, status = -1;
	printf("prewait\n");
	ret = waitpid(pid, &status, 0);
	printf("status=%d (return=%d)\n", status, ret);
	return status;
}

static int r_debug_ptrace_bp_write(int pid, u64 addr, int hw, int type)
{
	return R_TRUE;
}

static int r_debug_ptrace_bp_read(int pid, u64 addr, int hw, int type)
{
	return R_TRUE;
}

#if 0
static int r_debug_ptrace_import(struct r_debug_handle_t *from)
{
	//int pid = from->export(R_DEBUG_GET_PID);
	//int maps = from->export(R_DEBUG_GET_MAPS);
	return R_FALSE;
}
#endif

static struct r_debug_handle_t r_dbg_plugin_ptrace = {
	.name = "ptrace",
	.step = &r_debug_ptrace_step,
	.cont = &r_debug_ptrace_continue,
	.attach = &r_debug_ptrace_attach,
	.detach = &r_debug_ptrace_detach,
	.wait = &r_debug_ptrace_wait,
	.bp_write = &r_debug_ptrace_bp_write,
	//.bp_read = &r_debug_ptrace_bp_read,
//	.import = &r_debug_ptrace_import,
//	.export = &r_debug_ptrace_export,
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_dbg_plugin_ptrace
};

#if 0
int r_debug_ptrace_init(struct r_debug_t *dbg)
{
	dbg->step = r_debug_ptrace_step;
	dbg->cont = r_debug_ptrace_continue;
	dbg->attach = r_debug_ptrace_attach;
	dbg->detach = r_debug_ptrace_detach;
	return R_TRUE;
}
#endif
