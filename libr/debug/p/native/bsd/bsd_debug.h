#ifndef _BSD_DEBUG_H
#define _BSD_DEBUG_H
#include <r_debug.h>
#include <sys/ptrace.h>
#define R_DEBUG_REG_T struct reg
#define R_DEBUG_BSD_SYSCALL_STOP_NONE 0
#define R_DEBUG_BSD_SYSCALL_STOP_HIT 1
#define R_DEBUG_BSD_SYSCALL_STOP_CONT 2

int bsd_handle_signals(RDebug *dbg);
bool bsd_continue(RDebug *dbg, int pid, int sig, bool trace_syscalls);
bool bsd_continue_syscall(RDebug *dbg, int pid, int sig);
bool bsd_syscall_hooks_enabled(RDebug *dbg);
int bsd_handle_syscall_stop(RDebug *dbg, int pid);
bool bsd_reg_write(RDebug *dbg, int type, const ut8 *buf, int size);
RDebugInfo *bsd_info(RDebug *dbg, const char *arg);
RList *bsd_pid_list(RDebug *dbg, int pid, RList *list);
RList *bsd_native_sysctl_map(RDebug *dbg);
RList *bsd_desc_list(int pid);
RList *bsd_thread_list(RDebug *dbg, int pid, RList *list);
#endif
