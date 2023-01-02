/*  __
 -=(o '.
    \.-.\
    /|  \\
    '|  ||
     _\_):,_
*/

#ifndef LINUX_DEBUG_H
#define LINUX_DEBUG_H

#include <limits.h>
#include <sys/ptrace.h>

struct user_regs_struct_x86_64 {
  ut64 r15; ut64 r14; ut64 r13; ut64 r12; ut64 rbp; ut64 rbx; ut64 r11;
  ut64 r10; ut64 r9; ut64 r8; ut64 rax; ut64 rcx; ut64 rdx; ut64 rsi;
  ut64 rdi; ut64 orig_rax; ut64 rip; ut64 cs; ut64 eflags; ut64 rsp;
  ut64 ss; ut64 fs_base; ut64 gs_base; ut64 ds; ut64 es; ut64 fs; ut64 gs;
};

struct user_regs_struct_x86_32 {
  ut32 ebx; ut32 ecx; ut32 edx; ut32 esi; ut32 edi; ut32 ebp; ut32 eax;
  ut32 xds; ut32 xes; ut32 xfs; ut32 xgs; ut32 orig_eax; ut32 eip;
  ut32 xcs; ut32 eflags; ut32 esp; ut32 xss;
};

#if __ANDROID__

#if __arm64__ || __aarch64__
#define R_DEBUG_REG_T struct user_pt_regs

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#else
#define R_DEBUG_REG_T struct pt_regs
#endif

#else

#include <sys/user.h>
#if __i386__ || __x86_64__
#define R_DEBUG_REG_T struct user_regs_struct
#elif __s390x__ || __s390__
#define R_DEBUG_REG_T struct _user_regs_struct
#if 0
// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/s390/sys/user.h;hb=HEAD#l50
  50 struct _user_regs_struct
  51 {
  52   struct _user_psw_struct psw;          /* Program status word.  */
  53   unsigned long gprs[16];               /* General purpose registers.  */
  54   unsigned int  acrs[16];               /* Access registers.  */
  55   unsigned long orig_gpr2;              /* Original gpr2.  */
  56   struct _user_fpregs_struct fp_regs;   /* Floating point registers.  */
  57   struct _user_per_struct per_info;     /* Hardware tracing registers.  */
  58   unsigned long ieee_instruction_pointer;       /* Always 0.  */
  59 };
#endif
#elif __arm64__ || __aarch64__
#include <asm/ptrace.h>
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#define R_DEBUG_REG_T struct user_pt_regs
#elif __arm__
#define R_DEBUG_REG_T struct user_regs
#elif __POWERPC__
struct powerpc_regs_t {
	unsigned long gpr[32];
	unsigned long nip;
	unsigned long msr;
	unsigned long orig_gpr3;	/* Used for restarting system calls */
	unsigned long ctr;
	unsigned long link;
	unsigned long xer;
	unsigned long ccr;
#ifdef __powerpc64__
	unsigned long softe;		/* Soft enabled/disabled */
#else
	unsigned long mq;		/* 601 only (not used at present) */
					/* Used on APUS to hold IPL value. */
#endif
	unsigned long trap;		/* Reason for being here */
	/* N.B. for critical exceptions on 4xx, the dar and dsisr
	   fields are overloaded to hold srr0 and srr1. */
	unsigned long dar;		/* Fault registers */
	unsigned long dsisr;		/* on 4xx/Book-E used for ESR */
	unsigned long result;		/* Result of a system call */
};
#define R_DEBUG_REG_T struct powerpc_regs_t
#elif __riscv || __riscv__ || __riscv64__

#include <sys/ucontext.h>
#include <asm/ptrace.h>

// typedef ut64 riscv64_regs_t [65];
// #define R_DEBUG_REG_T riscv64_regs_t
#define R_DEBUG_REG_T struct user_regs_struct
// #define R_DEBUG_REG_T mcontext_t 77 784 in size (coz the fpu regs)

#elif __mips__

#include <sys/ucontext.h>
typedef ut64 mips64_regs_t [274];
#define R_DEBUG_REG_T mips64_regs_t

#elif __loongarch__

#include <sys/ucontext.h>
typedef ut64 la_regs_t [32];
#define R_DEBUG_REG_T la_regs_t
#endif
#endif

// SIGTRAP si_codes from <asm/siginfo.h>
#if !defined(TRAP_BRKPT) && !defined(TRAP_TRACE)
#define TRAP_BRKPT		1
#define TRAP_TRACE		2
#define TRAP_BRANCH		3
#define TRAP_HWBKPT		4
#define TRAP_UNK		5
#endif

//API
bool linux_set_options(RDebug *dbg, int pid);
int linux_step(RDebug *dbg);
RDebugReasonType linux_ptrace_event(RDebug *dbg, int pid, int status, bool dowait);
bool linux_attach(RDebug *dbg, int pid);
bool linux_attach_new_process(RDebug *dbg, int pid);
RDebugInfo *linux_info(RDebug *dbg, const char *arg);
RList *linux_pid_list(int pid, RList *list);
RList *linux_thread_list(RDebug *dbg, int pid, RList *list);
bool linux_select(RDebug *dbg, int pid, int tid);
RDebugPid *fill_pid_info(const char *info, const char *path, int tid);
bool linux_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
bool linux_reg_write(RDebug *dbg, int type, const ut8 *buf, int size);
RList *linux_desc_list(int pid);
bool linux_stop_threads(RDebug *dbg, int except);
int linux_handle_signals(RDebug *dbg, int tid);
int linux_dbg_wait(RDebug *dbg, int pid);
char *linux_reg_profile(RDebug *dbg);
int match_pid(const void *pid_o, const void *th_o);

#endif
