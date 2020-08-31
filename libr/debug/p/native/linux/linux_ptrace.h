#ifndef LINUX_PTRACE_H
#define LINUX_PTRACE_H

// PTRACE_* constants are defined only since glibc 2.4 but appeared much
// earlier in linux kernel - since 2.3.99-pre6
// So we define it manually
// Originally these constants are defined in Linux include/uapi/linux/ptrace.h
//
#if __linux__ && defined(__GLIBC__)

#if !defined(PTRACE_SETOPTIONS) && !defined(PTRACE_GETSIGINFO) && !defined(PTRACE_SETSIGINFO)
#define PTRACE_SETOPTIONS 0x4200
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SETSIGINFO 0x4203
#endif

#if !defined(PTRACE_O_TRACEFORK) && !defined(PTRACE_O_TRACEVFORK) && !defined(PTRACE_O_TRACECLONE) \
	&& !defined(PTRACE_O_TRACEEXEC) && !defined(PTRACE_O_TRACEVFORKDONE) && !defined(PTRACE_O_TRACEEXIT)

#define PTRACE_O_TRACESYSGOOD 1
#define PTRACE_O_TRACEFORK (1 << 1)
#define PTRACE_O_TRACEVFORK (1 << 2)
#define PTRACE_O_TRACECLONE (1 << 3)
#define PTRACE_O_TRACEEXEC (1 << 4)
#define PTRACE_O_TRACEVFORKDONE (1 << 5)
#define PTRACE_O_TRACEEXIT (1 << 6)

#endif

#endif

#endif
