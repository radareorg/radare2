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

// A special case of the older Glibc but the kernel newer than 2.5.46
// Sadly, there is no reliable and portable way to check the linux kernel
// version from headers, so we assume it's supported.
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && (__GLIBC__ <= 2) && (__GLIBC_MINOR__ <= 3)
#if !defined(PT_GETEVENTMSG) && !defined(PTRACE_GETEVENTMSG)
#define PTRACE_GETEVENTMSG 0x4201
#define PT_GETEVENTMSG PTRACE_GETEVENTMSG
#endif
#endif

#if !defined(PTRACE_EVENT_FORK) && !defined(PTRACE_EVENT_VFORK) && !defined(PTRACE_EVENT_CLONE) \
	&& !defined(PTRACE_EVENT_EXEC) && !defined(PTRACE_EVENT_VFORK_DONE) && !defined(PTRACE_EVENT_EXIT)

#define PTRACE_EVENT_FORK 1
#define PTRACE_EVENT_VFORK 2
#define PTRACE_EVENT_CLONE 3
#define PTRACE_EVENT_EXEC 4
#define PTRACE_EVENT_VFORK_DONE 5
#define PTRACE_EVENT_EXIT 6

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
