CFLAGS+=-Iptrace-wrap/include
PTRACEWRAP_OBJS=ptrace-wrap/src/ptrace_wrap.o
LINK+=$(PTRACEWRAP_OBJS)
