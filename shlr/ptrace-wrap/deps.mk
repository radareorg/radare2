CFLAGS+=-I$(STOP)/ptrace-wrap/include
LINK+=$(STOP)/ptrace-wrap/libptrace_wrap.$(EXT_AR)
PTRACEWRAP_OBJS=$(STOP)/ptrace-wrap/src/ptrace_wrap.o
