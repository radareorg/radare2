include ../config.mk

NAME=r_syscall
R2DEPS=r_util

OBJS=syscall.o ioports.o splugs.o
CFLAGS+=-D__UNIX__ -Wall

ifeq (${HAVE_GPERF},1)
OBJS+=d/darwin-arm-32.o
OBJS+=d/darwin-arm-64.o
OBJS+=d/darwin-x86-32.o
OBJS+=d/darwin-x86-64.o
OBJS+=d/dos-x86-16.o
OBJS+=d/freebsd-x86-32.o
OBJS+=d/ios-arm-32.o
OBJS+=d/ios-arm-64.o
OBJS+=d/ios-x86-32.o
OBJS+=d/linux-arm-32.o
OBJS+=d/linux-arm-64.o
OBJS+=d/linux-mips-32.o
OBJS+=d/linux-sparc-32.o
OBJS+=d/linux-x86-32.o
OBJS+=d/linux-x86-64.o
OBJS+=d/netbsd-x86-32.o
OBJS+=d/openbsd-x86-32.o
OBJS+=d/openbsd-x86-64.o
OBJS+=d/s110-arm-16.o
OBJS+=d/windows-x86-32.o
OBJS+=d/windows-x86-64.o
endif

EXTRA_TARGETS+=do
EXTRA_CLEAN=doclean

include ../rules.mk

.PHONY: do doclean

do:
	${MAKE} -C d

doclean:
	${MAKE} -C d clean
