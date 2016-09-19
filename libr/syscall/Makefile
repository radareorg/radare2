include ../config.mk

NAME=r_syscall
DEPS=r_util

OBJS=syscall.o ioports.o
CFLAGS+=-D__UNIX__ -Wall

EXTRA_TARGETS+=do
EXTRA_CLEAN=doclean

include ../rules.mk

.PHONY: do doclean

do:
	${MAKE} -C d

doclean:
	${MAKE} -C d clean
