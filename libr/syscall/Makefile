NAME=r_syscall
DEPS=r_util r_db
#OBJ=syscall.o freebsd.o netbsd.o linux.o darwin.o win7.o ioports.o openbsd.o

OBJ=syscall.o ioports.o
CFLAGS+=-DLIL_ENDIAN=1 -D__UNIX__ -Wall -g

EXTRA_CLEAN=doclean
EXTRA_TARGETS+=do

include ../rules.mk

.PHONY: do

do:
	@cd d ; ${MAKE}

doclean:
	@cd d ; ${MAKE} clean
