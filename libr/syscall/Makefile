NAME=r_syscall
DEPS=r_util
OBJ=syscall.o freebsd.o netbsd.o linux.o darwin.o win7.o ioports.o openbsd.o
CFLAGS+=-DLIL_ENDIAN=1 -D__UNIX__ -Wall -g

include ../rules.mk
