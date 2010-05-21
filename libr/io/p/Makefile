CFLAGS=-I../../include -Wall -DWORDSIZE=64 ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}.. -DCORELIB

include ../../config.mk

foo: all

ALL_TARGETS=
DEBUGS=ptrace.mk debug.mk malloc.mk shm.mk mach.mk w32dbg.mk procpid.mk
include ${DEBUGS}

#ALL_TARGETS+=io_ewf.so

all: ${ALL_TARGETS}
	@true

BINDEPS=

io_ewf.${LIB_SO}: io_ewf.o
	${CC} ${CFLAGS} ${PIC_CFLAGS} ${LDFLAGS_LIB} io_ewf.${LIB_SO} ewf.c -lr_io -L../../io ${LDFLAGS_LINKPTH}.. -lewf

clean:
	-rm -f *.so *.o *.dll *.dylib *.${EXT_SO}
