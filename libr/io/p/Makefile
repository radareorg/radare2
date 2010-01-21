CFLAGS=-I../../include -Wall -DWORDSIZE=64 ${PIC_CFLAGS} -shared -Wl,-R.. -DCORELIB

include ../../config.mk

foo: all

ALL_TARGETS=
DEBUGS=ptrace.mk debug.mk malloc.mk shm.mk
include ${DEBUGS}

#ALL_TARGETS+=io_ewf.so

all: ${ALL_TARGETS}
	@true

BINDEPS=

io_ewf.${LIB_SO}: io_ewf.o
	${CC} ${CFLAGS} ${PIC_CFLAGS}˘-shared -o io_ewf.${LIB_SO} ewf.c -lr_io -L../../io -Wl,-R.. -lewf

clean:
	-rm -f *.so *.o
