CFLAGS=-I../../include -Wall -DWORDSIZE=64 -fPIC -shared -Wl,-R.. -DCORELIB

include ../../config.mk

foo: all

ALL_TARGETS=
DEBUGS=ptrace.mk debug.mk malloc.mk shm.mk
include ${DEBUGS}

#ALL_TARGETS+=io_ewf.so

all: ${ALL_TARGETS}
	@true

BINDEPS=

io_ewf.so: io_ewf.o
	${CC} ${CFLAGS} -fPIC -shared -o io_ewf.so ewf.c -lr_io -L../../io -Wl,-R.. -lewf

clean:
	-rm -f *.so *.o
