CFLAGS+=-I../../include -Wall -DWORDSIZE=64 ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}.. -DCORELIB

include ../../config.mk

ifeq ($(WITHPIC),1)
# on solaris only
ifeq (${OSTYPE},solaris)
CFLAGS+=-lsocket
endif
# windows
ifeq (${OSTYPE},windows)
CFLAGS+=-lws2_32
endif

foo: all

ALL_TARGETS=
PLUGINS=ptrace.mk debug.mk gdb.mk malloc.mk shm.mk mach.mk w32dbg.mk procpid.mk windbg.mk bochs.mk qnx.mk r2k.mk null.mk
#zip.mk
#PLUGINS=ptrace.mk debug.mk gdb.mk malloc.mk mach.mk w32dbg.mk procpid.mk
include ${PLUGINS}

#ALL_TARGETS+=io_ewf.so

all: ${ALL_TARGETS}
	@true

BINDEPS=

io_ewf.${LIB_SO}: io_ewf.o
	${CC} ${CFLAGS} ${PIC_CFLAGS} ${LDFLAGS_LIB} io_ewf.${LIB_SO} ewf.c -lr_io -L../../io ${LDFLAGS_LINKPTH}.. -lewf

clean:
	-rm -f *.so *.o *.dll *.dylib *.${EXT_SO}

mrproper: clean
	-rm -f *.d

.PHONY: all clean foo mrproper
else
clean all:

.PHONY: all
endif
