CFLAGS+=-I../../include -Wall -DWORDSIZE=64 ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}.. -DR2_PLUGIN_INCORE

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

all: ${ALL_TARGETS}

ALL_TARGETS=
PLUGINS=ptrace.mk debug.mk gdb.mk malloc.mk shm.mk mach.mk w32dbg.mk procpid.mk windbg.mk bochs.mk qnx.mk r2k.mk ar.mk rbuf.mk gprobe.mk
#zip.mk
#PLUGINS=ptrace.mk debug.mk gdb.mk malloc.mk mach.mk w32dbg.mk procpid.mk
include ${PLUGINS}

#ALL_TARGETS+=io_ewf.so

BINDEPS=

io_ewf.${LIB_SO}: io_ewf.o
	${CC} ${CFLAGS} ${PIC_CFLAGS} ${LDFLAGS_LIB} io_ewf.${LIB_SO} ewf.c -lr_io -L../../io ${LDFLAGS_LINKPTH}.. -lewf

clean:
	-rm -f *.so *.o *.dll *.dylib *.${EXT_SO}

mrproper: clean
	-rm -f *.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
