OBJ_GDB=io_gdb.o

STATIC_OBJ+=${OBJ_GDB}
TARGET_GDB=io_gdb.${EXT_SO}
ALL_TARGETS+=${TARGET_GDB}

LIB_PATH=$(SHLR)/gdb/
CFLAGS+=-I$(SHLR)/gdb/include/
LDFLAGS+=$(SHLR)/gdb/lib/libgdbr.a

include $(LIBR)/socket/deps.mk

ifeq (${WITHPIC},0)
LINKFLAGS=../../socket/libr_socket.a
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS=-L../../socket -lr_socket
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif

${TARGET_GDB}: ${OBJ_GDB}
	${CC} $(call libname,io_gdb) ${OBJ_GDB} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
