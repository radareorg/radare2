OBJ_SYSGDB=io_sysgdb.o

STATIC_OBJ+=${OBJ_SYSGDB}
TARGET_SYSGDB=io_sysgdb.${EXT_SO}
ALL_TARGETS+=${TARGET_SYSGDB}

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

${TARGET_SYSGDB}: ${OBJ_SYSGDB}
	${CC} $(call libname,io_sysgdb) ${OBJ_SYSGDB} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
