OBJ_WINEDBG=io_winedbg.o

STATIC_OBJ+=${OBJ_WINEDBG}
TARGET_WINEDBG=io_winedbg.${EXT_SO}
ALL_TARGETS+=${TARGET_WINEDBG}

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

${TARGET_WINEDBG}: ${OBJ_WINEDBG}
	${CC} $(call libname,io_winedbg) ${OBJ_WINEDBG} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
