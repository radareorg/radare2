OBJ_EVM=io_evm.o

STATIC_OBJ+=${OBJ_EVM}
TARGET_EVM=io_evm.${EXT_SO}
ALL_TARGETS+=${TARGET_EVM}

include $(LIBR)/socket/deps.mk

ifeq (${WITHPIC},0)
LINKFLAGS=../../socket/libr_socket.a
LINKFLAGS+=-lcurl -ljansson
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS=-L../../socket -lr_socket
LINKFLAGS+=-lcurl -ljansson
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif


${TARGET_EVM}: ${OBJ_EVM}
	${CC} $(call libname,io_evm) ${OBJ_EVM} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
