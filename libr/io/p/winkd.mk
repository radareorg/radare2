OBJ_WINKD=io_winkd.o

STATIC_OBJ+=${OBJ_WINKD}
TARGET_WINKD=io_winkd.${EXT_SO}
ALL_TARGETS+=${TARGET_WINKD}

LIB_PATH=$(SHLR)/winkd
CFLAGS+=-I$(SHLR)/winkd
LDFLAGS+=$(SHLR)/winkd/libr_winkd.$(EXT_AR)

ifeq (${WITHPIC},0)
LINKFLAGS=../../util/libr_util.a
LINKFLAGS+= ../../util/libr_socket.a
LINKFLAGS+= ../../util/libr_hash.a
LINKFLAGS+=../../util/libr_crypto.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS=-L../../util -lr_util
LINKFLAGS+=-L../../socket -lr_socket
LINKFLAGS+=-L../../hash -lr_hash
LINKFLAGS+=-L../../crypto -lr_crypto
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_WINKD}: ${OBJ_WINKD}
	${CC} $(call libname,io_winkd) ${OBJ_WINKD} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
