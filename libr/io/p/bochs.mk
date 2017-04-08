OBJ_BOCHS=io_bochs.o

STATIC_OBJ+=${OBJ_BOCHS}
TARGET_BOCHS=io_bochs.${EXT_SO}
ALL_TARGETS+=${TARGET_BOCHS}

LIB_PATH=$(SHLR)/bochs/
CFLAGS+=-I$(SHLR)/bochs/include/
LDFLAGS+=$(SHLR)/bochs/lib/libbochs.$(EXT_AR)

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

${TARGET_BOCHS}: ${OBJ_BOCHS}
	${CC} $(call libname,io_bochs) ${OBJ_BOCHS} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
