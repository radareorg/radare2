OBJ_PIPE=io_pipe.o

STATIC_OBJ+=${OBJ_PIPE}
TARGET_PIPE=io_pipe.${EXT_SO}
ALL_TARGETS+=${TARGET_PIPE}

LIB_PATH=$(SHLR)/wind
CFLAGS+=-I$(SHLR)/wind
LDFLAGS+=$(SHLR)/wind/libr_wind.a

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_PIPE}: ${OBJ_PIPE}
	${CC} $(call libname,io_pipe) ${OBJ_PIPE} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
