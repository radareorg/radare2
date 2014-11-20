OBJ_WINDBG=io_windbg.o

STATIC_OBJ+=${OBJ_WINDBG}
TARGET_WINDBG=io_windbg.${EXT_SO}
ALL_TARGETS+=${TARGET_WINDBG}

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

${TARGET_WINDBG}: ${OBJ_WINDBG}
	${CC} $(call libname,io_windbg) ${OBJ_WINDBG} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
