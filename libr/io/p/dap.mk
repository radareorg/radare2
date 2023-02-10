#CFLAGS = -fPIC
#LDFLAGS = -shared

OBJ_DAP=io_dap.o

STATIC_OBJ+=${OBJ_DAP}
TARGET_DAP=io_dap.${EXT_SO}
ALL_TARGETS+=${TARGET_DAP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_DAP}: ${OBJ_DAP}
	${CC} $(call libname,io_dap) ${OBJ_DAP} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)