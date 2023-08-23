OBJ_DSC=io_dsc.o

STATIC_OBJ+=${OBJ_DSC}
TARGET_DSC=io_dsc.${EXT_SO}
ALL_TARGETS+=${TARGET_DSC}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_DSC}: ${OBJ_DSC}
	${CC_LIB} $(call libname,io_dsc) ${CFLAGS} -o ${TARGET_DSC} ${OBJ_DSC} ${LINKFLAGS}
