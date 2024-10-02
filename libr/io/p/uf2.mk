OBJ_UF2=io_uf2.o

STATIC_OBJ+=${OBJ_UF2}
TARGET_UF2=io_uf2.${EXT_SO}
ALL_TARGETS+=${TARGET_UF2}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_UF2}: ${OBJ_UF2}
	${CC_LIB} $(call libname,io_uf2) ${CFLAGS} -o ${TARGET_UF2} ${OBJ_UF2} ${LINKFLAGS}
