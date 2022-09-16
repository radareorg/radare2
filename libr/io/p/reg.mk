OBJ_REG=io_reg.o

STATIC_OBJ+=${OBJ_REG}
TARGET_REG=io_reg.${EXT_SO}
ALL_TARGETS+=${TARGET_REG}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_REG}: ${OBJ_REG}
	${CC_LIB} $(call libname,io_reg) ${CFLAGS} -o ${TARGET_REG} ${OBJS} ${LINKFLAGS}
