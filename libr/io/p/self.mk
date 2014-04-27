OBJ_SELF=io_self.o

STATIC_OBJ+=${OBJ_SELF}
TARGET_SELF=io_self.${EXT_SO}
ALL_TARGETS+=${TARGET_SELF}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_SELF}: ${OBJ_SELF}
	${CC_LIB} $(call libname,io_self) -o ${TARGET_SELF} \
		$(CFLAGS) ${OBJ_SELF} ${LINKFLAGS}
