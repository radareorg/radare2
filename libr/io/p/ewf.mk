OBJ_EWF=io_ewf.o

STATIC_OBJ+=${OBJ_EWF}
TARGET_EWF=io_ewf.${EXT_SO}
ALL_TARGETS+=${TARGET_EWF}

ifeq (${HAVE_LIB_EWF},1)
CFLAGS+=${EWF_CFLAGS}
LDFLAGS+=${EWF_LDFLAGS}
endif
#/opt/local/include

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_EWF}: ${OBJ_EWF}
	${CC_LIB} $(call libname,io_ewf) ${CFLAGS} -o ${TARGET_EWF} ${OBJ_EWF} ${LINKFLAGS}
