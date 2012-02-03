OBJ_EWF=io_ewf.o

STATIC_OBJ+=${OBJ_EWF}
TARGET_EWF=io_ewf.${EXT_SO}
ALL_TARGETS+=${TARGET_EWF}

CFLAGS+=${EWF_CFLAGS}
LDFLAGS+=${EWF_LDFLAGS}
#/opt/local/include

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../lib -lr_lib
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif

${TARGET_EWF}: ${OBJ_EWF}
	${CC_LIB} $(call libname,io_ewf) ${CFLAGS} -o ${TARGET_EWF} ${OBJ_EWF} ${LINKFLAGS}
