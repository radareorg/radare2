OBJ_ZIP=io_zip.o

STATIC_OBJ+=${OBJ_ZIP}
TARGET_ZIP=io_zip.${EXT_SO}
ALL_TARGETS+=${TARGET_ZIP}

CFLAGS+=-I../../shlr/zip/include 

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../lib -lr_lib 
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif

${TARGET_ZIP}: ${OBJ_ZIP}
	${CC_LIB} $(call libname,io_zip) ${CFLAGS} -o ${TARGET_ZIP} ${OBJS} ${LINKFLAGS}
# ${LDFLAGS}
