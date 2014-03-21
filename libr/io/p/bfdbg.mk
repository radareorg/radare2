OBJ_BFDBG=io_bfdbg.o

STATIC_OBJ+=${OBJ_BFDBG}
TARGET_BFDBG=io_bfdbg.${EXT_SO}
ALL_TARGETS+=${TARGET_BFDBG}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../cons/libr_cons.a
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L../../cons -lr_cons
LINKFLAGS+=-L.. -L../../lib -lr_io 
endif

${TARGET_BFDBG}: ${OBJ_BFDBG}
	${CC_LIB} ../debug/p/bfvm.c $(call libname,io_bfdbg) ${CFLAGS} -o ${TARGET_BFDBG} ${OBJ_BFDBG} ${LINKFLAGS}
