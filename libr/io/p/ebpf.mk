OBJ_EBPF=io_ebpf.o

STATIC_OBJ+=${OBJ_EBPF}
TARGET_EBPF=io_ebpf.${EXT_SO}
ALL_TARGETS+=${TARGET_EBPF}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_EBPF}: ${OBJ_EBPF}
	${CC_LIB} $(call libname,io_ebpf) ${CFLAGS} -o ${TARGET_EBPF} ${OBJ_EBPF} ${LINKFLAGS}
