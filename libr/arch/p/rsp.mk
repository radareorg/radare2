OBJ_RSP=p/rsp/plugin.o
CFLAGS+=-Iarch

STATIC_OBJ+=${OBJ_RSP}
OBJ_RSP+=p/rsp/rsp_idec.o
TARGET_RSP=arch_rsp.${EXT_SO}

ALL_TARGETS+=${TARGET_RSP}

${TARGET_RSP}: ${OBJ_RSP}
	${CC} $(call libname,arch_rsp) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RSP} ${OBJ_RSP}
