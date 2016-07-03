OBJ_RSP=anal_rsp.o
#RSP_ROOT=$(LIBR)/asm/arch/rsp
CFLAGS+=-I../asm/arch/rsp

STATIC_OBJ+=${OBJ_RSP}
OBJ_RSP+=../../asm/arch/rsp/rsp_idec.o
TARGET_RSP=anal_rsp.${EXT_SO}

ALL_TARGETS+=${TARGET_RSP}

${TARGET_RSP}: ${OBJ_RSP}
	${CC} $(call libname,anal_rsp) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RSP} ${OBJ_RSP}
