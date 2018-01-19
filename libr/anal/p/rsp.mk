OBJ_RSP=anal_rsp.o
CFLAGS+=-I$(LIBR)/asm/arch/rsp

STATIC_OBJ+=${OBJ_RSP}
TARGET_RSP=anal_rsp.${EXT_SO}

ifeq ($(WITHPIC),1)
OBJ_RSP+=../../asm/arch/rsp/rsp_idec.o
endif

ALL_TARGETS+=${TARGET_RSP}

${TARGET_RSP}: ${OBJ_RSP}
	${CC} $(call libname,anal_rsp) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RSP} ${OBJ_RSP}
