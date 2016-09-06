OBJ_RSP=asm_rsp.o
RSP_ROOT=$(LIBR)/asm/arch/rsp
OBJ_RSP+=$(RSP_ROOT)/rsp_idec.o
CFLAGS+=-I$(RSP_ROOT)


STATIC_OBJ+=${OBJ_RSP}
TARGET_RSP=asm_rsp.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_RSP}

${TARGET_RSP}: ${OBJ_RSP}
	${CC} $(call libname,asm_rsp) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RSP} ${OBJ_RSP}
endif
