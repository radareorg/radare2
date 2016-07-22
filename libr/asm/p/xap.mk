OBJ_XAP=asm_xap.o
#OBJ_XAP+=../arch/xap/dis.o

STATIC_OBJ+=${OBJ_XAP}
TARGET_XAP=asm_xap.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_XAP}

${TARGET_XAP}: ${OBJ_XAP}
	${CC} $(call libname,asm_xap) ${LDFLAGS} ${CFLAGS} -o asm_xap.${EXT_SO} ${OBJ_XAP}
endif
