OBJ_XAP=anal_xap.o

STATIC_OBJ+=${OBJ_XAP}
TARGET_XAP=anal_xap.${EXT_SO}

ALL_TARGETS+=${TARGET_XAP}

${TARGET_XAP}: ${OBJ_XAP}
	${CC} $(call libname,anal_xap) ${CFLAGS} -o anal_xap.${EXT_SO} ${OBJ_XAP}
