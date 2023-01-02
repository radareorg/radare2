OBJ_XAP=p/xap/plugin.o

STATIC_OBJ+=${OBJ_XAP}
TARGET_XAP=arch_xap.${EXT_SO}

ALL_TARGETS+=${TARGET_XAP}

${TARGET_XAP}: ${OBJ_XAP}
	${CC} $(call libname,arch_xap) ${CFLAGS} -o arch_xap.${EXT_SO} ${OBJ_XAP}
