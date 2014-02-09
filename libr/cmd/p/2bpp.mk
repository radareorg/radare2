OBJ_2BPP+=cmd_2bpp.o

STATIC_OBJ+=${OBJ_2BPP}
TARGET_2BPP=cmd_2bpp.${EXT_SO}

ALL_TARGETS+=${TARGET_2BPP}

${TARGET_2BPP}: ${OBJ_2BPP}
	${CC} $(call libname,cmd_2bpp) ${CFLAGS} -o ${TARGET_2BPP} ${OBJ_2BPP}
