OBJ_DALVIKPSEUDO+=parse_dalvik_pseudo.o

TARGET_DALVIKPSEUDO=parse_dalvik_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_DALVIKPSEUDO}
STATIC_OBJ+=${OBJ_DALVIKPSEUDO}

${TARGET_DALVIKPSEUDO}: ${OBJ_DALVIKPSEUDO}
	${CC} $(call libname,parse_dalvik_pseudo) -L../../util -lr_util -shared ${CFLAGS} -o ${TARGET_DALVIKPSEUDO} ${OBJ_DALVIKPSEUDO}
