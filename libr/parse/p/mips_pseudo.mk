OBJ_MIPSPSEUDO+=parse_mips_pseudo.o

TARGET_MIPSPSEUDO=parse_mips_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_MIPSPSEUDO}
STATIC_OBJ+=${OBJ_MIPSPSEUDO}

${TARGET_MIPSPSEUDO}: ${OBJ_MIPSPSEUDO}
	${CC} $(call libname,parse_mips_pseudo) -L../../util -lr_util -shared ${CFLAGS} -o ${TARGET_MIPSPSEUDO} ${OBJ_MIPSPSEUDO}
