OBJ_X86PSEUDO+=parse_x86_pseudo.o

TARGET_X86PSEUDO=parse_x86_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_X86PSEUDO}
STATIC_OBJ+=${OBJ_X86PSEUDO}

${TARGET_X86PSEUDO}: ${OBJ_X86PSEUDO}
	${CC} $(call libname,parse_x86_pseudo) -L../../util -lr_util -shared ${CFLAGS} -o ${TARGET_X86PSEUDO} ${OBJ_X86PSEUDO}
