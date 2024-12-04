OBJ_PPCPSEUDO+=$(LIBR)/arch/p/ppc/pseudo.o

TARGET_PPCPSEUDO=asm_ppc.${EXT_SO}
ALL_TARGETS+=${TARGET_PPCPSEUDO}
STATIC_OBJ+=${OBJ_PPCPSEUDO}

${TARGET_PPCPSEUDO}: ${OBJ_PPCPSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,asm_ppc) -L../../util -llibr_util \
		${LDFLAGS_SHARED} ${CFLAGS} ${LDFLAGS} -o ${TARGET_PPCPSEUDO} ${OBJ_PPCPSEUDO}
else
	${CC} $(call libname,asm_ppc) -L../../util -lr_util \
		${LDFLAGS_SHARED} ${CFLAGS} ${LDFLAGS} -o ${TARGET_PPCPSEUDO} ${OBJ_PPCPSEUDO}
endif
