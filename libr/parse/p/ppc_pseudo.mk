OBJ_PPCPSEUDO+=parse_ppc_pseudo.o

TARGET_PPCPSEUDO=parse_ppc_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_PPCPSEUDO}
STATIC_OBJ+=${OBJ_PPCPSEUDO}

${TARGET_PPCPSEUDO}: ${OBJ_PPCPSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_ppc_pseudo) -L../../util -llibr_util \
		${LDFLAGS_SHARED} ${CFLAGS} ${LDFLAGS} -o ${TARGET_PPCPSEUDO} ${OBJ_PPCPSEUDO}
else
	${CC} $(call libname,parse_ppc_pseudo) -L../../util -lr_util \
		${LDFLAGS_SHARED} ${CFLAGS} ${LDFLAGS} -o ${TARGET_PPCPSEUDO} ${OBJ_PPCPSEUDO}
endif
