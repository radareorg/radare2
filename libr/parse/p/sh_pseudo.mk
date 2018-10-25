OBJ_SHPSEUDO+=parse_sh_pseudo.o

TARGET_SHPSEUDO=parse_sh_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_SHPSEUDO}
STATIC_OBJ+=${OBJ_SHPSEUDO}

${TARGET_SHPSEUDO}: ${OBJ_SHPSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_sh_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_SHPSEUDO} ${OBJ_SHPSEUDO} $(LINK)
else
	${CC} $(call libname,parse_sh_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_SHPSEUDO} ${OBJ_SHPSEUDO} $(LINK)
endif
