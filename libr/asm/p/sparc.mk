OBJ_SPARCPSEUDO+=$(LIBR)/arch/p/sparc/pseudo.o

TARGET_SPARCPSEUDO=parse_sparc_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_SPARCPSEUDO}
STATIC_OBJ+=${OBJ_SPARCPSEUDO}

${TARGET_SPARCPSEUDO}: ${OBJ_SPARCPSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_sparc_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_SPARCPSEUDO} ${OBJ_SPARCPSEUDO}
else
	${CC} $(call libname,parse_sparc_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_SPARCPSEUDO} ${OBJ_SPARCPSEUDO}
endif
