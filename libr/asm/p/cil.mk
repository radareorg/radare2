OBJ_CILPSEUDO+=$(LIBR)/arch/p/cil/pseudo.o

TARGET_CILPSEUDO=parse_cil_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_CILPSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_CILPSEUDO}
${TARGET_CILPSEUDO}: ${OBJ_CILPSEUDO}
	${CC} $(call libname,parse_cil_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_CILPSEUDO} ${OBJ_CILPSEUDO}
endif
