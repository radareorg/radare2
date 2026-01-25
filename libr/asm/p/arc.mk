OBJ_ARCPSEUDO+=$(LIBR)/arch/p/arc/pseudo.o

TARGET_ARCPSEUDO=parse_arc_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_ARCPSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_ARCPSEUDO}
${TARGET_ARCPSEUDO}: ${OBJ_ARCPSEUDO}
	${CC} $(call libname,parse_arc_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_ARCPSEUDO} ${OBJ_ARCPSEUDO}
endif
