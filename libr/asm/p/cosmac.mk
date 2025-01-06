OBJ_COSMACPSEUDO+=$(LIBR)/arch/p/cosmac/pseudo.o

TARGET_COSMACPSEUDO=parse_cosmac_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_COSMACPSEUDO}
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_COSMACPSEUDO}
${TARGET_COSMACPSEUDO}: ${OBJ_COSMACPSEUDO}
	${CC} $(call libname,parse_cosmac_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_COSMACPSEUDO} ${OBJ_COSMACPSEUDO}
endif
