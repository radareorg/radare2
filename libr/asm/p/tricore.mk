OBJ_TRICOREPSEUDO+=$(LIBR)/arch/p/tricore/pseudo.o

TARGET_TRICOREPSEUDO=parse_tricore_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_TRICOREPSEUDO}
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
LDFLAGS+=-L../../reg -lr_reg
LDFLAGS+=-L../../cons -lr_cons

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_TRICOREPSEUDO}
${TARGET_TRICOREPSEUDO}: ${OBJ_TRICOREPSEUDO}
	${CC} $(call libname,parse_tricore_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_TRICOREPSEUDO} ${OBJ_TRICOREPSEUDO}
endif
