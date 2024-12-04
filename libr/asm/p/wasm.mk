OBJ_WASMPSEUDO+=$(LIBR)/arch/p/wasm/pseudo.o

TARGET_WASMPSEUDO=parse_wasm_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_WASMPSEUDO}

LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
LDFLAGS+=-L../../reg -lr_reg
LDFLAGS+=-L../../cons -lr_cons

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_WASMPSEUDO}
${TARGET_WASMPSEUDO}: ${OBJ_WASMPSEUDO}
	${CC} $(call libname,parse_wasm_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_WASMPSEUDO} ${OBJ_WASMPSEUDO}
endif
