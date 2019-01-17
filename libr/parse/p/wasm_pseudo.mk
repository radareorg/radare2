OBJ_WASMPSEUDO+=parse_wasm_pseudo.o

TARGET_WASMPSEUDO=parse_wasm_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_WASMPSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_WASMPSEUDO}
${TARGET_WASMPSEUDO}: ${OBJ_WASMPSEUDO}
	${CC} $(call libname,parse_wasm_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_WASMPSEUDO} ${OBJ_WASMPSEUDO}
endif
