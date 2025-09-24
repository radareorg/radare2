OBJ_VAXPSEUDO+=$(LIBR)/arch/p/vax/pseudo.o

TARGET_VAXPSEUDO=parse_vax_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_VAXPSEUDO}
STATIC_OBJ+=${OBJ_VAXPSEUDO}

ifeq ($(CC),cccl)
VAX_CFLAGS:=${CFLAGS}
else
VAX_CFLAGS:=${CFLAGS} ${LINK}
endif

${TARGET_VAXPSEUDO}: ${OBJ_VAXPSEUDO}
	${CC} $(call libname,parse_vax_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${VAX_CFLAGS} -o ${TARGET_VAXPSEUDO} ${OBJ_VAXPSEUDO}

