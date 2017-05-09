OBJ_M68KPSEUDO+=parse_m68k_pseudo.o

TARGET_M68KPSEUDO=parse_m68k_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_M68KPSEUDO}
STATIC_OBJ+=${OBJ_M68KPSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
LIBDEPS+=$(STOP)/zip/librz.lib
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
LIBDEPS+=$(STOP)/zip/librz.a
endif

${TARGET_M68KPSEUDO}: ${OBJ_M68KPSEUDO}
	${CC} $(call libname,parse_m68k_pseudo) ${LIBDEPS} \
		${LDFLAGS_SHARED} ${CFLAGS} -o ${TARGET_M68KPSEUDO} ${OBJ_M68KPSEUDO}
