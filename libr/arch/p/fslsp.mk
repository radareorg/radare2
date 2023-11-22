OBJ_FSLSP=p/fslsp/plugin.o

STATIC_OBJ+=${OBJ_FSLSP}
TARGET_FSLSP=arch_fslsp.${EXT_SO}

ALL_TARGETS+=${TARGET_FSLSP}

${TARGET_FSLSP}: ${OBJ_FSLSP}
	${CC} $(call libname,arch_fslsp) ${CFLAGS} -o arch_fslsp.${EXT_SO} ${OBJ_FSLSP}
