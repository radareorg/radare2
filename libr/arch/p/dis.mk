OBJ_DIS=p/dis/plugin.o

STATIC_OBJ+=$(OBJ_DIS)
TARGET_DIS=arch_dis.${EXT_SO}

ALL_TARGETS+=${TARGET_DIS}

${TARGET_DIS}: ${OBJ_DIS}
	${CC} ${CFLAGS} $(call libname,arch_dis) \
		-o arch_dis.${EXT_SO} ${OBJ_DIS}
