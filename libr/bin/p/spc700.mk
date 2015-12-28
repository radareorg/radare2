OBJ_SPC700=bin_spc700.o
STATIC_OBJ+=${OBJ_SPC700}
TARGET_SPC700=bin_spc700.${EXT_SO}

include $(SHLR)/zip/deps.mk

ALL_TARGETS+=${TARGET_SPC700}

${TARGET_SPC700}: ${OBJ_SPC700}
	${CC} $(call libname,bin_spc700) -shared ${CFLAGS} \
		-o ${TARGET_SPC700} ${OBJ_SPC700} ${LDFLAGS} ${LINK}
