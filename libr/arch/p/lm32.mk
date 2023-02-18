OBJ_LM32=anal_lm32.o

STATIC_OBJ+=${OBJ_LM32}
TARGET_LM32=anal_lm32.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_LM32}

${TARGET_LM32}: ${OBJ_LM32}
	${CC} $(call libname,anal_LM32) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_LM32} ${OBJ_LM32}
endif
