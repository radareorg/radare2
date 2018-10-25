OBJ_LM32=asm_lm32.o

STATIC_OBJ+=${OBJ_LM32}
TARGET_LM32=asm_lm32.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_LM32}

${TARGET_LM32}: ${OBJ_LM32}
	${CC} $(call libname,asm_LM32) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_LM32} ${OBJ_LM32}
endif
