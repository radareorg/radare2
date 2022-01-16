OBJ_JDH8=asm_jdh8.o

STATIC_OBJ+=${OBJ_JDH8}
TARGET_JDH8=asm_jdh8.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_JDH8}

${TARGET_JDH8}: ${OBJ_JDH8}
	${CC} ${call libname,asm_jdh8} ${CFLAGS} $(LDFLAGS) -o ${TARGET_JDH8} ${OBJ_JDH8}
endif
