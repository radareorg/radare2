OBJ_PROPELLER=asm_propeller.o
CFLAGS+=-I$(LIBR)/asm/arch/propeller/

STATIC_OBJ+=${OBJ_PROPELLER}
TARGET_PROPELLER=asm_propeller.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_PROPELLER}

${TARGET_PROPELLER}: ${OBJ_PROPELLER}
	${CC} $(call libname,asm_propeller) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_PROPELLER} ${OBJ_PROPELLER}
endif
