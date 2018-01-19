OBJ_EBC=anal_ebc.o
CFLAGS+=-I$(LIBR)/asm/arch/ebc/

STATIC_OBJ+=${OBJ_EBC}
TARGET_EBC=anal_ebc.${EXT_SO}

ifeq ($(WITHPIC),1)
OBJ_EBC+=$(LIBR)/asm/arch/ebc/ebc_disas.o
endif

ALL_TARGETS+=${TARGET_EBC}

${TARGET_EBC}: ${OBJ_EBC} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_ebc) ${CFLAGS} \
		-o ${TARGET_EBC} ${OBJ_EBC}
