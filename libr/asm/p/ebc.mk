EBC_ROOT=$(LIBR)/asm/arch/ebc
OBJ_EBC=asm_ebc.o
OBJ_EBC+=$(EBC_ROOT)/ebc_disas.o
CFLAGS+=-I$(EBC_ROOT)

STATIC_OBJ+=${OBJ_EBC}
TARGET_EBC=asm_ebc.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_EBC}

${TARGET_EBC}: ${OBJ_EBC}
	${CC} ${LDFLAGS} ${CFLAGS} \
	-o ${TARGET_EBC} ${OBJ_EBC}
endif
