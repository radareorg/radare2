# mcore

OBJ_MCORE=asm_mcore.o ../arch/mcore/mcore.o

STATIC_OBJ+=${OBJ_MCORE}
TARGET_MCORE=asm_mcore.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_MCORE}

${TARGET_MCORE}: ${OBJ_MCORE}
	${CC} -o ${TARGET_MCORE} ${OBJ_MCORE} \
		$(call libname,asm_mcore) ${LDFLAGS} ${CFLAGS} 
endif
