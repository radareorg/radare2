OBJ_AMD29K=asm_amd29k.o
OBJ_AMD29K+=../arch/amd29k/amd29k.o
CFLAGS+=-I./arch/amd29k/

STATIC_OBJ+=${OBJ_AMD29K}
TARGET_AMD29K=asm_amd29k.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_AMD29K}

${TARGET_AMD29K}: ${OBJ_AMD29K}
	${CC} $(call libname,asm_amd29k) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_AMD29K} ${OBJ_AMD29K}
endif
