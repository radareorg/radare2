OBJ_VAX=asm_vax.o
OBJ_VAX+=../arch/vax/vax-dis.o

STATIC_OBJ+=${OBJ_VAX}
TARGET_VAX=asm_vax.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_VAX}

${TARGET_VAX}: ${OBJ_VAX}
	${CC} $(call libname,asm_vax) ${LDFLAGS} \
		-I../arch/vax ${CFLAGS} -o asm_vax.${EXT_SO} ${OBJ_VAX}
endif
