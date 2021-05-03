OBJ_S390=asm_s390_gnu.o
OBJ_S390+=../arch/s390/gnu/s390-dis.o
OBJ_S390+=../arch/s390/gnu/s390-opc.o

STATIC_OBJ+=${OBJ_S390}
TARGET_S390=asm_s390_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_S390}

${TARGET_S390}: ${OBJ_S390}
	${CC} $(call libname,asm_s390_gnu) ${LDFLAGS} ${CFLAGS} -o asm_s390_gnu.${EXT_SO} ${OBJ_S390}
endif
