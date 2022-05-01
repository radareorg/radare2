OBJ_ANAL_S390GNU_GNU=anal_s390_gnu.o
OBJ_ANAL_S390GNU_GNU+=../../asm/arch/s390/gnu/s390-dis.o
OBJ_ANAL_S390GNU_GNU+=../../asm/arch/s390/gnu/s390-opc.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_ANAL_S390GNU_GNU}

TARGET_ANAL_S390GNU_GNU=anal_s390_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_ANAL_S390GNU_GNU}

${TARGET_ANAL_S390GNU_GNU}: ${OBJ_SYSTEMZ_GNU}
	${CC} ${CFLAGS} $(call libname,anal_s390_gnu) $(GNU_LDFLAGS) \
		-o anal_s390_gnu.${EXT_SO} ${OBJ_ANAL_S390GNU_GNU}
