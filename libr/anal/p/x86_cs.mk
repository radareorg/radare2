OBJ_X86_CS=anal_x86_cs.o
CFLAGS+=-I../../shlr/capstone/include
STATIC_OBJ+=${OBJ_X86_CS}
SHARED_X86_CS=../../shlr/capstone/libcapstone.a

SHARED_OBJ+=${SHARED_X86_CS}
TARGET_X86_CS=anal_x86_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_X86_CS}

${TARGET_X86_CS}: ${OBJ_X86_CS}
	${CC} ${CFLAGS} $(call libname,anal_x86_cs) \
		-o anal_x86_cs.${EXT_SO} ${OBJ_X86_CS}
