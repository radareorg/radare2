OBJ_X86_CS=anal_x86_cs.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=$(OBJ_X86_CS)

TARGET_X86_CS=anal_x86_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_X86_CS}

${TARGET_X86_CS}: ${OBJ_X86_CS}
	${CC} ${CFLAGS} $(call libname,anal_x86_cs) $(CS_CFLAGS) \
		-o anal_x86_cs.${EXT_SO} ${OBJ_X86_CS} $(CS_LDFLAGS)
