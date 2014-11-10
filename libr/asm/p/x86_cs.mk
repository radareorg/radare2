# capstone

OBJ_X86CS=asm_x86_cs.o

include ${CURDIR}capstone.mk

# SHARED2_X86CS=$(addprefix ../,${SHARED_X86CS})

STATIC_OBJ+=${OBJ_X86CS}
TARGET_X86CS=asm_x86_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_X86CS}

${TARGET_X86CS}: ${OBJ_X86CS}
	${CC} $(call libname,asm_x86) ${LDFLAGS} ${CFLAGS} ${CS_CFLAGS} \
		-o ${TARGET_X86CS} ${OBJ_X86CS} ${CS_LDFLAGS}
