OBJ_TMS320=asm_tms320.o
OBJ_TMS320+=../arch/tms320/tms320_dasm.o

#../arch/tms320/c55x_plus/hashvector.o
OBJ_TMS320+=../arch/tms320/c55x_plus/c55plus.o \
	    ../arch/tms320/c55x_plus/c55plus_decode.o \
	    ../arch/tms320/c55x_plus/decode_funcs.o \
	    ../arch/tms320/c55x_plus/hashtable.o \
	    ../arch/tms320/c55x_plus/ins.o \
	    ../arch/tms320/c55x_plus/utils.o

STATIC_OBJ+=${OBJ_TMS320}
TARGET_TMS320=asm_tms320.${EXT_SO}

include ${CURDIR}capstone.mk

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_TMS320}

STATIC_OBJ+=${OBJ_TMS320C64X_CS}
SHARED_OBJ+=${SHARED_TMS320C64X_CS}
#TARGET_TMS320C64X_CS=asm_tms320c64x.${EXT_SO}

${TARGET_TMS320}: ${OBJ_TMS320}
	${CC} $(call libname,asm_tms320) ${CS_CFLAGS} ${LDFLAGS} ${CFLAGS} ${OBJ_TMS320} ${CS_LDFLAGS}
endif
