OBJ_AVR=anal_avr.o
OBJ_AVR+=../../asm/arch/avr/avr_disasm.o
OBJ_AVR+=../../asm/arch/avr/format.o
OBJ_AVR+=../../asm/arch/avr/disasm.o

STATIC_OBJ+=${OBJ_AVR}
TARGET_AVR=anal_avr.${EXT_SO}

ALL_TARGETS+=${TARGET_AVR}

${TARGET_AVR}: ${OBJ_AVR}
	${CC} $(call libname,anal_avr) ${CFLAGS} -o anal_avr.${EXT_SO} ${OBJ_AVR}
