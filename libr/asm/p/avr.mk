OBJ_AVR=asm_avr.o

STATIC_OBJ+=${OBJ_AVR}
TARGET_AVR=asm_avr.${EXT_SO}

ALL_TARGETS+=${TARGET_AVR}

${TARGET_AVR}: ${OBJ_AVR}
	${CC} -I../arch/avr ${CFLAGS} -o asm_avr.${EXT_SO} ${OBJ_AVR}
	@#strip -s asm_x86.${EXT_SO}
