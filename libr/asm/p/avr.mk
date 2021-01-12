OBJ_AVR=asm_avr.o
OBJ_AVR+=../arch/avr/avr_disasm.o
OBJ_AVR+=../arch/avr/format.o
OBJ_AVR+=../arch/avr/disasm.o

STATIC_OBJ+=${OBJ_AVR}
TARGET_AVR=asm_avr.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_AVR}

${TARGET_AVR}: ${OBJ_AVR}
	${CC} $(call libname,asm_avr) ${LDFLAGS} \
		-I../arch/avr ${CFLAGS} -o asm_avr.${EXT_SO} ${OBJ_AVR}
endif
