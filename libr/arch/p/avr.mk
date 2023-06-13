OBJ_AVR=p/avr/plugin.o
OBJ_AVR+=p/avr/avr_disasm.o
OBJ_AVR+=p/avr/format.o
OBJ_AVR+=p/avr/disasm.o
OBJ_AVR+=p/avr/assemble.o

STATIC_OBJ+=${OBJ_AVR}
TARGET_AVR=avr.${EXT_SO}

ALL_TARGETS+=${TARGET_AVR}

${TARGET_AVR}: ${OBJ_AVR}
	${CC} $(call libname,avr) ${CFLAGS} -o avr.${EXT_SO} ${OBJ_AVR}
