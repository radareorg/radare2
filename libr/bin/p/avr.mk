OBJ_AVR=bin_avr.o

STATIC_OBJ+=${OBJ_AVR}
TARGET_AVR=bin_avr.${EXT_SO}

ALL_TARGETS+=${TARGET_AVR}

${TARGET_AVR}: ${OBJ_AVR}
	${CC} $(call libname,bin_avr) -shared ${CFLAGS} \
		-o ${TARGET_AVR} ${OBJ_AVR} $(LINK) $(LDFLAGS)
