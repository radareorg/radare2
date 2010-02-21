include ../../../config.mk
OBJ=interface.o gdbwrapper.o client.o
CFLAGS=-Iinclude -I../../../include
ERESIPATH=${HOME}/prg/eresi
BIN=client

all: ${BIN}

${BIN}: ${OBJ}
	 ${CC} ${OBJ} -o ${BIN}

sync:
	@if [ -d ${ERESIPATH} ]; then \
	cp -v ${ERESIPATH}/libgdbwrap/*.c . ; \
	cp -v ${ERESIPATH}/libgdbwrap/include/*.h include ; \
	echo Sync done ; \
	else \
	echo Give me ERESIPATH ; \
	fi

clean:
	-rm -f client ${OBJ} *.o a.out
