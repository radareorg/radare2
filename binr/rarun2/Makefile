BIN=rarun2
OBJ=main.o

all: ${BIN}

${BIN}: ${OBJ}
	${CC} -o ${BIN} ${OBJ}

mrproper clean:
	rm -f ${BIN} ${OBJ}

.PHONY: all clean
