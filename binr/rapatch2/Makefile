OBJ=rapatch.o
BIN=rapatch2${EXT_EXE}

CFLAGS+=-I../../libr/include
LDFLAGS+=-L../../libr/core -lr_core
LDFLAGS+=-L../../libr/util -lr_util
LDFLAGS+=-L../../libr/cons -lr_cons

all: ${BIN}

${BIN}: ${OBJ}
	${CC} -o ${BIN} ${OBJ} ${CFLAGS} ${LDFLAGS}

test: all
	cp /bin/ls ls
	./a.out ls patch.txt
	./ls

clean:
	rm -f a.out RaPatcher RaPatcher.c out.* ls
