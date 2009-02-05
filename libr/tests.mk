# Compiler
CC?=gcc
CFLAGS+=-I../../include -fPIC
LIBS?=

# Output
EXT_AR=a
EXT_SO=so
LIBAR=${LIB}.${EXT_AR}
LIBSO=${LIB}.${EXT_SO}

# Rules
all: ${BIN}
	@true

${BIN}: ${OBJ}
	${CC} ${LDFLAGS} ${OBJ} -o ${BIN} ${LIBS}

clean:
	-rm -f ${OBJ} ${BIN}

.PHONY: all clean ${BIN}
