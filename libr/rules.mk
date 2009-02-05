include ../config.mk

CFLAGS+=-DUSE_RIO=${USE_RIO}
CFLAGS+=${CFLAGS_APPEND}

# Compiler
CC?=gcc
CFLAGS+=-I../include -fPIC
CC_LIB=${CC} -shared -o ${LIBSO}
CC_AR=ar -r ${LIBAR}
LINK?=

# Debug
CFLAGS+=-g -Wall

# Output
EXT_AR=a
EXT_SO=so
LIB=lib${NAME}
LIBAR=${LIB}.${EXT_AR}
LIBSO=${LIB}.${EXT_SO}

# Rules
all: ${OBJ} ${LIBSO} ${LIBAR}
	@if [ -e t/Makefile ]; then (cd t && ${MAKE} all) ; else true ; fi
	@if [ -e plugins/Makefile ]; then (cd plugins && ${MAKE} all) ; else true ; fi

${LIBSO}:
	${CC_LIB} ${LDFLAGS} ${LINK} ${OBJ}
	@sh ../stripsyms.sh ${LIBSO} ${NAME}

${LIBAR}:
	${CC_AR} ${OBJ}

clean:
	-rm -f ${LIBSO} ${LIBAR} ${OBJ} ${BIN} *.so a.out *.a
	@if [ -e t/Makefile ]; then (cd t && ${MAKE} clean) ; else true ; fi

.PHONY: all clean ${LIBSO} ${LIBAR}
