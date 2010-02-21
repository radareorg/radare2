include ../../config.mk

all: plugin.${EXT_SO} test-plugin${EXT_EXE}
	@true

plugin.${EXT_SO}:
	${CC} -Wall -o plugin.${EXT_SO} ${LDFLAGS_LIB} plugin.c -I../../include

test-plugin${EXT_EXE}:
	${CC} -Wall -o test-plugin${EXT_EXE} test-plugin.c -I ../../include ../../lib/*.o ${DL_LIBS}

clean:
	-rm -f plugin.${EXT_SO} test-plugin${EXT_EXE}
