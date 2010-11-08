include ../../config.mk

all: plugin.${EXT_SO} test-plugin${EXT_EXE}
	@true

plugin.${EXT_SO}:
	${CC} ${CFLAGS} -shared -Wall -o plugin.${EXT_SO} ${LDFLAGS_LIB} plugin.c -I../../include

test-plugin${EXT_EXE}:
	${CC} ${CFLAGS} -Wall -o test-plugin${EXT_EXE} test-plugin.c -L../../util/ -lr_util -I../../include ../*.o ${DL_LIBS}

clean:
	-rm -f plugin.${EXT_SO} test-plugin${EXT_EXE}
