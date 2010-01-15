include ../../config.mk

CFLAGS=-I../../include -Wall
BINDEPS=

all: bininfo_addr2line.${EXT_SO}
	@true

bininfo_addr2line.${EXT_SO}: bininfo_addr2line.o
	${CC} ${CFLAGS} -fPIC -shared -o bininfo_addr2line.${EXT_SO} bininfo_addr2line.c

clean:
	-rm -f *.so *.o
