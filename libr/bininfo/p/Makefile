CFLAGS=-I../../include -Wall
BINDEPS=

all: bininfo_addr2line.so
	@true

bininfo_addr2line.so: bininfo_addr2line.o
	${CC} ${CFLAGS} -fPIC -shared -o bininfo_addr2line.so bininfo_addr2line.c

clean:
	-rm -f *.so *.o
