CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC -shared -Wl,-R..

all: parse_dummy.so parse_x86_pseudo.so
	@true

parse_dummy.so:
	${CC} ${CFLAGS} -o parse_dummy.so parse_dummy.c
	@#strip -s parse_dummy.so

parse_x86_pseudo.so: parse_x86_pseudo.o
	${CC} ${CFLAGS} -o parse_x86_pseudo.so parse_x86_pseudo.o
	@#strip -s parse_x86_pseudo.so

clean:
	-rm -f *.so *.o
