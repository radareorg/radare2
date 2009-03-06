CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC -shared -Wl,-R..
CFLAGS_IMP=-I../../include -I../arch/ -I../arch/include -w -fPIC -shared -Wl,-R..

all: parse_dummy.so parse_x86_pseudo.so parse_mreplace.so
	@true

parse_dummy.so: parse_dummy.o
	${CC} ${CFLAGS} -o parse_dummy.so parse_dummy.o
	@#strip -s parse_dummy.so

parse_x86_pseudo.so: parse_x86_pseudo.o
	${CC} ${CFLAGS} -o parse_x86_pseudo.so parse_x86_pseudo.o
	@#strip -s parse_x86_pseudo.so

parse_mreplace.so:
	${CC} ${CFLAGS_IMP} -o parse_mreplace.so \
		mreplace/mreplace.c mreplace/mmemory.c
	@#strip -s parse_mreplace.so

clean:
	-rm -f *.so *.o
