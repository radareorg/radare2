CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC -shared -Wl,-R..

OBJ_MREPLACE=mreplace/mreplace.o mreplace/mmemory.o

all: parse_dummy.so parse_x86_pseudo.so parse_mreplace.so
	@true

parse_dummy.so:
	${CC} ${CFLAGS} -o parse_dummy.so parse_dummy.c
	@#strip -s parse_dummy.so

parse_x86_pseudo.so: parse_x86_pseudo.o
	${CC} ${CFLAGS} -o parse_x86_pseudo.so parse_x86_pseudo.o
	@#strip -s parse_x86_pseudo.so

parse_mreplace.so: parse_mreplace.o ${OBJ_MREPLACE}
	${CC} ${CFLAGS} -o parse_mreplace.so parse_mreplace.o ${OBJ_MREPLACE}
	@#strip -s parse_mreplace.so

clean:
	-rm -f *.so *.o ${OBJ_MREPLACE}
