CFLAGS=-I ../../include -g
LDPATH=-L.. -L../../util -L../../lib
LDPATH+=-lr_io -lr_util -lr_lib

all: map cat read4

cat: cat.o
	${CC} cat.o ${LDPATH} -Wl,-R.. -lr_io -g -o cat

map: map.o
	${CC} map.o ${LDPATH} -lr_io -g -o map

read4: read4.o
	${CC} read4.o ${LDPATH} -lr_io -g -o read4

clean:
	rm -f cat read4 map *.o
