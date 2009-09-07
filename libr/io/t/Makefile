CFLAGS=-I ../../include -g

all: map cat read4

cat: cat.o
	${CC} cat.o -L.. -Wl,-R.. -lr_io -g -o cat

map: map.o
	${CC} map.o -L.. -Wl,-R.. -lr_io -g -o map

read4: read4.o
	${CC} read4.o -L.. -Wl,-R.. -lr_io -g -o read4

clean:
	rm -f cat read4 map *.o
