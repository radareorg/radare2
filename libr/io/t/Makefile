CFLAGS=-I ../../include -g
LDPATH=-L.. -Wl,-R.. -L../../util -L../../lib
LDPATH+=-lr_io -lr_util -lr_lib

all: map cat${EXT_EXE} read4${EXT_EXE}

cat${EXT_EXE}: cat.o
	${CC} cat.o ${LDPATH} -Wl,-R.. -g -o cat${EXT_EXE}

map${EXT_EXE}: map.o
	${CC} map.o ${LDPATH} -g -o map${EXT_EXE}

read4${EXT_EXE}: read4.o
	${CC} read4.o ${LDPATH} -g -o read4${EXT_EXE}

clean:
	rm -f cat read4 map *.o
