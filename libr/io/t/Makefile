include ../../config.mk
CFLAGS+=-I../../include -g

ifeq ($(WITHPIC),1)
LDPATH=-L.. ${LDFLAGS_LINKPATH}.. -L../../util -L../../lib
LDPATH+=-lr_io -lr_util -lr_lib
else
LDPATH=../../io/libr_io.a
LDPATH+=../../util/libr_util.a
LDPATH+=../../lib/libr_lib.a
endif

all: map${EXT_EXE} cat${EXT_EXE} read4${EXT_EXE}

cat${EXT_EXE}: cat.o
	${CC} cat.o ${LDPATH} -g -o cat${EXT_EXE}

map${EXT_EXE}: map.o
	${CC} map.o ${LDPATH} -g -o map${EXT_EXE}

read4${EXT_EXE}: read4.o
	${CC} read4.o ${LDPATH} -g -o read4${EXT_EXE}

clean:
	rm -f cat read4 map *.o
