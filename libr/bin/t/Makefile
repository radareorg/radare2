include ../../config.mk

OBJ=rabin2.o
BIN=rabin2${EXT_EXE}
BINDEPS=r_lib r_bin r_flags r_util r_cons
CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"
LIBS+=${DL_LIBS}

LDPATH=-L.. -L../../util
LDPATH+=-lr_util

all: ${BIN} test_meta${EXT_EXE} mach-ex${EXT_EXE} rpathdel${EXT_EXE}

test_meta${EXT_EXE}: test_meta.o
	${CC} test_meta.o ${LDPATH} ${LDFLAGS} -o test_meta${EXT_EXE} 

rpatdel${EXT_EXE}: rpathdel.o
	${CC} rpathdel.o ${LDPATH} ${LDFLAGS} -o rpathdel${EXT_EXE} 

mach-ex${EXT_EXE}:
	${CC} -o mach-ex${EXT_EXE} mach-ex.c

myclean:
	rm -f test_meta test_meta.o mach-ex rpathdel

include ../../rules.mk
