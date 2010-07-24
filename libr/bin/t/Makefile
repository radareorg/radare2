include ../../config.mk

BINDEPS=r_lib r_bin r_flags r_util r_cons
CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"
LIBS+=${DL_LIBS}

LDPATH=-L.. -L../../util
LDPATH+=-lr_util

all: test_meta${EXT_EXE} mach-ex${EXT_EXE} rpathdel${EXT_EXE}

test_meta${EXT_EXE}: test_meta.o
	${CC} test_meta.o ${LDPATH} ${LDFLAGS} -o test_meta${EXT_EXE} 

rpathdel${EXT_EXE}: rpathdel.o
	${CC} rpathdel.o ${LDPATH} ${LDFLAGS} -o rpathdel${EXT_EXE} 

mach-ex${EXT_EXE}:
	${CC} ${CFLAGS} -o mach-ex${EXT_EXE} ${LDFLAGS} mach-ex.c

myclean:
	rm -f test_meta test_meta.o mach-ex rpathdel

include ../../rules.mk
