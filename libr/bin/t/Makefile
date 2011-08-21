include ../../config.mk

BINDEPS=r_lib r_bin r_flags r_util r_cons
CFLAGS+=-DLIBDIR=\"${LIBDIR}\"
LIBS+=${DL_LIBS}

LDPATH=-L.. -L../../util
LDPATH+=-lr_util

all: test_meta${EXT_EXE} rpathdel${EXT_EXE} test_create${EXT_EXE}

test_meta${EXT_EXE}: test_meta.o
	${CC} test_meta.o ${LDPATH} ${LDFLAGS} -o test_meta${EXT_EXE} 

rpathdel${EXT_EXE}: rpathdel.o
	${CC} rpathdel.o ${LDPATH} ${LDFLAGS} -o rpathdel${EXT_EXE} 

test_create${EXT_EXE}: test_create.o
	${CC} test_create.o ${LDPATH} ${LDFLAGS} -o test_create${EXT_EXE} 

myclean:
	rm -f test_meta${EXT_EXE} test_meta.o rpathdel${EXT_EXE} rpathdel.o

include ../../rules.mk
