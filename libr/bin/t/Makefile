include ../../config.mk

BINDEPS=r_lib r_bin r_flags r_util r_cons
CFLAGS+=-DLIBDIR=\"${LIBDIR}\"

all: test_meta${EXT_EXE} rpathdel${EXT_EXE} test_create${EXT_EXE}

myclean:
	rm -f test_meta${EXT_EXE} test_meta.o rpathdel${EXT_EXE} rpathdel.o

include ../../rules.mk
