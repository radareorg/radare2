include ../../../global.mk
include $(LTOP)/config.mk

BINDEPS=r_bin r_flags r_util r_cons
CFLAGS+=-DLIBDIR=\"${LIBDIR}\"

all: test_meta${EXT_EXE} rpathdel${EXT_EXE} test_create${EXT_EXE}

myclean:
	rm -f *.d test_meta${EXT_EXE} test_meta.o rpathdel${EXT_EXE} rpathdel.o test_create${EXT_EXE}

include $(LTOP)/rules.mk
