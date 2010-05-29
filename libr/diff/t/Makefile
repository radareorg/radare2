include ../../config.mk

BINDEPS=r_core r_cons r_diff r_util r_flags r_lib r_io r_hash r_cmd r_config r_asm r_anal
BINDEPS+=r_parse r_lang r_debug r_print r_line r_bin r_search r_meta r_reg r_bp r_util r_syscall r_sign

CFLAGS+=-DVERSION=\"${VERSION}\"
CFLAGS+=-g -I../../include

all: test${EXT_EXE}

test${EXT_EXE}: test.o
	${CC} ${CFLAGS} test.o ${LDFLAGS} -o test${EXT_EXE}

myclean:
	rm -f test${EXT_EXE} test.o

include ../../rules.mk
