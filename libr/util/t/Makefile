BINDEPS=foo
include ../../config.mk
FLAGS=-I../../include -Wl,-R.. -L.. -lr_util -g -DVERSION=\"${VERSION}\"

BINS=test${EXT_EXE}
BINS+=rax2${EXT_EXE}
BINS+=ralloc${EXT_EXE}
BINS+=iter${EXT_EXE}
BINS+=file_slurp_hexpairs${EXT_EXE}
BINS+=pool${EXT_EXE}
BINS+=test_sys${EXT_EXE}
BINS+=test_str${EXT_EXE}

all: ${BINS}

ralloc${EXT_EXE}:
	${CC} ${FLAGS} ralloc.c -o ralloc${EXT_EXE}

test${EXT_EXE}:
	${CC} ${FLAGS} test.c -o test${EXT_EXE}

test_sys${EXT_EXE}: test_sys.c
	${CC} ${FLAGS} test_sys.c -o test_sys${EXT_EXE}

test_str${EXT_EXE}: test_str.c
	${CC} ${FLAGS} test_str.c -o test_str${EXT_EXE}

pool${EXT_EXE}:
	${CC} ${FLAGS} pool.c -o pool${EXT_EXE}

rax2${EXT_EXE}:
	${CC} ${FLAGS} rax2.c -o rax2${EXT_EXE}

iter${EXT_EXE}:
	${CC} ${FLAGS} iter.c -o iter${EXT_EXE}

file_slurp_hexpairs${EXT_EXE}:
	${CC} ${FLAGS} test_file_slurp_hexpairs.c -o file_slurp_hexpairs${EXT_EXE}

myclean:
	rm -f ${BINS}

.PHONY: myclean clean all

include ../../rules.mk
