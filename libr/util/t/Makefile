BINDEPS=foo
include ../../config.mk
ifeq ($(WITHPIC),1)
FLAGS=-I../../include -Wl,-R.. -L.. -lr_util -g -DVERSION=\"${VERSION}\"
EFLAGS=
else
FLAGS=-I../../include -g -DVERSION=\"${VERSION}\"
EFLAGS=../libr_util.a
endif

BINS=test${EXT_EXE}
BINS+=rax2${EXT_EXE}
BINS+=ralloc${EXT_EXE}
BINS+=array${EXT_EXE}
BINS+=pool${EXT_EXE}
BINS+=test_sys${EXT_EXE}
BINS+=test_str${EXT_EXE}
BINS+=test_file_slurp_hexpairs${EXT_EXE}
BINS+=test_cmd_str${EXT_EXE}

all: ${BINS}

ralloc${EXT_EXE}:
	${CC} ${FLAGS} ralloc.c ${EFLAGS} -o ralloc${EXT_EXE}

test${EXT_EXE}:
	${CC} ${FLAGS} test.c ${EFLAGS} -o test${EXT_EXE}

test_sys${EXT_EXE}: test_sys.c
	${CC} ${FLAGS} test_sys.c ${EFLAGS} -o test_sys${EXT_EXE}

test_str${EXT_EXE}: test_str.c
	${CC} ${FLAGS} test_str.c ${EFLAGS} -o test_str${EXT_EXE}

pool${EXT_EXE}:
	${CC} ${FLAGS} pool.c ${EFLAGS} -o pool${EXT_EXE}

rax2${EXT_EXE}:
	${CC} ${FLAGS} rax2.c ${EFLAGS} -o rax2${EXT_EXE}

array${EXT_EXE}:
	${CC} ${FLAGS} array.c ${EFLAGS} -o array${EXT_EXE}

test_file_slurp_hexpairs${EXT_EXE}:
	${CC} ${FLAGS} test_file_slurp_hexpairs.c ${EFLAGS} -o test_file_slurp_hexpairs${EXT_EXE}

test_cmd_str${EXT_EXE}:
	${CC} ${FLAGS} test_cmd_str.c ${EFLAGS} -o test_cmd_str${EXT_EXE}

myclean:
	rm -f ${BINS}

.PHONY: myclean clean all

include ../../rules.mk
