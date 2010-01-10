# TODO: append EXECEXT to BINS
FLAGS=-I../../include -Wl,-R.. -L.. -lr_util -g -DVERSION=\"${VERSION}\"

all: test rax2 ralloc iter file_slurp_hexpairs pool test_sys test_str

ralloc:
	${CC} ${FLAGS} ralloc.c -o ralloc

test:
	${CC} ${FLAGS} test.c -o test

test_sys: test_sys.c
	${CC} ${FLAGS} test_sys.c -o test_sys

test_str: test_str.c
	${CC} ${FLAGS} test_str.c -o test_str

pool:
	${CC} ${FLAGS} pool.c -o pool

rax2:
	${CC} ${FLAGS} rax2.c -o rax2

iter:
	${CC} ${FLAGS} iter.c -o iter

file_slurp_hexpairs:
	${CC} ${FLAGS} test_file_slurp_hexpairs.c -o file_slurp_hexpairs

clean:
	rm -f a.out calc rax2 ralloc test test_sys pool iter test_str pool file_slurp_hexpairs

include ../../rules.mk
