# TODO: append EXECEXT to BINS
FLAGS=-I../../include -Wl,-R.. -L.. -lr_util -g

all: test rax2 ralloc iter file_slurp_hexpairs pool

ralloc:
	${CC} ${FLAGS} ralloc.c -o ralloc

test:
	${CC} ${FLAGS} test.c -o test

pool:
	${CC} ${FLAGS} pool.c -o pool

rax2:
	${CC} ${FLAGS} rax2.c -o rax2

iter:
	${CC} ${FLAGS} iter.c -o iter

file_slurp_hexpairs:
	${CC} -I../../include test_file_slurp_hexpairs.c -lr_util -o file_slurp_hexpairs


clean:
	rm -f calc rax2 ralloc test
