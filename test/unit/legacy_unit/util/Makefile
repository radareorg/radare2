include ../../config.mk

BINDEPS=r_util

LDFLAGS+=-lr_util -L..

BINS=sparse
BINS+=array
BINS+=pool
BINS+=argv
BINS+=test_sys
BINS+=test_str
BINS+=test_file_slurp_hexpairs
BINS+=test_cmd_str
BINS+=test_queue
BINS+=test_tree
BINS+=test_graph

all: ${BINS}

${BINS}: $(addsuffix .o,$(BINS))
	$(CC) $(LDFLAGS) -o $@ $@.o

myclean:
	rm -f ${BINS} *.o

clean:: myclean

.PHONY: myclean clean all

include ../../rules.mk
