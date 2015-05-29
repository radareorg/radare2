include ../../config.mk

BINDEPS=r_util

LDFLAGS+=-lr_util -L..

BINS=test
BINS+=set0
BINS+=sparse
BINS+=rax2
#BINS+=ralloc
BINS+=array
BINS+=pool
BINS+=argv
BINS+=test_sys
BINS+=test_str
BINS+=test_file_slurp_hexpairs
BINS+=test_cmd_str

all: ${BINS}

${BINS}: $(addsuffix .o,$(BINS))
	$(CC) $(LDFLAGS) -o $@ $< 

myclean:
	rm -f ${BINS} *.o

clean:: myclean

.PHONY: myclean clean all

include ../../rules.mk
