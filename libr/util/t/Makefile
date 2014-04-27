include ../../config.mk

BINDEPS=r_util

BINS=test
BINS=set0
BINS+=rax2
BINS+=ralloc
BINS+=array
BINS+=pool
BINS+=argv
BINS+=test_sys
BINS+=test_str
BINS+=test_file_slurp_hexpairs
BINS+=test_cmd_str

all: ${BINS}

myclean:
	rm -f ${BINS}

.PHONY: myclean clean all

include ../../rules.mk
