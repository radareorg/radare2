include ../../config.mk

BINDEPS=r_util

BINS=test${EXT_EXE}
BINS=set0${EXT_EXE}
BINS+=rax2${EXT_EXE}
BINS+=ralloc${EXT_EXE}
BINS+=array${EXT_EXE}
BINS+=pool${EXT_EXE}
BINS+=argv${EXT_EXE}
BINS+=test_sys${EXT_EXE}
BINS+=test_str${EXT_EXE}
BINS+=test_file_slurp_hexpairs${EXT_EXE}
BINS+=test_cmd_str${EXT_EXE}

all: ${BINS}

myclean:
	rm -f ${BINS}

.PHONY: myclean clean all

include ../../rules.mk
