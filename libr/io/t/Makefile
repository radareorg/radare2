BINDEPS=r_io r_util r_lib r_socket

all: map${EXT_EXE} cat${EXT_EXE} read4${EXT_EXE}

EXTRA_CLEAN=myclean
include ../../rules.mk

myclean:
	rm -f cat read4 map *.o
