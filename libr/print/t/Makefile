include ../../config.mk

all: hex fmt

BIN=hex
OBJ=hex.o
BINDEPS=r_cons r_print r_util

fmt${EXT_EXE}: fmt.o

myclean:
	rm -f fmt fmt.o

include ../../rules.mk
