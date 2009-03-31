NAME=r_diff
OBJ=diff.o
DEPS=r_util

EXTRA_TARGETS=linediff
EXTRA_CLEAN=clean_me

all: real_all

clean_me:
	rm -f linediff

linediff:
	gcc -Wall bdiff.c -I ../include/ -L../util -Wl,-R../util -lr_util -o linediff

include ../rules.mk
