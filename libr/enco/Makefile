#include ../config.mk
#include ../../global.mk

NAME=r_enco
DEPS=r_util r_io r_socket r_magic r_hash r_syscall r_bin

.PHONY: do doclean

do:	
	${MAKE} -C d
	${MAKE} -C p

doclean:
	${MAKE} -C d clean

include ../rules.mk
