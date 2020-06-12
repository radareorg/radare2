include ../config.mk

NAME=r_lang
OBJS=lang.o
R2DEPS=r_util r_cons

include ../rules.mk

pop:
	make
	r2 -c '#!rust' -
