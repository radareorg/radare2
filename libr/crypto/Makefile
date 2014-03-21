NAME=r_crypto
DEPS=r_util
CFLAGS+=-DCORELIB

include ../config.mk

foo:
	@for a in ${LIBSO} ${LIBAR} plugins ; do ${MAKE} $$a ; done

include ${STATIC_CRYPTO_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst crypto_,p/crypto_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} crypto.o

pre:
	@if [ ! -e ${LIBSO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
