NAME=r_crypto
R2DEPS=r_util
CFLAGS+=-DR2_PLUGIN_INCORE

include ../config.mk

foo:
	@for TARGET in ${LIBSO} ${LIBAR} plugins ; do ${MAKE} $$TARGET ; done

include ${STATIC_CRYPTO_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst crypto_,p/crypto_,$(STATIC_OBJ)))

OBJS=${STATIC_OBJS} crypto.o des.o
include hash/deps.mk

pre:
	@if [ ! -e ${LIBSO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
