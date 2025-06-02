NAME=r_muta
R2DEPS=r_util
CFLAGS+=-DR2_PLUGIN_INCORE

include ../config.mk

foo:
	@for TARGET in ${LIBSO} ${LIBAR} plugins ; do ${MAKE} $$TARGET ; done

include ${STATIC_MUTA_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst muta_,p/muta_,$(STATIC_OBJ)))

OBJS=${STATIC_OBJS} muta.o
include hash/deps.mk
include signature/ed25519/deps.mk

pre:
	@if [ ! -e ${LIBSO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
