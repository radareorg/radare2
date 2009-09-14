NAME=r_crypto
DEPS=r_lib
CFLAGS+=-DCORELIB

foo: pre libr_crypto.so plugins

include ../config.mk
include ${STATIC_CRYPTO_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst crypto_,p/crypto_,$(STATIC_OBJ)))
OBJ=${STATIC_OBJS} crypto.o

pre:
	@if [ ! -e libr_crypto.so ]; then rm -f ${STATIC_OBJS} ; fi

re:
	rm -f crypto.o libr_crypto.so
	${MAKE}
	rm -f t/fastcall.o
	sudo ${MAKE} install
	cd t && ${MAKE}

plugins:
	cd p && ${MAKE} all

include ../rules.mk
