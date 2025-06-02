OBJ_AES=muta_aes.o

ifeq ($(WANT_SSL_CRYPTO),1)
OBJ_AES+=p/algo/crypto_aes_ssl.o
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
LDFLAGS+=-lmuta
else
OBJ_AES+=p/algo/crypto_aes.o
endif

R2DEPS+=r_util
# DEPFLAGS=-L../../util -lr_util -L.. -lr_codec

STATIC_OBJ+=${OBJ_AES}
TARGET_AES=muta_aes.${EXT_SO}

ALL_TARGETS+=${TARGET_AES}

${TARGET_AES}: ${OBJ_AES}
	${CC} $(call libname,muta_aes) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_AES} ${OBJ_AES} $(DEPFLAGS)
