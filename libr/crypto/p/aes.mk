OBJ_AES=crypto_aes.o

ifeq ($(WANT_SSL_CRYPTO),1)
OBJ_AES+=crypto_aes_algo_ssl.o
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
LDFLAGS+=-lcrypto
else
OBJ_AES+=crypto_aes_algo.o
endif

R2DEPS+=r_util
DEPFLAGS=-L../../util -lr_util -L.. -lr_crypto

STATIC_OBJ+=${OBJ_AES}
TARGET_AES=crypto_aes.${EXT_SO}

ALL_TARGETS+=${TARGET_AES}

${TARGET_AES}: ${OBJ_AES}
	${CC} $(call libname,crypto_aes) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_AES} ${OBJ_AES} $(DEPFLAGS)
