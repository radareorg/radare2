OBJ_AES=crypto_aes.o crypto_aes_algo.o

R2DEPS+=r_util
DEPFLAGS=-L../../util -lr_util -L.. -lr_crypto

STATIC_OBJ+=${OBJ_AES}
TARGET_AES=crypto_aes.${EXT_SO}

ALL_TARGETS+=${TARGET_AES}

${TARGET_AES}: ${OBJ_AES}
	${CC} $(call libname,crypto_aes) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_AES} ${OBJ_AES} $(DEPFLAGS)
