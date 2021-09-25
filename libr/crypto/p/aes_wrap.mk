OBJ_AES_WRAP=crypto_aes_wrap.o

STATIC_OBJ+=${OBJ_AES_WRAP}
TARGET_AES_WRAP=crypto_aes_wrap.${EXT_SO}

ALL_TARGETS+=${TARGET_AES_WRAP}
DEPFLAGS=-L.. -lr_crypto  -I../../../include

${TARGET_AES_WRAP}: ${OBJ_AES_WRAP}
	${CC} $(call libname,crypto_aes_wrap) $(DEPFLAGS) \
		${LDFLAGS} ${CFLAGS} -o ${TARGET_AES_WRAP} ${OBJ_AES_WRAP}
