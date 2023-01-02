OBJ_ENTROPY=crypto_entropy.o

R2DEPS+=r_util
DEPFLAGS=-L../../util -lr_util -L.. -lr_crypto

STATIC_OBJ+=${OBJ_ENTROPY}
TARGET_ENTROPY=crypto_entropy.${EXT_SO}

ALL_TARGETS+=${TARGET_ENTROPY}

${TARGET_ENTROPY}: ${OBJ_ENTROPY}
	${CC} $(call libname,crypto_entropy) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_ENTROPY} ${OBJ_ENTROPY} $(DEPFLAGS)
