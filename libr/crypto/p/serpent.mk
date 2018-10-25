OBJ_SERPENT=crypto_serpent.o crypto_serpent_algo.o

DEPS+=r_util
DEPFLAGS=-L../../util -lr_util -L.. -lr_crypto

STATIC_OBJ+=${OBJ_SERPENT}
TARGET_SERPENT=crypto_serpent.${EXT_SO}

ALL_TARGETS+=${TARGET_SERPENT}

${TARGET_SERPENT}: ${OBJ_SERPENT}
	${CC} $(call libname,crypto_serpent) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_SERPENT} ${OBJ_SERPENT} $(DEPFLAGS)
