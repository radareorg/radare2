OBJ_BECH32=muta_bech32.o

STATIC_OBJ+=${OBJ_BECH32}
TARGET_BECH32=muta_bech32.${EXT_SO}

ALL_TARGETS+=${TARGET_BECH32}
# DEPFLAGS=-L.. -lr_muta -I../../../include

${TARGET_BECH32}: ${OBJ_BECH32}
	${CC} $(call libname,muta_bech32) $(DEPFLAGS) \
		${LDFLAGS} ${CFLAGS} -o ${TARGET_BECH32} ${OBJ_BECH32}
