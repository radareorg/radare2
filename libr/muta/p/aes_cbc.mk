OBJ_AES_CBC=muta_aes_cbc.o

STATIC_OBJ+=${OBJ_AES_CBC}
TARGET_AES_CBC=muta_aes_cbc.${EXT_SO}

ALL_TARGETS+=${TARGET_AES_CBC}
# DEPFLAGS=-L.. -lr_muta -I../../../include

${TARGET_AES_CBC}: ${OBJ_AES_CBC}
	${CC} $(call libname,muta_aes_cbc) $(DEPFLAGS) \
		${LDFLAGS} ${CFLAGS} -o ${TARGET_AES_CBC} ${OBJ_AES_CBC}
